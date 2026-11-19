#!/usr/bin/env python3
"""
Real TCP and UDP applications behind a ruleset, checked on the wire.

What it shows
-------------
* A real server, not synthetic packets: it binds TCP 80 and UDP 53 inside the
  sandbox, running as ``nobody`` with only ``CAP_NET_BIND_SERVICE``. NSE
  verifies that identity before the server is allowed to start.
* A real client on the host talks to it through the veth link.
* A capture writes the traffic to a PCAP file progressively, keeping only
  counters in memory.
* The negative claim ("DNS gets no answer") is never trusted on its own:
  1. Before the ruleset is loaded, the same query gets an answer, so the
     server and the path work.
  2. The capture sees the query go out, so it is watching the right path.
  3. The capture sees a TCP reply come back, so it can see the sandbox answer.
  Only then does "no DNS answer on the wire" mean the ruleset blocked it.

Run::

    sudo python3 examples/real_application.py [--out DIR]

Expected: every check prints ``[OK]`` and the exit code is 0. DIR (default
``nse-example-output/real_application``) receives ``wire.pcap``,
``capture.json`` and ``server.json``.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import shutil
import socket
import sys
from pathlib import Path

from nse import CaptureLimits, NetnsController, PCAPAsserter, ProcessIdentity
from nse.core.rule_engine import RuleEngine

HOST = "10.0.1.1"  # the host end of the veth link
SANDBOX = "10.0.1.2"  # the server, inside the namespace

RULES = """
table inet app {
    chain input {
        type filter hook input priority 0; policy drop;
        ct state established,related accept
        tcp dport 80 accept
    }
}
"""

#: The application: an echo server on TCP 80 and UDP 53, dual stack.
SERVER = r"""
import socket, threading

def tcp():
    s = socket.socket(socket.AF_INET6)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("::", 80))
    s.listen()
    while True:
        conn, _ = s.accept()
        with conn:
            conn.sendall(b"tcp:" + conn.recv(1024))

def udp():
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.bind(("::", 53))
    while True:
        data, peer = s.recvfrom(1024)
        s.sendto(b"udp:" + data, peer)

threading.Thread(target=tcp, daemon=True).start()
threading.Thread(target=udp, daemon=True).start()
print("ready", flush=True)
threading.Event().wait()
"""

NOBODY = ProcessIdentity(uid=65534, gid=65534, capabilities={"net_bind_service"})

failures: list[str] = []


def check(ok: bool, message: str) -> bool:
    print(f"  [{'OK' if ok else 'FAIL'}] {message}")
    if not ok:
        failures.append(message)
    return ok


def tcp_exchange(payload: bytes) -> bytes | None:
    try:
        with socket.create_connection((SANDBOX, 80), timeout=2) as conn:
            conn.sendall(payload)
            return conn.recv(1024)
    except OSError:
        return None


def udp_exchange(payload: bytes) -> bytes | None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(1.0)
        sock.sendto(payload, (SANDBOX, 53))
        try:
            return sock.recv(1024)
        except OSError:
            return None


def count(pcap: Path, *, src: str, proto: str, port_field: str, port: int) -> int:
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.utils import rdpcap

    layer = TCP if proto == "tcp" else UDP
    return sum(
        1
        for frame in rdpcap(str(pcap))
        if frame.haslayer(IP)
        and frame[IP].src == src
        and frame.haslayer(layer)
        and getattr(frame[layer], port_field) == port
    )


async def main(out: Path) -> int:
    python = shutil.which("python3", path="/usr/bin:/bin")
    if python is None:
        print("needs a system python3 that nobody can execute", file=sys.stderr)
        return 2
    out.mkdir(parents=True, exist_ok=True)
    pcap = out / "wire.pcap"
    pcap.unlink(missing_ok=True)  # captures never overwrite an existing file

    controller = NetnsController()
    async with controller.create_namespace(
        "nse_ex_app", host_ip=f"{HOST}/24", peer_ip=f"{SANDBOX}/24"
    ) as ns:
        print("1. The server starts with a verified, unprivileged identity")
        server = await ns.start_process([python, "-u", "-c", SERVER], identity=NOBODY)
        await server.wait_for_output(b"ready", timeout=10)
        check(server.identity.uids == (65534,) * 4, f"runs as uid 65534: {server.identity.uids}")
        check(
            server.identity.capabilities_effective == ("net_bind_service",),
            f"holds only net_bind_service: {server.identity.capabilities_effective}",
        )

        print("2. Positive control, no ruleset yet: both services answer")
        check(await asyncio.to_thread(tcp_exchange, b"hello") == b"tcp:hello", "TCP 80 echoes")
        check(await asyncio.to_thread(udp_exchange, b"query") == b"udp:query", "UDP 53 echoes")

        print("3. With the ruleset: HTTP passes, DNS does not")
        await asyncio.to_thread(RuleEngine(use_nsenter=controller.use_nsenter).load, RULES, ns.name)
        capture = PCAPAsserter(
            ns.ext_iface,
            filter="tcp port 80 or udp port 53",
            output=pcap,
            limits=CaptureLimits(max_duration=60, max_file_bytes=1_000_000),
        )
        await capture.start()
        check(
            await asyncio.to_thread(tcp_exchange, b"hello") == b"tcp:hello", "TCP 80 still echoes"
        )
        check(await asyncio.to_thread(udp_exchange, b"query") is None, "UDP 53 gets no answer")
        report = await capture.stop_report()
        (out / "capture.json").write_text(report.model_dump_json(indent=2))

        print("4. The wire agrees, and the capture is shown to be able to see it")
        check(report.instrument_healthy, f"capture healthy: {report.termination} {report.errors}")
        check(report.window_complete is True, f"nothing dropped or cut off: {report.kernel_drops}")
        check(report.packets_stored == 0, "memory held counters only (file mode)")
        queries = count(pcap, src=HOST, proto="udp", port_field="dport", port=53)
        tcp_replies = count(pcap, src=SANDBOX, proto="tcp", port_field="sport", port=80)
        dns_replies = count(pcap, src=SANDBOX, proto="udp", port_field="sport", port=53)
        check(queries >= 1, f"control: the DNS query is on the wire ({queries})")
        check(tcp_replies >= 1, f"control: replies from the sandbox are visible ({tcp_replies})")
        check(dns_replies == 0, f"no DNS answer left the sandbox ({dns_replies})")

        result = await server.terminate()
        (out / "server.json").write_text(result.model_dump_json(indent=2))

    print(f"Artifacts in {out}")
    if failures:
        print(f"FAILED: {len(failures)} check(s)")
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--out", type=Path, default=Path("nse-example-output/real_application"))
    args = parser.parse_args()
    if os.geteuid() != 0:
        sys.exit("run as root: sudo python3 examples/real_application.py")
    sys.exit(asyncio.run(main(args.out)))
