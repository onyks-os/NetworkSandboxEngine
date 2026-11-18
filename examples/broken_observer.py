#!/usr/bin/env python3
"""
A deliberately failing experiment: the policy is fine, the observer is broken.

Two broken observers, both of which would make a negative assertion pass if
nothing checked the instrument:

1. **A blind trace oracle.** ``NSE_FORCE_BLIND`` makes the trace parser
   understand nothing, as a kernel format change would. With no verdicts at
   all, "no ACCEPT was seen" looks like "everything was dropped". NSE's
   readiness canary is never observed, so the run is an *instrument failure*,
   not a pass.
2. **A capture on the wrong interface.** The claim is "nothing leaves the
   sandbox on UDP 9". The capture watches the host's loopback instead of the
   veth link, so it sees nothing, and the claim looks proven. The positive
   control, a probe datagram that must appear in the capture, does not appear,
   so the claim is rejected. The same probe on the right interface is seen,
   which also shows that the traffic does leave.

Run::

    sudo python3 examples/broken_observer.py [--out DIR]

Expected: ``FAILED AS EXPECTED`` twice and exit code 0. Exit code 1 means the
demo itself is broken: a broken observer went unnoticed. DIR (default
``nse-example-output/broken_observer``) receives ``blind-experiment.json``,
``capture-wrong-interface.json`` and ``capture-right-interface.json``.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import socket
import sys
from pathlib import Path
from typing import Any

from nse import NetnsController, PCAPAsserter
from nse.core.pipeline import run_test_pipeline_report
from nse.models.capture_report import CaptureReport
from nse.models.test_request import PacketSpec, TestRequest

RULES = """
table inet web {
    chain input {
        type filter hook input priority 0; policy drop;
        tcp dport 80 accept
    }
}
"""

HOST, SANDBOX = "10.0.3.1", "10.0.3.2"
PROBE = "import socket, sys; socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b'probe', (sys.argv[1], 9))"


async def blind_oracle(out: Path) -> bool:
    print("1. Blind trace oracle")
    os.environ["NSE_FORCE_BLIND"] = "1"
    try:
        report = await run_test_pipeline_report(
            TestRequest(
                rules=RULES,
                packets=[
                    PacketSpec(protocol="tcp", dst_port=80),
                    PacketSpec(protocol="tcp", dst_port=22),
                ],
            ),
            timeout=120,
        )
    finally:
        del os.environ["NSE_FORCE_BLIND"]
    report.write(out / "blind-experiment.json")
    result = report.result
    print(
        f"   outcome={result.outcome} readiness={result.oracle.readiness} verdicts={result.verdicts}"
    )
    if result.outcome == "instrument_failure" and result.oracle.readiness == "missed":
        print("   FAILED AS EXPECTED: no verdict is reported from an oracle that cannot see.")
        return True
    print("   UNEXPECTED: a blind oracle was not reported as an instrument failure")
    return False


async def captured_probes(ns: Any, iface: str, out: Path, name: str) -> CaptureReport:
    asserter = PCAPAsserter(iface, filter="udp port 9")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
        receiver.bind((HOST, 9))
        receiver.settimeout(5)
        await asserter.start()
        await ns.exec_argv([sys.executable, "-c", PROBE, HOST])  # sandbox -> host
        # An observable effect instead of a sleep: once the host has received
        # the probe, it has crossed the veth link and its packet taps.
        assert await asyncio.to_thread(receiver.recv, 64) == b"probe"
    report = await asserter.stop_report()
    (out / f"{name}.json").write_text(report.model_dump_json(indent=2))
    return report


async def wrong_interface(out: Path) -> bool:
    print("2. Capture on the wrong interface")
    controller = NetnsController()
    async with controller.create_namespace(
        "nse_ex_observer", host_ip=f"{HOST}/24", peer_ip=f"{SANDBOX}/24"
    ) as ns:
        wrong = await captured_probes(ns, "lo", out, "capture-wrong-interface")
        right = await captured_probes(ns, ns.ext_iface, out, "capture-right-interface")
    naive = wrong.instrument_healthy and wrong.packets_observed == 0
    print(f"   naive claim on lo: 'no UDP 9 left the sandbox' -> {naive}")
    control_on_lo = wrong.packets_observed >= 1
    control_on_veth = right.packets_observed >= 1
    print(f"   positive control on lo: probe seen = {control_on_lo}")
    print(f"   positive control on {ns.ext_iface}: probe seen = {control_on_veth}")
    if naive and not control_on_lo and control_on_veth:
        print("   FAILED AS EXPECTED: the control rejects the claim; on the right interface")
        print("   the probe is seen, so traffic does leave the sandbox.")
        return True
    print("   UNEXPECTED: the wrong observer was not exposed by its positive control")
    return False


async def main(out: Path) -> int:
    out.mkdir(parents=True, exist_ok=True)
    results = [await blind_oracle(out), await wrong_interface(out)]
    return 0 if all(results) else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--out", type=Path, default=Path("nse-example-output/broken_observer"))
    args = parser.parse_args()
    if os.geteuid() != 0:
        sys.exit("run as root: sudo python3 examples/broken_observer.py")
    sys.exit(asyncio.run(main(args.out)))
