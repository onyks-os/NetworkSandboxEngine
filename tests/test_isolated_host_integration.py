"""The host endpoint and NSE's own firewall, on a real kernel (root only).

The default simple topology puts ``host_ip`` in the namespace NSE runs in, so a
firewall there (firewalld's zone for a new interface, ufw, a hand-written
ruleset) filters what the sandbox sends to it. These tests install such a
firewall, scoped to the test's own interface and removed afterwards, and check
that the default topology is warned about and that ``isolated_host=True`` takes
the endpoint, its server and its capture out of the path.
"""

from __future__ import annotations

import contextlib
import logging
import os
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from nse.core import host_firewall
from nse.core.netns_controller import NetnsController
from nse.core.paths import resolve
from nse.core.sniffer import PCAPAsserter
from nse.core.utils import is_in_container

pytestmark = [
    pytest.mark.integration,
    pytest.mark.asyncio,
    pytest.mark.skipif(os.geteuid() != 0, reason="requires root and real network namespaces"),
]

PORT = 9999
ECHO = (
    "import socket, sys\n"
    "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
    "s.bind((sys.argv[1], int(sys.argv[2])))\n"
    "print('bound', flush=True)\n"
    "while True:\n"
    "    data, peer = s.recvfrom(2048)\n"
    "    s.sendto(data, peer)\n"
)
ASK = (
    "import socket, sys\n"
    "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
    "s.settimeout(2)\n"
    "s.sendto(b'ping', (sys.argv[1], int(sys.argv[2])))\n"
    "try:\n"
    "    print(s.recv(2048).decode())\n"
    "except OSError:\n"
    "    sys.exit(1)\n"
)
TABLE = "nse_test_hostfw"


@contextlib.contextmanager
def host_firewall_for(iface: str) -> Iterator[None]:
    """Reject local input from *iface* only, as firewalld's default zone would."""
    nft = resolve("nft")
    subprocess.run(
        [nft, "-f", "-"],
        input=(
            f"table inet {TABLE} {{\n"
            "  chain input {\n"
            "    type filter hook input priority 0; policy accept;\n"
            f'    iifname != "{iface}" accept\n'
            "    reject\n"
            "  }\n"
            "}\n"
        ),
        text=True,
        check=True,
    )
    try:
        yield
    finally:
        subprocess.run([nft, "delete", "table", "inet", TABLE], check=False)


def _controller() -> NetnsController:
    return NetnsController(use_nsenter=True if is_in_container() else None)


async def _echo_round_trip(server: object, client: object, address: str) -> bool:
    echo = await server.start_process(  # type: ignore[attr-defined]
        [sys.executable, "-c", ECHO, address, str(PORT)], stdout="capture"
    )
    try:
        await echo.wait_for_output(b"bound", timeout=10)
        result = await client.run_process(  # type: ignore[attr-defined]
            [sys.executable, "-c", ASK, address, str(PORT)], timeout=10
        )
        return result.returncode == 0 and b"ping" in result.stdout
    finally:
        await echo.terminate()


async def test_default_topology_is_filtered_by_nses_firewall_and_warns(
    runtime_registry: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The failure TransparentTorProxy saw on Fedora, reproduced and diagnosed."""
    monkeypatch.setattr(host_firewall, "_findings", None)  # read the real ruleset
    controller = _controller()
    # Interface names are derived from the namespace name, so the firewall can
    # be installed before the namespace exists and match nothing else.
    from nse.core.netns_controller import NamespaceSandbox

    iface = NamespaceSandbox(controller, "nse_fwdefault").ext_iface
    with host_firewall_for(iface), caplog.at_level(logging.WARNING, logger="nse.core.netns"):
        async with controller.create_namespace("nse_fwdefault") as ns:
            # The echo server runs where host_ip lives: NSE's own namespace.
            echo = subprocess.Popen(
                [sys.executable, "-c", ECHO, ns._source_v4, str(PORT)], stdout=subprocess.PIPE
            )
            try:
                assert echo.stdout is not None
                assert echo.stdout.readline() == b"bound\n"
                result = await ns.run_process(
                    [sys.executable, "-c", ASK, ns._source_v4, str(PORT)], timeout=10
                )
                assert result.returncode == 1, "the host firewall should have dropped the ping"
            finally:
                echo.kill()
                echo.wait()
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert any(TABLE in w and "isolated_host=True" in w for w in warnings), warnings


async def test_isolated_host_is_not_filtered_and_captures_in_its_namespace(
    runtime_registry: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(host_firewall, "_findings", None)
    controller = _controller()
    from nse.core.netns_controller import NamespaceSandbox

    iface = NamespaceSandbox(controller, "nse_fwiso").ext_iface
    with host_firewall_for(iface), caplog.at_level(logging.WARNING, logger="nse.core.netns"):
        async with controller.create_namespace("nse_fwiso", isolated_host=True) as ns:
            assert ns.host is not None
            assert ns.ext_netns == "nsh_nse_fwiso"
            assert not Path(f"/sys/class/net/{ns.ext_iface}").exists()  # not in NSE's namespace

            asserter = PCAPAsserter(
                iface=ns.ext_iface, filter=f"udp port {PORT}", netns=ns.ext_netns
            )
            await asserter.start()
            assert await _echo_round_trip(ns.host, ns, ns._source_v4)
            report = await asserter.stop_report()
            assert report.netns == ns.ext_netns
            assert report.instrument_healthy
            assert report.window_complete is True
            assert report.packets_observed == 2  # request and reply

            # Injection from the isolated endpoint into the sandbox, captured inside it.
            inbound = PCAPAsserter(iface=ns.peer_iface, filter="udp port 53", netns=ns.name)
            await inbound.start()
            await ns.inject_packet("udp", 53, "10.0.1.2")
            packets = await inbound.stop()
            assert len(packets) == 1

            # And the reverse direction through the host view.
            outbound = PCAPAsserter(iface=ns.ext_iface, filter="udp port 54", netns=ns.ext_netns)
            await outbound.start()
            await ns.host.inject_packet("udp", 54, "10.0.1.1")
            assert len(await outbound.stop()) == 1

    assert not [r for r in caplog.records if r.levelno == logging.WARNING]
    netns = subprocess.run([resolve("ip"), "netns", "list"], capture_output=True, text=True)
    assert "nse_fwiso" not in netns.stdout


async def test_a_capture_in_nses_namespace_still_works_after_one_in_another(
    runtime_registry: Path,
) -> None:
    """Entering a namespace moves only the capture thread, never the process."""
    controller = _controller()
    before = os.stat("/proc/self/ns/net").st_ino
    async with controller.create_namespace("nse_fwboth", isolated_host=True) as iso:
        inside = PCAPAsserter(iface=iso.ext_iface, netns=iso.ext_netns)
        await inside.start()
        await inside.stop()
    assert os.stat("/proc/self/ns/net").st_ino == before
    async with controller.create_namespace("nse_fwplain") as plain:
        outside = PCAPAsserter(iface=plain.ext_iface, filter="udp port 55")
        await outside.start()
        await plain.inject_packet("udp", 55, "8.8.8.8", src_ip="10.0.0.2")
        assert len(await outside.stop()) == 1
