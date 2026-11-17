"""Real PCAPAsserter readiness and failure reporting on kernel interfaces (root only)."""

from __future__ import annotations

import asyncio
import os
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from nse import CaptureError, CaptureStartError, NetnsController, PCAPAsserter
from nse.core.paths import resolve

pytestmark = [
    pytest.mark.integration,
    pytest.mark.asyncio,
    pytest.mark.skipif(os.geteuid() != 0, reason="requires root and real network interfaces"),
]

_SEND = (
    "import socket,sys; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); "
    "s.sendto(sys.argv[3].encode(), (sys.argv[1], int(sys.argv[2])))"
)


def _capture_threads() -> list[threading.Thread]:
    return [t for t in threading.enumerate() if t.name.startswith("nse-capture-")]


def _descriptors() -> dict[str, str]:
    result = {}
    for fd in os.listdir("/proc/self/fd"):
        try:
            result[fd] = os.readlink(f"/proc/self/fd/{fd}")
        except OSError:  # the descriptor listdir itself used is already gone
            continue
    return result


def _send_from(controller: NetnsController, netns: str, host: str, port: int, payload: str) -> None:
    subprocess.run(
        [*controller.exec_prefix(netns), sys.executable, "-c", _SEND, host, str(port), payload],
        capture_output=True,
        check=True,
        timeout=5,
    )


async def test_packet_sent_immediately_after_start_is_captured(runtime_registry: Path) -> None:
    """No sleep between start() and the stimulus, repeated to expose any race.

    The host socket receiving the datagram proves it already crossed the packet
    taps (they run before the IP layer), so stop() needs no settling delay either.
    """
    controller = NetnsController()
    async with controller.create_namespace("nse_capready") as ns:
        # Measured inside the namespace: the controller's owner lease stays open
        # for its lifetime by design; only the captures must not add descriptors.
        fds = _descriptors()
        host = ns._source_v4
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
            receiver.bind((host, 0))
            receiver.settimeout(5)
            port = receiver.getsockname()[1]
            for attempt in range(25):
                asserter = PCAPAsserter(ns.ext_iface, filter=f"udp port {port}")
                await asserter.start()
                payload = f"ready-{attempt}"
                _send_from(controller, ns.name, host, port, payload)
                assert receiver.recv(1024) == payload.encode()
                packets = await asserter.stop()
                assert len(packets) == 1, (attempt, packets)
                assert payload.encode() in bytes(packets[0])
                report = await asserter.stop_report()
                assert report.instrument_healthy
                assert report.kernel_packets == 1
                assert report.kernel_drops == 0
                assert report.window_complete is True
        assert not _capture_threads()
        assert _descriptors() == fds


async def test_quiet_interface_stops_promptly_with_an_honest_empty_result(
    runtime_registry: Path,
) -> None:
    controller = NetnsController()
    async with controller.create_namespace("nse_capquiet") as ns:
        asserter = PCAPAsserter(ns.ext_iface, filter="udp port 9")
        await asserter.start()
        loop = asyncio.get_running_loop()
        began = loop.time()
        assert await asserter.stop() == []
        assert loop.time() - began < 2
        report = await asserter.stop_report()
        assert report.instrument_healthy
        assert report.window_complete is True


async def test_missing_interface_fails_at_start() -> None:
    asserter = PCAPAsserter("nsecap-missing")
    with pytest.raises(CaptureStartError) as caught:
        await asserter.start()
    assert caught.value.reason == "interface_missing"
    with pytest.raises(CaptureError):
        await asserter.stop()
    assert not _capture_threads()


async def test_invalid_filter_fails_at_start() -> None:
    asserter = PCAPAsserter("lo", filter="this is not bpf", replace_default_filter=True)
    with pytest.raises(CaptureStartError) as caught:
        await asserter.start()
    assert caught.value.reason == "filter_invalid"
    assert not _capture_threads()


async def test_interface_removed_mid_capture_is_a_backend_failure() -> None:
    ip = resolve("ip")
    subprocess.run(
        [ip, "link", "add", "nsecap0", "type", "veth", "peer", "name", "nsecap1"],
        check=True,
        timeout=5,
    )
    try:
        subprocess.run([ip, "link", "set", "nsecap0", "up"], check=True, timeout=5)
        asserter = PCAPAsserter("nsecap0")
        await asserter.start()
        subprocess.run([ip, "link", "del", "nsecap0"], check=True, timeout=5)
        report = await asserter.stop_report()
        assert report.termination in ("backend_terminated", "stopped")
        if report.termination == "stopped":  # the stop raced the error: still not healthy
            assert report.errors
        assert not report.instrument_healthy
        with pytest.raises(CaptureError):
            await asserter.stop()
    finally:
        subprocess.run([ip, "link", "del", "nsecap0"], capture_output=True, timeout=5)
    assert not _capture_threads()
