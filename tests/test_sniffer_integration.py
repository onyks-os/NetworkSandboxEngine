"""Real PCAPAsserter readiness and failure reporting on kernel interfaces (root only)."""

from __future__ import annotations

import asyncio
import gc
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest
from scapy.layers.inet import UDP
from scapy.layers.l2 import Ether
from scapy.utils import rdpcap

from nse import CaptureError, CaptureStartError, NetnsController, PCAPAsserter
from nse.core import sniffer
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
    # Controllers of earlier tests hold their owner lease until collected; collect
    # them now so that none of their descriptors closes during the measurement.
    gc.collect()
    result = {}
    for fd in os.listdir("/proc/self/fd"):
        try:
            result[fd] = os.readlink(f"/proc/self/fd/{fd}")
        except OSError:  # the descriptor listdir itself used is already gone
            continue
    return result


#: Sends argv[3] datagrams of argv[4] bytes as fast as possible.
_FLOOD = (
    "import socket,sys; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); "
    "d=(sys.argv[1], int(sys.argv[2])); p=b'x'*int(sys.argv[4]); "
    "[s.sendto(p, d) for _ in range(int(sys.argv[3]))]"
)


def _flood_from(
    controller: NetnsController, netns: str, host: str, port: int, count: int, size: int
) -> None:
    subprocess.run(
        [
            *controller.exec_prefix(netns),
            sys.executable,
            "-c",
            _FLOOD,
            host,
            str(port),
            str(count),
            str(size),
        ],
        capture_output=True,
        check=True,
        timeout=30,
    )


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


async def test_file_capture_writes_the_real_frames(runtime_registry: Path, tmp_path: Path) -> None:
    controller = NetnsController()
    path = tmp_path / "veth.pcap"
    async with controller.create_namespace("nse_capfile") as ns:
        host = ns._source_v4
        asserter = PCAPAsserter(ns.ext_iface, filter="udp port 9", output=path)
        await asserter.start()
        for index in range(20):
            _send_from(controller, ns.name, host, 9, f"file-{index}")
        assert await asserter.stop() == []  # file mode: no sample unless declared
        report = await asserter.stop_report()
    assert report.instrument_healthy
    assert report.window_complete is True
    assert report.packets_observed == report.packets_written == report.kernel_packets == 20
    assert report.artifact_complete is True
    assert report.bytes_written == path.stat().st_size
    frames = rdpcap(str(path))
    assert all(frame.haslayer(Ether) for frame in frames)  # LINKTYPE_ETHERNET from the veth
    assert [bytes(frame[UDP].payload) for frame in frames] == [
        f"file-{index}".encode() for index in range(20)
    ]
    assert not _capture_threads()


async def test_disk_full_is_reported_with_a_readable_partial_file(
    runtime_registry: Path, tmp_path: Path
) -> None:
    mountpoint = tmp_path / "small"
    mountpoint.mkdir()
    mounted = subprocess.run(
        ["mount", "-t", "tmpfs", "-o", "size=64k", "nse-capture-full", str(mountpoint)],
        capture_output=True,
        timeout=10,
    )
    if mounted.returncode != 0:
        pytest.skip(f"cannot mount a small tmpfs: {mounted.stderr.decode().strip()}")
    try:
        path = mountpoint / "full.pcap"
        controller = NetnsController()
        async with controller.create_namespace("nse_capfull") as ns:
            host = ns._source_v4
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
                receiver.bind((host, 0))
                port = receiver.getsockname()[1]
                asserter = PCAPAsserter(ns.ext_iface, filter=f"udp port {port}", output=path)
                await asserter.start()
                for _ in range(25):  # ~260 KB of frames, paced so the socket buffer keeps up
                    _flood_from(controller, ns.name, host, port, 10, 1000)
                with pytest.raises(CaptureError) as caught:
                    await asserter.stop()
        report = caught.value.report
        assert report is not None
        assert any("No space left on device" in error for error in report.errors), report.errors
        assert not report.instrument_healthy
        assert report.window_complete is False
        assert report.artifact_complete is False
        assert report.artifacts == [str(path)]
        assert report.packets_written is not None
        assert 0 < report.packets_written < report.packets_observed
        assert len(rdpcap(str(path))) > 0  # what reached the disk is still readable
    finally:
        subprocess.run(["umount", str(mountpoint)], capture_output=True, timeout=10)
    assert not _capture_threads()


async def test_a_slow_writer_shows_up_as_kernel_drops_not_memory(
    runtime_registry: Path, tmp_path: Path
) -> None:
    """There is no writer queue: a slow file fills the socket buffer, and the kernel says so."""
    path = tmp_path / "slow.pcap"
    real_open = sniffer._open_socket
    real_write = sniffer._PcapFile.write

    def small_buffer(iface: str, bpf: str) -> object:
        sock = real_open(iface, bpf)
        sock.ins.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        return sock

    def slow(self: object, timestamp: float, raw: bytes) -> None:
        time.sleep(0.005)
        real_write(self, timestamp, raw)  # type: ignore[arg-type]

    controller = NetnsController()
    async with controller.create_namespace("nse_capslow") as ns:
        host = ns._source_v4
        with (
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver,
            patch.object(sniffer, "_open_socket", small_buffer),
            patch.object(sniffer._PcapFile, "write", slow),
        ):
            receiver.bind((host, 0))
            port = receiver.getsockname()[1]
            asserter = PCAPAsserter(ns.ext_iface, filter=f"udp port {port}", output=path)
            await asserter.start()
            _flood_from(controller, ns.name, host, port, 2000, 200)
            report = await asserter.stop_report(timeout=30)
            thread = asserter._loop_thread
    assert report.instrument_healthy  # the instrument worked ...
    assert report.kernel_drops, report  # ... but could not keep up, and the kernel says so
    assert report.window_complete is False
    assert report.packets_observed < 2000
    assert thread is not None
    assert thread.packets == []  # memory stayed bounded: nothing queued in userspace
    assert report.artifact_complete is True  # every packet that was read was written
    assert len(rdpcap(str(path))) == report.packets_written
