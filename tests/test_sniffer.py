"""PCAPAsserter readiness, state machine and report, without privileges.

The kernel packet socket is replaced by a datagram socketpair, so select(),
draining and closing are exercised for real; only opening and the kernel
counters are simulated.
"""

from __future__ import annotations

import asyncio
import contextlib
import errno
import gc
import json
import os
import socket
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from pydantic import ValidationError
from scapy.error import Scapy_Exception
from scapy.packet import Raw
from scapy.utils import rdpcap

from nse import (
    CaptureError,
    CaptureLimits,
    CaptureReport,
    CaptureStartError,
    CaptureStateError,
    PCAPAsserter,
)
from nse.core import sniffer
from nse.core.sniffer import DEFAULT_FILTER

pytestmark = pytest.mark.asyncio

CRASH = b"\x00crash"


class FakeSocket:
    def __init__(self, recv_gate: threading.Event | None = None) -> None:
        self.ins, self.peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.closed = False
        self.recv_gate = recv_gate

    def recv(self) -> Raw:
        data = self.ins.recv(65535)
        if self.recv_gate is not None:
            self.recv_gate.wait(10)
        if data == CRASH:
            raise OSError(errno.ENETDOWN, "Network is down")
        return Raw(data)

    def send(self, payload: bytes) -> None:
        self.peer.send(payload)

    def close(self) -> None:
        self.closed = True
        self.ins.close()
        self.peer.close()


class Backend:
    """Controls what the capture loop sees: socket, open behaviour, counters."""

    def __init__(self) -> None:
        self.socket = FakeSocket()
        self.open_error: BaseException | None = None
        self.open_gate: threading.Event | None = None
        self.stats: tuple[int, int] | None = (0, 0)
        self.stats_calls = 0
        self.linktype = 1
        self.hardware_type: int | None = 1

    def open(self, iface: str, bpf: str) -> FakeSocket:
        self.iface, self.bpf = iface, bpf
        if self.open_gate is not None:
            self.open_gate.wait(10)
        if self.open_error is not None:
            raise self.open_error
        return self.socket

    def read_stats(self, sock: Any) -> tuple[int, int]:
        self.stats_calls += 1
        if self.stats is None:
            raise OSError(errno.ENOPROTOOPT, "Protocol not available")
        return self.stats


@pytest.fixture
def backend() -> Iterator[Backend]:
    fake = Backend()
    with (
        patch.object(sniffer, "_open_socket", fake.open),
        patch.object(sniffer, "_read_stats", fake.read_stats),
        patch.object(sniffer, "_linktype", lambda sock: fake.linktype),
        patch.object(sniffer, "_hardware_type", lambda sock: fake.hardware_type),
    ):
        yield fake
    if fake.open_gate is not None:
        fake.open_gate.set()
    if fake.socket.recv_gate is not None:
        fake.socket.recv_gate.set()
    _wait_for(lambda: not _capture_threads(), 5)
    if not fake.socket.closed:
        fake.socket.close()


def _capture_threads() -> list[threading.Thread]:
    return [t for t in threading.enumerate() if t.name.startswith("nse-capture-")]


def _wait_for(condition: Callable[[], bool], timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.01)
    return condition()


def _open_fds() -> int:
    gc.collect()  # a socket an earlier test dropped must not close mid-measurement
    return len(os.listdir("/proc/self/fd"))


# --------------------------------------------------------------------------- happy path


async def test_packets_sent_right_after_start_and_right_before_stop_are_kept(
    backend: Backend,
) -> None:
    asserter = PCAPAsserter("veth0", filter="udp port 53")
    await asserter.start()
    assert asserter.state == "running"
    assert backend.bpf == f"({DEFAULT_FILTER}) and (udp port 53)"
    for index in range(50):  # immediately, without any sleep: queued, then drained at stop
        backend.socket.send(f"packet-{index}".encode())
    backend.stats = (50, 0)
    packets = await asserter.stop()
    assert [bytes(p) for p in packets] == [f"packet-{i}".encode() for i in range(50)]
    assert all(p.sniffed_on == "veth0" for p in packets)

    report = await asserter.stop_report()
    assert report.termination == "stopped"
    assert report.instrument_healthy
    assert report.window_complete is True
    assert report.packets_observed == report.packets_stored == 50
    assert report.bytes_observed == sum(len(f"packet-{i}") for i in range(50))
    assert report.packets_written is None
    assert report.artifacts == []
    assert report.requested_filter == "udp port 53"
    assert report.effective_filter == backend.bpf
    assert not report.default_filter_replaced
    assert report.backend == "scapy-l2listen"
    assert report.backend_version
    assert report.start_requested_at <= report.started_at <= report.stop_requested_at  # type: ignore[operator]
    assert report.stop_requested_at <= report.stopped_at  # type: ignore[operator]
    assert backend.socket.closed


async def test_stop_without_traffic_is_prompt_and_an_honest_empty_result(
    backend: Backend,
) -> None:
    asserter = PCAPAsserter("veth0")
    await asserter.start()
    began = time.monotonic()
    assert await asserter.stop() == []
    assert time.monotonic() - began < 1.0
    report = await asserter.stop_report()
    assert report.instrument_healthy
    assert report.window_complete is True
    assert report.kernel_packets == 0
    assert report.kernel_drops == 0


async def test_unavailable_counters_are_unknown_never_zero(backend: Backend) -> None:
    backend.stats = None
    asserter = PCAPAsserter("veth0")
    await asserter.start()
    report = await asserter.stop_report()
    assert report.instrument_healthy
    assert report.kernel_packets is None
    assert report.kernel_drops is None
    assert report.window_complete is None
    assert "PACKET_STATISTICS unavailable" in (report.stats_unavailable_reason or "")


async def test_kernel_drops_mark_the_window_incomplete_but_keep_the_historic_list(
    backend: Backend, caplog: pytest.LogCaptureFixture
) -> None:
    asserter = PCAPAsserter("veth0")
    await asserter.start()
    backend.socket.send(b"kept")
    backend.stats = (3, 2)
    assert [bytes(p) for p in await asserter.stop()] == [b"kept"]
    report = await asserter.stop_report()
    assert report.instrument_healthy
    assert report.window_complete is False
    assert "dropped 2 packet" in caplog.text


async def test_counters_are_reset_at_readiness(backend: Backend) -> None:
    asserter = PCAPAsserter("veth0")
    await asserter.start()
    assert backend.stats_calls == 1  # the reset read, before start() returned
    await asserter.stop()
    assert backend.stats_calls == 2


async def test_report_serialises_with_derived_fields(backend: Backend) -> None:
    asserter = PCAPAsserter("veth0", filter="icmp6", replace_default_filter=True)
    await asserter.start()
    report = await asserter.stop_report()
    data = json.loads(report.model_dump_json())
    assert data["instrument_healthy"] is True
    assert data["window_complete"] is True
    assert data["effective_filter"] == "icmp6"
    assert data["default_filter_replaced"] is True
    assert isinstance(report, CaptureReport)


# --------------------------------------------------------------------------- start failures


@pytest.mark.parametrize(
    ("error", "reason"),
    [
        (OSError(errno.ENODEV, "interface 'nope' does not exist"), "interface_missing"),
        (
            Scapy_Exception("Cannot set filter: Failed to compile filter expression x"),
            "filter_invalid",
        ),
        (
            Scapy_Exception("Cannot set filter: libpcap is not available. Cannot compile filter !"),
            "backend_unavailable",
        ),
        (PermissionError(errno.EPERM, "Operation not permitted"), "permission_denied"),
        (RuntimeError("something else"), "backend_error"),
    ],
)
async def test_start_failure_is_classified_and_leaves_nothing_behind(
    backend: Backend, error: BaseException, reason: str
) -> None:
    fds = _open_fds()
    backend.open_error = error
    asserter = PCAPAsserter("nope")
    with pytest.raises(CaptureStartError) as caught:
        await asserter.start()
    assert caught.value.reason == reason
    assert caught.value.report is not None
    assert caught.value.report.termination == "start_failed"
    assert caught.value.report.start_failure == reason
    assert not _capture_threads()
    assert _open_fds() == fds

    report = await asserter.stop_report()
    assert report is caught.value.report
    assert not report.instrument_healthy
    assert report.window_complete is False
    assert report.started_at is None
    assert report.stats_unavailable_reason == "capture never became ready"
    with pytest.raises(CaptureError) as historic:
        await asserter.stop()
    assert historic.value.report is report


async def test_start_timeout_releases_the_socket_once_the_backend_answers(
    backend: Backend,
) -> None:
    backend.open_gate = threading.Event()
    asserter = PCAPAsserter("slow0")
    with pytest.raises(CaptureStartError) as caught:
        await asserter.start(timeout=0.05)
    assert caught.value.reason == "timeout"
    report = await asserter.stop_report()
    assert report.termination == "start_timeout"
    assert not report.instrument_healthy
    backend.open_gate.set()  # the open completes late: the loop must close it at once
    assert _wait_for(lambda: backend.socket.closed and not _capture_threads(), 5)


async def test_cancelling_start_releases_resources(backend: Backend) -> None:
    backend.open_gate = threading.Event()
    asserter = PCAPAsserter("slow0")
    task = asyncio.ensure_future(asserter.start())
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, timeout=10)
    report = await asserter.stop_report()
    assert report.termination == "start_cancelled"
    backend.open_gate.set()
    assert _wait_for(lambda: backend.socket.closed and not _capture_threads(), 5)


# --------------------------------------------------------------------------- runtime failures


async def test_backend_crash_is_an_error_not_an_empty_capture(backend: Backend) -> None:
    asserter = PCAPAsserter("veth0")
    await asserter.start()
    backend.socket.send(b"seen")
    backend.socket.send(CRASH)  # the interface vanishes mid-capture
    assert _wait_for(lambda: not _capture_threads(), 5)
    report = await asserter.stop_report()
    assert report.termination == "backend_terminated"
    assert any("ENETDOWN" in e or "Network is down" in e for e in report.errors)
    assert report.packets_observed == 1
    with pytest.raises(CaptureError, match="backend_terminated"):
        await asserter.stop()


async def test_stop_timeout_is_reported_and_raises(backend: Backend) -> None:
    backend.socket.recv_gate = threading.Event()  # recv() blocks: a wedged backend
    asserter = PCAPAsserter("veth0")
    await asserter.start()
    backend.socket.send(b"stuck")
    report = await asserter.stop_report(timeout=0.1)
    assert report.termination == "stop_timeout"
    assert report.stopped_at is None
    with pytest.raises(CaptureError, match="stop_timeout"):
        await asserter.stop()


# --------------------------------------------------------------------------- state machine


async def test_double_start_is_refused(backend: Backend) -> None:
    asserter = PCAPAsserter("veth0")
    await asserter.start()
    with pytest.raises(CaptureStateError):
        await asserter.start()
    await asserter.stop()
    with pytest.raises(CaptureStateError):
        await asserter.start()


async def test_stop_before_start_is_refused_not_an_empty_success(backend: Backend) -> None:
    asserter = PCAPAsserter("veth0")
    with pytest.raises(CaptureStateError):
        await asserter.stop()
    with pytest.raises(CaptureStateError):
        await asserter.stop_report()


async def test_one_finalisation_feeds_every_stop_call(backend: Backend) -> None:
    asserter = PCAPAsserter("veth0")
    await asserter.start()
    backend.socket.send(b"one")
    reports = await asyncio.gather(asserter.stop_report(), asserter.stop_report(), asserter.stop())
    assert reports[0] is reports[1]
    first = await asserter.stop()
    second = await asserter.stop()
    assert [bytes(p) for p in first] == [bytes(p) for p in second] == [b"one"]
    assert first is not second  # callers may mutate their list safely
    assert await asserter.stop_report() is reports[0]
    assert backend.stats_calls == 2


async def test_stop_waits_for_a_start_in_progress(backend: Backend) -> None:
    backend.open_gate = threading.Event()
    asserter = PCAPAsserter("veth0")
    starting = asyncio.ensure_future(asserter.start())
    await asyncio.sleep(0.02)
    stopping = asyncio.ensure_future(asserter.stop_report())
    await asyncio.sleep(0.02)
    assert not stopping.done()
    backend.open_gate.set()
    assert await starting is None
    report = await stopping
    assert report.termination == "stopped"
    assert report.instrument_healthy


async def test_repeated_sessions_leak_no_thread_or_descriptor(backend: Backend) -> None:
    backend.socket.close()  # the fixture's socket is replaced below; exclude it
    fds = _open_fds()
    for _ in range(5):
        backend.socket = FakeSocket()
        asserter = PCAPAsserter("veth0")
        await asserter.start()
        backend.socket.send(b"x")
        await asserter.stop()
    assert not _capture_threads()
    assert _open_fds() == fds


# --------------------------------------------------------------------------- filters


async def test_filter_composition_is_unchanged() -> None:
    assert PCAPAsserter("veth0").filter == DEFAULT_FILTER
    assert PCAPAsserter("veth0", filter="port 53").filter == f"({DEFAULT_FILTER}) and (port 53)"
    assert PCAPAsserter("veth0", filter="icmp6", replace_default_filter=True).filter == "icmp6"
    assert PCAPAsserter("veth0", replace_default_filter=True).filter == DEFAULT_FILTER


async def test_missing_interface_is_detected_before_opening_a_socket() -> None:
    with pytest.raises(OSError) as caught:
        sniffer._open_socket("nse-no-such-if0", DEFAULT_FILTER)
    assert caught.value.errno == errno.ENODEV


async def test_a_filter_that_does_not_compile_never_opens_an_unfiltered_socket() -> None:
    """Scapy < 2.6 logs a failed attach and opens the socket anyway, unfiltered."""
    from scapy.arch import common
    from scapy.config import conf

    opened: list[object] = []
    with (
        patch.object(socket, "if_nametoindex", return_value=1),
        patch.object(
            common,
            "compile_filter",
            side_effect=Scapy_Exception("Failed to compile filter expression x"),
        ),
        patch.object(conf, "L2listen", lambda **kw: opened.append(kw)),
    ):
        asserter = PCAPAsserter("veth0", filter="x", replace_default_filter=True)
        with pytest.raises(CaptureStartError) as caught:
            await asserter.start()
    assert caught.value.reason == "filter_invalid"
    assert opened == []


# --------------------------------------------------------------------------- internals


@pytest.mark.parametrize(
    ("error", "reason"),
    [
        (ImportError("no module"), "backend_unavailable"),
        (OSError(errno.ENXIO, "No such device or address"), "interface_missing"),
        (OSError(errno.EACCES, "Permission denied"), "permission_denied"),
    ],
)
async def test_remaining_start_failure_classes(error: BaseException, reason: str) -> None:
    assert sniffer._classify(error) == reason


async def test_open_socket_compiles_frees_then_opens_filtered() -> None:
    from scapy.arch import common
    from scapy.config import conf

    calls: list[object] = []
    with (
        patch.object(socket, "if_nametoindex", return_value=1),
        patch.object(
            common, "compile_filter", lambda bpf, iface: calls.append(("compile", bpf)) or "prog"
        ),
        patch.object(
            common, "free_filter", lambda program: calls.append(("free", program)), create=True
        ),
        patch.object(conf, "L2listen", lambda **kw: calls.append(("open", kw)) or "sock"),
    ):
        assert sniffer._open_socket("veth0", "udp") == "sock"
    assert calls == [
        ("compile", "udp"),
        ("free", "prog"),
        ("open", {"iface": "veth0", "filter": "udp"}),
    ]


async def test_read_stats_decodes_tpacket_stats() -> None:
    import struct

    class Ins:
        def getsockopt(self, level: int, option: int, size: int) -> bytes:
            assert (level, option, size) == (263, 6, 8)
            return struct.pack("II", 7, 2)

    class Sock:
        ins = Ins()

    assert sniffer._read_stats(Sock()) == (7, 2)


async def test_raw_bytes_fall_back_to_serialisation() -> None:
    packet = Raw(b"abcd")
    packet.original = None  # e.g. a packet rebuilt by a session
    assert sniffer._raw_bytes(packet) == b"abcd"


async def test_exceptional_socket_condition_terminates_the_backend(backend: Backend) -> None:
    real_select = sniffer.select.select

    def broken(read: list[Any], write: list[Any], exc: list[Any], *timeout: float) -> Any:
        if not timeout or timeout[0] is None:  # the blocking wait of the capture loop
            return [], [], [backend.socket.ins]
        return real_select(read, write, exc, *timeout)

    with patch.object(sniffer.select, "select", broken):
        asserter = PCAPAsserter("veth0")
        await asserter.start()
        assert _wait_for(lambda: not _capture_threads(), 5)
        report = await asserter.stop_report()
    assert report.termination == "backend_terminated"
    assert any("exceptional condition" in e for e in report.errors)


async def test_drain_budget_and_drain_failure_are_reported() -> None:
    loop = sniffer._CaptureLoop("veth0", "udp", lambda exc: None)
    queued = FakeSocket()
    queued.send(b"left behind")
    loop._finish(queued, drain_budget=0)
    assert loop.errors == ["stop drain budget exhausted with packets still queued"]
    loop.close_pipe()

    loop = sniffer._CaptureLoop("veth0", "udp", lambda exc: None)
    failing = FakeSocket()
    failing.send(CRASH)
    loop._finish(failing)
    assert loop.errors[0].startswith("drain failed")
    loop.close_pipe()

    loop = sniffer._CaptureLoop("veth0", "udp", lambda exc: None)
    empty = FakeSocket()
    loop._finish(empty, drain_budget=0)  # nothing queued: an exhausted budget is no error
    assert loop.errors == []
    loop.close_pipe()


async def test_close_failure_is_reported() -> None:
    loop = sniffer._CaptureLoop("veth0", "udp", lambda exc: None)
    sock = FakeSocket()

    def refuse() -> None:
        raise OSError(errno.EBADF, "Bad file descriptor")

    sock.close = refuse  # type: ignore[method-assign]
    loop._finish(sock)
    assert loop.errors == ["socket close failed: OSError(9, 'Bad file descriptor')"]
    loop.close_pipe()
    sock.ins.close()
    sock.peer.close()


async def test_a_thread_that_cannot_start_leaves_no_descriptor(backend: Backend) -> None:
    backend.socket.close()
    fds = _open_fds()
    with patch.object(
        sniffer._CaptureLoop, "start", side_effect=RuntimeError("can't start new thread")
    ):
        asserter = PCAPAsserter("veth0")
        with pytest.raises(CaptureStartError) as caught:
            await asserter.start()
    assert caught.value.reason == "backend_error"
    assert _open_fds() == fds
    report = await asserter.stop_report()
    asserter._shutdown(1.0)  # idempotent once the report exists
    assert await asserter.stop_report() is report


# --------------------------------------------------------------------------- file mode and limits


def _payloads(count: int, prefix: str = "packet") -> list[bytes]:
    return [f"{prefix}-{index:04d}".encode() for index in range(count)]


def _send_all(backend: Backend, payloads: list[bytes]) -> None:
    for payload in payloads:
        backend.socket.send(payload)


def _pcap_payloads(path: Path) -> list[bytes]:
    return [bytes(packet) for packet in rdpcap(str(path))]


async def test_file_mode_writes_a_readable_pcap_and_keeps_no_packets_in_memory(
    backend: Backend, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    path = tmp_path / "capture.pcap"
    payloads = _payloads(300)
    asserter = PCAPAsserter("veth0", output=path)
    await asserter.start()
    _send_all(backend, payloads)
    backend.stats = (300, 0)
    assert await asserter.stop() == []  # the declared sample: none
    assert "returning 0 of 300 packet(s)" in caplog.text
    assert asserter._loop_thread is not None
    assert asserter._loop_thread.packets == []  # bounded memory, not a list rebuilt at stop

    report = await asserter.stop_report()
    assert report.output_mode == "file"
    assert report.limits.max_stored_packets == 0  # the file-mode default, reported
    assert report.packets_observed == report.packets_written == 300
    assert report.packets_stored == report.bytes_stored == 0
    assert report.limits_reached == ["max_stored_packets"]
    assert report.artifacts == [str(path)]
    assert report.artifact_complete is True
    assert report.bytes_written == path.stat().st_size == 24 + sum(16 + len(p) for p in payloads)
    assert report.instrument_healthy
    assert report.window_complete is True  # the sample limit does not truncate the record
    assert _pcap_payloads(path) == payloads


async def test_file_mode_returns_only_the_declared_sample(backend: Backend, tmp_path: Path) -> None:
    path = tmp_path / "capture.pcap"
    payloads = _payloads(20)
    asserter = PCAPAsserter("veth0", output=path, limits=CaptureLimits(max_stored_packets=3))
    await asserter.start()
    _send_all(backend, payloads)
    backend.stats = (20, 0)
    assert [bytes(p) for p in await asserter.stop()] == payloads[:3]
    report = await asserter.stop_report()
    assert report.packets_stored == 3
    assert report.window_complete is True
    assert _pcap_payloads(path) == payloads


async def test_an_empty_file_capture_is_still_a_readable_pcap(
    backend: Backend, tmp_path: Path
) -> None:
    path = tmp_path / "empty.pcap"
    asserter = PCAPAsserter("veth0", output=str(path))
    await asserter.start()
    assert path.stat().st_size == 24  # the header is on disk once start() returns
    report = await asserter.stop_report()
    assert report.packets_written == 0
    assert report.artifact_complete is True
    assert len(rdpcap(str(path))) == 0


async def test_relative_output_is_reported_as_an_absolute_path(
    backend: Backend, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    asserter = PCAPAsserter("veth0", output="relative.pcap")
    await asserter.start()
    report = await asserter.stop_report()
    assert report.artifacts == [str(tmp_path / "relative.pcap")]


async def test_an_existing_file_is_never_overwritten(backend: Backend, tmp_path: Path) -> None:
    path = tmp_path / "evidence.pcap"
    path.write_bytes(b"previous run")
    asserter = PCAPAsserter("veth0", output=path)
    with pytest.raises(CaptureStartError) as caught:
        await asserter.start()
    assert caught.value.reason == "output_unavailable"
    assert path.read_bytes() == b"previous run"
    report = await asserter.stop_report()
    assert report.start_failure == "output_unavailable"
    assert report.artifacts == []  # not ours: never reported as this capture's artifact
    assert report.artifact_complete is False
    assert _wait_for(lambda: backend.socket.closed, 5)  # the socket opened first is released


async def test_an_unsupported_link_type_fails_before_creating_the_file(
    backend: Backend, tmp_path: Path
) -> None:
    path = tmp_path / "capture.pcap"
    backend.socket.send(b"queued before readiness")

    def unsupported(sock: Any) -> int:
        raise sniffer._OutputError(errno.EOPNOTSUPP, "PCAP output is not supported")

    with patch.object(sniffer, "_linktype", unsupported):
        asserter = PCAPAsserter("veth0", output=path)
        with pytest.raises(CaptureStartError) as caught:
            await asserter.start()
    assert caught.value.reason == "output_unavailable"
    assert not path.exists()
    report = await asserter.stop_report()
    assert report.packets_observed == 0  # a socket that never became ready is not drained
    assert backend.stats_calls == 0
    assert backend.socket.closed


async def test_linktype_follows_the_bound_hardware_type() -> None:
    class Sock:
        def __init__(self, hatype: int) -> None:
            self.ins = self
            self.hatype = hatype

        def getsockname(self) -> tuple[Any, ...]:
            return ("veth0", 3, 0, self.hatype, b"")

    assert sniffer._linktype(Sock(1)) == 1  # Ethernet
    assert sniffer._linktype(Sock(772)) == 1  # loopback frames carry an Ethernet header
    assert sniffer._linktype(Sock(65534)) == 101  # tun: raw IP
    with pytest.raises(sniffer._OutputError, match="ARPHRD 776"):
        sniffer._linktype(Sock(776))


async def test_header_write_failure_is_an_output_failure(tmp_path: Path) -> None:
    path = tmp_path / "capture.pcap"
    with patch("builtins.open") as opener:
        opener.return_value.write.side_effect = OSError(errno.ENOSPC, "No space left on device")
        with pytest.raises(sniffer._OutputError, match="PCAP header"):
            sniffer._PcapFile(str(path), 1)
        opener.return_value.close.assert_called_once()


async def test_timestamps_are_split_without_overflowing_the_microseconds(tmp_path: Path) -> None:
    path = tmp_path / "ts.pcap"
    writer = sniffer._PcapFile(str(path), 1)
    writer.write(1.9999999, b"carry")
    writer.write(1700000000.25, b"quarter")
    writer.close()
    data = path.read_bytes()
    first = data[24:40]
    second = data[40 + 5 : 56 + 5]
    assert first[:8] == (2).to_bytes(4, "little") + (0).to_bytes(4, "little")
    assert second[:8] == (1700000000).to_bytes(4, "little") + (250000).to_bytes(4, "little")
    assert [float(p.time) for p in rdpcap(str(path))] == [2.0, 1700000000.25]


async def test_max_file_bytes_keeps_the_file_a_readable_prefix(
    backend: Backend, tmp_path: Path
) -> None:
    path = tmp_path / "capped.pcap"
    payloads = _payloads(100)  # 11 bytes each: 27 per record
    limit = 24 + 27 * 10 + 26  # room for 10 records and almost an 11th
    asserter = PCAPAsserter("veth0", output=path, limits=CaptureLimits(max_file_bytes=limit))
    await asserter.start()
    _send_all(backend, payloads[:50])
    backend.socket.send(b"x")  # small enough to fit, but after the limit: never written
    backend.stats = (51, 0)
    await asserter.stop()
    report = await asserter.stop_report()
    assert report.packets_observed == 51
    assert report.packets_written == 10
    assert report.bytes_written == path.stat().st_size == 24 + 27 * 10 <= limit
    assert report.limits_reached == ["max_stored_packets", "max_file_bytes"]
    assert report.artifact_complete is False
    assert report.instrument_healthy  # a declared limit, not a fault
    assert report.window_complete is False  # but the record is not the whole window
    assert _pcap_payloads(path) == payloads[:10]


async def test_max_file_bytes_requires_an_output_file() -> None:
    with pytest.raises(ValueError, match="needs an output file"):
        PCAPAsserter("veth0", limits=CaptureLimits(max_file_bytes=1024))


async def test_max_packets_ends_the_capture_by_itself(backend: Backend) -> None:
    asserter = PCAPAsserter("veth0", limits=CaptureLimits(max_packets=5))
    _send_all(backend, _payloads(8))  # queued up front: the loop closes the socket at 5
    await asserter.start()
    assert _wait_for(lambda: not _capture_threads(), 5)  # before stop() was called
    backend.stats = (8, 0)  # read by the loop as it ended itself
    packets = await asserter.stop()
    assert [bytes(p) for p in packets] == _payloads(5)
    report = await asserter.stop_report()
    assert report.termination == "limit_reached"
    assert report.limits_reached == ["max_packets"]
    assert report.packets_observed == 5
    assert report.instrument_healthy
    assert report.window_complete is False
    assert backend.socket.closed


async def test_max_packets_also_bounds_the_stop_drain(backend: Backend) -> None:
    gate = threading.Event()
    backend.socket.recv_gate = gate
    asserter = PCAPAsserter("veth0", limits=CaptureLimits(max_packets=3))
    await asserter.start()
    _send_all(backend, _payloads(6))
    stopping = asyncio.ensure_future(asserter.stop_report())
    await asyncio.sleep(0.05)  # the loop is blocked in recv() on the first packet
    gate.set()
    report = await stopping
    assert report.packets_observed == 3
    assert "max_packets" in report.limits_reached
    assert report.window_complete is False


async def test_max_duration_ends_the_capture_by_itself(backend: Backend) -> None:
    asserter = PCAPAsserter("veth0", limits=CaptureLimits(max_duration=0.2))
    await asserter.start()
    began = time.monotonic()
    backend.socket.send(b"early")
    assert _wait_for(lambda: not _capture_threads(), 5)
    assert 0.15 <= time.monotonic() - began < 2
    backend.stats = (1, 0)
    assert [bytes(p) for p in await asserter.stop()] == [b"early"]
    report = await asserter.stop_report()
    assert report.termination == "limit_reached"
    assert report.limits_reached == ["max_duration"]
    assert report.instrument_healthy
    assert report.window_complete is False


async def test_max_duration_under_continuous_traffic(backend: Backend) -> None:
    asserter = PCAPAsserter("veth0", limits=CaptureLimits(max_duration=0.2))
    await asserter.start()
    running = True

    def flood() -> None:
        while running:
            with contextlib.suppress(OSError):
                backend.socket.send(b"busy")
            time.sleep(0.001)

    sender = threading.Thread(target=flood)
    sender.start()
    try:
        assert _wait_for(lambda: not _capture_threads(), 5)
    finally:
        running = False
        sender.join()
    report = await asserter.stop_report()
    assert report.termination == "limit_reached"
    assert report.packets_observed > 0


@pytest.mark.parametrize(
    ("limits", "kept", "reached"),
    [
        (CaptureLimits(max_stored_packets=4), 4, "max_stored_packets"),
        (CaptureLimits(max_stored_bytes=11 * 7 + 10), 7, "max_stored_bytes"),
    ],
)
async def test_memory_limits_keep_a_prefix_and_mark_the_record_incomplete(
    backend: Backend, limits: CaptureLimits, kept: int, reached: str
) -> None:
    payloads = _payloads(30)
    asserter = PCAPAsserter("veth0", limits=limits)
    await asserter.start()
    _send_all(backend, payloads)
    backend.socket.send(b"x")  # would fit the byte budget, but comes after the cut
    backend.stats = (31, 0)
    assert [bytes(p) for p in await asserter.stop()] == payloads[:kept]
    report = await asserter.stop_report()
    assert report.packets_observed == 31
    assert report.packets_stored == kept
    assert report.bytes_stored == 11 * kept
    assert report.limits_reached == [reached]
    assert report.instrument_healthy
    assert report.window_complete is False  # in memory mode the list is the record


async def test_disk_full_is_a_failed_capture_with_a_partial_artifact(
    backend: Backend, tmp_path: Path
) -> None:
    path = tmp_path / "full.pcap"
    real_write = sniffer._PcapFile.write

    def write(self: Any, timestamp: float, raw: bytes) -> None:
        if self.packets == 5:
            raise OSError(errno.ENOSPC, "No space left on device")
        real_write(self, timestamp, raw)

    with patch.object(sniffer._PcapFile, "write", write):
        asserter = PCAPAsserter("veth0", output=path)
        await asserter.start()
        _send_all(backend, _payloads(20))
        backend.stats = (20, 0)
        with pytest.raises(CaptureError) as caught:
            await asserter.stop()
    report = caught.value.report
    assert report is not None
    assert report.errors == ["PCAP write failed: OSError(28, 'No space left on device')"]
    assert report.packets_observed == 20  # counting goes on: the counters stay meaningful
    assert report.packets_written == 5
    assert report.artifacts == [str(path)]  # the partial file is reported, not hidden
    assert report.artifact_complete is False
    assert not report.instrument_healthy
    assert report.window_complete is False
    assert _pcap_payloads(path) == _payloads(5)


async def test_flush_and_close_failures_are_reported(backend: Backend, tmp_path: Path) -> None:
    path = tmp_path / "flaky.pcap"

    def refuse(self: Any) -> None:
        raise OSError(errno.EIO, "Input/output error")

    with (
        patch.object(sniffer, "_FLUSH_IDLE", 0.02),
        patch.object(sniffer._PcapFile, "flush", refuse),
    ):
        asserter = PCAPAsserter("veth0", output=path)
        await asserter.start()
        backend.socket.send(b"one")
        assert _wait_for(lambda: bool(asserter._loop_thread and asserter._loop_thread.errors), 5)
        with patch.object(sniffer._PcapFile, "close", refuse):
            report = await asserter.stop_report()
    assert report.errors == [
        "PCAP flush failed: OSError(5, 'Input/output error')",
        "PCAP close failed: OSError(5, 'Input/output error')",
    ]
    assert report.artifact_complete is False
    assert not report.instrument_healthy


async def test_an_idle_capture_flushes_the_file(backend: Backend, tmp_path: Path) -> None:
    path = tmp_path / "live.pcap"
    with patch.object(sniffer, "_FLUSH_IDLE", 0.02):
        asserter = PCAPAsserter("veth0", output=path)
        await asserter.start()
        backend.socket.send(b"visible before stop")
        assert _wait_for(lambda: path.stat().st_size == 24 + 16 + 19, 5)
        await asserter.stop_report()


async def test_limits_are_validated() -> None:
    for bad in (
        {"max_packets": 0},
        {"max_duration": 0},
        {"max_duration": float("nan")},
        {"max_duration": float("inf")},
        {"max_file_bytes": 23},
        {"max_stored_packets": -1},
        {"max_stored_bytes": -1},
        {"max_packet": 3},
    ):
        with pytest.raises(ValidationError):
            CaptureLimits(**bad)


async def test_bounded_report_serialises(backend: Backend, tmp_path: Path) -> None:
    asserter = PCAPAsserter(
        "veth0", output=tmp_path / "c.pcap", limits=CaptureLimits(max_packets=10)
    )
    await asserter.start()
    data = json.loads((await asserter.stop_report()).model_dump_json())
    assert data["output_mode"] == "file"
    assert data["limits"]["max_packets"] == 10
    assert data["limits"]["max_stored_packets"] == 0
    assert data["artifact_complete"] is True
    assert data["window_complete"] is True


async def test_a_wedged_writer_is_a_stop_timeout_not_a_complete_file(
    backend: Backend, tmp_path: Path
) -> None:
    path = tmp_path / "wedged.pcap"
    release = threading.Event()
    real_write = sniffer._PcapFile.write

    def stall(self: Any, timestamp: float, raw: bytes) -> None:
        if self.packets == 2:
            release.wait(10)  # e.g. a stalled network filesystem
        real_write(self, timestamp, raw)

    with patch.object(sniffer._PcapFile, "write", stall):
        asserter = PCAPAsserter("veth0", output=path)
        await asserter.start()
        _send_all(backend, _payloads(5))
        assert _wait_for(lambda: asserter._loop_thread.observed == 3, 5)  # type: ignore[union-attr]
        report = await asserter.stop_report(timeout=0.1)
        release.set()
    assert report.termination == "stop_timeout"
    assert report.packets_written == 2
    assert report.artifacts == [str(path)]
    assert report.artifact_complete is False
    assert report.window_complete is False
    with pytest.raises(CaptureError, match="stop_timeout"):
        await asserter.stop()


# The SystemExit is meant to escape the thread: that is the case under test.
@pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning")
async def test_a_thread_killed_before_readiness_does_not_leave_start_waiting(
    backend: Backend,
) -> None:
    backend.open_error = SystemExit(1)  # not an Exception: the loop does not catch it
    asserter = PCAPAsserter("veth0")
    began = time.monotonic()
    with pytest.raises(CaptureStartError) as caught:
        await asserter.start(timeout=5)
    assert time.monotonic() - began < 2  # answered at once, not at the start deadline
    assert caught.value.reason == "backend_error"
    assert "exited before readiness" in str(caught.value)


async def test_a_capture_in_another_namespace_enters_it_from_the_capture_thread(
    backend: Backend,
) -> None:
    entered: list[tuple[str, str]] = []
    with patch.object(
        sniffer, "enter_netns", lambda name: entered.append((name, threading.current_thread().name))
    ):
        asserter = PCAPAsserter(iface="vhr-x", netns="nsh_x")
        await asserter.start()
        report = await asserter.stop_report()
    assert entered == [("nsh_x", "nse-capture-vhr-x")]
    assert backend.iface == "vhr-x"
    assert report.netns == "nsh_x"
    assert report.termination == "stopped"


async def test_a_missing_capture_namespace_is_a_missing_interface(backend: Backend) -> None:
    def missing(name: str) -> None:
        raise OSError(errno.ENODEV, f"network namespace {name!r} does not exist")

    with patch.object(sniffer, "enter_netns", missing):
        asserter = PCAPAsserter(iface="vhr-x", netns="nsh_gone")
        with pytest.raises(CaptureStartError) as info:
            await asserter.start()
    assert info.value.reason == "interface_missing"
    assert "nsh_gone" in str(info.value)
    assert not hasattr(backend, "iface")  # no socket was opened


async def test_a_capture_without_netns_stays_in_nses_namespace(backend: Backend) -> None:
    with patch.object(sniffer, "enter_netns") as enter:
        asserter = PCAPAsserter(iface="veth0")
        await asserter.start()
        report = await asserter.stop_report()
    enter.assert_not_called()
    assert report.netns is None


# --------------------------------------------------------------------------- beacons and link


def _beacon_frame(label: str, token: str) -> bytes:
    from nse.core import beacons

    return beacons.frame(label, token)


def _fake_sender(backend: Backend, deliver: bool = True) -> Callable[..., Any]:
    """A beacons.send stand-in: build the beacon, and put its frame on the fake link."""
    from nse.core import beacons

    async def send(iface: str, netns: str | None, label: str) -> Any:
        beacon = beacons.Beacon(
            label=label,
            token=os.urandom(16).hex(),
            iface=iface,
            netns=netns,
            sent_at=time.time(),
            sent_monotonic=time.monotonic(),
        )
        if deliver:
            backend.socket.send(beacons.frame(label, beacon.token))
        return beacon

    return send


async def test_marked_window_is_complete_and_beacons_stay_out_of_the_packets(
    backend: Backend,
) -> None:
    asserter = PCAPAsserter("veth0")
    await asserter.start()
    with patch.object(sniffer._beacons, "send", _fake_sender(backend)):
        first = await asserter.mark("start")
        backend.socket.send(b"payload")
        await asserter.mark("end")
    packets = await asserter.stop()
    report = await asserter.stop_report()
    assert [bytes(p) for p in packets] == [b"payload"]
    assert [s.label for s in report.beacons_seen] == ["start", "end"]
    assert report.beacons_seen[0].token == first.token
    assert report.beacons_seen[0].index == 0
    assert report.beacons_missing == []
    assert report.packets_observed == 3
    assert report.packets_stored == 1
    assert report.window_complete is True
    assert first.iface == "veth0"
    assert first.netns is None


async def test_a_beacon_the_capture_did_not_see_makes_the_window_incomplete(
    backend: Backend,
) -> None:
    asserter = PCAPAsserter("veth0")
    await asserter.start()
    with patch.object(sniffer._beacons, "send", _fake_sender(backend, deliver=False)):
        await asserter.mark("start")
    await asserter.stop()  # healthy, so no error: the window is what is not vouched for
    report = await asserter.stop_report()
    assert report.instrument_healthy
    assert report.beacons_missing == ["start"]
    assert report.window_complete is False


async def test_a_beacon_sent_by_a_sandbox_is_expected_too(backend: Backend) -> None:
    asserter = PCAPAsserter("veth0")
    await asserter.start()
    send = _fake_sender(backend)

    class Sandbox:
        async def beacon(self, label: str) -> Any:
            return await send("vrh-x", "nse_x", label)

    beacon = await asserter.mark("via", via=Sandbox())
    other = await send("vrh-x", "nse_x", "other")
    asserter.expect(other)
    await asserter.stop()
    report = await asserter.stop_report()
    assert beacon.netns == "nse_x"
    assert [b.label for b in report.beacons_expected] == ["via", "other"]
    assert report.window_complete is True
    with pytest.raises(CaptureStateError, match="already stopped"):
        asserter.expect(other)


async def test_mark_is_refused_where_a_beacon_cannot_prove_anything(backend: Backend) -> None:
    asserter = PCAPAsserter("veth0", filter="udp")
    with pytest.raises(CaptureStateError, match="not running"):
        await asserter.mark("early")
    await asserter.start()
    with pytest.raises(CaptureStateError, match="beacons=True"):
        await asserter.mark("filtered")
    await asserter.stop()

    backend.socket = FakeSocket()
    backend.hardware_type = 65534
    raw_ip = PCAPAsserter("tun0")
    await raw_ip.start()
    with pytest.raises(CaptureStateError, match="not on an Ethernet link"):
        await raw_ip.mark("tun")
    await raw_ip.stop()


async def test_beacons_true_admits_beacons_through_a_custom_filter(backend: Backend) -> None:
    asserter = PCAPAsserter("veth0", filter="udp port 53", beacons=True)
    assert asserter.filter == f"(({DEFAULT_FILTER}) and (udp port 53)) or (ether proto 0x88b5)"
    await asserter.start()
    assert backend.bpf == asserter.filter
    with patch.object(sniffer._beacons, "send", _fake_sender(backend)):
        await asserter.mark("ok")
    await asserter.stop()
    assert (await asserter.stop_report()).window_complete is True
    assert PCAPAsserter("veth0", beacons=True).filter == DEFAULT_FILTER


async def test_beacon_frames_are_written_to_the_file(backend: Backend, tmp_path: Path) -> None:
    out = tmp_path / "beacons.pcap"
    asserter = PCAPAsserter("veth0", output=out)
    await asserter.start()
    frame = _beacon_frame("w", "ab" * 16)
    backend.socket.send(frame)
    await asserter.stop()
    assert _pcap_payloads(out) == [frame]
    assert (await asserter.stop_report()).beacons_seen[0].label == "w"


@pytest.mark.parametrize(
    ("hardware_type", "link_type"), [(1, 1), (772, 1), (65534, 101), (999, None), (None, None)]
)
async def test_the_report_names_the_link(
    backend: Backend, hardware_type: int | None, link_type: int | None
) -> None:
    backend.hardware_type = hardware_type
    asserter = PCAPAsserter("veth0")
    await asserter.start()
    await asserter.stop()
    report = await asserter.stop_report()
    assert report.hardware_type == hardware_type
    assert report.link_type == link_type
    assert report.snaplen == 65535
    assert report.required_bytes is None
    assert report.snaplen_sufficient is None


async def test_required_bytes_beyond_the_snaplen_is_never_complete(backend: Backend) -> None:
    with patch("scapy.data.MTU", 64):
        short = PCAPAsserter("veth0", required_bytes=100)
        await short.start()
        backend.socket.send(b"x" * 64)
        backend.socket.send(b"y" * 10)
        await short.stop()
    report = await short.stop_report()
    assert report.snaplen == 64
    assert report.packets_truncated == 1
    assert report.snaplen_sufficient is False
    assert report.window_complete is False

    backend.socket = FakeSocket()
    enough = PCAPAsserter("veth0", required_bytes=1500)
    await enough.start()
    await enough.stop()
    assert (await enough.stop_report()).snaplen_sufficient is True
    assert (await enough.stop_report()).window_complete is True
    with pytest.raises(ValueError, match="required_bytes"):
        PCAPAsserter("veth0", required_bytes=0)


async def test_hardware_type_is_read_from_the_bound_socket() -> None:
    class Bound:
        class ins:
            @staticmethod
            def getsockname() -> tuple[Any, ...]:
                return ("veth0", 3, 0, 772, b"")

    class Unbound:
        class ins:
            @staticmethod
            def getsockname() -> str:
                return ""

    assert sniffer._hardware_type(Bound()) == 772
    assert sniffer._hardware_type(Unbound()) is None
