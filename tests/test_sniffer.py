"""PCAPAsserter readiness, state machine and report, without privileges.

The kernel packet socket is replaced by a datagram socketpair, so select(),
draining and closing are exercised for real; only opening and the kernel
counters are simulated.
"""

from __future__ import annotations

import asyncio
import errno
import json
import os
import socket
import threading
import time
from collections.abc import Callable, Iterator
from typing import Any
from unittest.mock import patch

import pytest
from scapy.error import Scapy_Exception
from scapy.packet import Raw

from nse import CaptureError, CaptureReport, CaptureStartError, CaptureStateError, PCAPAsserter
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
        await task
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
    await starting
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


async def test_packet_length_falls_back_to_serialisation() -> None:
    packet = Raw(b"abcd")
    packet.original = None  # e.g. a packet rebuilt by a session
    assert sniffer._packet_length(packet) == 4


async def test_exceptional_socket_condition_terminates_the_backend(backend: Backend) -> None:
    real_select = sniffer.select.select

    def broken(read: list[Any], write: list[Any], exc: list[Any], *timeout: float) -> Any:
        if not timeout:  # the blocking wait of the capture loop
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
