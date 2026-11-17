# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""
PCAPAsserter: packet capture with confirmed readiness and a diagnostic report.

Designed for automated headless pipeline testing to verify zero-leak policies.

Readiness contract
------------------
``await start()`` returns only once the kernel packet socket exists, carries the
BPF filter and is bound to the interface. From that moment every matching packet
is queued for the capture, so a stimulus may be sent immediately - no sleep is
needed. If the socket cannot be armed, ``start()`` raises
:class:`CaptureStartError` with a classified reason instead of failing later.

The capture loop is NSE's own thread over Scapy's ``L2ListenSocket`` rather than
``AsyncSniffer``: across the supported Scapy versions ``AsyncSniffer`` either
swallows backend errors or re-raises them only at ``stop()``, and it discards
packets already queued when the stop signal arrives. Here, ``stop`` drains what
the kernel has already queued before closing the socket.

Result contract
---------------
One finalisation produces a :class:`~nse.models.capture_report.CaptureReport`
shared by :meth:`PCAPAsserter.stop` (historic ``list[Packet]`` API) and
:meth:`PCAPAsserter.stop_report`. ``stop()`` raises :class:`CaptureError` when
the instrument was not healthy, so a broken capture can no longer look like an
empty, successful one.
"""

from __future__ import annotations

import asyncio
import contextlib
import errno
import logging
import os
import select
import socket
import struct
import threading
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, Literal

from nse.core.async_work import finish_work
from nse.models.capture_report import CaptureReport, StartFailure, Termination

if TYPE_CHECKING:
    from scapy.packet import Packet

logger = logging.getLogger("nse.core.sniffer")

#: ICMPv6 message types 133-137: Router Solicitation, Router Advertisement,
#: Neighbour Solicitation, Neighbour Advertisement and Redirect. All of them are
#: link-local by definition - they carry a hop limit of 255 and are discarded by
#: the first router - so none can reach a remote observer and none belongs in a
#: leak assertion.
ND_TYPE_MIN = 133
ND_TYPE_MAX = 137

#: Background chatter suppressed on every capture unless a caller opts out.
#:
#: This used to read ``not arp and not icmp6``, which was broader than the noise
#: it meant to describe. ICMPv6 is not only Neighbour Discovery: the expression
#: also discarded echo request/reply to a **globally routable** address, which is
#: cleartext traffic leaving the host - precisely what a class named for
#: "asserting that no traffic leaks outside sandbox boundaries" exists to catch.
#: Because the filter is compiled into BPF, those packets never reached
#: userspace, so no consumer could see or recover them.
#:
#: Narrowed to the ND types the comment always claimed. See
#: https://github.com/onyks-os/NetworkSandboxEngine/issues/14.
DEFAULT_FILTER = (
    f"not arp and not (icmp6 and icmp6[icmp6type] >= {ND_TYPE_MIN} "
    f"and icmp6[icmp6type] <= {ND_TYPE_MAX})"
)

#: Default seconds ``start()`` waits for the backend to confirm readiness.
DEFAULT_START_TIMEOUT = 5.0
#: Default seconds ``stop()`` waits for the capture loop to drain and exit.
DEFAULT_STOP_TIMEOUT = 5.0

_SOL_PACKET = 263
_PACKET_STATISTICS = 6
_BACKEND = "scapy-l2listen"

State = Literal["created", "starting", "running", "finished"]


class CaptureError(RuntimeError):
    """The capture instrument failed; ``report`` holds the evidence."""

    def __init__(self, message: str, report: CaptureReport | None = None) -> None:
        super().__init__(message)
        self.report = report


class CaptureStartError(CaptureError):
    """``start()`` could not arm the capture; ``reason`` classifies why."""

    def __init__(
        self,
        message: str,
        reason: StartFailure | Literal["timeout", "cancelled"],
        report: CaptureReport | None = None,
    ) -> None:
        super().__init__(message, report)
        self.reason = reason


class CaptureStateError(RuntimeError):
    """The capture was used out of order (double start, stop before start)."""


def _classify(exc: BaseException) -> StartFailure:
    text = str(exc)
    if isinstance(exc, PermissionError) or getattr(exc, "errno", None) in (
        errno.EPERM,
        errno.EACCES,
    ):
        return "permission_denied"
    if getattr(exc, "errno", None) in (errno.ENODEV, errno.ENXIO):
        return "interface_missing"
    if "libpcap is not available" in text:
        return "backend_unavailable"
    if "Cannot set filter" in text or ("filter" in text.lower() and "compile" in text.lower()):
        return "filter_invalid"
    if isinstance(exc, ImportError):
        return "backend_unavailable"
    return "backend_error"


def _open_socket(iface: str, bpf: str) -> Any:
    """Open, filter and bind Scapy's Linux listen socket on *iface*."""
    # scapy.all, not scapy.config: Scapy < 2.6 registers the platform sockets
    # (conf.L2listen) and the link layers used for dissection only on this import.
    from scapy.all import conf
    from scapy.arch import common

    try:
        socket.if_nametoindex(iface)
    except OSError as exc:
        raise OSError(errno.ENODEV, f"interface {iface!r} does not exist") from exc
    # Compile explicitly first. Scapy < 2.6 logs a filter that fails to compile
    # (invalid expression, libpcap missing) and then opens the socket UNFILTERED;
    # a capture must never silently observe something other than what was asked.
    program = common.compile_filter(bpf, iface)
    free = getattr(common, "free_filter", None)
    if free is not None:
        free(program)
    return conf.L2listen(iface=iface, filter=bpf)


def _read_stats(sock: Any) -> tuple[int, int]:
    """Read and reset the kernel's PACKET_STATISTICS (tp_packets, tp_drops)."""
    raw = sock.ins.getsockopt(_SOL_PACKET, _PACKET_STATISTICS, 8)
    packets, drops = struct.unpack("II", raw[:8])
    return packets, drops


def _packet_length(packet: Any) -> int:
    original = getattr(packet, "original", None)
    if isinstance(original, (bytes, bytearray)):
        return len(original)
    return len(bytes(packet))


class _CaptureLoop(threading.Thread):
    """Owns the kernel socket from opening to closing."""

    def __init__(
        self,
        iface: str,
        bpf: str,
        on_ready: Callable[[BaseException | None], None],
    ) -> None:
        super().__init__(name=f"nse-capture-{iface}", daemon=True)
        self.iface = iface
        self.bpf = bpf
        self._on_ready = on_ready
        self._wake_r, self._wake_w = os.pipe()
        # Guards the pipe fds: a stop request must never write to a descriptor
        # the loop has already closed (its number may belong to another file).
        self._fd_lock = threading.Lock()
        self.stop_requested = threading.Event()
        self.packets: list[Packet] = []
        self.bytes = 0
        self.started_at: float | None = None
        self.stopped_at: float | None = None
        self.errors: list[str] = []
        self.start_error: BaseException | None = None
        self.kernel: tuple[int, int] | None = None
        self.stats_reason: str | None = None

    def request_stop(self) -> None:
        if not self.stop_requested.is_set():
            self.stop_requested.set()
            with self._fd_lock, contextlib.suppress(OSError):
                if self._wake_w >= 0:
                    os.write(self._wake_w, b"x")

    def run(self) -> None:
        sock: Any = None
        try:
            try:
                sock = _open_socket(self.iface, self.bpf)
            except BaseException as exc:
                self.start_error = exc
                self._on_ready(exc)
                return
            self.started_at = time.time()
            try:
                _read_stats(sock)  # reset: count only what arrives after readiness
            except Exception as exc:
                self.stats_reason = f"PACKET_STATISTICS unavailable: {exc}"
            self._on_ready(None)
            self._loop(sock)
        except BaseException as exc:
            self.errors.append(f"capture loop failed: {exc!r}")
        finally:
            if sock is not None:
                self._finish(sock)
            self.close_pipe()
            self.stopped_at = time.time()

    def close_pipe(self) -> None:
        with self._fd_lock:
            for fd in (self._wake_r, self._wake_w):
                if fd >= 0:
                    with contextlib.suppress(OSError):
                        os.close(fd)
            self._wake_r = self._wake_w = -1

    def _read_one(self, sock: Any) -> None:
        packet = sock.recv()
        if packet is None:
            return
        packet.sniffed_on = self.iface
        self.bytes += _packet_length(packet)
        self.packets.append(packet)

    def _loop(self, sock: Any) -> None:
        while not self.stop_requested.is_set():
            readable, _, broken = select.select([sock.ins, self._wake_r], [], [sock.ins])
            if broken:
                raise OSError("socket reported an exceptional condition")
            if sock.ins in readable:
                self._read_one(sock)

    def _finish(self, sock: Any, drain_budget: float = 1.0) -> None:
        """Read the kernel counters, then drain everything already queued, then close.

        Counters first: every packet they count is in the queue (or dropped) at
        that moment, so the drain that follows reads at least all of them.
        """
        if self.stats_reason is None:
            try:
                self.kernel = _read_stats(sock)
            except Exception as exc:
                self.stats_reason = f"PACKET_STATISTICS unavailable: {exc}"
        if not self.errors:
            deadline = time.monotonic() + drain_budget
            try:
                while select.select([sock.ins], [], [], 0)[0]:
                    if time.monotonic() >= deadline:
                        self.errors.append("stop drain budget exhausted with packets still queued")
                        break
                    self._read_one(sock)
            except Exception as exc:
                self.errors.append(f"drain failed: {exc!r}")
        try:
            sock.close()
        except Exception as exc:
            self.errors.append(f"socket close failed: {exc!r}")


class PCAPAsserter:
    """
    Packet capture on one interface, used to assert that no traffic leaks
    outside sandbox boundaries. Single use: start once, stop once (stop and
    stop_report may be called repeatedly and return the same result).
    """

    def __init__(
        self,
        iface: str,
        filter: str | None = None,
        *,
        replace_default_filter: bool = False,
    ) -> None:
        """
        Arm a sniffer on *iface*.

        *filter* is combined with :data:`DEFAULT_FILTER` unless
        *replace_default_filter* is set, in which case it is used alone. The
        override exists because the default is compiled into BPF and evaluated
        in the kernel: a packet it excludes never reaches userspace, so a caller
        that needs to assert on suppressed traffic cannot compensate downstream.
        Combining is the safe default; replacing is the escape hatch.
        """
        self.iface = iface
        self.requested_filter = filter
        self.replace_default_filter = bool(filter) and replace_default_filter
        if filter and replace_default_filter:
            self.filter = filter
        elif filter:
            self.filter = f"({DEFAULT_FILTER}) and ({filter})"
        else:
            self.filter = DEFAULT_FILTER

        self.state: State = "created"
        self._loop_thread: _CaptureLoop | None = None
        self._start_requested_at = 0.0
        self._stop_requested_at: float | None = None
        self._start_outcome: Termination | None = None
        self._start_failure: StartFailure | None = None
        self._final: asyncio.Future[CaptureReport] | None = None
        self._report: CaptureReport | None = None
        self._settled = asyncio.Event()  # set once start() has succeeded or failed

    # ------------------------------------------------------------------ start
    async def start(self, timeout: float = DEFAULT_START_TIMEOUT) -> None:
        """Arm the capture and return once the kernel socket is filtering and bound.

        Raises :class:`CaptureStartError` (``reason`` is ``interface_missing``,
        ``filter_invalid``, ``permission_denied``, ``backend_unavailable``,
        ``backend_error``, ``timeout`` or ``cancelled``) and leaves no thread or
        socket behind. :meth:`stop_report` then describes the failure.
        """
        if self.state != "created":
            raise CaptureStateError(f"capture on {self.iface} already started (single use)")
        self.state = "starting"
        self._start_requested_at = time.time()
        logger.info("Starting PCAP sniffer on %s with BPF filter: %s", self.iface, self.filter)

        loop = asyncio.get_running_loop()
        ready: asyncio.Future[None] = loop.create_future()

        def on_ready(exc: BaseException | None) -> None:
            def resolve() -> None:
                if ready.done():
                    return
                if exc is None:
                    ready.set_result(None)
                else:
                    ready.set_exception(exc)

            with contextlib.suppress(RuntimeError):  # loop closed: nobody is waiting
                loop.call_soon_threadsafe(resolve)

        thread = _CaptureLoop(self.iface, self.filter, on_ready)
        self._loop_thread = thread
        try:
            thread.start()
            await asyncio.wait_for(asyncio.shield(ready), timeout)
        except asyncio.TimeoutError:
            await self._abort("start_timeout")
            raise CaptureStartError(
                f"capture on {self.iface} did not confirm readiness within {timeout}s",
                "timeout",
                self._report,
            ) from None
        except asyncio.CancelledError:
            await self._abort("start_cancelled")
            raise
        except BaseException as exc:
            self._start_failure = _classify(exc)
            await self._abort("start_failed")
            raise CaptureStartError(
                f"capture on {self.iface} could not start ({self._start_failure}): {exc}",
                self._start_failure,
                self._report,
            ) from exc
        finally:
            # A late readiness signal must find the future done, not raise unobserved.
            ready.cancel()
            if self.state == "starting":
                self.state = "running"
            self._settled.set()

    async def _abort(self, outcome: Termination) -> None:
        self._start_outcome = outcome
        self.state = "finished"
        await finish_work(asyncio.get_running_loop().run_in_executor(None, self._shutdown, 1.0))

    # ------------------------------------------------------------------- stop
    async def stop(self, timeout: float = DEFAULT_STOP_TIMEOUT) -> list[Packet]:
        """Stop the capture and return the packets it stored.

        Raises :class:`CaptureError` when the instrument was not healthy (start
        failure, backend crash, stop timeout, socket errors): an empty list is
        only ever returned for a capture that worked and saw nothing. Kernel
        drops do not raise here; they are logged and reported by
        :meth:`stop_report` as ``window_complete=False``.
        """
        report = await self.stop_report(timeout)
        if not report.instrument_healthy:
            raise CaptureError(
                f"capture on {self.iface} is not trustworthy: termination={report.termination}"
                + (f", errors={report.errors}" if report.errors else ""),
                report,
            )
        if report.kernel_drops:
            logger.warning(
                "capture on %s: kernel dropped %d packet(s); the list is incomplete",
                self.iface,
                report.kernel_drops,
            )
        assert self._loop_thread is not None
        return list(self._loop_thread.packets)

    async def stop_report(self, timeout: float = DEFAULT_STOP_TIMEOUT) -> CaptureReport:
        """Stop the capture (once) and return its :class:`CaptureReport`.

        Never raises for an instrument failure - that is what the report is for.
        Raises :class:`CaptureStateError` if called before :meth:`start`.
        """
        if self.state == "created":
            raise CaptureStateError(f"capture on {self.iface} was never started")
        if self._report is not None:
            return self._report
        if self._final is None:
            self._final = asyncio.ensure_future(self._finalize(timeout))
        return await asyncio.shield(self._final)

    async def _finalize(self, timeout: float) -> CaptureReport:
        await self._settled.wait()  # stop raced start(): let start settle first
        if self._report is None:
            logger.info("Stopping PCAP sniffer on %s", self.iface)
            self.state = "finished"
            await finish_work(
                asyncio.get_running_loop().run_in_executor(None, self._shutdown, timeout)
            )
        assert self._report is not None
        return self._report

    def _shutdown(self, timeout: float) -> None:
        """Blocking: signal the loop, join it within *timeout*, build the report once."""
        if self._report is not None:
            return
        thread = self._loop_thread
        assert thread is not None
        ended_early = not thread.is_alive() and thread.start_error is None
        self._stop_requested_at = time.time()
        thread.request_stop()
        if thread.ident is None:  # Thread.start() itself failed: run() never owned the fds
            thread.close_pipe()
        else:
            thread.join(timeout)
        alive = thread.is_alive()

        termination: Termination
        errors = list(thread.errors)
        if self._start_outcome is not None:
            termination = self._start_outcome
            if thread.start_error is not None:
                errors.insert(0, f"start failed: {thread.start_error!r}")
        elif alive:
            termination = "stop_timeout"
            errors.append(f"capture loop still running {timeout}s after stop was requested")
        elif ended_early:
            termination = "backend_terminated"
            if not errors:  # pragma: no cover - the loop only exits early by raising
                errors.append("capture loop ended before stop was requested")
        else:
            termination = "stopped"
        if alive and self._start_outcome is not None:
            errors.append("capture thread did not exit after start was abandoned")

        kernel = thread.kernel
        reason = thread.stats_reason
        if kernel is None and reason is None:
            reason = (
                "capture never became ready"
                if thread.started_at is None
                else "counters not read before the capture ended"
            )

        from scapy import VERSION as scapy_version

        self._report = CaptureReport(
            iface=self.iface,
            requested_filter=self.requested_filter,
            effective_filter=self.filter,
            default_filter_replaced=self.replace_default_filter,
            backend=_BACKEND,
            backend_version=str(scapy_version),
            termination=termination,
            start_failure=self._start_failure,
            errors=errors,
            start_requested_at=self._start_requested_at,
            started_at=thread.started_at,
            stop_requested_at=self._stop_requested_at,
            stopped_at=None if alive else thread.stopped_at,
            packets_observed=len(thread.packets),
            bytes_observed=thread.bytes,
            packets_stored=len(thread.packets),
            packets_written=None,
            artifacts=[],
            kernel_packets=kernel[0] if kernel else None,
            kernel_drops=kernel[1] if kernel else None,
            stats_unavailable_reason=None if kernel else reason,
        )
