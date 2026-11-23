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

Bounded captures
----------------
By default every packet is kept in memory, as before. With ``output=`` the
capture writes a PCAP file progressively from the capture thread and keeps only
a bounded sample in memory (none unless one is declared). :class:`CaptureLimits`
bounds packets, duration, file size and stored bytes; reaching any of them is
listed in the report. There is no writer queue: the file is written by the
thread that reads the socket, so the kernel socket buffer is the only queue, and
a writer too slow to keep up shows up as kernel drops (``window_complete`` is
then ``False``), never as unbounded memory.
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

from nse.core import beacons as _beacons
from nse.core.async_work import finish_work
from nse.core.utils import enter_netns
from nse.models.capture_report import (
    PCAP_HEADER_BYTES,
    PCAP_RECORD_HEADER_BYTES,
    Beacon,
    BeaconSighting,
    CaptureLimits,
    CaptureReport,
    LimitName,
    StartFailure,
    Termination,
)

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

#: Classic PCAP (microsecond timestamps), written little-endian.
_PCAP_MAGIC = 0xA1B2C3D4
_PCAP_SNAPLEN = 262144
#: Linux ARPHRD_* hardware type of the bound socket -> PCAP LINKTYPE_*. Loopback
#: frames carry an Ethernet header on Linux; ARPHRD_NONE (tun) delivers raw IP.
_ARPHRD_TO_LINKTYPE = {1: 1, 772: 1, 65534: 101}
#: Hardware types whose frames carry an Ethernet header, so a beacon can cross them.
_ETHERNET_HARDWARE = frozenset({1, 772})
#: Buffer for the PCAP file; flushed when it fills, when the capture is idle for
#: _FLUSH_IDLE seconds, and on close.
_WRITE_BUFFER = 64 * 1024
_FLUSH_IDLE = 1.0

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


class _OutputError(OSError):
    """The PCAP file could not be prepared; classified as ``output_unavailable``."""


def _classify(exc: BaseException) -> StartFailure:
    text = str(exc)
    if isinstance(exc, _OutputError):
        return "output_unavailable"
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


def _raw_bytes(packet: Any) -> bytes:
    """The bytes as received; re-serialised only when the original is not kept."""
    original = getattr(packet, "original", None)
    if isinstance(original, (bytes, bytearray)):
        return bytes(original)
    return bytes(packet)


def _hardware_type(sock: Any) -> int | None:
    """Linux ARPHRD_* type of the interface *sock* is bound to; None if it cannot be read."""
    try:
        return int(sock.ins.getsockname()[3])
    except (OSError, IndexError, TypeError, ValueError):
        return None


def _linktype(sock: Any) -> int:
    """PCAP link type of the frames *sock* delivers, from its bound hardware type."""
    hatype = sock.ins.getsockname()[3]
    try:
        return _ARPHRD_TO_LINKTYPE[hatype]
    except KeyError:
        raise _OutputError(
            errno.EOPNOTSUPP, f"PCAP output is not supported for link type ARPHRD {hatype}"
        ) from None


class _PcapFile:
    """Classic PCAP file written progressively; created exclusively, never overwritten."""

    def __init__(self, path: str, linktype: int) -> None:
        self.path = path
        try:
            self._file = open(path, "xb", buffering=_WRITE_BUFFER)  # noqa: SIM115 - closed in close()
        except OSError as exc:
            raise _OutputError(exc.errno, f"cannot create PCAP file {path!r}: {exc}") from exc
        header = struct.pack("<IHHiIII", _PCAP_MAGIC, 2, 4, 0, 0, _PCAP_SNAPLEN, linktype)
        try:
            self._file.write(header)
            self._file.flush()
        except OSError as exc:
            with contextlib.suppress(OSError):
                self._file.close()
            raise _OutputError(exc.errno, f"cannot write PCAP header to {path!r}: {exc}") from exc
        self.packets = 0
        self.bytes = PCAP_HEADER_BYTES
        self.dirty = False

    def write(self, timestamp: float, raw: bytes) -> None:
        seconds = int(timestamp)
        micros = round((timestamp - seconds) * 1_000_000)
        if micros >= 1_000_000:
            seconds, micros = seconds + 1, micros - 1_000_000
        length = len(raw)
        self._file.write(struct.pack("<IIII", seconds, micros, length, length))
        self._file.write(raw)
        self.packets += 1
        self.bytes += PCAP_RECORD_HEADER_BYTES + length
        self.dirty = True

    def flush(self) -> None:
        self._file.flush()
        self.dirty = False

    def close(self) -> None:
        self._file.close()


class _CaptureLoop(threading.Thread):
    """Owns the kernel socket from opening to closing."""

    def __init__(
        self,
        iface: str,
        bpf: str,
        on_ready: Callable[[BaseException | None], None],
        limits: CaptureLimits | None = None,
        output: str | None = None,
        netns: str | None = None,
    ) -> None:
        super().__init__(name=f"nse-capture-{iface}", daemon=True)
        self.iface = iface
        self.netns = netns
        self.bpf = bpf
        self._on_ready = on_ready
        self._signalled = False
        self.limits = limits or CaptureLimits()
        self.output = output
        self._wake_r, self._wake_w = os.pipe()
        # Guards the pipe fds: a stop request must never write to a descriptor
        # the loop has already closed (its number may belong to another file).
        self._fd_lock = threading.Lock()
        self.stop_requested = threading.Event()
        self.packets: list[Packet] = []
        self.observed = 0
        self.bytes = 0
        self.stored_bytes = 0
        self.storing = True
        self.writer: _PcapFile | None = None
        self.writing = True
        self.writer_failed = False
        self.written: int | None = None
        self.written_bytes: int | None = None
        self.limits_reached: list[LimitName] = []
        self.ended_by_limit = False
        self.socket_failed = False  # the socket itself broke: nothing left to drain
        self.started_at: float | None = None
        self.stopped_at: float | None = None
        self.errors: list[str] = []
        self.start_error: BaseException | None = None
        self.kernel: tuple[int, int] | None = None
        self.stats_reason: str | None = None
        self.beacons: list[BeaconSighting] = []
        self.truncated = 0
        self.hardware_type: int | None = None
        self.snaplen: int | None = None

    def request_stop(self) -> None:
        if not self.stop_requested.is_set():
            self.stop_requested.set()
            with self._fd_lock, contextlib.suppress(OSError):
                if self._wake_w >= 0:
                    os.write(self._wake_w, b"x")

    def _signal_ready(self, exc: BaseException | None) -> None:
        if not self._signalled:
            self._signalled = True
            self._on_ready(exc)

    def run(self) -> None:
        sock: Any = None
        try:
            try:
                if self.netns is not None:
                    # Only this thread moves: the interface is looked up and the
                    # socket created and bound in that namespace.
                    enter_netns(self.netns)
                sock = _open_socket(self.iface, self.bpf)
                self._describe_link(sock)
                if self.output is not None:
                    self.writer = _PcapFile(self.output, _linktype(sock))
            except Exception as exc:
                if sock is not None:  # opened, but the file could not be: never ready
                    with contextlib.suppress(Exception):
                        sock.close()
                    sock = None
                self.start_error = exc
                self._signal_ready(exc)
                return
            self.started_at = time.time()
            try:
                _read_stats(sock)  # reset: count only what arrives after readiness
            except Exception as exc:
                self.stats_reason = f"PACKET_STATISTICS unavailable: {exc}"
            self._signal_ready(None)
            self._loop(sock)
        except Exception as exc:
            self.socket_failed = True
            self.errors.append(f"capture loop failed: {exc!r}")
        finally:
            # Whatever ended the thread (even SystemExit), start() must not wait
            # for a readiness signal that can no longer come.
            if not self._signalled:
                self.start_error = RuntimeError("capture thread exited before readiness")
                self._signal_ready(self.start_error)
            if sock is not None:
                self._finish(sock)
            self._close_writer()
            self.close_pipe()
            self.stopped_at = time.time()

    def _describe_link(self, sock: Any) -> None:
        from scapy.data import MTU

        self.snaplen = int(MTU)  # what the backend asks for on every read
        self.hardware_type = _hardware_type(sock)

    def close_pipe(self) -> None:
        with self._fd_lock:
            for fd in (self._wake_r, self._wake_w):
                if fd >= 0:
                    with contextlib.suppress(OSError):
                        os.close(fd)
            self._wake_r = self._wake_w = -1

    def _reach(self, name: LimitName) -> None:
        if name not in self.limits_reached:
            self.limits_reached.append(name)

    def _store(self, packet: Packet, size: int) -> None:
        if not self.storing:
            return
        limits = self.limits
        if limits.max_stored_packets is not None and len(self.packets) >= limits.max_stored_packets:
            self.storing = False
            self._reach("max_stored_packets")
        elif (
            limits.max_stored_bytes is not None
            and self.stored_bytes + size > limits.max_stored_bytes
        ):
            self.storing = False
            self._reach("max_stored_bytes")
        else:
            self.packets.append(packet)
            self.stored_bytes += size

    def _write(self, packet: Packet, raw: bytes) -> None:
        writer = self.writer
        if writer is None or not self.writing:
            return
        limit = self.limits.max_file_bytes
        if limit is not None and writer.bytes + PCAP_RECORD_HEADER_BYTES + len(raw) > limit:
            self.writing = False  # keep the file a contiguous prefix of the capture
            self._reach("max_file_bytes")
            return
        try:
            writer.write(float(packet.time), raw)
        except Exception as exc:
            self.writing = False
            self.writer_failed = True
            self.errors.append(f"PCAP write failed: {exc!r}")

    def _flush(self) -> None:
        writer = self.writer
        if writer is None or self.writer_failed or not writer.dirty:
            return
        try:
            writer.flush()
        except Exception as exc:
            self.writing = False
            self.writer_failed = True
            self.errors.append(f"PCAP flush failed: {exc!r}")

    def _close_writer(self) -> None:
        writer = self.writer
        if writer is None:
            return
        self.writer = None
        try:
            writer.close()
        except Exception as exc:
            self.writer_failed = True
            self.errors.append(f"PCAP close failed: {exc!r}")
        self.written = writer.packets
        self.written_bytes = writer.bytes

    def _read_one(self, sock: Any) -> bool:
        """Read one packet; ``False`` once max_packets is reached."""
        packet = sock.recv()
        if packet is None:
            return True
        packet.sniffed_on = self.iface
        raw = _raw_bytes(packet)
        self.observed += 1
        self.bytes += len(raw)
        if self.snaplen is not None and len(raw) >= self.snaplen:
            self.truncated += 1
        beacon = _beacons.parse(raw)
        if beacon is not None:  # recorded, written, never in the packet list
            token, label = beacon
            self.beacons.append(
                BeaconSighting(
                    label=label, token=token, seen_at=float(packet.time), index=self.observed - 1
                )
            )
        else:
            self._store(packet, len(raw))
        self._write(packet, raw)
        limit = self.limits.max_packets
        if limit is not None and self.observed >= limit:
            self._reach("max_packets")
            return False
        return True

    def _loop(self, sock: Any) -> None:
        duration = self.limits.max_duration
        deadline = None if duration is None else time.monotonic() + duration
        while not self.stop_requested.is_set():
            timeout = None if self.writer is None else _FLUSH_IDLE
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self._reach("max_duration")
                    self.ended_by_limit = True
                    return
                timeout = remaining if timeout is None else min(timeout, remaining)
            readable, _, broken = select.select([sock.ins, self._wake_r], [], [sock.ins], timeout)
            if broken:
                raise OSError("socket reported an exceptional condition")
            if sock.ins in readable:
                if not self._read_one(sock):
                    self.ended_by_limit = True
                    return
            elif not readable:
                self._flush()  # idle: make the file current

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
        # A file error does not stop the drain: the counters must stay meaningful.
        if not self.socket_failed and "max_packets" not in self.limits_reached:
            deadline = time.monotonic() + drain_budget
            try:
                while select.select([sock.ins], [], [], 0)[0]:
                    if time.monotonic() >= deadline:
                        self.errors.append("stop drain budget exhausted with packets still queued")
                        break
                    if not self._read_one(sock):
                        break
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
        output: str | os.PathLike[str] | None = None,
        limits: CaptureLimits | None = None,
        netns: str | None = None,
        beacons: bool = False,
        required_bytes: int | None = None,
    ) -> None:
        """
        Arm a sniffer on *iface*.

        *netns* names the network namespace that holds *iface*; by default it is
        the namespace NSE runs in. The capture thread enters it before opening
        the socket, so nothing else in the process changes namespace. For a
        sandbox, pass ``iface=sandbox.ext_iface, netns=sandbox.ext_netns``.

        *filter* is combined with :data:`DEFAULT_FILTER` unless
        *replace_default_filter* is set, in which case it is used alone. The
        override exists because the default is compiled into BPF and evaluated
        in the kernel: a packet it excludes never reaches userspace, so a caller
        that needs to assert on suppressed traffic cannot compensate downstream.
        Combining is the safe default; replacing is the escape hatch.

        *output* switches to file mode: packets are written progressively to a
        new PCAP file at that path (an existing file is never overwritten; that
        is a start failure), and memory keeps only a sample, by default none
        (``max_stored_packets=0``). *limits* bounds the capture in either mode;
        see :class:`~nse.models.capture_report.CaptureLimits`.

        *beacons* admits beacon frames (:meth:`mark`) through a custom
        *filter*; the default filter already admits them. *required_bytes*
        declares how much of each frame the caller needs: a capture that reads
        less is never ``window_complete``.
        """
        if required_bytes is not None and required_bytes < 1:
            raise ValueError("required_bytes must be positive")
        limits = limits or CaptureLimits()
        if output is None and limits.max_file_bytes is not None:
            raise ValueError("max_file_bytes needs an output file")
        if (
            output is not None
            and limits.max_stored_packets is None
            and limits.max_stored_bytes is None
        ):
            limits = limits.model_copy(update={"max_stored_packets": 0})
        self.output = None if output is None else os.path.abspath(os.fspath(output))
        self.limits = limits
        self.iface = iface
        self.netns = netns
        self.requested_filter = filter
        self.replace_default_filter = bool(filter) and replace_default_filter
        if filter and replace_default_filter:
            self.filter = filter
        elif filter:
            self.filter = f"({DEFAULT_FILTER}) and ({filter})"
        else:
            self.filter = DEFAULT_FILTER
        self.beacons = beacons
        if beacons and filter:
            self.filter = f"({self.filter}) or ({_beacons.FILTER})"
        self.required_bytes = required_bytes
        self._expected: list[Beacon] = []

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

        thread = _CaptureLoop(
            self.iface, self.filter, on_ready, self.limits, self.output, self.netns
        )
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

    # ---------------------------------------------------------------- beacons
    async def mark(self, label: str, *, via: Any = None) -> Beacon:
        """Send a beacon this capture must see, and expect it.

        With no *via*, the frame is sent on the captured interface itself, so
        seeing it proves the capture was reading at that moment. With
        ``via=sandbox`` it is sent by :meth:`NamespaceSandbox.beacon` from the
        sandbox's end of its link, so seeing it also proves the path from the
        sandbox reaches the capture. Mark before and after a window: the report
        is ``window_complete`` only if every expected beacon was seen.

        Raises :class:`CaptureStateError` unless the capture is running, or if
        a custom filter was given without ``beacons=True`` (it may drop them),
        and ``OSError`` if the frame cannot be sent.
        """
        if self.state != "running":
            raise CaptureStateError(f"capture on {self.iface} is not running")
        if self.requested_filter and not self.beacons:
            raise CaptureStateError(
                f"capture on {self.iface} has a custom filter that may drop beacons; "
                "create it with beacons=True"
            )
        thread = self._loop_thread
        assert thread is not None
        if thread.hardware_type not in _ETHERNET_HARDWARE:
            raise CaptureStateError(
                f"capture on {self.iface} is not on an Ethernet link "
                f"(ARPHRD {thread.hardware_type}): beacon frames cannot cross it"
            )
        if via is None:
            beacon = await _beacons.send(self.iface, self.netns, label)
        else:
            beacon = await via.beacon(label)
        self._expected.append(beacon)
        return beacon

    def expect(self, beacon: Beacon) -> None:
        """Expect *beacon*, sent by other means (e.g. ``sandbox.beacon()``), in this capture."""
        if self.state == "finished" or self._report is not None:
            raise CaptureStateError(f"capture on {self.iface} has already stopped")
        self._expected.append(beacon)

    # ------------------------------------------------------------------- stop
    async def stop(self, timeout: float = DEFAULT_STOP_TIMEOUT) -> list[Packet]:
        """Stop the capture and return the packets it stored.

        Raises :class:`CaptureError` when the instrument was not healthy (start
        failure, backend crash, stop timeout, socket or file errors): an empty
        list is only ever returned for a capture that worked and kept everything
        it saw, or for a bounded capture whose report says otherwise. Kernel
        drops and reached limits do not raise here; they are logged and reported
        by :meth:`stop_report` (``window_complete=False``). In file mode, or with
        ``max_stored_*`` limits, the list is only the declared sample: assert on
        the report and its counters, not on the list.
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
                "capture on %s: kernel dropped %d packet(s); the capture is incomplete",
                self.iface,
                report.kernel_drops,
            )
        if report.packets_stored < report.packets_observed - len(report.beacons_seen):
            logger.warning(
                "capture on %s: returning %d of %d packet(s) observed (%s mode, limits %s); "
                "use stop_report() for the counters",
                self.iface,
                report.packets_stored,
                report.packets_observed,
                report.output_mode,
                report.limits_reached,
            )
        if report.termination == "limit_reached":
            logger.warning(
                "capture on %s ended itself at %s before stop() was called",
                self.iface,
                report.limits_reached,
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
        elif ended_early and thread.ended_by_limit:
            termination = "limit_reached"
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

        written, written_bytes, artifacts, artifact_complete = self._artifact_state(thread, alive)

        from scapy import VERSION as scapy_version

        self._report = CaptureReport(
            iface=self.iface,
            netns=self.netns,
            requested_filter=self.requested_filter,
            effective_filter=self.filter,
            default_filter_replaced=self.replace_default_filter,
            backend=_BACKEND,
            backend_version=str(scapy_version),
            output_mode="memory" if self.output is None else "file",
            limits=self.limits,
            termination=termination,
            start_failure=self._start_failure,
            errors=errors,
            start_requested_at=self._start_requested_at,
            started_at=thread.started_at,
            stop_requested_at=self._stop_requested_at,
            stopped_at=None if alive else thread.stopped_at,
            packets_observed=thread.observed,
            bytes_observed=thread.bytes,
            packets_stored=len(thread.packets),
            bytes_stored=thread.stored_bytes,
            packets_written=written,
            bytes_written=written_bytes,
            artifacts=artifacts,
            artifact_complete=artifact_complete,
            limits_reached=list(thread.limits_reached),
            kernel_packets=kernel[0] if kernel else None,
            kernel_drops=kernel[1] if kernel else None,
            stats_unavailable_reason=None if kernel else reason,
            hardware_type=thread.hardware_type,
            link_type=(
                None
                if thread.hardware_type is None
                else _ARPHRD_TO_LINKTYPE.get(thread.hardware_type)
            ),
            snaplen=thread.snaplen,
            required_bytes=self.required_bytes,
            packets_truncated=thread.truncated,
            beacons_expected=list(self._expected),
            beacons_seen=list(thread.beacons),
        )

    def _artifact_state(
        self, thread: _CaptureLoop, alive: bool
    ) -> tuple[int | None, int | None, list[str], bool | None]:
        """File-mode fields of the report: what was written and whether it is whole."""
        if self.output is None:
            return None, None, [], None
        if thread.written is None:  # never opened, or the thread still owns it
            if alive and thread.writer is not None:
                return thread.writer.packets, thread.writer.bytes, [self.output], False
            return None, None, [], False
        try:
            size: int | None = os.stat(self.output).st_size  # what is really on disk
        except OSError:
            size = thread.written_bytes
        complete = not alive and not thread.writer_failed and thread.written == thread.observed
        return thread.written, size, [self.output], complete
