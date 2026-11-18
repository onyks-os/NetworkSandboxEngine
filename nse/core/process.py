# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""
Managed application processes inside a network namespace.

Launch chain
------------
::

    <namespace prefix> [setpriv <identity> --] sh -c PROBE nse-launch argv...

1. The namespace prefix (``ip netns exec`` or ``nsenter``) enters the network
   namespace with NSE's own privileges.
2. ``setpriv`` (util-linux) applies the requested identity: UID, GID,
   supplementary groups, capabilities. It refuses, rather than continuing,
   when any part cannot be applied. Nothing runs as a ``preexec_fn`` in NSE's
   multi-threaded process.
3. A POSIX shell probe, which already *is* the final process (same PID), sends
   its own ``/proc/$$/status`` to NSE and blocks. NSE compares the identity the
   kernel reports with the request and only then lets the probe ``exec`` the
   application. On a mismatch the application never starts: there is no
   fallback to root.

The handshake runs over the chain's stdin, one end of a socketpair: the probe
writes the report to descriptor 0 and reads the answer from it, then starts the
application with stdin on ``/dev/null``. Only descriptors 0-2 are involved, so it
works with any POSIX ``sh`` (dash only redirects descriptors 0-9), and the
application inherits none of NSE's descriptors.

Boundary
--------
Each managed process leads a new session, so its process group is stopped as a
unit (SIGTERM, a grace period, then SIGKILL). A descendant that leaves the group
(``setsid``, daemonisation) is still inside the network namespace, and the
namespace is the boundary NSE enforces before deleting it:
:func:`terminate_namespace` stops every process in it. Membership is checked
through a pidfd, so a recycled PID is never signalled, and crash recovery needs
no PID records at all. A process that moves itself to another network namespace
(which requires CAP_SYS_ADMIN) is outside this boundary.
"""

from __future__ import annotations

import asyncio
import contextlib
import ctypes
import errno
import logging
import os
import signal
import socket
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Literal, Union

from nse.core.async_work import run_blocking
from nse.core.paths import resolve
from nse.models.process import (
    CAPABILITIES,
    EffectiveIdentity,
    ProcessIdentity,
    ProcessResult,
    Termination,
)

logger = logging.getLogger("nse.core.process")

#: ``(st_dev, st_ino)`` of a network namespace, as from ``stat()``.
NetnsIdentity = tuple[int, int]
Output = Union[Literal["capture", "discard"], str, "os.PathLike[str]"]
Stream = Literal["stdout", "stderr"]
StartFailure = Literal[
    "program_not_found", "launch_failed", "timeout", "identity_mismatch", "identity_unsupported"
]

#: Seconds start_process() waits for the launch chain to report the identity.
DEFAULT_START_TIMEOUT = 5.0
#: Seconds between SIGTERM and SIGKILL when NSE stops a process.
DEFAULT_GRACE = 2.0
#: Bytes kept per captured stream; the rest is counted and discarded.
DEFAULT_OUTPUT_LIMIT = 1024 * 1024
#: Seconds to finish reading captured output once the process has ended.
_OUTPUT_DRAIN = 1.0
_REPORT_LIMIT = 64 * 1024
_LAUNCHER = "nse-launch"

_REPORT_END = b"nse-identity-end\n"
_MISSING = b"nse-program-missing\n"

#: The probe; "$@" is the application's argv. Descriptor 0 is the handshake
#: socket. Redirection order matters: stdout goes to the socket before stdin is
#: pointed at the status file.
_PROBE = """if ! command -v "$1" >/dev/null 2>&1; then printf 'nse-program-missing\\n' >&0; exit 127; fi
while IFS= read -r line; do printf '%s\\n' "$line"; done >&0 </proc/$$/status
printf 'nse-identity-end\\n' >&0
IFS= read -r go || exit 125
[ "$go" = go ] || exit 125
exec "$@" </dev/null
"""


class ProcessStartError(RuntimeError):
    """The application was not started; ``reason`` says why, ``stderr`` what the chain said."""

    def __init__(self, message: str, reason: StartFailure, stderr: bytes = b"") -> None:
        super().__init__(message)
        self.reason = reason
        self.stderr = stderr


class IdentityError(ProcessStartError):
    """The kernel reported an identity other than the one requested; nothing ran."""

    def __init__(
        self, message: str, observed: EffectiveIdentity | None, problems: list[str]
    ) -> None:
        super().__init__(message, "identity_mismatch")
        self.observed = observed
        self.problems = problems


class ProcessExitedError(RuntimeError):
    """The process ended before producing the awaited output; ``result`` says how."""

    def __init__(self, message: str, result: ProcessResult) -> None:
        super().__init__(message)
        self.result = result


def validate_argv(argv: Sequence[str | os.PathLike[str]]) -> list[str]:
    """Return *argv* as a list of ``str`` or explain, before any process starts, why not."""
    if isinstance(argv, (str, bytes, bytearray)) or not isinstance(argv, Sequence):
        raise TypeError(
            "argv must be a sequence of arguments, not a single string; "
            "use exec() for a whitespace-split command"
        )
    arguments: list[str] = []
    for index, raw in enumerate(argv):
        value = os.fspath(raw) if isinstance(raw, os.PathLike) else raw
        if not isinstance(value, str):
            raise TypeError(
                f"argv[{index}] must be str or os.PathLike[str], got {type(value).__name__}"
            )
        if "\0" in value:
            raise ValueError(
                f"argv[{index}] contains a NUL character, which no process can receive"
            )
        arguments.append(value)
    if not arguments or not arguments[0]:
        raise ValueError("argv must start with a non-empty program name")
    return arguments


# --------------------------------------------------------------------------- pidfd

#: pidfd_send_signal(2) and pidfd_open(2). Both postdate the unified syscall
#: numbering, so the numbers are the same on every Linux architecture.
_SYS_PIDFD_SEND_SIGNAL = 424
_SYS_PIDFD_OPEN = 434


def _syscall(number: int, *args: int) -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    result = int(libc.syscall(number, *args))
    if result < 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))  # ESRCH becomes ProcessLookupError
    return result


def pidfd_open(pid: int) -> int:
    """``os.pidfd_open``, or the raw syscall on Python builds that lack the wrapper."""
    if hasattr(os, "pidfd_open"):
        return os.pidfd_open(pid)
    return _syscall(_SYS_PIDFD_OPEN, pid, 0)


def pidfd_send_signal(pidfd: int, sig: int) -> None:
    """``signal.pidfd_send_signal``, or the raw syscall when the wrapper is missing."""
    if hasattr(signal, "pidfd_send_signal"):
        signal.pidfd_send_signal(pidfd, sig)
    else:
        _syscall(_SYS_PIDFD_SEND_SIGNAL, pidfd, sig, 0, 0)


# --------------------------------------------------------------------------- the namespace boundary


def _netns_of(pid: int) -> NetnsIdentity | None:
    try:
        info = os.stat(f"/proc/{pid}/ns/net")
    except OSError:  # gone, a zombie, or a kernel thread we may not inspect
        return None
    return info.st_dev, info.st_ino


def _stat_fields(pid: int) -> list[bytes] | None:
    """Fields of /proc/<pid>/stat after the command name: [0] state, [2] pgrp, [19] start."""
    try:
        data = Path(f"/proc/{pid}/stat").read_bytes()
    except OSError:
        return None
    return data[data.rindex(b")") + 2 :].split()


def _belongs(pid: int, netns: NetnsIdentity, pgid: int | None) -> bool:
    if _netns_of(pid) != netns:
        return False
    if pgid is None:
        return True
    fields = _stat_fields(pid)
    return fields is not None and int(fields[2]) == pgid


class ProtectedNamespaceError(RuntimeError):
    """Refusal to sweep the namespace NSE itself, or PID 1, runs in: never a sandbox."""


def _refuse_protected(netns: NetnsIdentity) -> None:
    protected = {_netns_of(os.getpid()), _netns_of(1)} - {None}
    if netns in protected:
        raise ProtectedNamespaceError(
            f"network namespace {netns} is the host's or NSE's own; refusing to signal it"
        )


def namespace_processes(netns: NetnsIdentity, *, pgid: int | None = None) -> list[int]:
    """PIDs of the processes in network namespace *netns* (and process group *pgid*).

    Raises :class:`ProtectedNamespaceError` for NSE's own or PID 1's namespace.
    """
    _refuse_protected(netns)
    own = os.getpid()
    members = []
    for entry in os.scandir("/proc"):
        if (
            entry.name.isdigit()
            and int(entry.name) != own
            and _belongs(int(entry.name), netns, pgid)
        ):
            members.append(int(entry.name))
    return members


def _send(pid: int, netns: NetnsIdentity, sig: int, pgid: int | None) -> bool:
    """Signal *pid* only if it is still a member; never a process that reused the PID."""
    try:
        pidfd = pidfd_open(pid)
    except ProcessLookupError:
        return False
    except OSError as exc:
        if exc.errno != errno.ENOSYS:
            return False
        return _send_without_pidfd(pid, netns, sig, pgid)
    try:
        # The pidfd pins the process. If the PID was recycled after pidfd_open,
        # the pidfd's process is dead and the signal fails harmlessly with ESRCH.
        if not _belongs(pid, netns, pgid):
            return False
        pidfd_send_signal(pidfd, sig)
        return True
    except ProcessLookupError:
        return False
    finally:
        os.close(pidfd)


def _send_without_pidfd(pid: int, netns: NetnsIdentity, sig: int, pgid: int | None) -> bool:
    """Kernels before 5.3: membership and start time checked on both sides (best effort)."""
    before = _stat_fields(pid)
    if before is None or not _belongs(pid, netns, pgid):
        return False
    after = _stat_fields(pid)
    if after is None or after[19] != before[19]:
        return False
    try:
        os.kill(pid, sig)
    except ProcessLookupError:
        return False
    return True


def signal_namespace(netns: NetnsIdentity, sig: int, *, pgid: int | None = None) -> int:
    """Signal every process in *netns* (and group *pgid*); return how many were signalled."""
    return sum(_send(pid, netns, sig, pgid) for pid in namespace_processes(netns, pgid=pgid))


def _wait_until_empty(netns: NetnsIdentity, timeout: float, pgid: int | None = None) -> bool:
    deadline = time.monotonic() + timeout
    while namespace_processes(netns, pgid=pgid):
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.02)
    return True


def terminate_namespace(
    netns: NetnsIdentity, *, grace: float = 1.0, timeout: float = 3.0
) -> list[int]:
    """Stop every process in *netns*: SIGTERM, *grace*, SIGKILL. Return the survivors.

    Blocking. Called before a namespace is deleted, so that nothing NSE started,
    nor anything those processes left behind, keeps running in it unseen.
    """
    if not namespace_processes(netns):
        return []
    signal_namespace(netns, signal.SIGTERM)
    if _wait_until_empty(netns, grace):
        return []
    signal_namespace(netns, signal.SIGKILL)
    _wait_until_empty(netns, timeout)
    return namespace_processes(netns)


# --------------------------------------------------------------------------- output


class _Capture:
    """Reads one pipe without blocking the loop; keeps at most *limit* bytes."""

    def __init__(self, fd: int, limit: int) -> None:
        self.fd = fd
        self.limit = limit
        self.data = bytearray()
        self.dropped = 0
        self.eof = False
        self.changed = asyncio.Event()
        self._loop = asyncio.get_running_loop()
        os.set_blocking(fd, False)
        self._loop.add_reader(fd, self._readable)

    def _readable(self) -> None:
        try:
            chunk = os.read(self.fd, 65536)
        except BlockingIOError:
            return
        except OSError:
            chunk = b""
        if not chunk:
            self.close()
            return
        room = max(self.limit - len(self.data), 0)
        self.data += chunk[:room]
        self.dropped += len(chunk) - min(room, len(chunk))
        self.changed.set()

    async def wait_eof(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while not self.eof:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            self.changed.clear()
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self.changed.wait(), remaining)
        return True

    def close(self) -> None:
        if self.fd >= 0:
            self._loop.remove_reader(self.fd)
            os.close(self.fd)
            self.fd = -1
        self.eof = True
        self.changed.set()


async def _read_report(sock: socket.socket) -> bytes:
    """The probe's report: up to its end marker, the missing-program line, or EOF."""
    loop = asyncio.get_running_loop()
    buffer = bytearray()
    while not (buffer.endswith(_REPORT_END) or buffer == _MISSING):
        chunk = await loop.sock_recv(sock, 65536)
        if not chunk or len(buffer) + len(chunk) > _REPORT_LIMIT:
            break  # the chain died before reporting, or is not the probe talking
        buffer.extend(chunk)
    return bytes(buffer)


# --------------------------------------------------------------------------- identity


def _setpriv_args(identity: ProcessIdentity) -> list[str]:
    args: list[str] = []
    if identity.uid is not None:
        args.append(f"--reuid={identity.uid}")
    if identity.gid is not None:
        args.append(f"--regid={identity.gid}")
    groups = identity.effective_groups
    if groups is not None:
        args.append(f"--groups={','.join(map(str, groups))}" if groups else "--clear-groups")
    if identity.capabilities is not None:
        spec = ",".join(["-all", *(f"+{name}" for name in sorted(identity.capabilities))])
        args += [f"--inh-caps={spec}", f"--ambient-caps={spec}", f"--bounding-set={spec}"]
    if identity.no_new_privileges:
        args.append("--no-new-privs")
    return args


def _cap_last_cap() -> int:
    return int(Path("/proc/sys/kernel/cap_last_cap").read_text())


def _check_kernel_supports(identity: ProcessIdentity) -> None:
    if not identity.capabilities:
        return
    last = _cap_last_cap()
    unsupported = sorted(c for c in identity.capabilities if CAPABILITIES.index(c) > last)
    if unsupported:
        raise ProcessStartError(
            f"this kernel does not support capabilities {unsupported}", "identity_unsupported"
        )


def _pidfd(pid: int) -> int | None:
    try:
        return pidfd_open(pid)
    except OSError:
        return None


# --------------------------------------------------------------------------- the handle


class ManagedProcess:
    """A process started by :func:`spawn_process`. Stop it with :meth:`terminate`
    or ``async with``; :meth:`wait` and :meth:`terminate` return the same
    :class:`~nse.models.process.ProcessResult` however often they are called."""

    def __init__(
        self,
        *,
        proc: asyncio.subprocess.Process,
        pidfd: int | None,
        argv: list[str],
        command: list[str],
        netns: NetnsIdentity,
        identity: EffectiveIdentity,
        started_at: float,
        captures: dict[Stream, _Capture],
        paths: dict[Stream, str],
    ) -> None:
        self._proc = proc
        self._pidfd = pidfd
        self.argv = argv
        self.command = command
        self.netns = netns
        self.identity = identity
        self.started_at = started_at
        self._captures = captures
        self._paths = paths
        self._exited: asyncio.Future[int] = asyncio.ensure_future(proc.wait())
        self._termination: Termination = "exited"
        self._stop_task: asyncio.Future[ProcessResult] | None = None
        self._finish_task: asyncio.Future[ProcessResult] | None = None

    @property
    def pid(self) -> int:
        return self._proc.pid

    @property
    def returncode(self) -> int | None:
        """None while the process runs."""
        return self._proc.returncode

    def output(self, stream: Stream = "stdout") -> bytes:
        """What has been captured from *stream* so far."""
        return bytes(self._capture(stream).data)

    def _capture(self, stream: Stream) -> _Capture:
        try:
            return self._captures[stream]
        except KeyError:
            raise ValueError(f"{stream} is not captured for this process") from None

    async def wait_for_output(
        self, marker: bytes, *, timeout: float, stream: Stream = "stdout"
    ) -> None:
        """Return once *marker* appears in the captured *stream*: an explicit readiness signal.

        Raises :class:`ProcessExitedError` if the process ends first and
        ``TimeoutError`` (leaving the process running) if *timeout* expires.
        """
        capture = self._capture(stream)
        deadline = time.monotonic() + timeout
        while marker not in capture.data:
            if self._exited.done():
                await capture.wait_eof(_OUTPUT_DRAIN)  # what it printed last may be in flight
                if marker in capture.data:
                    return
                result = await self._finish()
                raise ProcessExitedError(
                    f"process {self.argv[0]!r} exited with {result.returncode} before "
                    f"printing {marker!r}",
                    result,
                )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"{marker!r} not seen on {stream} within {timeout}s")
            capture.changed.clear()
            changed: asyncio.Future[object] = asyncio.ensure_future(capture.changed.wait())
            exited: asyncio.Future[object] = asyncio.ensure_future(asyncio.shield(self._exited))
            try:
                await asyncio.wait(
                    {changed, exited}, timeout=remaining, return_when=asyncio.FIRST_COMPLETED
                )
            finally:
                changed.cancel()
                exited.cancel()

    async def wait(
        self, timeout: float | None = None, *, grace: float = DEFAULT_GRACE
    ) -> ProcessResult:
        """Wait for the process to end. If *timeout* expires, stop it (termination
        ``timeout``); if the waiting task is cancelled, stop it and re-raise."""
        try:
            await asyncio.wait_for(asyncio.shield(self._exited), timeout)
        except asyncio.TimeoutError:
            return await self._stop("timeout", grace)
        except asyncio.CancelledError:
            with contextlib.suppress(asyncio.CancelledError):
                await asyncio.shield(self._stop("cancelled", grace))
            raise
        return await self._stop("exited", grace)

    async def terminate(self, grace: float = DEFAULT_GRACE) -> ProcessResult:
        """Stop the process and its group: SIGTERM, *grace* seconds, then SIGKILL."""
        return await self._stop("terminated", grace)

    async def __aenter__(self) -> ManagedProcess:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.terminate()

    def _stop(self, reason: Termination, grace: float) -> asyncio.Future[ProcessResult]:
        if self._stop_task is None:
            self._stop_task = asyncio.ensure_future(self._do_stop(reason, grace))
        return asyncio.shield(self._stop_task)

    def _signal_group(self, sig: int) -> None:
        if self._pidfd is not None and not self._exited.done():
            with contextlib.suppress(ProcessLookupError):
                pidfd_send_signal(self._pidfd, sig)
        signal_namespace(self.netns, sig, pgid=self.pid)

    async def _do_stop(self, reason: Termination, grace: float) -> ProcessResult:
        if not self._exited.done():
            self._termination = reason
            await run_blocking(self._signal_group, signal.SIGTERM)
            done, _ = await asyncio.wait({self._exited}, timeout=grace)
            if not done:
                await run_blocking(self._signal_group, signal.SIGKILL)
                await asyncio.shield(self._exited)
        if reason != "exited":
            # NSE was asked to stop it: what the leader left in its group, still
            # in the namespace, goes too. After a natural exit such members are
            # left to the namespace teardown, which stops everything in it.
            await run_blocking(signal_namespace, self.netns, signal.SIGKILL, pgid=self.pid)
        return await self._finish()

    def _finish(self) -> asyncio.Future[ProcessResult]:
        """The single finalisation, shared by every caller (stop, readiness, wait)."""
        if self._finish_task is None:
            self._finish_task = asyncio.ensure_future(self._build_result())
        return asyncio.shield(self._finish_task)

    async def _build_result(self) -> ProcessResult:
        await asyncio.shield(self._exited)
        complete = True
        for capture in self._captures.values():
            if not await capture.wait_eof(_OUTPUT_DRAIN):
                complete = False
            capture.close()
        if self._pidfd is not None:
            os.close(self._pidfd)
            self._pidfd = None
        stdout, stderr = self._captures.get("stdout"), self._captures.get("stderr")
        returncode = self._proc.returncode
        assert returncode is not None
        return ProcessResult(
            argv=self.argv,
            command=self.command,
            pid=self.pid,
            identity=self.identity,
            termination=self._termination,
            returncode=returncode,
            started_at=self.started_at,
            ended_at=time.time(),
            stdout=None if stdout is None else bytes(stdout.data),
            stderr=None if stderr is None else bytes(stderr.data),
            stdout_path=self._paths.get("stdout"),
            stderr_path=self._paths.get("stderr"),
            stdout_dropped=0 if stdout is None else stdout.dropped,
            stderr_dropped=0 if stderr is None else stderr.dropped,
            output_complete=complete,
        )


# --------------------------------------------------------------------------- spawning


def _paths(stdout: str | None, stderr: str | None) -> dict[Stream, str]:
    paths: dict[Stream, str] = {}
    if stdout is not None:
        paths["stdout"] = stdout
    if stderr is not None:
        paths["stderr"] = stderr
    return paths


def _open_output(target: Output, fds: list[int]) -> tuple[int | None, str | None, int]:
    """Return (child fd or None, file path, read end or -1); record fds to close."""
    if target == "capture":
        read_end, write_end = os.pipe()
        fds += [read_end, write_end]
        return write_end, None, read_end
    if target == "discard":
        return None, None, -1
    path = os.path.abspath(os.fspath(target))
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o644)
    fds.append(fd)
    return fd, path, -1


async def spawn_process(
    prefix: Sequence[str],
    argv: Sequence[str | os.PathLike[str]],
    *,
    netns: NetnsIdentity,
    identity: ProcessIdentity | None = None,
    env: Mapping[str, str] | None = None,
    cwd: str | os.PathLike[str] | None = None,
    stdout: Output = "capture",
    stderr: Output = "capture",
    max_output_bytes: int = DEFAULT_OUTPUT_LIMIT,
    start_timeout: float = DEFAULT_START_TIMEOUT,
) -> ManagedProcess:
    """Start *argv* through *prefix* (which enters namespace *netns*) and return its handle.

    Returns only after the kernel has confirmed the requested *identity* for the
    process; raises :class:`ProcessStartError` (or :class:`IdentityError`) and
    leaves nothing running otherwise. stdin is ``/dev/null``. *stdout* and
    *stderr* are ``"capture"`` (at most *max_output_bytes* kept, the rest
    counted), ``"discard"``, or a path to a new file (never overwritten).
    """
    args = validate_argv(argv)
    requested = identity or ProcessIdentity()
    _check_kernel_supports(requested)
    if max_output_bytes < 0:
        raise ValueError("max_output_bytes must be non-negative")
    launcher = [resolve("setpriv"), *_setpriv_args(requested), "--"] if requested.requested else []

    fds: list[int] = []  # every descriptor opened here, closed on any failure
    handshake, chain_end = socket.socketpair()
    try:
        handshake.setblocking(False)
        out_fd, out_path, out_read = _open_output(stdout, fds)
        err_fd, err_path, err_read = _open_output(stderr, fds)
        command = [*prefix, *launcher, resolve("sh"), "-c", _PROBE, _LAUNCHER, *args]
        proc = await asyncio.create_subprocess_exec(
            *command,
            stdin=chain_end.fileno(),
            stdout=asyncio.subprocess.DEVNULL if out_fd is None else out_fd,
            stderr=asyncio.subprocess.DEVNULL if err_fd is None else err_fd,
            start_new_session=True,
            env=None if env is None else dict(env),
            cwd=cwd,
        )
    except BaseException:
        handshake.close()
        chain_end.close()
        for fd in fds:
            with contextlib.suppress(OSError):
                os.close(fd)
        raise

    # The child holds its ends now; the parent keeps the handshake and read ends.
    chain_end.close()
    for child_end in (out_fd, err_fd):
        if child_end is not None:
            os.close(child_end)
    pidfd = _pidfd(proc.pid)
    captures: dict[Stream, _Capture] = {}
    if out_read >= 0:
        captures["stdout"] = _Capture(out_read, max_output_bytes)
    if err_read >= 0:
        captures["stderr"] = _Capture(err_read, max_output_bytes)

    async def abandon() -> bytes:
        """Stop whatever the chain started; return what it wrote to stderr."""
        handshake.close()  # a waiting probe reads EOF and exits without exec
        try:
            await asyncio.wait_for(asyncio.shield(proc.wait()), 1.0)
        except asyncio.TimeoutError:
            if pidfd is not None:
                with contextlib.suppress(ProcessLookupError):
                    pidfd_send_signal(pidfd, signal.SIGKILL)
            await run_blocking(signal_namespace, netns, signal.SIGKILL, pgid=proc.pid)
            await proc.wait()
        stderr_capture = captures.get("stderr")
        if stderr_capture is not None:
            await stderr_capture.wait_eof(_OUTPUT_DRAIN)
        text = b"" if stderr_capture is None else bytes(stderr_capture.data)
        for capture in captures.values():
            capture.close()
        if pidfd is not None:
            os.close(pidfd)
        return text

    try:
        report = await asyncio.wait_for(_read_report(handshake), start_timeout)
    except asyncio.TimeoutError:
        stderr_text = await abandon()
        raise ProcessStartError(
            f"{args[0]!r} did not reach the identity check within {start_timeout}s",
            "timeout",
            stderr_text,
        ) from None
    except BaseException:
        await asyncio.shield(abandon())
        raise

    if report == _MISSING:
        stderr_text = await abandon()
        raise ProcessStartError(f"program {args[0]!r} not found", "program_not_found", stderr_text)
    observed: EffectiveIdentity | None = None
    if report.endswith(_REPORT_END):
        with contextlib.suppress(ValueError):
            observed = EffectiveIdentity.from_status(
                report[: -len(_REPORT_END)].decode(errors="replace")
            )
    if observed is None:
        stderr_text = await abandon()
        detail = stderr_text.decode(errors="replace").strip()
        raise ProcessStartError(
            f"the launch chain for {args[0]!r} failed before the identity check"
            + (f": {detail}" if detail else ""),
            "launch_failed",
            stderr_text,
        )
    problems = observed.mismatches(requested)
    if problems:
        await abandon()
        raise IdentityError(
            f"refusing to start {args[0]!r}: " + "; ".join(problems), observed, problems
        )

    started_at = time.time()
    try:
        await asyncio.get_running_loop().sock_sendall(handshake, b"go\n")
    finally:
        handshake.close()
    logger.info("Started %s (pid %d) as uid %d", args, proc.pid, observed.uids[1])
    return ManagedProcess(
        proc=proc,
        pidfd=pidfd,
        argv=args,
        command=command,
        netns=netns,
        identity=observed,
        started_at=started_at,
        captures=captures,
        paths=_paths(out_path, err_path),
    )
