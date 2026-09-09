# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""
TraceHarvester: parse `nft monitor trace` output into TraceEvent objects.

nft monitor trace emits lines like::

    trace id 1be8aad4 ip filter input packet: iif "veth0" ...
    trace id 1be8aad4 ip filter input rule 0x4 (handle 3) tcp dport 80 accept (verdict accept)
    trace id 1be8aad4 ip filter input verdict accept
    trace id 1be8aad4 ip filter input policy accept

Each line is parsed into a TraceEvent and pushed onto an ``asyncio.Queue``.
The sentinel value ``None`` is pushed when monitoring ends.

Reliability contract
--------------------

This module is an *oracle*: downstream code decides PASS/FAIL from what it
reports. An oracle that silently reports nothing is worse than one that crashes,
so every way this class can stop seeing is made observable:

* :attr:`state` records *why* the read loop ended — a crash, a timeout and a
  clean end are three distinguishable outcomes, not one silent sentinel.
* :attr:`unparsed_trace_lines` counts lines that look like trace output but that
  the regexes did not understand. A kernel or nftables format change shows up
  here as a number, instead of vanishing at DEBUG level.
* :meth:`wait_for_event` lets a caller prove the harvester is actually seeing
  kernel events (see the canary probe in :mod:`nse.core.pipeline`) rather than
  merely having scheduled its read loop.

The deadline is a mutable attribute (:meth:`extend_deadline`) because the
previous fixed timeout could expire while packets were still being injected,
truncating the verdict stream without any error.
"""

from __future__ import annotations

import asyncio
import contextlib
import enum
import logging
import os
import re
import time
from collections.abc import Callable
from typing import TYPE_CHECKING

from nse.core.paths import resolve

if TYPE_CHECKING:
    from nse.models.trace_event import TraceEvent

logger = logging.getLogger("nse.core.trace_harvester")

# How many unparsed lines to keep verbatim for the error message.
_MAX_UNPARSED_SAMPLES = 5

#: The read loop re-checks its deadline this often. It must stay short: a read
#: parked on a long timeout cannot notice that extend_deadline() moved the
#: deadline, which is the whole mechanism that keeps long runs alive.
_DEADLINE_POLL_INTERVAL = 0.2


class HarvestState(str, enum.Enum):
    """Terminal state of the trace read loop."""

    NOT_STARTED = "not_started"
    RUNNING = "running"
    #: `nft monitor trace` closed its stdout after a stop() was requested.
    STOPPED = "stopped"
    #: stdout reached EOF without anybody asking for it (the monitor died).
    CLEAN_EOF = "clean_eof"
    #: The deadline expired while the monitor was still running.
    TIMEOUT = "timeout"
    #: The read loop raised.
    ERROR = "error"

    @property
    def is_healthy(self) -> bool:
        """True only for the states that mean 'the oracle worked as intended'."""
        return self in (HarvestState.STOPPED, HarvestState.RUNNING)


# --- Regex patterns for nft monitor trace output --------------------------
#
# nftables identifiers are not `\w+`: table and chain names accept '-', '.' and
# '/' and may be printed quoted. Matching them with `\w+` made the parser fail
# *silently* on any ruleset using a hyphenated table name.
#: Either a quoted name (which may contain spaces) or a bare one.
_IDENT = r'(?P<%s>"[^"]+"|[A-Za-z0-9_./-]+)'
_PREFIX = (
    r"trace id (?P<trace_id>[0-9a-fA-F]+) "
    + (_IDENT % "family")
    + " "
    + (_IDENT % "table")
    + " "
    + (_IDENT % "chain")
    + " "
)


def _unquote(value: str | None) -> str | None:
    """Strip the quotes nft puts around names that need them."""
    if value is None:
        return None
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


_PACKET_RE = re.compile(_PREFIX + r"packet:(?:.*?\biif \"?(?P<iif>[^\s\"]+)\"?)?")
_RULE_RE = re.compile(
    _PREFIX + r"rule (?:(?P<rule_id>0x[\da-f]+) \(handle (?P<handle>\d+)\) )?"
    r"(?P<rule_text>.+?)(?: \(verdict (?P<verdict>\w+)\))?$"
)
_VERDICT_RE = re.compile(_PREFIX + r"(?:verdict|policy) (?P<verdict>\w+)")

#: A line that starts like trace output. Anything matching this that none of the
#: three patterns above understands is an oracle failure, not noise.
_TRACE_LINE_RE = re.compile(r"^trace id \S+ ")


class TraceHarvester:
    """
    Async subprocess wrapper for `nft monitor trace`.

    Usage::

        harvester = TraceHarvester()
        await harvester.start(netns_name="nse_abc", queue=event_queue)
        await harvester.wait_for_event(timeout=1.0)   # prove it can see
        # later…
        state = await harvester.aclose()
    """

    def __init__(self) -> None:
        self._proc: asyncio.subprocess.Process | None = None
        self._task: asyncio.Task[None] | None = None
        self._ready_event = asyncio.Event()
        self._event_signal = asyncio.Event()
        self._stop_requested = False
        self._deadline: float = 0.0

        self.state: HarvestState = HarvestState.NOT_STARTED
        #: Exception that ended the read loop, if any.
        self.error: BaseException | None = None
        #: trace ids observed so far, in first-seen order.
        self.seen_trace_ids: list[str] = []
        #: Lines that look like trace output but that no pattern matched.
        self.unparsed_trace_lines: int = 0
        #: Lines that do not look like trace output at all (banners, warnings).
        self.unparsed_other_lines: int = 0
        #: A few unparsed lines kept verbatim, for the failure message.
        self.unparsed_samples: list[str] = []

    # ------------------------------------------------------------------
    # Readiness / liveness
    # ------------------------------------------------------------------

    async def wait_ready(self, timeout: float = 2.0) -> bool:
        """
        Wait until the read loop is scheduled and reading.

        .. warning::
           This proves only that *this process* is ready to read. It does **not**
           prove that ``nft monitor trace`` has subscribed to the kernel's
           netlink group, so it is not sufficient on its own to conclude that a
           later packet will be observed. Use :meth:`wait_for_event` with a
           canary packet for that.
        """
        try:
            await asyncio.wait_for(self._ready_event.wait(), timeout=timeout)
            return True
        except asyncio.TimeoutError:
            return False

    async def wait_for_event(self, timeout: float = 1.0) -> bool:
        """
        Wait until at least one trace event has been parsed since the last
        :meth:`arm_event_signal`.

        This is the real readiness proof: it returns True only once the kernel
        has actually delivered a trace event through the monitor process.
        """
        try:
            await asyncio.wait_for(self._event_signal.wait(), timeout=timeout)
            return True
        except asyncio.TimeoutError:
            return False

    def arm_event_signal(self) -> None:
        """Clear the event signal so the next :meth:`wait_for_event` waits for a *new* event."""
        self._event_signal.clear()

    def extend_deadline(self, seconds: float) -> None:
        """
        Push the read-loop deadline at least *seconds* into the future.

        Called after every packet injection so a long packet sequence cannot run
        past a deadline that was fixed when the loop started.
        """
        target = asyncio.get_event_loop().time() + seconds
        self._deadline = max(self._deadline, target)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(
        self,
        netns_name: str,
        queue: asyncio.Queue[TraceEvent | None],
        timeout: float = 10.0,
        use_nsenter: bool = False,
        on_event: Callable[[TraceEvent], None] | None = None,
    ) -> None:
        """
        Launch `nft monitor trace` inside *netns_name* and begin streaming.

        Args:
            netns_name: The target network namespace.
            queue:      Output queue (TraceEvent or None sentinel on completion).
            timeout:    Initial seconds of inactivity before giving up. Extend it
                        with :meth:`extend_deadline` as work proceeds.
            use_nsenter: Use nsenter fallback in container environments.
            on_event:   Optional callback invoked synchronously on every parsed TraceEvent.
        """
        self._ready_event.clear()
        self._event_signal.clear()
        self._stop_requested = False
        self.error = None
        if use_nsenter:
            cmd = [
                resolve("nsenter"),
                f"--net=/var/run/netns/{netns_name}",
                "--",
                resolve("nft"),
                "monitor",
                "trace",
            ]
        else:
            cmd = [resolve("ip"), "netns", "exec", netns_name, resolve("nft"), "monitor", "trace"]
        logger.debug("Starting trace monitor: %s", " ".join(cmd))

        self._proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=None,
        )
        self.state = HarvestState.RUNNING
        self._deadline = asyncio.get_event_loop().time() + timeout
        self._task = asyncio.ensure_future(self._read_loop(queue=queue, on_event=on_event))

    async def _read_loop(
        self,
        queue: asyncio.Queue[TraceEvent | None],
        on_event: Callable[[TraceEvent], None] | None = None,
    ) -> None:
        """Read stdout line by line, parse, and push to queue."""

        assert self._proc is not None
        assert self._proc.stdout is not None

        self._ready_event.set()
        end_state = HarvestState.CLEAN_EOF

        try:
            while True:
                remaining = self._deadline - asyncio.get_event_loop().time()
                if remaining <= 0:
                    logger.warning("Trace monitor deadline reached with the monitor still open.")
                    end_state = (
                        HarvestState.STOPPED if self._stop_requested else HarvestState.TIMEOUT
                    )
                    break

                try:
                    line_bytes = await asyncio.wait_for(
                        self._proc.stdout.readline(),
                        timeout=min(remaining, _DEADLINE_POLL_INTERVAL),
                    )
                except asyncio.TimeoutError:
                    # Not necessarily the end: re-read the deadline, which an
                    # injection may have pushed further out while we waited.
                    continue

                if not line_bytes:
                    # EOF. Expected when we asked the monitor to stop; otherwise
                    # the monitor died on its own and the oracle went blind.
                    end_state = (
                        HarvestState.STOPPED if self._stop_requested else HarvestState.CLEAN_EOF
                    )
                    break

                line = line_bytes.decode(errors="replace").strip()
                if not line:
                    continue

                event = _parse_line(line)
                if event is None:
                    self._record_unparsed(line)
                    continue

                logger.debug("TraceEvent: %s", event)
                if event.trace_id and event.trace_id not in self.seen_trace_ids:
                    self.seen_trace_ids.append(event.trace_id)
                await queue.put(event)
                self._event_signal.set()
                if on_event is not None:
                    on_event(event)

        except asyncio.CancelledError:
            self.state = HarvestState.STOPPED
            raise
        except Exception as exc:
            logger.exception("Error in trace read loop")
            self.error = exc
            end_state = HarvestState.ERROR
        finally:
            if self.state is HarvestState.RUNNING:
                self.state = end_state
            with contextlib.suppress(asyncio.CancelledError):
                await queue.put(None)
            self._terminate_process()

    def _record_unparsed(self, line: str) -> None:
        """Account for a line the parser did not understand."""
        if _TRACE_LINE_RE.match(line):
            self.unparsed_trace_lines += 1
            logger.warning("Unparsed TRACE line (oracle blind spot): %r", line)
        else:
            self.unparsed_other_lines += 1
            logger.debug("Unparsed non-trace line: %r", line)
        if len(self.unparsed_samples) < _MAX_UNPARSED_SAMPLES:
            self.unparsed_samples.append(line)

    def _terminate_process(self) -> None:
        if self._proc and self._proc.returncode is None:
            with contextlib.suppress(ProcessLookupError, OSError):
                self._proc.terminate()

    def stop(self) -> None:
        """
        Ask the monitor to terminate. Does not cancel the read loop, so events
        already buffered are still parsed; prefer :meth:`aclose`, which waits.
        """
        self._stop_requested = True
        self._terminate_process()

    async def aclose(self, timeout: float = 2.0) -> HarvestState:
        """
        Stop the monitor, drain the read loop, and return the terminal state.

        Unlike the old ``stop()``, this never cancels the read loop out from
        under a partially-parsed line, so the state it returns is trustworthy.
        """
        self.stop()
        if self._task is not None and not self._task.done():
            try:
                await asyncio.wait_for(asyncio.shield(self._task), timeout=timeout)
            except asyncio.TimeoutError:
                self._task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await self._task
            except asyncio.CancelledError:
                self.state = HarvestState.STOPPED
        if self.state is HarvestState.RUNNING:
            self.state = HarvestState.STOPPED
        return self.state

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    def health_errors(self) -> list[str]:
        """
        Return the reasons this harvester cannot be trusted, empty if it can.

        The pipeline turns each of these into an ``error`` TraceEvent, which the
        CLI runner already fails on.
        """
        problems: list[str] = []
        if self.state is HarvestState.TIMEOUT:
            problems.append(
                "trace monitor timed out while still running: the verdict stream is truncated"
            )
        elif self.state is HarvestState.CLEAN_EOF:
            problems.append(
                "trace monitor exited on its own before the run finished "
                "(is `nft monitor trace` available inside the namespace?)"
            )
        elif self.state is HarvestState.ERROR:
            problems.append(f"trace read loop crashed: {self.error!r}")
        elif self.state is HarvestState.NOT_STARTED:
            problems.append("trace monitor was never started")

        if self.unparsed_trace_lines:
            sample = "; ".join(repr(s) for s in self.unparsed_samples[:3])
            problems.append(
                f"{self.unparsed_trace_lines} trace line(s) could not be parsed - the "
                f"parser does not understand this nftables/kernel output: {sample}"
            )
        return problems


# ---------------------------------------------------------------------------
# Line parser
# ---------------------------------------------------------------------------


def _parse_line(line: str) -> TraceEvent | None:
    """Attempt to parse a single `nft monitor trace` line into a TraceEvent."""
    from nse.models.trace_event import TraceEvent

    # Test hook: simulate a parser that understands nothing, which is what a
    # kernel/nftables format change looks like from the outside. The suite
    # asserts that a blind parser makes the whole run fail rather than pass;
    # see tests/test_oracle_blindness.py.
    if os.environ.get("NSE_FORCE_BLIND"):
        return None

    now = time.time()

    m = _PACKET_RE.match(line)
    if m:
        return TraceEvent(
            type="hook",
            trace_id=m.group("trace_id"),
            family=_unquote(m.group("family")),
            table=_unquote(m.group("table")),
            chain=_unquote(m.group("chain")),
            hook=m.group("iif") or "",
            timestamp=now,
        )

    m = _RULE_RE.match(line)
    if m:
        verdict = m.group("verdict")
        return TraceEvent(
            type="match",
            trace_id=m.group("trace_id"),
            family=_unquote(m.group("family")),
            table=_unquote(m.group("table")),
            chain=_unquote(m.group("chain")),
            rule_handle=int(m.group("handle")) if m.group("handle") else None,
            rule_text=m.group("rule_text").strip(),
            verdict=verdict.upper() if verdict else None,
            timestamp=now,
        )

    m = _VERDICT_RE.match(line)
    if m:
        return TraceEvent(
            type="verdict",
            trace_id=m.group("trace_id"),
            family=_unquote(m.group("family")),
            table=_unquote(m.group("table")),
            chain=_unquote(m.group("chain")),
            verdict=m.group("verdict").upper(),
            timestamp=now,
        )

    return None
