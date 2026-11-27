# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""
Background stimuli at a fixed rate, and what became of each one.

A single probe says what happened at one instant. A rule change, a reload or a
teardown is a window of time, and what matters is what happened to the traffic
*throughout* it. A :class:`StimulusStream` sends the same stimulus once per
period from a process inside the sandbox, numbering every attempt;
:func:`correlate` then says, per sequence number, whether it was not sent,
refused, sent but not seen, seen on the wire or received, and whether the
stream covered the window without pausing::

    from nse import streams, stimuli

    stream = streams.StimulusStream(stimuli.udp("10.0.1.1", 9999), period=0.05)
    async with await stream.start(sandbox, identity=user) as running:
        await asyncio.sleep(0.5)
        reload_started = time.monotonic()
        RuleEngine().load(new_rules, sandbox.name)
        reload_done = time.monotonic()
        await asyncio.sleep(0.5)
    log = running.log()
    joined = streams.correlate(log, packets, receipts, capture=report)
    during = joined.between(reload_started, reload_done)
    assert during.conclusive, during.describe()
    assert not during.with_status("on_wire", "received")

Attempt times are ``CLOCK_MONOTONIC``, the clock :func:`time.monotonic` reads,
so they compare directly with times taken by the test.

A stream can also run somewhere NSE does not manage, a VM over ssh for
instance: :meth:`StimulusStream.command` gives the agent's command line, and
:meth:`~nse.models.stream.StreamLog.parse` reads what it printed. With a
:class:`~nse.models.clock.ClockMap` built from clocked beacons,
``correlate(..., clock=...)`` places the attempts on the capture's clock.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from nse import _agents
from nse.core import probe_packets
from nse.core.paths import BinaryNotFoundError
from nse.core.process import ManagedProcess, ProcessExitedError, ProcessStartError
from nse.models.capture_report import CaptureReport
from nse.models.clock import ClockMap
from nse.models.process import ProcessIdentity, ProcessResult
from nse.models.stimulus import ReceiptLog
from nse.models.stream import (
    Correlation,
    Fate,
    FateStatus,
    StreamLog,
    capture_gaps_between,
    capture_spans,
    covered_times,
    gaps_between,
    parse_log,
)
from nse.stimuli import Stimulus, default_python

__all__ = [
    "RunningStream",
    "StimulusStream",
    "StreamStartError",
    "correlate",
]

_STARTED = b'"event": "started"'
_OUTPUT_LIMIT = 64 * 1024 * 1024
_DEFAULT_MAX_GAP_PERIODS = 3.0


class StreamStartError(RuntimeError):
    """The stream's program did not start; ``result`` holds what it left behind."""

    def __init__(self, message: str, result: ProcessResult | None = None) -> None:
        super().__init__(message)
        self.result = result


@dataclass(frozen=True)
class StimulusStream:
    """*stimulus*, once every *period* seconds, until stopped or a bound is reached.

    *count* stops after that many attempts and *duration* after that many
    seconds; with neither, the stream runs until :meth:`RunningStream.stop`.
    Each attempt opens its own socket in its own thread, so an attempt that
    waits (a TCP connect to a dropped port, a reply timeout) does not delay the
    next one. At most *max_in_flight* attempts run at once; a slot that would
    exceed it is skipped and shows as a gap.
    """

    stimulus: Stimulus
    period: float
    count: int | None = None
    duration: float | None = None
    max_in_flight: int = 256

    def __post_init__(self) -> None:
        if self.period <= 0:
            raise ValueError("period must be positive")
        if self.count is not None and self.count < 1:
            raise ValueError("count must be at least 1")
        if self.duration is not None and self.duration <= 0:
            raise ValueError("duration must be positive")
        if self.max_in_flight < 1:
            raise ValueError("max_in_flight must be at least 1")

    def plan(self, stream_id: str) -> dict[str, Any]:
        """What the agent is told to do: the stimulus's plan plus the schedule."""
        template = stream_id + "0" * 8
        plan = self.stimulus.plan(template)
        plan["stream"] = {
            "prefix": stream_id,
            "template_id": template,
            "period": self.period,
            "count": self.count,
            "duration": self.duration,
            "max_in_flight": self.max_in_flight,
        }
        return plan

    def command(self, python: str = "python3") -> tuple[list[str], str]:
        """The agent's command line, to run wherever the stream should run, and its stream ID.

        The program is standard-library Python, run with *python* (``-I -S``).
        It prints the log to standard output: read it with
        ``StreamLog.parse(output, stream_id, final=..., stream=self)``. It stops
        on SIGTERM, or by itself with *count* or *duration*.
        """
        stream_id = probe_packets.new_probe_id()[:16]
        argv = [python, "-I", "-S", "-c", _agents.source("stimulus")]
        argv.append(json.dumps(self.plan(stream_id)))
        return argv, stream_id

    async def start(
        self,
        sandbox: Any,
        *,
        identity: ProcessIdentity | None = None,
        python: str | None = None,
        ready_timeout: float = 10.0,
    ) -> RunningStream:
        """Start the stream in *sandbox* as *identity*; return once it has begun.

        Raises :class:`StreamStartError` if the program does not say it started
        within *ready_timeout* seconds. A stream whose attempts all fail is
        still a started stream: each failure is in its log.
        """
        argv, stream_id = self.command(python or default_python())
        try:
            process = await sandbox.start_process(
                argv, identity=identity, max_output_bytes=_OUTPUT_LIMIT
            )
        except (ProcessStartError, BinaryNotFoundError) as exc:
            raise StreamStartError(
                f"stream of {self.stimulus.kind} could not start: {exc}", None
            ) from exc
        try:
            await process.wait_for_output(_STARTED, timeout=ready_timeout)
        except ProcessExitedError as exc:
            raise StreamStartError(
                f"stream of {self.stimulus.kind} did not start: {_stderr(exc.result)}",
                exc.result,
            ) from None
        except TimeoutError:
            result = await process.terminate()
            raise StreamStartError(
                f"stream of {self.stimulus.kind} did not start within {ready_timeout}s",
                result,
            ) from None
        return RunningStream(self, process, stream_id)


def _stderr(result: ProcessResult) -> str:
    text = (result.stderr or b"").decode(errors="replace").strip()
    return text[-400:] or f"exited with status {result.returncode}"


class RunningStream:
    """A started stream: read its log while it runs, stop it, or wait for its end."""

    def __init__(self, stream: StimulusStream, process: ManagedProcess, stream_id: str) -> None:
        self.stream = stream
        self.process = process
        self.stream_id = stream_id
        self._final: StreamLog | None = None

    def log(self) -> StreamLog:
        """The attempts so far (final once the stream has ended)."""
        if self._final is not None:
            return self._final
        return self._parse(self.process.output("stdout"), final=False, result=None)

    async def stop(self) -> StreamLog:
        """Stop the stream, let the attempts in flight finish, return the final log."""
        if self._final is None:
            budget = self.stream.stimulus._budget()
            result = await self.process.terminate(grace=budget)
            self._final = self._parse(self.process.output("stdout"), final=True, result=result)
        return self._final

    async def wait(self, timeout: float | None = None) -> StreamLog:
        """Wait for a stream with a *count* or *duration* to end on its own."""
        if self._final is None:
            result = await self.process.wait(timeout)
            self._final = self._parse(self.process.output("stdout"), final=True, result=result)
        return self._final

    async def __aenter__(self) -> RunningStream:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.stop()

    def _parse(self, output: bytes, *, final: bool, result: ProcessResult | None) -> StreamLog:
        dropped = self.process.output_dropped("stdout")
        how = "was killed" if result is None else f"ended ({result.termination})"
        log = parse_log(
            output,
            self.stream_id,
            final=final,
            stream=self.stream,
            identity=None if result is None else result.identity,
            missing_end=f"the stream {how} without reporting its end",
            extra_problems=["the stream's output exceeded the limit and was cut"]
            if dropped
            else [],
        )
        if final and result is not None and result.termination == "exited" and result.returncode:
            problem = f"the stream exited with status {result.returncode}: {_stderr(result)}"
            log = log.model_copy(update={"problems": (*log.problems, problem), "complete": False})
        return log


def correlate(
    stream: StreamLog,
    packets: Iterable[Any] | None,
    receipts: ReceiptLog | None = None,
    *,
    capture: CaptureReport | None = None,
    max_gap_periods: float = _DEFAULT_MAX_GAP_PERIODS,
    nat: bool = False,
    clock: ClockMap | None = None,
) -> Correlation:
    """Join a stream with a capture and a receiver's log, per sequence number.

    *packets* is what the capture returned (``None`` when there was no
    capture). A packet that was seen counts whatever the capture's health; an
    absence counts as ``False`` only with a *capture* report that is healthy
    and complete (``window_complete is True``), and ``None`` otherwise.
    *receipts* likewise counts an absence only when the log is complete.

    *nat* recognises attempts whose destination a NAT rewrote, as
    :func:`nse.stimuli.requests_in` does.

    *clock* places every attempt on the capture's clock (:attr:`Fate.capture_time`),
    from the stream's ``boot_id`` and each attempt's ``CLOCK_BOOTTIME``. The
    window and :meth:`Correlation.between` are then on the capture's clock, and
    an attempt the map cannot place makes the window inconclusive.

    The window is inconclusive (:attr:`Correlation.conclusive` is ``False``)
    when the stream's log is incomplete, when no attempt started for longer
    than *max_gap_periods* periods, when the capture or the receiver cannot
    vouch for an absence, or when they contradict each other.
    """
    if max_gap_periods < 1:
        raise ValueError("max_gap_periods must be at least 1")
    problems = [f"stream log: {problem}" for problem in stream.problems]
    if not stream.complete and not stream.problems:
        problems.append("stream log: not final (read it after stop() or wait())")
    index = (
        probe_packets.RequestIndex(stream.attempts[0].result, packets, nat=nat)
        if packets is not None and stream.attempts
        else None
    )
    capture_conclusive = (
        capture is not None and capture.instrument_healthy and capture.window_complete is True
    )
    if packets is None:
        problems.append("no capture: nothing can be said about the wire")
    elif not capture_conclusive:
        problems.append(
            "the capture cannot vouch for an absence"
            if capture is not None
            else "no capture report: an absence on the wire cannot be vouched for"
        )
    if receipts is not None and not receipts.complete:
        problems.append("the receiver's log is incomplete: " + "; ".join(receipts.problems))

    by_probe: dict[str, int] = {}
    unmarked = ReceiptLog(complete=True)
    if receipts is not None:
        for receipt in receipts.receipts:
            if receipt.probe_id is not None:
                by_probe[receipt.probe_id] = by_probe.get(receipt.probe_id, 0) + 1
        unmarked = ReceiptLog(
            receipts=tuple(r for r in receipts.receipts if r.probe_id is None), complete=True
        )

    fates: list[Fate] = []
    contradictions: list[str] = []
    expected = max((attempt.seq for attempt in stream.attempts), default=0)
    for seq in range(1, expected + 1):
        attempt = stream.attempt(seq)
        if attempt is None:
            fates.append(
                Fate(seq=seq, status="not_sent", attempt=None, on_wire=None, received=None)
            )
            continue
        result = attempt.result
        if index is None:
            on_wire: bool | None = None
        elif index.requests(result):
            on_wire = True
        else:
            on_wire = False if capture_conclusive else None
        received: bool | None = None
        if receipts is not None:
            if by_probe.get(result.probe_id) or unmarked.matching(result):
                received = True
            elif receipts.complete:
                received = False
        if received and on_wire is False:
            contradictions.append(
                f"seq {seq}: the receiver logged it but the capture did not see it: "
                "the capture is blind to this path"
            )
        if on_wire and (
            result.outcome == "could_not_run"
            or (result.outcome == "refused" and result.stage == "send")
        ):
            contradictions.append(
                f"seq {seq}: the capture saw it although the process reported "
                f"{result.outcome}: the probe's report is wrong"
            )
        fates.append(
            Fate(
                seq=seq,
                status=_status(result.outcome, on_wire, received),
                attempt=attempt,
                on_wire=on_wire,
                received=received,
            )
        )
    times = covered_times(fates)
    if not times:
        problems.append("no attempt of the stream could run: nothing was tested")
    gaps = gaps_between(times, max_gap_periods * stream.period)
    window: tuple[float | None, float | None] = (
        (times[0][1], times[-1][1]) if times else (None, None)
    )
    if clock is not None:
        fates, window = _on_capture_clock(stream, fates, clock, problems)
        gaps = capture_gaps_between(capture_spans(fates), max_gap_periods * stream.period)
    return Correlation(
        period=stream.period,
        max_gap_periods=max_gap_periods,
        clock="monotonic" if clock is None else "capture",
        fates=tuple(fates),
        gaps=tuple(gaps),
        window_start=window[0],
        window_end=window[1],
        problems=tuple(problems),
        contradictions=tuple(contradictions),
    )


def _on_capture_clock(
    stream: StreamLog, fates: list[Fate], clock: ClockMap, problems: list[str]
) -> tuple[list[Fate], tuple[float | None, float | None]]:
    """*fates* with their capture times, and the window they span on the capture clock."""
    if stream.boot_id is None:
        problems.append("the stream's log has no boot_id: it cannot be placed on the capture clock")
    elif clock.boot(stream.boot_id) is None:
        problems.append(
            f"the clock map has no mapping for the stream's boot {stream.boot_id[:8]}"
            + (": " + "; ".join(clock.problems) if clock.problems else "")
        )
    placed: list[Fate] = []
    unplaced: list[int] = []
    for fate in fates:
        if fate.attempt is None:
            placed.append(fate)
            continue
        mapped = clock.to_capture(stream.boot_id, fate.attempt.started_boottime)
        if mapped is None:
            unplaced.append(fate.seq)
            placed.append(fate)
            continue
        placed.append(
            fate.model_copy(
                update={"capture_time": mapped.time, "capture_uncertainty": mapped.uncertainty}
            )
        )
    if unplaced:
        problems.append(
            f"{len(unplaced)} attempt(s) cannot be placed on the capture clock "
            f"(outside the beacons of their boot), first seq {unplaced[0]}"
        )
    times = sorted(f.capture_time for f in placed if f.capture_time is not None and f.covers)
    return placed, ((times[0], times[-1]) if times else (None, None))


def _status(outcome: str, on_wire: bool | None, received: bool | None) -> FateStatus:
    # The strongest evidence wins: what a receiver logged or a capture saw
    # happened, whatever the process says.
    if received:
        return "received"
    if on_wire:
        return "on_wire"
    if outcome == "could_not_run":
        return "not_sent"
    if outcome == "refused":
        return "refused"
    return "sent_not_seen"
