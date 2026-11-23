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
from nse.models.process import ProcessIdentity, ProcessResult
from nse.models.stimulus import ReceiptLog
from nse.models.stream import (
    Correlation,
    Fate,
    FateStatus,
    StreamAttempt,
    StreamLog,
    covered_times,
    gaps_between,
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
        stream_id = probe_packets.new_probe_id()[:16]
        argv = [python or default_python(), "-I", "-S", "-c", _agents.source("stimulus")]
        argv.append(json.dumps(self.plan(stream_id)))
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
        problems: list[str] = []
        attempts: dict[int, StreamAttempt] = {}
        started: float | None = None
        end: dict[str, Any] | None = None
        text = output.decode(errors="replace")
        lines = text.split("\n")
        if not text.endswith("\n"):
            cut = lines.pop()  # unfinished: only a problem once nothing more will come
            if final and cut.strip():
                problems.append("the stream's last line was cut off")
        stimulus = self.stream.stimulus
        for line in lines:
            if not line.strip():
                continue
            try:
                event = json.loads(line)
                kind = event["event"]
                if kind == "started":
                    started = float(event["monotonic"])
                elif kind == "end":
                    end = event
                elif kind == "attempt":
                    seq = int(event["seq"])
                    attempts[seq] = StreamAttempt(
                        seq=seq,
                        started_monotonic=float(event["started_monotonic"]),
                        result=stimulus._from_report(
                            str(event["probe_id"]),
                            event,
                            None if result is None else result.identity,
                        ),
                    )
                else:
                    raise ValueError(f"unknown event {kind!r}")
            except (KeyError, TypeError, ValueError) as exc:
                problems.append(f"unreadable line in the stream's output ({exc}): {line[:200]!r}")
        if self.process.output_dropped("stdout"):
            problems.append("the stream's output exceeded the limit and was cut")
        expected = len(attempts) if end is None else int(end.get("attempts", -1))
        missing = sorted(set(range(1, expected + 1)) - set(attempts))
        if missing:
            problems.append(
                f"{len(missing)} attempt(s) missing from the log, first seq {missing[0]}"
            )
        if final and end is None:
            how = "was killed" if result is None else f"ended ({result.termination})"
            problems.append(f"the stream {how} without reporting its end")
        if final and result is not None and result.termination == "exited" and result.returncode:
            problems.append(f"the stream exited with status {result.returncode}: {_stderr(result)}")
        return StreamLog(
            stream_id=self.stream_id,
            period=self.stream.period,
            started_monotonic=started,
            attempts=tuple(attempts[seq] for seq in sorted(attempts)),
            ended=None if end is None else end.get("reason"),
            complete=final and not problems,
            problems=tuple(problems),
        )


def correlate(
    stream: StreamLog,
    packets: Iterable[Any] | None,
    receipts: ReceiptLog | None = None,
    *,
    capture: CaptureReport | None = None,
    max_gap_periods: float = _DEFAULT_MAX_GAP_PERIODS,
    nat: bool = False,
) -> Correlation:
    """Join a stream with a capture and a receiver's log, per sequence number.

    *packets* is what the capture returned (``None`` when there was no
    capture). A packet that was seen counts whatever the capture's health; an
    absence counts as ``False`` only with a *capture* report that is healthy
    and complete (``window_complete is True``), and ``None`` otherwise.
    *receipts* likewise counts an absence only when the log is complete.

    *nat* recognises attempts whose destination a NAT rewrote, as
    :func:`nse.stimuli.requests_in` does.

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
    return Correlation(
        period=stream.period,
        max_gap_periods=max_gap_periods,
        fates=tuple(fates),
        gaps=tuple(gaps),
        window_start=times[0][1] if times else None,
        window_end=times[-1][1] if times else None,
        problems=tuple(problems),
        contradictions=tuple(contradictions),
    )


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
