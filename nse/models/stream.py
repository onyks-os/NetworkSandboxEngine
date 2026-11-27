# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""
A stream of stimuli and what became of each one.

A :class:`StreamLog` is what a background :class:`~nse.streams.StimulusStream`
did: one :class:`StreamAttempt` per sequence number, with the time it started
and its :class:`~nse.models.stimulus.StimulusResult`. A :class:`Correlation`
joins the log with a capture and a receiver's log and says, per sequence
number, how far the attempt got (:data:`FateStatus`), and whether the stream
itself can vouch for the window it covers: a stream that stopped sending for a
while (a :class:`Gap`) says nothing about that while.
"""

from __future__ import annotations

import itertools
import json
from collections.abc import Iterable
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

from nse.models.stimulus import StimulusResult

#: How far one attempt of a stream got, from least to most evidence of travel.
#:
#: - ``not_sent``: no packet can have been produced (``could_not_run``), or
#:   the attempt's record is missing from the stream's log;
#: - ``refused``: a socket call failed, and the packet was not seen on the wire;
#: - ``sent_not_seen``: it left the socket and the capture does not have it;
#: - ``on_wire``: the capture has it, the receiver does not;
#: - ``received``: the receiver logged it.
FateStatus = Literal["not_sent", "refused", "sent_not_seen", "on_wire", "received"]

EndReason = Literal["stopped", "count", "duration"]

#: The clock a :class:`Correlation`'s times are on: the stream's own
#: ``CLOCK_MONOTONIC``, or the capture's, through a :class:`~nse.models.clock.ClockMap`.
TimeBase = Literal["monotonic", "capture"]

#: A suspend shorter than this (seconds) is clock noise between two readings.
_SUSPEND_NOISE = 1e-3


class _Stimulus(Protocol):
    def _from_report(
        self, probe_id: str, report: dict[str, Any], identity: Any
    ) -> StimulusResult: ...


class StreamSource(Protocol):
    """What :meth:`StreamLog.parse` needs of the stream that wrote the log:
    a :class:`~nse.streams.StimulusStream`."""

    @property
    def stimulus(self) -> _Stimulus: ...

    @property
    def period(self) -> float: ...


class StreamAttempt(BaseModel):
    """One attempt of a stream: its sequence number, when it started, what happened."""

    model_config = ConfigDict(frozen=True)

    seq: int = Field(ge=1)
    started_monotonic: float = Field(
        description="CLOCK_MONOTONIC when the attempt started, comparable with time.monotonic()."
    )
    started_boottime: float | None = Field(
        default=None,
        description="CLOCK_BOOTTIME at the same moment; it also counts time spent suspended. "
        "None from an agent that did not report it.",
    )
    result: StimulusResult


class StreamLog(BaseModel):
    """Every attempt a stream made, and whether that record is complete."""

    model_config = ConfigDict(frozen=True)

    stream_id: str = Field(description="Prefix of every attempt's probe ID.")
    period: float = Field(gt=0)
    started_monotonic: float | None = Field(
        default=None, description="When the stream began, before its first attempt."
    )
    started_boottime: float | None = Field(
        default=None, description="CLOCK_BOOTTIME when the stream began."
    )
    boot_id: str | None = Field(
        default=None,
        description="The /proc/sys/kernel/random/boot_id of the machine the stream ran on; "
        "None if it could not be read. A log spanning boots is never complete.",
    )
    attempts: tuple[StreamAttempt, ...] = ()
    ended: EndReason | None = Field(
        default=None,
        description="Why the stream ended; None if it did not say (still running, killed).",
    )
    complete: bool = Field(
        description="Every attempt started is in the log: sequence numbers from 1 with no "
        "gap, the stream said how many it started, and nothing was dropped."
    )
    problems: tuple[str, ...] = ()

    def attempt(self, seq: int) -> StreamAttempt | None:
        for attempt in self.attempts:
            if attempt.seq == seq:
                return attempt
        return None

    @classmethod
    def parse(
        cls,
        output: bytes,
        stream_id: str,
        *,
        final: bool,
        stream: StreamSource,
        identity: Any = None,
    ) -> StreamLog:
        """The log in a stream agent's *output*, wherever it ran.

        *stream* is the :class:`~nse.streams.StimulusStream` whose
        :meth:`~nse.streams.StimulusStream.command` produced it, and *stream_id*
        the ID that call returned. Pass ``final=True`` once no more output will
        come: only then can a cut line or a missing end make the log incomplete.
        A log that ends without the stream's end event (the stream was killed,
        or its machine shut down or rebooted), or that holds more than one run
        of the stream, is never complete.
        """
        return parse_log(
            output,
            stream_id,
            final=final,
            stream=stream,
            identity=identity,
            missing_end="the log ends before the stream reported its end: it was killed, "
            "or its machine shut down or rebooted",
        )


def parse_log(
    output: bytes,
    stream_id: str,
    *,
    final: bool,
    stream: StreamSource,
    identity: Any,
    missing_end: str,
    extra_problems: Iterable[str] = (),
) -> StreamLog:
    """:meth:`StreamLog.parse`, with what a caller that ran the stream knows added."""
    problems: list[str] = []
    attempts: dict[int, StreamAttempt] = {}
    runs: list[dict[str, Any]] = []
    end: dict[str, Any] | None = None
    repeated: set[int] = set()
    text = output.decode(errors="replace")
    lines = text.split("\n")
    if not text.endswith("\n"):
        cut = lines.pop()  # unfinished: only a problem once nothing more will come
        if final and cut.strip():
            problems.append("the stream's last line was cut off")
    for line in lines:
        if not line.strip():
            continue
        try:
            event = json.loads(line)
            kind = event["event"]
            if kind == "started":
                runs.append(
                    {
                        "monotonic": float(event["monotonic"]),
                        "boottime": _optional_float(event.get("boottime")),
                        "boot_id": event.get("boot_id"),
                    }
                )
            elif kind == "end":
                end = event
            elif kind == "attempt":
                seq = int(event["seq"])
                if seq in attempts:
                    repeated.add(seq)
                attempts[seq] = StreamAttempt(
                    seq=seq,
                    started_monotonic=float(event["started_monotonic"]),
                    started_boottime=_optional_float(event.get("started_boottime")),
                    result=stream.stimulus._from_report(str(event["probe_id"]), event, identity),
                )
            else:
                raise ValueError(f"unknown event {kind!r}")
        except (KeyError, TypeError, ValueError) as exc:
            problems.append(f"unreadable line in the stream's output ({exc}): {line[:200]!r}")
    if len(runs) > 1:
        boots = list(dict.fromkeys(str(run["boot_id"]) for run in runs))
        if len(boots) > 1:
            problems.append(
                f"the log spans {len(boots)} boots ({', '.join(b[:8] for b in boots)}): "
                "the machine rebooted while the stream ran"
            )
        else:
            problems.append(f"the log holds {len(runs)} runs of the stream, not one")
    if repeated:
        problems.append(f"{len(repeated)} sequence number(s) appear more than once")
    problems.extend(extra_problems)
    expected = len(attempts) if end is None else int(end.get("attempts", -1))
    missing = sorted(set(range(1, expected + 1)) - set(attempts))
    if missing:
        problems.append(f"{len(missing)} attempt(s) missing from the log, first seq {missing[0]}")
    if final and end is None:
        problems.append(missing_end)
    first = runs[0] if runs else {}
    return StreamLog(
        stream_id=stream_id,
        period=stream.period,
        started_monotonic=first.get("monotonic"),
        started_boottime=first.get("boottime"),
        boot_id=first.get("boot_id"),
        attempts=tuple(attempts[seq] for seq in sorted(attempts)),
        ended=None if end is None else end.get("reason"),
        complete=final and not problems,
        problems=tuple(problems),
    )


def _optional_float(value: Any) -> float | None:
    return None if value is None else float(value)


class Gap(BaseModel):
    """A stretch of time with no attempt that could run, longer than the correlation allows."""

    model_config = ConfigDict(frozen=True)

    start: float = Field(description="Start of the last covering attempt before the gap.")
    end: float = Field(description="Start of the first covering attempt after it.")
    after_seq: int | None = Field(
        description="The attempt before the gap; None at a window's edge."
    )
    before_seq: int | None = Field(
        description="The attempt after the gap; None at a window's edge."
    )
    suspended: float = Field(
        default=0.0,
        description="Seconds the machine was suspended within the gap: CLOCK_BOOTTIME "
        "advanced by that much more than CLOCK_MONOTONIC, which stops while suspended.",
    )

    @property
    def seconds(self) -> float:
        """How long the stream did not cover, suspended time included."""
        return self.end - self.start + self.suspended


class Fate(BaseModel):
    """What became of one sequence number."""

    model_config = ConfigDict(frozen=True)

    seq: int
    status: FateStatus
    attempt: StreamAttempt | None = Field(description="None when the log lacks this attempt.")
    on_wire: bool | None = Field(
        description="The capture has it (True), a complete capture does not (False), "
        "or the capture cannot say (None)."
    )
    received: bool | None = Field(
        description="As for on_wire, from the receiver's log; None without a receiver."
    )
    capture_time: float | None = Field(
        default=None,
        description="When the attempt started, on the capture's clock (correlate(clock=...)); "
        "None without a clock map, or when the map cannot place it.",
    )
    capture_uncertainty: float | None = Field(
        default=None, description="capture_time is within this many seconds of the truth."
    )

    @property
    def conclusive(self) -> bool:
        """The status rests only on facts the instruments could vouch for."""
        if self.attempt is None:
            return False
        if self.status == "received":
            return True
        if self.status == "on_wire":
            return self.received is not None
        return self.on_wire is False and self.received is not True

    @property
    def started_monotonic(self) -> float | None:
        return None if self.attempt is None else self.attempt.started_monotonic

    @property
    def covers(self) -> bool:
        """The attempt exercised the path: it is logged and its socket could be used.

        An attempt that ``could_not_run`` produced no packet, so it covers no
        time: a stream of them is a stream of gaps.
        """
        return self.attempt is not None and self.attempt.result.outcome != "could_not_run"


class Correlation(BaseModel):
    """A stream, its capture and its receiver, joined per sequence number.

    :attr:`conclusive` is ``False`` whenever any instrument cannot vouch for the
    window: the stream's log is incomplete, the stream paused for longer than
    ``max_gap_periods`` periods, the capture was unhealthy or not complete, the
    receiver's log was incomplete, or the instruments contradict each other.
    A test should assert it before asserting on any absence.
    """

    model_config = ConfigDict(frozen=True)

    period: float
    max_gap_periods: float
    clock: TimeBase = Field(
        default="monotonic",
        description="The clock of window_start, window_end, the gaps and between(): the "
        "stream's CLOCK_MONOTONIC, or the capture's when correlated with a clock map.",
    )
    fates: tuple[Fate, ...]
    gaps: tuple[Gap, ...]
    window_start: float | None = Field(description="Start of the first attempt considered.")
    window_end: float | None = Field(description="Start of the last attempt considered.")
    problems: tuple[str, ...] = Field(
        default=(), description="Why the window is inconclusive, apart from the gaps."
    )
    contradictions: tuple[str, ...] = ()

    @property
    def conclusive(self) -> bool:
        return not self.gaps and not self.problems and not self.contradictions

    def counts(self) -> dict[str, int]:
        """How many sequence numbers ended in each status."""
        counts: dict[str, int] = {}
        for fate in self.fates:
            counts[fate.status] = counts.get(fate.status, 0) + 1
        return counts

    def with_status(self, *statuses: FateStatus) -> list[Fate]:
        return [fate for fate in self.fates if fate.status in statuses]

    def between(self, start: float, end: float) -> Correlation:
        """The attempts that started between *start* and *end*.

        The times are on :attr:`clock`: monotonic seconds, or the capture's
        clock for a correlation made with a clock map. A gap is reported where
        the stream did not cover the interval: before the first attempt in it,
        after the last one, between two of them, or over the whole interval
        when no attempt started in it.

        On the capture's clock an attempt is in the interval only if its whole
        uncertainty is. One whose uncertainty crosses *start* or *end* cannot
        be placed on either side, and makes the result inconclusive.
        """
        if end < start:
            raise ValueError("end is before start")
        if self.clock == "capture":
            return self._between_capture(start, end)
        limit = self.max_gap_periods * self.period
        fates = tuple(
            fate
            for fate in self.fates
            if fate.started_monotonic is not None and start <= fate.started_monotonic <= end
        )
        times = covered_times(fates)
        gaps: list[Gap] = []
        if not times:
            gaps.append(Gap(start=start, end=end, after_seq=None, before_seq=None))
        else:
            first_seq, first, _ = times[0]
            last_seq, last, _ = times[-1]
            if first - start > limit:
                gaps.append(Gap(start=start, end=first, after_seq=None, before_seq=first_seq))
            gaps.extend(gaps_between(times, limit))
            if end - last > limit:
                gaps.append(Gap(start=last, end=end, after_seq=last_seq, before_seq=None))
        # Sequence numbers missing from the log cannot be placed in time, so a
        # log with holes keeps its problem (in ``problems``) here too.
        return self.model_copy(
            update={
                "fates": fates,
                "gaps": tuple(gaps),
                "window_start": start,
                "window_end": end,
            }
        )

    def _between_capture(self, start: float, end: float) -> Correlation:
        limit = self.max_gap_periods * self.period
        fates: list[Fate] = []
        problems = list(self.problems)
        for fate in self.fates:
            if fate.capture_time is None or fate.capture_uncertainty is None:
                continue  # unplaced attempts are already a problem of the whole correlation
            low = fate.capture_time - fate.capture_uncertainty
            high = fate.capture_time + fate.capture_uncertainty
            if high < start or low > end:
                continue
            if low < start or high > end:
                edge = start if low < start <= high else end
                problems.append(
                    f"seq {fate.seq} started at {fate.capture_time:.6f} \u00b1 "
                    f"{fate.capture_uncertainty:.6f}s on the capture clock: across the edge "
                    f"{edge:.6f}, so it cannot be placed on either side"
                )
                continue
            fates.append(fate)
        spans = capture_spans(fates)
        gaps: list[Gap] = []
        if not spans:
            gaps.append(Gap(start=start, end=end, after_seq=None, before_seq=None))
        else:
            first_seq, _, first_high = spans[0]
            last_seq, last_low, _ = spans[-1]
            if first_high - start > limit:
                gaps.append(Gap(start=start, end=first_high, after_seq=None, before_seq=first_seq))
            gaps.extend(capture_gaps_between(spans, limit))
            if end - last_low > limit:
                gaps.append(Gap(start=last_low, end=end, after_seq=last_seq, before_seq=None))
        return self.model_copy(
            update={
                "fates": tuple(fates),
                "gaps": tuple(gaps),
                "window_start": start,
                "window_end": end,
                "problems": tuple(problems),
            }
        )

    def describe(self) -> str:
        parts = [f"{len(self.fates)} attempt(s)"]
        parts += [f"{status}: {n}" for status, n in sorted(self.counts().items())]
        if self.gaps:
            parts.append(
                "gaps: "
                + ", ".join(
                    f"{gap.seconds:.3f}s after seq {gap.after_seq}"
                    + (f" ({gap.suspended:.3f}s suspended)" if gap.suspended else "")
                    for gap in self.gaps
                )
            )
        parts += [f"INCONCLUSIVE: {problem}" for problem in self.problems]
        parts += [f"CONTRADICTION: {problem}" for problem in self.contradictions]
        return "; ".join(parts)


def gaps_between(times: list[tuple[int, float, float | None]], limit: float) -> list[Gap]:
    """Gaps longer than *limit* seconds between consecutive ``(seq, monotonic, boottime)``.

    The time elapsed between two attempts is measured on CLOCK_BOOTTIME when
    both have it, so a suspend, which CLOCK_MONOTONIC does not count, is a gap
    too, with its length in :attr:`Gap.suspended`.
    """
    gaps = []
    for (seq_a, a, boot_a), (seq_b, b, boot_b) in itertools.pairwise(times):
        elapsed = b - a
        suspended = 0.0
        if boot_a is not None and boot_b is not None:
            suspended = (boot_b - boot_a) - elapsed
            suspended = suspended if suspended > _SUSPEND_NOISE else 0.0
        if elapsed + suspended > limit:
            gaps.append(Gap(start=a, end=b, after_seq=seq_a, before_seq=seq_b, suspended=suspended))
    return gaps


def covered_times(fates: Iterable[Fate]) -> list[tuple[int, float, float | None]]:
    """``(seq, monotonic, boottime)`` of the attempts that cover time, in time order."""
    return sorted(
        (
            (fate.seq, fate.attempt.started_monotonic, fate.attempt.started_boottime)
            for fate in fates
            if fate.attempt and fate.covers
        ),
        key=lambda triple: triple[1],
    )


def capture_spans(fates: Iterable[Fate]) -> list[tuple[int, float, float]]:
    """``(seq, earliest, latest)`` on the capture clock of the placed attempts that
    cover time, in time order: each attempt's capture time widened by its uncertainty."""
    return sorted(
        (
            (
                fate.seq,
                fate.capture_time - fate.capture_uncertainty,
                fate.capture_time + fate.capture_uncertainty,
            )
            for fate in fates
            if fate.covers
            and fate.capture_time is not None
            and fate.capture_uncertainty is not None
        ),
        key=lambda span: span[1],
    )


def capture_gaps_between(spans: list[tuple[int, float, float]], limit: float) -> list[Gap]:
    """Gaps longer than *limit* between consecutive *spans*, measured so that an
    uncertainty can only lengthen a gap, never hide one."""
    return [
        Gap(start=low_a, end=high_b, after_seq=seq_a, before_seq=seq_b)
        for (seq_a, low_a, _), (seq_b, _, high_b) in itertools.pairwise(spans)
        if high_b - low_a > limit
    ]
