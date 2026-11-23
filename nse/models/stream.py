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
from collections.abc import Iterable
from typing import Literal

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


class StreamAttempt(BaseModel):
    """One attempt of a stream: its sequence number, when it started, what happened."""

    model_config = ConfigDict(frozen=True)

    seq: int = Field(ge=1)
    started_monotonic: float = Field(
        description="CLOCK_MONOTONIC when the attempt started, comparable with time.monotonic()."
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

    @property
    def seconds(self) -> float:
        return self.end - self.start


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
        """The attempts that started between *start* and *end* (monotonic seconds).

        A gap is reported where the stream did not cover the interval: before
        the first attempt in it, after the last one, between two of them, or
        over the whole interval when no attempt started in it.
        """
        if end < start:
            raise ValueError("end is before start")
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
            first_seq, first = times[0]
            last_seq, last = times[-1]
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

    def describe(self) -> str:
        parts = [f"{len(self.fates)} attempt(s)"]
        parts += [f"{status}: {n}" for status, n in sorted(self.counts().items())]
        if self.gaps:
            parts.append(
                "gaps: "
                + ", ".join(f"{gap.seconds:.3f}s after seq {gap.after_seq}" for gap in self.gaps)
            )
        parts += [f"INCONCLUSIVE: {problem}" for problem in self.problems]
        parts += [f"CONTRADICTION: {problem}" for problem in self.contradictions]
        return "; ".join(parts)


def gaps_between(times: list[tuple[int, float]], limit: float) -> list[Gap]:
    """Gaps longer than *limit* seconds between consecutive ``(seq, started)`` pairs."""
    return [
        Gap(start=a, end=b, after_seq=seq_a, before_seq=seq_b)
        for (seq_a, a), (seq_b, b) in itertools.pairwise(times)
        if b - a > limit
    ]


def covered_times(fates: Iterable[Fate]) -> list[tuple[int, float]]:
    """``(seq, started)`` of the attempts that cover time, in time order."""
    return sorted(
        (
            (fate.seq, fate.attempt.started_monotonic)
            for fate in fates
            if fate.attempt and fate.covers
        ),
        key=lambda pair: pair[1],
    )
