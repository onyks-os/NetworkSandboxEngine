# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""
Reduce a trace event stream to one verdict per stimulus.

Shared by the CLI runner, which compares the verdicts with the expected ones,
and the experiment report, which records them. One implementation, so the
report can never describe a different result from the one the runner judged.
"""

from __future__ import annotations

from collections.abc import Iterable

from nse.models.trace_event import TraceEvent

#: Trace events from this table are NSE's own tracing scaffolding, not the
#: ruleset under test.
SCAFFOLD_TABLE = "nse_trace"


def trace_verdicts(events: Iterable[TraceEvent]) -> list[tuple[str, str]]:
    """``(trace_id, verdict)`` for every stimulus that reached the user ruleset, in order.

    A packet traverses several chains and produces several trace lines under a
    single trace id. DROP and REJECT win over ACCEPT, because a packet that was
    accepted by one chain and dropped by another did not get through.

    Events from the ``nse_trace`` scaffolding table are excluded, as are
    responses and background traffic. A trace that reached the user ruleset
    without any verdict is left out on purpose: it becomes a count mismatch,
    which is an oracle error, rather than being quietly rounded to a pass.
    """
    order: list[str] = []
    verdicts: dict[str, list[str]] = {}
    reached_user_ruleset: set[str] = set()

    for evt in events:
        if evt.type == "error" or not evt.trace_id or evt.packet_role in ("response", "background"):
            continue
        if evt.trace_id not in verdicts:
            verdicts[evt.trace_id] = []
            order.append(evt.trace_id)
        if evt.table and evt.table != SCAFFOLD_TABLE:
            reached_user_ruleset.add(evt.trace_id)
            if evt.verdict:
                verdicts[evt.trace_id].append(evt.verdict.upper())

    reduced: list[tuple[str, str]] = []
    for trace_id in order:
        if trace_id not in reached_user_ruleset:
            continue
        seen = verdicts[trace_id]
        if any(v in ("DROP", "REJECT") for v in seen):
            reduced.append((trace_id, "DROP"))
        elif any(v == "ACCEPT" for v in seen):
            reduced.append((trace_id, "ACCEPT"))
    return reduced


def reduce_verdicts(events: Iterable[TraceEvent]) -> list[str]:
    """One verdict per observed stimulus, in order; see :func:`trace_verdicts`."""
    return [verdict for _, verdict in trace_verdicts(events)]
