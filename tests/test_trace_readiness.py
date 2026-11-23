"""Tracing locally generated traffic, and proving the trace monitor is attached.

``nft`` and ``nft monitor trace`` are replaced: the ruleset text and the
readiness logic are checked here; the kernel side is in the integration tests.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from nse import stimuli
from nse.core.rule_engine import RuleEngine
from nse.core.trace_harvester import HarvestState, TraceHarvester, TraceReadiness
from nse.models.stimulus import Endpoint, StimulusResult
from nse.models.trace_event import TraceEvent


def _loaded(engine: RuleEngine) -> str:
    texts: list[str] = []

    def run(cmd: list[str], **kwargs: Any) -> Any:
        texts.append(Path(cmd[-1]).read_text())
        return MagicMock(returncode=0)

    with patch("subprocess.run", side_effect=run):
        engine.load("table ip t {}", "nse_x")
    return texts[0]


def test_output_tracing_is_opt_in() -> None:
    plain = _loaded(RuleEngine())
    assert "hook prerouting priority -300" in plain
    assert "hook output" not in plain
    traced = _loaded(RuleEngine(trace_output=True))
    assert "chain nse_trace_output" in traced
    assert "type filter hook output priority -350" in traced
    assert traced.index("nse_trace_output") < traced.index("table ip t {}")


def _event(trace_id: str, dst: str = "10.0.1.1", port: int | None = 7777, **kw: Any) -> TraceEvent:
    fields: dict[str, Any] = {
        "type": "hook",
        "trace_id": trace_id,
        "packet_dst_ip": dst,
        "packet_protocol": "udp",
        "packet_dst_port": port,
    }
    fields.update(kw)
    return TraceEvent(**fields)


def test_trace_matches_compares_destination_transport_and_port() -> None:
    udp = stimuli.trace_matches(stimuli.udp("10.0.1.1", 7777))
    assert udp(_event("a"))
    assert not udp(_event("a", port=53))
    assert not udp(_event("a", dst="10.0.1.9"))
    assert not udp(_event("a", packet_protocol="tcp"))
    assert not udp(_event("a", dst="not-an-ip"))
    assert not udp(TraceEvent(type="match", trace_id="a"))
    v6 = stimuli.trace_matches(stimuli.icmp_echo("fd00::1"))
    assert v6(_event("b", dst="fd00:0::1", port=None, packet_protocol="icmp"))


class Harvester(TraceHarvester):
    """A harvester whose monitor is simulated: delivering an event runs the real
    predicate and signal logic of the read loop."""

    def __init__(self) -> None:
        super().__init__()
        self.state = HarvestState.RUNNING
        self._deadline = 0.0

    def deliver(self, event: TraceEvent) -> None:
        if self._event_predicate is None or self._event_predicate(event):
            if event.trace_id:
                self.matched_trace_ids.add(event.trace_id)
            self._event_signal.set()


@pytest.mark.asyncio
async def test_readiness_needs_the_canarys_own_trace_to_come_back() -> None:
    harvester = Harvester()
    sends: list[int] = []
    predicate = stimuli.trace_matches(stimuli.udp("10.0.1.1", 7777))

    async def send() -> str | None:
        sends.append(1)
        harvester.deliver(_event("noise", dst="10.9.9.9"))  # not the canary
        if len(sends) == 3:
            harvester.deliver(_event("canary-3"))
        return None

    ready = await harvester.prove_ready(send, predicate, attempts=5, timeout=0.05)
    assert ready.ready
    assert ready.attempts == 3
    assert ready.trace_ids == frozenset({"canary-3"})
    assert "ready after 3" in ready.describe()


@pytest.mark.asyncio
async def test_a_monitor_that_never_sees_the_canary_is_not_ready() -> None:
    harvester = Harvester()

    async def send() -> str | None:
        return None

    ready = await harvester.prove_ready(send, attempts=2, timeout=0.01)
    assert not ready.ready
    assert ready.attempts == 2
    assert "NOT proven ready" in ready.describe()
    assert "no canary trace came back" in ready.describe()
    harvester.state = HarvestState.CLEAN_EOF  # the monitor died: say so
    again = await harvester.prove_ready(send, attempts=1, timeout=0.01)
    assert any("exited on its own" in p for p in again.problems)
    with pytest.raises(ValueError):
        await harvester.prove_ready(send, attempts=0)


@pytest.mark.asyncio
async def test_a_canary_that_could_not_be_sent_proves_nothing() -> None:
    harvester = Harvester()

    async def send() -> str | None:
        harvester.deliver(_event("unrelated"))  # an event, but no canary was sent
        return "socket: EPERM"

    ready = await harvester.prove_ready(send, attempts=2, timeout=0.01)
    assert not ready.ready
    assert ready.problems == (
        "attempt 1: the canary was not sent: socket: EPERM",
        "attempt 2: the canary was not sent: socket: EPERM",
    )


def test_without_drops_every_trace_that_touched_the_canary() -> None:
    predicate = stimuli.trace_matches(stimuli.udp("10.0.1.1", 7777))
    readiness = TraceReadiness(
        ready=True, attempts=1, trace_ids=frozenset({"c1"}), predicate=predicate
    )
    events = [
        _event("c1"),
        TraceEvent(type="verdict", trace_id="c1", verdict="ACCEPT"),
        _event("c2"),  # a later canary trace, seen after readiness
        TraceEvent(type="match", trace_id="c2", rule_text="accept"),
        _event("s1", port=53),  # the subject
        TraceEvent(type="match", trace_id="s1", rule_text="drop"),
        TraceEvent(type="error", raw_message="x"),
    ]
    kept = readiness.without(events)
    assert [e.trace_id for e in kept] == ["s1", "s1", None]
    bare = TraceReadiness(ready=True, attempts=1, trace_ids=frozenset({"c1"}))
    assert len(bare.without(events)) == 5


@pytest.mark.asyncio
async def test_trace_ready_sends_the_canary_from_the_sandbox() -> None:
    harvester = Harvester()
    canary = stimuli.udp("10.0.1.1", 7777)
    runs: list[Any] = []

    def result(outcome: str) -> StimulusResult:
        return StimulusResult(
            kind="udp",
            transport="udp",
            family=4,
            probe_id="ab" * 12,
            destination=Endpoint(address="10.0.1.1", port=7777),
            payload=b"",
            outcome=outcome,  # type: ignore[arg-type]
            stage="socket" if outcome == "could_not_run" else None,
        )

    outcomes = iter(["could_not_run", "sent"])

    async def run(self: Any, sandbox: Any, **options: Any) -> StimulusResult:
        runs.append((sandbox, options))
        outcome = next(outcomes)
        if outcome == "sent":
            asyncio.get_running_loop().call_soon(harvester.deliver, _event("c"))
        return result(outcome)

    identity = object()
    with patch.object(stimuli.Stimulus, "run", run):
        ready = await stimuli.trace_ready(
            harvester,
            "sandbox",
            canary,
            identity=identity,
            timeout=0.5,  # type: ignore[arg-type]
        )
    assert ready.ready
    assert ready.attempts == 2
    assert "could_not_run" in ready.problems[0]
    assert runs[0] == ("sandbox", {"identity": identity, "python": None})
