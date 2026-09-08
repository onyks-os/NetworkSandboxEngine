# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""
Unit tests for the pipeline, with every system boundary stubbed.

The behaviour under test is the oracle contract: a run whose canary was never
observed must report an `error` event instead of a verdict stream. That is what
makes "no leak" mean something — without it, a monitor that never attached and a
firewall that blocked everything produce identical output.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from nse.core import pipeline as pipeline_module
from nse.core.pipeline import (
    _canary_spec,
    _probe_oracle,
    _without_canaries,
    parse_conntrack_line,
    read_conntrack_table,
    run_test_pipeline,
)
from nse.core.trace_harvester import HarvestState
from nse.models.test_request import PacketSpec, TestRequest, TopologyType
from nse.models.trace_event import TraceEvent

# ---------------------------------------------------------------------------
# _without_canaries
# ---------------------------------------------------------------------------


def _evt(trace_id: str | None, type_: str = "verdict") -> TraceEvent:
    return TraceEvent(type=type_, trace_id=trace_id, table="filter", verdict="ACCEPT")


def test_without_canaries_removes_probe_events() -> None:
    events = [_evt("canary1"), _evt("real1"), _evt("canary2"), _evt("real2")]
    kept = _without_canaries(events, {"canary1", "canary2"})
    assert [e.trace_id for e in kept] == ["real1", "real2"]


def test_without_canaries_is_a_noop_with_no_canaries() -> None:
    events = [_evt("a"), _evt("b")]
    assert _without_canaries(events, set()) is events


def test_without_canaries_keeps_events_without_a_trace_id() -> None:
    events = [_evt(None, "error"), _evt("canary1")]
    kept = _without_canaries(events, {"canary1"})
    assert len(kept) == 1
    assert kept[0].type == "error"


def test_canary_spec_uses_reserved_ports() -> None:
    spec = _canary_spec(dst_ip="10.0.0.2", src_ip="10.0.0.1")
    assert spec.protocol == "udp"
    assert spec.dst_port == pipeline_module._CANARY_DST_PORT
    assert spec.src_port == pipeline_module._CANARY_SRC_PORT
    assert (spec.src_ip, spec.dst_ip) == ("10.0.0.1", "10.0.0.2")


def test_canary_spec_works_for_ipv6() -> None:
    spec = _canary_spec(dst_ip="fd00::2", src_ip="fd00::1")
    assert spec.dst_ip == "fd00::2"


# ---------------------------------------------------------------------------
# _probe_oracle
# ---------------------------------------------------------------------------


class FakeHarvester:
    """Records deadline extensions and answers wait_for_event on cue."""

    def __init__(self, sees_after: int | None = 1) -> None:
        self.sees_after = sees_after
        self.attempts = 0
        self.extensions = 0
        self.armed = 0
        self.seen_trace_ids: list[str] = []

    def arm_event_signal(self) -> None:
        self.armed += 1

    def extend_deadline(self, seconds: float) -> None:
        self.extensions += 1

    async def wait_for_event(self, timeout: float = 1.0) -> bool:
        self.attempts += 1
        if self.sees_after is not None and self.attempts >= self.sees_after:
            self.seen_trace_ids.append(f"canary{self.attempts}")
            return True
        return False


async def _probe(harvester: Any, injector: Any, attempts: int = 3) -> bool:
    return await _probe_oracle(
        label="test",
        harvester=harvester,
        injector=injector,
        spec=_canary_spec("10.0.0.2", "10.0.0.1"),
        target_netns="nse_x",
        veth_host="vhr-x",
        veth_peer="veth-nse",
        host_netns=None,
        attempts=attempts,
        interval=0.01,
    )


@pytest.mark.asyncio
async def test_probe_succeeds_on_the_first_observed_event() -> None:
    harvester = FakeHarvester(sees_after=1)
    injector = MagicMock()
    assert await _probe(harvester, injector) is True
    assert injector.inject.call_count == 1
    assert harvester.armed == 1


@pytest.mark.asyncio
async def test_probe_retries_until_the_kernel_answers() -> None:
    harvester = FakeHarvester(sees_after=3)
    injector = MagicMock()
    assert await _probe(harvester, injector, attempts=5) is True
    assert injector.inject.call_count == 3


@pytest.mark.asyncio
async def test_probe_fails_when_nothing_is_ever_observed() -> None:
    """The blind case. Everything downstream depends on this returning False."""
    harvester = FakeHarvester(sees_after=None)
    injector = MagicMock()
    assert await _probe(harvester, injector, attempts=4) is False
    assert injector.inject.call_count == 4


@pytest.mark.asyncio
async def test_probe_survives_injection_errors_and_keeps_trying() -> None:
    harvester = FakeHarvester(sees_after=2)
    injector = MagicMock()
    injector.inject.side_effect = [RuntimeError("no such device"), None, None]
    assert await _probe(harvester, injector, attempts=4) is True


@pytest.mark.asyncio
async def test_probe_extends_the_deadline_on_every_attempt() -> None:
    harvester = FakeHarvester(sees_after=None)
    await _probe(harvester, MagicMock(), attempts=3)
    assert harvester.extensions == 3


# ---------------------------------------------------------------------------
# run_test_pipeline — the canary contract
# ---------------------------------------------------------------------------


class StubHarvester:
    """Full TraceHarvester stand-in whose visibility is scripted."""

    def __init__(self, readiness: bool = True, liveness: bool = True) -> None:
        self._answers = {"readiness": readiness, "liveness": liveness}
        self._phase = "readiness"
        self.seen_trace_ids: list[str] = []
        self.state = HarvestState.NOT_STARTED
        self.closed = False
        self._problems: list[str] = []

    async def start(self, **kwargs: Any) -> None:
        self.state = HarvestState.RUNNING

    async def wait_ready(self, timeout: float = 2.0) -> bool:
        return True

    def arm_event_signal(self) -> None:
        pass

    def extend_deadline(self, seconds: float) -> None:
        pass

    async def wait_for_event(self, timeout: float = 1.0) -> bool:
        answer = self._answers[self._phase]
        if answer:
            self.seen_trace_ids.append(f"{self._phase}-canary")
        return answer

    def advance(self) -> None:
        self._phase = "liveness"

    async def aclose(self, timeout: float = 2.0) -> HarvestState:
        self.closed = True
        self.state = HarvestState.STOPPED
        return self.state

    def stop(self) -> None:
        pass

    def health_errors(self) -> list[str]:
        return self._problems


def _request() -> TestRequest:
    return TestRequest(
        rules="table ip filter { chain input { type filter hook input priority 0; } }",
        packets=[PacketSpec(protocol="tcp", dst_port=80)],
        topology=TopologyType.SIMPLE,
    )


async def _run_pipeline_with(harvester: StubHarvester) -> list[TraceEvent]:
    controller = MagicMock()
    controller.use_nsenter = False

    injector = MagicMock()

    def inject(spec: Any, *args: Any, **kwargs: Any) -> None:
        # Canaries keep the readiness answer; the moment a real test packet has
        # been injected, later probes are asking the liveness question.
        if spec.dst_port != pipeline_module._CANARY_DST_PORT:
            harvester.advance()

    injector.inject.side_effect = inject

    with (
        patch.object(pipeline_module, "TraceHarvester", lambda: harvester),
        patch.object(pipeline_module, "ScapyInjector", lambda **_: injector),
        patch.object(pipeline_module, "RuleEngine", MagicMock()),
        patch.object(pipeline_module, "start_mock_listener", MagicMock()),
        patch.object(pipeline_module, "read_conntrack_table", lambda *a, **k: []),
        patch.object(pipeline_module.subprocess, "run", MagicMock()),
    ):
        return await run_test_pipeline(request=_request(), controller=controller)


@pytest.mark.asyncio
async def test_pipeline_reports_an_oracle_error_when_readiness_canary_is_lost() -> None:
    """
    A blind monitor must produce an error, never an empty-but-clean verdict list.
    An empty list is indistinguishable from 'the firewall dropped everything'.
    """
    events = await _run_pipeline_with(StubHarvester(readiness=False))
    errors = [e for e in events if e.type == "error"]
    assert len(errors) == 1
    assert "readiness canary" in (errors[0].raw_message or "")


@pytest.mark.asyncio
async def test_pipeline_does_not_inject_test_packets_when_blind() -> None:
    harvester = StubHarvester(readiness=False)
    controller = MagicMock()
    controller.use_nsenter = False
    injector = MagicMock()

    with (
        patch.object(pipeline_module, "TraceHarvester", lambda: harvester),
        patch.object(pipeline_module, "ScapyInjector", lambda **_: injector),
        patch.object(pipeline_module, "RuleEngine", MagicMock()),
        patch.object(pipeline_module, "start_mock_listener", MagicMock()),
        patch.object(pipeline_module, "read_conntrack_table", lambda *a, **k: []),
        patch.object(pipeline_module.subprocess, "run", MagicMock()),
    ):
        await run_test_pipeline(request=_request(), controller=controller)

    # Only canary attempts; the user's packet was never injected because no
    # verdict from it could have been trusted.
    assert injector.inject.call_count == pipeline_module._CANARY_ATTEMPTS


@pytest.mark.asyncio
async def test_pipeline_reports_an_oracle_error_when_liveness_canary_is_lost() -> None:
    """Catches the monitor dying part-way, which truncates the verdict stream."""
    events = await _run_pipeline_with(StubHarvester(readiness=True, liveness=False))
    errors = [e for e in events if e.type == "error"]
    assert len(errors) == 1
    assert "liveness canary" in (errors[0].raw_message or "")


@pytest.mark.asyncio
async def test_pipeline_is_clean_when_both_canaries_are_observed() -> None:
    events = await _run_pipeline_with(StubHarvester(readiness=True, liveness=True))
    assert [e for e in events if e.type == "error"] == []


@pytest.mark.asyncio
async def test_pipeline_surfaces_harvester_health_problems() -> None:
    harvester = StubHarvester()
    harvester._problems = ["3 trace line(s) could not be parsed"]
    events = await _run_pipeline_with(harvester)
    errors = [e for e in events if e.type == "error"]
    assert len(errors) == 1
    assert "could not be parsed" in (errors[0].raw_message or "")


@pytest.mark.asyncio
async def test_pipeline_reports_rule_validation_errors() -> None:
    from nse.core.rule_engine import RuleValidationError

    controller = MagicMock()
    controller.use_nsenter = False
    engine = MagicMock()
    engine.load.side_effect = RuleValidationError([{"raw": "syntax error"}])

    with (
        patch.object(pipeline_module, "TraceHarvester", StubHarvester),
        patch.object(pipeline_module, "ScapyInjector", lambda **_: MagicMock()),
        patch.object(pipeline_module, "RuleEngine", lambda **_: engine),
        patch.object(pipeline_module, "start_mock_listener", MagicMock()),
        patch.object(pipeline_module.subprocess, "run", MagicMock()),
    ):
        events = await run_test_pipeline(request=_request(), controller=controller)

    errors = [e for e in events if e.type == "error"]
    assert len(errors) == 1
    assert "syntax error" in (errors[0].raw_message or "")


@pytest.mark.asyncio
async def test_pipeline_reports_unexpected_exceptions() -> None:
    controller = MagicMock()
    controller.use_nsenter = False
    controller.create_netns.side_effect = OSError("netns quota exceeded")

    with (
        patch.object(pipeline_module, "TraceHarvester", StubHarvester),
        patch.object(pipeline_module, "ScapyInjector", lambda **_: MagicMock()),
        patch.object(pipeline_module, "RuleEngine", MagicMock()),
        patch.object(pipeline_module, "start_mock_listener", MagicMock()),
        patch.object(pipeline_module.subprocess, "run", MagicMock()),
    ):
        events = await run_test_pipeline(request=_request(), controller=controller)

    errors = [e for e in events if e.type == "error"]
    assert len(errors) == 1
    assert "quota" in (errors[0].raw_message or "")


# ---------------------------------------------------------------------------
# conntrack parsing
# ---------------------------------------------------------------------------


def test_parse_conntrack_line_returns_none_for_short_lines() -> None:
    assert parse_conntrack_line("too short") is None


def test_parse_conntrack_line_returns_none_without_addresses() -> None:
    assert parse_conntrack_line("ipv4 2 tcp 6 431999 ESTABLISHED nothing here") is None


def test_parse_conntrack_line_udp_defaults_to_established() -> None:
    line = "ipv4 2 udp 17 29 src=10.0.0.1 dst=10.0.0.2 sport=1234 dport=53"
    entry = parse_conntrack_line(line)
    assert entry is not None
    assert entry["proto"] == "UDP"
    assert entry["state"] == "ESTABLISHED"
    assert entry["dport"] == 53


def test_parse_conntrack_line_unknown_tcp_state() -> None:
    line = "ipv4 2 tcp 6 120 WEIRD src=10.0.0.1 dst=10.0.0.2 sport=1 dport=2"
    entry = parse_conntrack_line(line)
    assert entry is not None
    assert entry["state"] == "UNKNOWN"


def test_read_conntrack_table_falls_back_to_ip_conntrack() -> None:
    import subprocess as sp

    good = MagicMock(stdout="ipv4 2 udp 17 29 src=10.0.0.1 dst=10.0.0.2 sport=1 dport=53\n")
    with patch("subprocess.run", side_effect=[sp.CalledProcessError(1, "cat"), good]) as run:
        entries = read_conntrack_table("nse_x")
    assert len(entries) == 1
    assert "ip_conntrack" in " ".join(run.call_args[0][0])


def test_read_conntrack_table_returns_empty_when_both_paths_fail() -> None:
    import subprocess as sp

    with patch("subprocess.run", side_effect=sp.CalledProcessError(1, "cat")):
        assert read_conntrack_table("nse_x") == []


def test_read_conntrack_table_uses_nsenter_when_asked() -> None:
    with patch("subprocess.run", return_value=MagicMock(stdout="")) as run:
        read_conntrack_table("nse_x", use_nsenter=True)
    assert run.call_args[0][0][0] == "nsenter"


# ---------------------------------------------------------------------------
# Topology, conntrack and teardown paths
# ---------------------------------------------------------------------------


def _gateway_request() -> TestRequest:
    return TestRequest(
        rules="table ip filter { chain forward { type filter hook forward priority 0; } }",
        packets=[PacketSpec(protocol="udp", dst_port=53, src_ip="10.0.1.1", dst_ip="10.0.2.2")],
        topology=TopologyType.GATEWAY,
    )


async def _run(
    request: TestRequest,
    harvester: StubHarvester,
    *,
    controller: Any = None,
    conntrack: list[dict[str, Any]] | None = None,
    listener: Any = None,
) -> list[TraceEvent]:
    controller = controller or MagicMock()
    controller.use_nsenter = False
    injector = MagicMock()

    def inject(spec: Any, *args: Any, **kwargs: Any) -> None:
        if spec.dst_port != pipeline_module._CANARY_DST_PORT:
            harvester.advance()

    injector.inject.side_effect = inject

    with (
        patch.object(pipeline_module, "TraceHarvester", lambda: harvester),
        patch.object(pipeline_module, "ScapyInjector", lambda **_: injector),
        patch.object(pipeline_module, "RuleEngine", MagicMock()),
        patch.object(
            pipeline_module, "start_mock_listener", MagicMock(return_value=listener or MagicMock())
        ),
        patch.object(pipeline_module, "read_conntrack_table", lambda *a, **k: conntrack or []),
        patch.object(pipeline_module.subprocess, "run", MagicMock()),
    ):
        return await run_test_pipeline(request=request, controller=controller)


@pytest.mark.asyncio
async def test_gateway_topology_builds_and_tears_down_both_namespaces() -> None:
    controller = MagicMock()
    await _run(_gateway_request(), StubHarvester(), controller=controller)
    controller.create_gateway_topology.assert_called_once()
    assert controller.destroy_netns.call_count == 2
    assert controller.create_netns.call_count == 0


@pytest.mark.asyncio
async def test_simple_topology_tears_down_one_namespace() -> None:
    controller = MagicMock()
    await _run(_request(), StubHarvester(), controller=controller)
    assert controller.destroy_netns.call_count == 1


@pytest.mark.asyncio
async def test_conntrack_entries_become_events() -> None:
    entries = [
        {
            "proto": "UDP",
            "state": "ESTABLISHED",
            "src": "10.0.0.1",
            "dst": "10.0.0.2",
            "sport": 1234,
            "dport": 53,
        }
    ]
    events = await _run(_request(), StubHarvester(), conntrack=entries)
    conntrack_events = [e for e in events if e.type == "conntrack"]
    assert len(conntrack_events) == 1
    assert "dport=53" not in (conntrack_events[0].rule_text or "")
    assert "10.0.0.2:53" in (conntrack_events[0].rule_text or "")


@pytest.mark.asyncio
async def test_a_listener_that_refuses_to_die_is_killed() -> None:
    listener = MagicMock()
    listener.terminate.side_effect = OSError("already gone")
    await _run(_request(), StubHarvester(), listener=listener)
    listener.kill.assert_called_once()


@pytest.mark.asyncio
async def test_a_listener_that_hangs_on_wait_is_killed() -> None:
    import subprocess as sp

    listener = MagicMock()
    listener.wait.side_effect = sp.TimeoutExpired("python", 0.5)
    await _run(_request(), StubHarvester(), listener=listener)
    listener.kill.assert_called_once()


@pytest.mark.asyncio
async def test_pipeline_creates_a_controller_when_none_is_given() -> None:
    harvester = StubHarvester(readiness=False)
    with (
        patch.object(pipeline_module, "NetnsController") as controller_cls,
        patch.object(pipeline_module, "TraceHarvester", lambda: harvester),
        patch.object(pipeline_module, "ScapyInjector", lambda **_: MagicMock()),
        patch.object(pipeline_module, "RuleEngine", MagicMock()),
        patch.object(pipeline_module, "start_mock_listener", MagicMock()),
        patch.object(pipeline_module, "read_conntrack_table", lambda *a, **k: []),
        patch.object(pipeline_module.subprocess, "run", MagicMock()),
    ):
        controller_cls.return_value.use_nsenter = False
        await run_test_pipeline(request=_request())
    controller_cls.assert_called_once()


@pytest.mark.asyncio
async def test_pipeline_streams_into_a_caller_supplied_queue() -> None:
    queue: asyncio.Queue[TraceEvent | None] = asyncio.Queue()
    harvester = StubHarvester(readiness=False)
    controller = MagicMock()
    controller.use_nsenter = False
    with (
        patch.object(pipeline_module, "TraceHarvester", lambda: harvester),
        patch.object(pipeline_module, "ScapyInjector", lambda **_: MagicMock()),
        patch.object(pipeline_module, "RuleEngine", MagicMock()),
        patch.object(pipeline_module, "start_mock_listener", MagicMock()),
        patch.object(pipeline_module, "read_conntrack_table", lambda *a, **k: []),
        patch.object(pipeline_module.subprocess, "run", MagicMock()),
    ):
        await run_test_pipeline(request=_request(), controller=controller, queue=queue)
    assert not queue.empty()
