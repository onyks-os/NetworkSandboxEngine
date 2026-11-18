"""run_test_pipeline_report(): one experiment, two results, every outcome distinct.

The kernel side is scripted: a harvester that turns each injected packet into
the trace events the kernel would emit, so attribution, verdict reduction and
the canary checks all run for real. No root needed.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from nse.core import environment as environment_module
from nse.core import pipeline as pipeline_module
from nse.core.mock_listener import ListenerStartError
from nse.core.naming import derive_names
from nse.core.pipeline import run_test_pipeline, run_test_pipeline_report
from nse.core.rule_engine import RuleValidationError
from nse.core.trace_harvester import HarvestState
from nse.models.artifacts import artifact_entry, write_text_atomic
from nse.models.capture_report import CaptureReport
from nse.models.experiment_report import ExperimentReport, PositiveControl
from nse.models.process import EffectiveIdentity, ProcessResult
from nse.models.test_request import PacketSpec, TestRequest, TopologyType
from nse.models.trace_event import TraceEvent

pytestmark = pytest.mark.asyncio

CANARY_PORT = pipeline_module._CANARY_DST_PORT


class ScriptedKernel:
    """Harvester and injector in one: injected packets become trace events."""

    def __init__(
        self,
        verdicts: dict[int, str],
        *,
        readiness: bool = True,
        liveness: bool = True,
        inject_error: BaseException | None = None,
        hang: bool = False,
    ) -> None:
        self.verdicts = verdicts
        self.visible = {"readiness": readiness, "liveness": liveness}
        self.inject_error = inject_error
        self.hang = hang
        self.phase = "readiness"
        self.on_event: Any = None
        self.matched_trace_ids: set[str] = set()
        self.state = HarvestState.NOT_STARTED
        self._canary_seen = False
        self.serial = 0

    # -- harvester ----------------------------------------------------------
    async def start(self, *, on_event: Any, **_: Any) -> None:
        self.on_event = on_event
        self.state = HarvestState.RUNNING

    async def wait_ready(self, timeout: float = 2.0) -> bool:
        return True

    def arm_event_signal(self, predicate: Any = None) -> None:
        self.matched_trace_ids.clear()
        self._canary_seen = False

    def extend_deadline(self, seconds: float) -> None:
        pass

    async def wait_for_event(self, timeout: float = 1.0) -> bool:
        return self._canary_seen

    async def aclose(self, timeout: float = 2.0) -> HarvestState:
        self.state = HarvestState.STOPPED
        return self.state

    def health_errors(self) -> list[str]:
        return []

    # -- injector -----------------------------------------------------------
    def inject(self, spec: PacketSpec, *args: Any) -> None:
        if spec.dst_port == CANARY_PORT:
            if not self.visible[self.phase]:
                return
            trace_id = f"{self.phase}-canary-{self.serial}"
            self.serial += 1
            self._emit(trace_id, spec, "accept", table="nse_trace")
            self.matched_trace_ids.add(trace_id)
            self._canary_seen = True
            return
        self.phase = "liveness"  # the first real packet ends the readiness phase
        if self.hang:
            import time

            time.sleep(0.5)
        if self.inject_error is not None:
            raise self.inject_error
        trace_id = f"stim-{self.serial}"
        self.serial += 1
        self._emit(trace_id, spec, self.verdicts.get(spec.dst_port or 0, "accept"))

    def _emit(self, trace_id: str, spec: PacketSpec, verdict: str, table: str = "filter") -> None:
        fields = {
            "trace_id": trace_id,
            "table": table,
            "chain": "input",
            "packet_src_ip": spec.src_ip,
            "packet_dst_ip": spec.dst_ip,
            "packet_protocol": spec.protocol,
            "packet_src_port": spec.src_port or 12345,
            "packet_dst_port": spec.dst_port or 80,
        }
        self.on_event(TraceEvent(type="hook", **fields))
        self.on_event(TraceEvent(type="verdict", verdict=verdict, **fields))


def _request(*ports: int) -> TestRequest:
    return TestRequest(
        rules="table ip filter { chain input { type filter hook input priority 0; } }",
        packets=[PacketSpec(protocol="tcp", dst_port=port) for port in ports or (80,)],
        topology=TopologyType.SIMPLE,
    )


STATUS = "Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nGroups:\t\nCapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapBnd:\t0\nCapAmb:\t0\n"


def _listener_result(port: int) -> ProcessResult:
    return ProcessResult(
        argv=["python", "-m", "nse.core.mock_listener", "--port", str(port)],
        command=["python"],
        pid=1000 + port,
        identity=EffectiveIdentity.from_status(STATUS),
        termination="terminated",
        returncode=-15,
        started_at=0,
        ended_at=1,
    )


def _listeners() -> AsyncMock:
    """start_listener stand-in whose handles stop with a real ProcessResult."""

    async def start(prefix: Any, netns: Any, proto: str, port: int) -> Any:
        handle = AsyncMock()
        handle.terminate.return_value = _listener_result(port)
        return handle

    return AsyncMock(side_effect=start)


def _controller(residual: list[str] | None = None) -> MagicMock:
    controller = MagicMock()
    controller.use_nsenter = False
    controller.namespace_identity.return_value = (0, 1)
    controller.residual_resources.return_value = residual or []
    return controller


async def _report(
    kernel: ScriptedKernel,
    request: TestRequest | None = None,
    *,
    controller: Any = None,
    engine: Any = None,
    listener: Any = None,
    entry: Any = run_test_pipeline_report,
    **options: Any,
) -> Any:
    controller = controller or _controller()
    with (
        patch.object(pipeline_module, "TraceHarvester", lambda: kernel),
        patch.object(pipeline_module, "ScapyInjector", lambda **_: kernel),
        patch.object(pipeline_module, "RuleEngine", lambda **_: engine or MagicMock()),
        patch.object(pipeline_module, "start_listener", listener or _listeners()),
        patch.object(pipeline_module, "read_conntrack_table", lambda *a, **k: []),
        patch.object(pipeline_module, "_INJECT_SETTLE", 0),
        patch.object(pipeline_module, "_DRAIN_DELAY", 0),
        patch.object(pipeline_module, "_CANARY_INTERVAL", 0.001),
    ):
        return await entry(request=request or _request(80, 22), controller=controller, **options)


# --------------------------------------------------------------------------- the clean run


async def test_a_clean_run_reports_input_environment_verdicts_and_canaries() -> None:
    report = await _report(ScriptedKernel({80: "accept", 22: "drop"}))
    assert isinstance(report, ExperimentReport)
    assert report.schema_name == "nse.experiment-report"
    assert report.schema_version == 1
    result = report.result
    assert result.outcome == "completed"
    assert result.verdicts == ["ACCEPT", "DROP"]
    assert [s.verdicts for s in result.stimuli] == [["ACCEPT"], ["DROP"]]
    assert result.oracle.readiness == result.oracle.liveness == "observed"
    assert result.teardown_complete
    assert report.measurement_valid
    # Canaries are evidence of the instrument, kept apart from the user's events.
    assert all("canary" not in (e.trace_id or "") for e in report.observations.events)
    assert {e.trace_id for e in report.observations.canary_events} == {
        "readiness-canary-0",
        "liveness-canary-3",
    }
    assert report.observations.canaries["readiness"].attempts == 1
    assert [s.trace_ids for s in report.observations.stimuli] == [["stim-1"], ["stim-2"]]
    assert all(s.injected_at for s in report.observations.stimuli)
    # Input and environment, for reconstruction.
    assert report.input.request.packets[1].dst_port == 22
    assert len(report.input.rules_sha256) == len(report.input.request_sha256) == 64
    assert report.environment.python
    assert "nft" in report.environment.tools
    names = derive_names(report.run.test_id)
    assert report.run.namespaces == {"sandbox": names.netns}
    assert report.run.interfaces == {"host": names.veth_host, "sandbox": names.veth_router_host}
    assert {"setup", "rules", "injection", "teardown"} <= set(report.run.phases)


async def test_both_entry_points_run_the_same_experiment() -> None:
    events = await _report(ScriptedKernel({22: "drop"}), entry=run_test_pipeline)
    report = await _report(ScriptedKernel({22: "drop"}))
    strip = [(e.type, e.trace_id, e.verdict, e.packet_role) for e in events]
    assert strip == [
        (e.type, e.trace_id, e.verdict, e.packet_role) for e in report.observations.events
    ]


async def test_reproducible_sections_match_across_runs_and_run_sections_do_not() -> None:
    first = await _report(ScriptedKernel({22: "drop"}))
    second = await _report(ScriptedKernel({22: "drop"}))
    assert first.input == second.input
    assert first.environment == second.environment
    assert first.result == second.result
    assert first.run.test_id != second.run.test_id


async def test_json_is_stable_and_round_trips(tmp_path: Path) -> None:
    report = await _report(ScriptedKernel({}))
    text = report.to_json()
    data = json.loads(text)
    assert data["schema"] == "nse.experiment-report"
    assert list(data) == sorted(data)  # stable field order
    assert data["measurement_valid"] is True
    assert ExperimentReport.model_validate(data).result == report.result
    entry = report.write(tmp_path / "out" / "experiment.json")
    assert (tmp_path / "out" / "experiment.json").read_text() == text
    assert entry == artifact_entry(tmp_path / "out" / "experiment.json")


# --------------------------------------------------------------------------- distinct outcomes


async def test_a_blind_oracle_is_an_instrument_failure() -> None:
    report = await _report(ScriptedKernel({}, readiness=False))
    assert report.result.outcome == "instrument_failure"
    assert report.result.oracle.readiness == "missed"
    assert report.result.oracle.liveness == "not_reached"
    assert report.result.verdicts == []
    assert report.result.errors[0].stage == "readiness"
    assert report.result.errors[0].kind == "oracle"
    assert not report.measurement_valid


async def test_a_truncated_trace_is_an_instrument_failure() -> None:
    report = await _report(ScriptedKernel({}, liveness=False))
    assert report.result.outcome == "instrument_failure"
    assert report.result.oracle.liveness == "missed"
    assert report.result.errors[0].stage == "liveness"


async def test_invalid_rules_are_their_own_outcome() -> None:
    engine = MagicMock()
    engine.load.side_effect = RuleValidationError(["line 1: syntax error"])
    report = await _report(ScriptedKernel({}), engine=engine)
    assert report.result.outcome == "rules_invalid"
    assert report.result.errors[0].stage == "rules"
    assert report.result.oracle.readiness == "not_reached"


async def test_a_listener_that_cannot_bind_is_a_setup_failure() -> None:
    failure = ListenerStartError("mock listener tcp/80 exited (1) before it was bound", "tcp", 80)
    report = await _report(ScriptedKernel({}), listener=AsyncMock(side_effect=failure))
    assert report.result.outcome == "setup_failure"
    assert report.result.errors[0].stage == "listeners"
    assert report.result.errors[0].kind == "ListenerStartError"


async def test_an_injection_failure_is_an_execution_failure() -> None:
    report = await _report(ScriptedKernel({}, inject_error=OSError("no such device")))
    assert report.result.outcome == "execution_failure"
    assert report.result.errors[0].stage == "injection"
    assert report.result.oracle.readiness == "observed"


async def test_a_timeout_stops_the_run_and_still_tears_down() -> None:
    controller = _controller()
    report = await _report(ScriptedKernel({}, hang=True), controller=controller, timeout=0.1)
    assert report.result.outcome == "timeout"
    assert report.result.errors[0].kind == "timeout"
    assert report.result.errors[0].stage == "injection"
    assert any("timeout" in (e.raw_message or "") for e in report.observations.events)
    controller._cleanup_run.assert_called_once()


async def test_a_failed_teardown_is_recorded_and_still_raised_by_the_list_api() -> None:
    controller = _controller()
    controller._cleanup_run.side_effect = OSError("ip netns del failed")
    report = await _report(ScriptedKernel({}), controller=controller)
    assert report.result.outcome == "completed"  # the measurement itself was fine
    assert not report.result.teardown_complete
    assert report.result.errors[-1].stage == "teardown"
    assert not report.measurement_valid
    with pytest.raises(OSError, match="ip netns del failed"):
        await _report(ScriptedKernel({}), controller=controller, entry=run_test_pipeline)


async def test_residual_resources_make_teardown_incomplete() -> None:
    report = await _report(ScriptedKernel({}), controller=_controller(["namespace nse_x"]))
    assert report.result.residual_resources == ["namespace nse_x"]
    assert not report.result.teardown_complete


async def test_cancellation_still_propagates_and_tears_down() -> None:
    controller = _controller()
    task = asyncio.ensure_future(_report(ScriptedKernel({}, hang=True), controller=controller))
    await asyncio.sleep(0.2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    controller._cleanup_run.assert_called_once()


async def test_listener_results_are_part_of_the_evidence() -> None:
    report = await _report(ScriptedKernel({}))
    processes = report.observations.processes
    assert sorted(p.argv[-1] for p in processes) == ["22", "80"]  # one per port
    assert all(p.identity.uids == (0, 0, 0, 0) for p in processes)


async def test_a_listener_that_fails_to_stop_is_logged_not_recorded() -> None:
    async def start(*args: Any) -> Any:
        handle = AsyncMock()
        handle.terminate.side_effect = OSError("gone")
        return handle

    report = await _report(ScriptedKernel({}), listener=AsyncMock(side_effect=start))
    assert report.observations.processes == []
    assert report.result.teardown_complete  # the namespace sweep still stops it


async def test_identical_packets_share_their_traces() -> None:
    report = await _report(ScriptedKernel({80: "accept"}), _request(80, 80))
    assert [s.verdicts for s in report.result.stimuli] == [["ACCEPT"] * 2] * 2
    assert report.result.verdicts == ["ACCEPT", "ACCEPT"]


async def test_gateway_runs_name_both_namespaces() -> None:
    request = TestRequest(
        rules="table ip filter { chain forward { type filter hook forward priority 0; } }",
        packets=[PacketSpec(protocol="udp", dst_port=53, src_ip="10.0.1.1", dst_ip="10.0.2.2")],
        topology=TopologyType.GATEWAY,
    )
    report = await _report(ScriptedKernel({}), request)
    assert set(report.run.namespaces) == {"router", "server"}
    assert set(report.run.interfaces) == {"host", "router_host", "router_server", "server"}


# --------------------------------------------------------------------------- caller attachments


def _capture(tmp_path: Path, *, healthy: bool = True) -> CaptureReport:
    pcap = tmp_path / "leak.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1pcap")
    return CaptureReport(
        iface="veth0",
        requested_filter=None,
        effective_filter="not arp",
        default_filter_replaced=False,
        backend="scapy-l2listen",
        backend_version="2.8.0",
        termination="stopped" if healthy else "backend_terminated",
        errors=[] if healthy else ["boom"],
        start_requested_at=0,
        started_at=1,
        stop_requested_at=2,
        stopped_at=3,
        packets_observed=0,
        bytes_observed=0,
        packets_stored=0,
        artifacts=[str(pcap)],
    )


async def test_captures_and_controls_are_linked_and_hashed(tmp_path: Path) -> None:
    report = await _report(ScriptedKernel({}))
    linked = report.attach(
        captures=[_capture(tmp_path)],
        controls=[PositiveControl(name="flushed ruleset lets the probe through", passed=True)],
    )
    assert linked.measurement_valid
    assert linked.artifacts == [artifact_entry(tmp_path / "leak.pcap")]
    assert report.observations.captures == []  # attach returns a copy
    twice = linked.attach(captures=[_capture(tmp_path)])
    assert len(twice.artifacts) == 1  # the same file is hashed once

    assert not report.attach(controls=[PositiveControl(name="c", passed=False)]).measurement_valid
    assert not report.attach(captures=[_capture(tmp_path, healthy=False)]).measurement_valid


async def test_atomic_write_leaves_no_partial_file(tmp_path: Path) -> None:
    target = tmp_path / "report.json"
    target.write_text("previous")
    with (
        patch.object(os, "replace", side_effect=OSError("disk full")),
        pytest.raises(OSError, match="disk full"),
    ):
        write_text_atomic(target, "new")
    assert target.read_text() == "previous"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["report.json"]


# --------------------------------------------------------------------------- environment


async def test_environment_reports_unknowns_as_none() -> None:
    environment_module.tool_version.cache_clear()
    try:
        with patch.object(environment_module, "resolve_optional", lambda name: None):
            assert environment_module.tool_version("nft") is None
        with patch.object(environment_module.subprocess, "run", side_effect=OSError("exec")):
            assert environment_module.tool_version("ip") is None
    finally:
        environment_module.tool_version.cache_clear()
    assert environment_module._package_version("nse-no-such-package") is None
    environment = environment_module.collect_environment(use_nsenter=True)
    assert environment.use_nsenter
    assert environment.dependencies["pydantic"]


async def test_reports_are_readable_by_the_collector(tmp_path: Path) -> None:
    """Written by root, uploaded by the CI user: 0644 unless asked otherwise."""
    write_text_atomic(tmp_path / "report.json", "{}")
    assert (tmp_path / "report.json").stat().st_mode & 0o777 == 0o644
    write_text_atomic(tmp_path / "private.json", "{}", mode=0o600)
    assert (tmp_path / "private.json").stat().st_mode & 0o777 == 0o600
