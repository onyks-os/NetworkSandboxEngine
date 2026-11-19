"""The experiment report from a real kernel run (root only)."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from nse.core.netns_controller import NetnsController
from nse.core.pipeline import run_test_pipeline_report
from nse.models.experiment_report import ExperimentReport
from nse.models.test_request import PacketSpec, TestRequest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.asyncio,
    pytest.mark.skipif(os.geteuid() != 0, reason="requires root and real network namespaces"),
]

RULES = """
table ip filter {
    chain input {
        type filter hook input priority 0; policy drop;
        tcp dport 80 accept
    }
}
"""


def _request() -> TestRequest:
    return TestRequest(
        rules=RULES,
        packets=[PacketSpec(protocol="tcp", dst_port=80), PacketSpec(protocol="tcp", dst_port=22)],
    )


async def test_a_real_run_is_fully_reported_and_reproducible(
    runtime_registry: Path, tmp_path: Path
) -> None:
    controller = NetnsController()
    first = await run_test_pipeline_report(_request(), controller=controller)
    second = await run_test_pipeline_report(_request(), controller=controller)

    for report in (first, second):
        assert report.result.outcome == "completed", report.result.errors
        assert report.result.verdicts == ["ACCEPT", "DROP"]
        assert [s.verdicts for s in report.result.stimuli] == [["ACCEPT"], ["DROP"]]
        assert report.result.oracle.readiness == report.result.oracle.liveness == "observed"
        assert report.result.teardown_complete
        assert report.result.residual_resources == []
        assert report.measurement_valid
        # The listeners were managed processes; their verified identity is evidence.
        assert sorted(
            p.argv[p.argv.index("--port") + 1] for p in report.observations.processes
        ) == [
            "22",
            "80",
        ]
        assert all(p.identity.uids == (0, 0, 0, 0) for p in report.observations.processes)
        assert report.environment.tools["nft"]
        assert report.environment.tools["ip"]
        assert not Path(f"/var/run/netns/{report.run.namespaces['sandbox']}").exists()

    # Same request, same host: the reproducible sections agree.
    assert first.input == second.input
    assert first.environment == second.environment
    assert first.result == second.result
    assert first.run.test_id != second.run.test_id

    path = tmp_path / "experiment.json"
    first.write(path)
    assert ExperimentReport.model_validate(json.loads(path.read_text())).result == first.result


async def test_a_blind_oracle_is_reported_as_an_instrument_failure(
    runtime_registry: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NSE_FORCE_BLIND", "1")
    report = await run_test_pipeline_report(_request(), controller=NetnsController())
    assert report.result.outcome == "instrument_failure"
    assert report.result.oracle.readiness == "missed"
    assert report.result.verdicts == []
    assert report.result.teardown_complete  # a broken instrument still cleans up
    assert not report.measurement_valid


async def test_invalid_rules_are_reported_and_cleaned_up(runtime_registry: Path) -> None:
    request = TestRequest(
        rules="table ip filter { this is not nft }", packets=[PacketSpec(protocol="tcp")]
    )
    report = await run_test_pipeline_report(request, controller=NetnsController())
    assert report.result.outcome == "rules_invalid"
    assert report.result.errors[0].stage == "rules"
    assert report.result.teardown_complete
