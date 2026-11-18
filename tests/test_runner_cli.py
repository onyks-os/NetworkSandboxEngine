# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""
End-to-end tests for the runner's exit code, with the pipeline stubbed out.

These need no root: they replace `run_test_pipeline` with a function that
returns a chosen event stream, which is exactly the surface that decides whether
CI goes green. The headline case is `test_blind_run_exits_nonzero`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from nse.cli import runner as runner_module
from nse.cli.runner import SuiteOutcome, run_suite
from nse.core.verdicts import reduce_verdicts
from nse.models.artifacts import artifact_entry
from nse.models.experiment_report import (
    CanaryObservation,
    Environment,
    ExperimentInput,
    ExperimentReport,
    ExperimentResult,
    Observations,
    OracleStatus,
    RunInfo,
    StageError,
)
from nse.models.test_request import TestRequest
from nse.models.trace_event import TraceEvent


def make_report(
    events: list[TraceEvent],
    request: TestRequest,
    *,
    outcome: Any = "completed",
    teardown_errors: tuple[str, ...] = (),
    residual: tuple[str, ...] = (),
) -> ExperimentReport:
    """A report as the pipeline would build it around *events*."""
    observed = CanaryObservation(status="observed", attempts=1)
    return ExperimentReport(
        input=ExperimentInput.of(request),
        environment=Environment(
            nse="test",
            python="3",
            python_implementation="CPython",
            dependencies={},
            kernel="test",
            machine="x86_64",
            tools={},
            use_nsenter=False,
            in_container=False,
        ),
        result=ExperimentResult(
            outcome=outcome,
            oracle=OracleStatus(readiness="observed", liveness="observed"),
            verdicts=reduce_verdicts(events),
            stimuli=[],
            errors=[
                StageError(stage="teardown", kind="OSError", message=m) for m in teardown_errors
            ],
            teardown_complete=not teardown_errors and not residual,
            residual_resources=list(residual),
        ),
        observations=Observations(
            events=events,
            canaries={"readiness": observed, "liveness": observed},
            stimuli=[],
        ),
        run=RunInfo(
            test_id="t",
            ownership_id="o",
            namespaces={},
            interfaces={},
            started_at=0,
            ended_at=1,
            phases={},
        ),
    )


def as_report_pipeline(fake_pipeline: Any, **report_options: Any) -> Any:
    """Turn an events-returning stub into a ``run_test_pipeline_report`` stub."""

    async def report_pipeline(**kwargs: Any) -> ExperimentReport:
        events = await fake_pipeline(**kwargs)
        return make_report(events, kwargs["request"], **report_options)

    return report_pipeline


SUITE = [
    {
        "name": "allow 80 deny 22",
        "rules": "table ip filter { chain input { type filter hook input priority 0; } }",
        "packets": [
            {"protocol": "tcp", "dst_port": 80, "expected_verdict": "ACCEPT"},
            {"protocol": "tcp", "dst_port": 22, "expected_verdict": "DROP"},
        ],
    }
]


def _events(*pairs: tuple[str, str]) -> list[TraceEvent]:
    events: list[TraceEvent] = []
    for trace_id, value in pairs:
        events.append(TraceEvent(type="hook", trace_id=trace_id, table="filter", chain="input"))
        events.append(
            TraceEvent(
                type="verdict", trace_id=trace_id, table="filter", chain="input", verdict=value
            )
        )
    return events


def _run_with(events: Any) -> SuiteOutcome:
    """Run the suite against a stubbed pipeline returning *events*."""

    async def fake_pipeline(**_: Any) -> list[TraceEvent]:
        if isinstance(events, BaseException):
            raise events
        return events

    with patch.object(runner_module, "run_test_pipeline_report", as_report_pipeline(fake_pipeline)):
        return run_suite(SUITE, MagicMock())


def test_matching_verdicts_exit_zero() -> None:
    outcome = _run_with(_events(("a1", "accept"), ("b2", "drop")))
    assert outcome.exit_code == 0
    assert (outcome.passed, outcome.failed) == (1, 0)


def test_blind_run_exits_nonzero() -> None:
    """
    The regression that shipped: the oracle observed nothing, so the runner
    printed `[FAIL] Oracle Error` and then exited 0 anyway.
    """
    outcome = _run_with([])
    assert outcome.exit_code == 1
    assert outcome.oracle_errors == 1


def test_truncated_run_exits_nonzero() -> None:
    outcome = _run_with(_events(("a1", "accept")))
    assert outcome.exit_code == 1
    assert outcome.oracle_errors == 1


def test_extra_verdicts_exit_nonzero() -> None:
    outcome = _run_with(_events(("a1", "accept"), ("b2", "drop"), ("c3", "accept")))
    assert outcome.exit_code == 1
    assert outcome.oracle_errors == 1


def test_wrong_verdict_exits_nonzero_without_blaming_the_oracle() -> None:
    outcome = _run_with(_events(("a1", "drop"), ("b2", "drop")))
    assert outcome.exit_code == 1
    assert outcome.failed == 1
    assert outcome.oracle_errors == 0


def test_pipeline_error_event_exits_nonzero() -> None:
    events = [TraceEvent(type="error", trace_id="run", raw_message="oracle: canary lost")]
    outcome = _run_with(events)
    assert outcome.exit_code == 1
    assert outcome.oracle_errors == 1


def test_pipeline_crash_exits_nonzero() -> None:
    outcome = _run_with(RuntimeError("nft exploded"))
    assert outcome.exit_code == 1
    assert outcome.oracle_errors == 1


def test_malformed_case_exits_nonzero_without_running_the_pipeline() -> None:
    called = False

    async def fake_pipeline(**_: Any) -> list[TraceEvent]:
        nonlocal called
        called = True
        return []

    bad_suite = [{"name": "bad", "rules": "x", "packets": [{"protocol": "tcp", "typo": 1}]}]
    with patch.object(runner_module, "run_test_pipeline_report", as_report_pipeline(fake_pipeline)):
        outcome = run_suite(bad_suite, MagicMock())

    assert outcome.exit_code == 1
    assert called is False


def test_one_bad_case_does_not_stop_the_others() -> None:
    suite = [
        {"name": "bad", "rules": "x", "packets": [{"protocol": "tcp", "typo": 1}]},
        SUITE[0],
    ]

    async def fake_pipeline(**_: Any) -> list[TraceEvent]:
        return _events(("a1", "accept"), ("b2", "drop"))

    with patch.object(runner_module, "run_test_pipeline_report", as_report_pipeline(fake_pipeline)):
        outcome = run_suite(suite, MagicMock())

    assert (outcome.passed, outcome.failed) == (1, 1)
    assert outcome.exit_code == 1


# ---------------------------------------------------------------------------
# main()
# ---------------------------------------------------------------------------


def _write_suite(tmp_path: Path) -> str:
    path = tmp_path / "suite.json"
    path.write_text(json.dumps({"tests": SUITE}))
    return str(path)


def test_main_exits_one_when_the_oracle_is_blind(tmp_path: Path) -> None:
    async def fake_pipeline(**_: Any) -> list[TraceEvent]:
        return []

    with (
        patch.object(runner_module, "run_test_pipeline_report", as_report_pipeline(fake_pipeline)),
        patch.object(runner_module, "NetnsController", MagicMock()),
        patch("sys.argv", ["nse-runner", "--file", _write_suite(tmp_path)]),
        pytest.raises(SystemExit) as exc,
    ):
        runner_module.main()
    assert exc.value.code == 1


def test_main_exits_zero_on_a_clean_run(tmp_path: Path) -> None:
    async def fake_pipeline(**_: Any) -> list[TraceEvent]:
        return _events(("a1", "accept"), ("b2", "drop"))

    with (
        patch.object(runner_module, "run_test_pipeline_report", as_report_pipeline(fake_pipeline)),
        patch.object(runner_module, "NetnsController", MagicMock()),
        patch("sys.argv", ["nse-runner", "--file", _write_suite(tmp_path)]),
        pytest.raises(SystemExit) as exc,
    ):
        runner_module.main()
    assert exc.value.code == 0


def test_main_exits_one_on_an_unreadable_suite(tmp_path: Path) -> None:
    with (
        patch("sys.argv", ["nse-runner", "--file", str(tmp_path / "missing.yaml")]),
        pytest.raises(SystemExit) as exc,
    ):
        runner_module.main()
    assert exc.value.code == 1


def test_check_cli_dependencies_exits_without_yaml() -> None:
    with (
        patch.object(runner_module, "yaml", None),
        pytest.raises(SystemExit) as exc,
    ):
        runner_module.check_cli_dependencies()
    assert exc.value.code == 1


# ---------------------------------------------------------------------------
# Distinct outcomes and the JSON report
# ---------------------------------------------------------------------------

RIGHT = _events(("a1", "accept"), ("b2", "drop"))


def _run_reports(**report_options: Any) -> tuple[SuiteOutcome, list[dict[str, Any]]]:
    async def fake_pipeline(**_: Any) -> list[TraceEvent]:
        return RIGHT

    records: list[dict[str, Any]] = []
    with patch.object(
        runner_module,
        "run_test_pipeline_report",
        as_report_pipeline(fake_pipeline, **report_options),
    ):
        outcome = run_suite(SUITE, MagicMock(), records=records)
    return outcome, records


def test_a_passing_case_is_recorded_with_its_experiment() -> None:
    outcome, records = _run_reports()
    assert outcome.exit_code == 0
    (record,) = records
    assert record["status"] == "passed"
    assert record["expected"] == record["observed"] == ["ACCEPT", "DROP"]
    assert record["experiment"]["schema"] == "nse.experiment-report"


def test_incomplete_teardown_fails_even_with_the_right_verdicts(
    capsys: pytest.CaptureFixture[str],
) -> None:
    outcome, records = _run_reports(residual=("namespace nse_x",))
    assert outcome.exit_code == 1
    assert outcome.teardown_errors == 1
    assert records[0]["status"] == "teardown_incomplete"
    assert records[0]["teardown_complete"] is False
    assert "[TEARDOWN ERROR] left behind: namespace nse_x" in capsys.readouterr().out


def test_a_teardown_error_is_shown() -> None:
    outcome, records = _run_reports(teardown_errors=("ip netns del failed",))
    assert outcome.exit_code == 1
    assert "  [TEARDOWN ERROR] ip netns del failed" in records[0]["lines"]


@pytest.mark.parametrize(
    ("engine_outcome", "status", "label"),
    [
        ("timeout", "timeout", "[TIMEOUT]"),
        ("rules_invalid", "rules_invalid", "[RULES ERROR]"),
        ("setup_failure", "setup_error", "[SETUP ERROR]"),
        ("instrument_failure", "instrument_error", "[ORACLE ERROR]"),
        ("execution_failure", "instrument_error", "[ORACLE ERROR]"),
    ],
)
def test_each_engine_outcome_has_its_own_status(
    engine_outcome: str, status: str, label: str
) -> None:
    async def fake_pipeline(**_: Any) -> list[TraceEvent]:
        return [TraceEvent(type="error", trace_id="t", raw_message=f"{engine_outcome} happened")]

    records: list[dict[str, Any]] = []
    with patch.object(
        runner_module,
        "run_test_pipeline_report",
        as_report_pipeline(fake_pipeline, outcome=engine_outcome),
    ):
        outcome = run_suite(SUITE, MagicMock(), records=records)
    assert outcome.exit_code == 1
    assert records[0]["status"] == status
    assert records[0]["lines"] == [f"  {label} {engine_outcome} happened"]


def test_wrong_verdicts_and_crashes_and_bad_entries_are_distinct() -> None:
    async def wrong(**_: Any) -> list[TraceEvent]:
        return _events(("a1", "drop"), ("b2", "drop"))

    records: list[dict[str, Any]] = []
    with patch.object(runner_module, "run_test_pipeline_report", as_report_pipeline(wrong)):
        run_suite(SUITE, MagicMock(), records=records)

    async def crash(**_: Any) -> list[TraceEvent]:
        raise RuntimeError("nft exploded")

    with patch.object(runner_module, "run_test_pipeline_report", as_report_pipeline(crash)):
        run_suite(SUITE, MagicMock(), records=records)
    run_suite([{"name": "bad", "rules": "x", "packets": []}], MagicMock(), records=records)
    assert [r["status"] for r in records] == ["failed", "crashed", "invalid_case"]
    assert records[1]["experiment"] is None


def test_report_dir_writes_report_and_manifest(tmp_path: Path) -> None:
    async def fake_pipeline(**_: Any) -> list[TraceEvent]:
        return RIGHT

    out = tmp_path / "artifacts"
    suite = _write_suite(tmp_path)
    with (
        patch.object(runner_module, "run_test_pipeline_report", as_report_pipeline(fake_pipeline)),
        patch.object(runner_module, "NetnsController", MagicMock()),
        patch("sys.argv", ["nse-runner", "--file", suite, "--report-dir", str(out)]),
        pytest.raises(SystemExit) as exc,
    ):
        runner_module.main()
    assert exc.value.code == 0
    report = json.loads((out / "report.json").read_text())
    manifest = json.loads((out / "manifest.json").read_text())
    assert report["schema"] == "nse.suite-report"
    assert report["summary"]["exit_code"] == 0
    assert report["suite"]["file"]["sha256"] == artifact_entry(suite).sha256
    assert [c["status"] for c in report["cases"]] == ["passed"]
    assert manifest["artifacts"][0] == artifact_entry(out / "report.json").model_dump()


def test_a_failed_suite_still_writes_its_report(tmp_path: Path) -> None:
    out = tmp_path / "artifacts"
    with (
        patch(
            "sys.argv",
            ["nse-runner", "--file", str(tmp_path / "missing.yaml"), "--report-dir", str(out)],
        ),
        pytest.raises(SystemExit) as exc,
    ):
        runner_module.main()
    assert exc.value.code == 1
    report = json.loads((out / "report.json").read_text())
    assert report["error"].startswith("cannot read the suite")
    assert report["summary"] is None
    assert report["suite"]["file"] is None


def test_an_interrupted_suite_writes_what_it_has(tmp_path: Path) -> None:
    out = tmp_path / "artifacts"
    with (
        patch.object(runner_module, "run_suite", MagicMock(side_effect=KeyboardInterrupt)),
        patch.object(runner_module, "NetnsController", MagicMock()),
        patch(
            "sys.argv", ["nse-runner", "--file", _write_suite(tmp_path), "--report-dir", str(out)]
        ),
        pytest.raises(KeyboardInterrupt),
    ):
        runner_module.main()
    assert json.loads((out / "report.json").read_text())["error"].startswith(
        "interrupted: KeyboardInterrupt"
    )


def test_an_unwritable_report_fails_the_run(tmp_path: Path) -> None:
    async def fake_pipeline(**_: Any) -> list[TraceEvent]:
        return RIGHT

    blocker = tmp_path / "file"
    blocker.write_text("not a directory")
    with (
        patch.object(runner_module, "run_test_pipeline_report", as_report_pipeline(fake_pipeline)),
        patch.object(runner_module, "NetnsController", MagicMock()),
        patch(
            "sys.argv",
            ["nse-runner", "--file", _write_suite(tmp_path), "--report-dir", str(blocker / "x")],
        ),
        pytest.raises(SystemExit) as exc,
    ):
        runner_module.main()
    assert exc.value.code == 1  # the verdicts passed, but the asked-for evidence is missing


def test_timeout_is_passed_to_every_case_and_validated(tmp_path: Path) -> None:
    seen: list[Any] = []

    async def fake_pipeline(**kwargs: Any) -> list[TraceEvent]:
        seen.append(kwargs["timeout"])
        return RIGHT

    with (
        patch.object(runner_module, "run_test_pipeline_report", as_report_pipeline(fake_pipeline)),
        patch.object(runner_module, "NetnsController", MagicMock()),
        patch("sys.argv", ["nse-runner", "--file", _write_suite(tmp_path), "--timeout", "30"]),
        pytest.raises(SystemExit),
    ):
        runner_module.main()
    assert seen == [30.0]
    with (
        patch("sys.argv", ["nse-runner", "--file", "x", "--timeout", "0"]),
        pytest.raises(SystemExit) as exc,
    ):
        runner_module.main()
    assert exc.value.code == 2


def test_wrong_verdicts_with_incomplete_teardown_report_both() -> None:
    async def wrong(**_: Any) -> list[TraceEvent]:
        return _events(("a1", "drop"), ("b2", "drop"))

    records: list[dict[str, Any]] = []
    with patch.object(
        runner_module,
        "run_test_pipeline_report",
        as_report_pipeline(wrong, residual=("link vhr-x",)),
    ):
        outcome = run_suite(SUITE, MagicMock(), records=records)
    assert records[0]["status"] == "failed"  # the ruleset is the primary finding
    assert records[0]["teardown_complete"] is False
    assert (outcome.failed, outcome.teardown_errors) == (1, 1)
