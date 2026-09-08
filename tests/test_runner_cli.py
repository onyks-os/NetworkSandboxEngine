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
from nse.models.trace_event import TraceEvent

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

    with patch.object(runner_module, "run_test_pipeline", fake_pipeline):
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
    with patch.object(runner_module, "run_test_pipeline", fake_pipeline):
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

    with patch.object(runner_module, "run_test_pipeline", fake_pipeline):
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
        patch.object(runner_module, "run_test_pipeline", fake_pipeline),
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
        patch.object(runner_module, "run_test_pipeline", fake_pipeline),
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
