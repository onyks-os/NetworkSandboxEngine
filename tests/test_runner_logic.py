# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""
Unit tests for the pure decision logic of the YAML runner.

`nse/cli/runner.py` is what turns a trace stream into an exit code, so these
tests exist to make one property impossible to regress: **the runner must never
report success from an absence of evidence.** The regression they guard was real
— the count-mismatch branch printed a failure banner without setting the failure
flag, so a run that observed zero verdicts exited 0.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nse.cli.runner import (
    CaseOutcome,
    SuiteConfigError,
    SuiteOutcome,
    build_case,
    collect_oracle_errors,
    evaluate_case,
    load_suite,
    reduce_verdicts,
)
from nse.models.test_request import TopologyType
from nse.models.trace_event import TraceEvent


def hook(trace_id: str, table: str = "filter") -> TraceEvent:
    return TraceEvent(type="hook", trace_id=trace_id, table=table, chain="input")


def verdict(trace_id: str, value: str, table: str = "filter") -> TraceEvent:
    return TraceEvent(type="verdict", trace_id=trace_id, table=table, chain="input", verdict=value)


def error(message: str) -> TraceEvent:
    return TraceEvent(type="error", trace_id="run", verdict="ERROR", raw_message=message)


# ---------------------------------------------------------------------------
# reduce_verdicts
# ---------------------------------------------------------------------------


def test_reduce_verdicts_empty_stream_yields_nothing() -> None:
    """The whole point: no events must not become an implicit pass."""
    assert reduce_verdicts([]) == []


def test_reduce_verdicts_one_accept() -> None:
    assert reduce_verdicts([hook("a1"), verdict("a1", "accept")]) == ["ACCEPT"]


def test_reduce_verdicts_preserves_injection_order() -> None:
    events = [
        hook("a1"),
        verdict("a1", "accept"),
        hook("b2"),
        verdict("b2", "drop"),
        hook("c3"),
        verdict("c3", "accept"),
    ]
    assert reduce_verdicts(events) == ["ACCEPT", "DROP", "ACCEPT"]


def test_reduce_verdicts_drop_beats_accept_within_one_packet() -> None:
    """Accepted by one chain and dropped by another means it did not get through."""
    events = [hook("a1"), verdict("a1", "accept"), verdict("a1", "drop")]
    assert reduce_verdicts(events) == ["DROP"]


def test_reduce_verdicts_reject_counts_as_drop() -> None:
    assert reduce_verdicts([hook("a1"), verdict("a1", "reject")]) == ["DROP"]


def test_reduce_verdicts_ignores_scaffolding_table() -> None:
    """nse_trace only switches tracing on; its events are not results."""
    events = [
        hook("a1", table="nse_trace"),
        verdict("a1", "accept", table="nse_trace"),
    ]
    assert reduce_verdicts(events) == []


def test_reduce_verdicts_scaffolding_then_user_table_counts_once() -> None:
    events = [
        hook("a1", table="nse_trace"),
        verdict("a1", "accept", table="nse_trace"),
        hook("a1", table="filter"),
        verdict("a1", "drop", table="filter"),
    ]
    assert reduce_verdicts(events) == ["DROP"]


def test_reduce_verdicts_user_table_without_verdict_is_not_a_pass() -> None:
    """
    A packet that reached the ruleset but produced no verdict is missing
    evidence. It must fall out of the list so the count mismatch fires, rather
    than being rounded up to ACCEPT.
    """
    assert reduce_verdicts([hook("a1", table="filter")]) == []


def test_reduce_verdicts_skips_error_events() -> None:
    assert reduce_verdicts([error("boom"), hook("a1"), verdict("a1", "accept")]) == ["ACCEPT"]


def test_reduce_verdicts_skips_events_without_trace_id() -> None:
    orphan = TraceEvent(type="verdict", table="filter", verdict="ACCEPT")
    assert reduce_verdicts([orphan]) == []


def test_reduce_verdicts_is_case_insensitive() -> None:
    assert reduce_verdicts([hook("a1"), verdict("a1", "AcCePt")]) == ["ACCEPT"]


# ---------------------------------------------------------------------------
# collect_oracle_errors
# ---------------------------------------------------------------------------


def test_collect_oracle_errors_returns_messages() -> None:
    assert collect_oracle_errors([error("blind"), hook("a1")]) == ["blind"]


def test_collect_oracle_errors_handles_missing_message() -> None:
    evt = TraceEvent(type="error", trace_id="run", verdict="ERROR")
    assert collect_oracle_errors([evt]) == ["unspecified pipeline error"]


# ---------------------------------------------------------------------------
# evaluate_case — the regression that shipped
# ---------------------------------------------------------------------------


def test_evaluate_case_zero_observed_verdicts_fails() -> None:
    """
    THE regression test. Two packets expected, nothing observed. This exact
    input used to print `=> SUCCESS` and exit 0.
    """
    outcome = evaluate_case("blind run", ["ACCEPT", "DROP"], [])
    assert outcome.passed is False
    assert outcome.oracle_error is True
    assert "observed 0" in " ".join(outcome.lines)


def test_evaluate_case_fewer_observed_than_expected_fails() -> None:
    events = [hook("a1"), verdict("a1", "accept")]
    outcome = evaluate_case("truncated", ["ACCEPT", "DROP"], events)
    assert outcome.passed is False
    assert outcome.oracle_error is True


def test_evaluate_case_more_observed_than_expected_fails() -> None:
    """Extra verdicts used to be truncated away by zip(strict=False)."""
    events = [
        hook("a1"),
        verdict("a1", "accept"),
        hook("b2"),
        verdict("b2", "accept"),
    ]
    outcome = evaluate_case("noisy", ["ACCEPT"], events)
    assert outcome.passed is False
    assert outcome.oracle_error is True


def test_evaluate_case_all_matching_passes() -> None:
    events = [hook("a1"), verdict("a1", "accept"), hook("b2"), verdict("b2", "drop")]
    outcome = evaluate_case("good", ["ACCEPT", "DROP"], events)
    assert outcome.passed is True
    assert outcome.oracle_error is False
    assert all(line.startswith("  [OK]") for line in outcome.lines)


def test_evaluate_case_mismatch_is_a_firewall_failure_not_an_oracle_error() -> None:
    """A wrong verdict is the ruleset's fault; the instrument worked fine."""
    events = [hook("a1"), verdict("a1", "drop")]
    outcome = evaluate_case("wrong", ["ACCEPT"], events)
    assert outcome.passed is False
    assert outcome.oracle_error is False
    assert "expected ACCEPT, got DROP" in " ".join(outcome.lines)


def test_evaluate_case_pipeline_error_short_circuits() -> None:
    events = [error("readiness canary was never observed")]
    outcome = evaluate_case("blind", ["ACCEPT"], events)
    assert outcome.passed is False
    assert outcome.oracle_error is True
    assert "readiness canary" in " ".join(outcome.lines)


def test_evaluate_case_error_wins_over_matching_verdicts() -> None:
    """
    Even if the verdicts happen to line up, an oracle error means the run is
    not evidence. It must not be reported as a pass.
    """
    events = [error("truncated stream"), hook("a1"), verdict("a1", "accept")]
    outcome = evaluate_case("suspicious", ["ACCEPT"], events)
    assert outcome.passed is False
    assert outcome.oracle_error is True


# ---------------------------------------------------------------------------
# SuiteOutcome
# ---------------------------------------------------------------------------


def test_suite_outcome_all_passing_exits_zero() -> None:
    outcome = SuiteOutcome()
    outcome.record(CaseOutcome(name="a", passed=True))
    assert outcome.exit_code == 0
    assert (outcome.passed, outcome.failed) == (1, 0)


def test_suite_outcome_any_failure_exits_one() -> None:
    outcome = SuiteOutcome()
    outcome.record(CaseOutcome(name="a", passed=True))
    outcome.record(CaseOutcome(name="b", passed=False))
    assert outcome.exit_code == 1


def test_suite_outcome_counts_oracle_errors_separately() -> None:
    outcome = SuiteOutcome()
    outcome.record(CaseOutcome(name="a", passed=False, oracle_error=True))
    assert (outcome.failed, outcome.oracle_errors) == (1, 1)
    assert outcome.exit_code == 1


# ---------------------------------------------------------------------------
# build_case
# ---------------------------------------------------------------------------


def _minimal_case(**overrides: object) -> dict:
    case = {
        "name": "case",
        "rules": "table ip filter {}",
        "packets": [{"protocol": "tcp", "dst_port": 80, "expected_verdict": "ACCEPT"}],
    }
    case.update(overrides)
    return case


def test_build_case_minimal() -> None:
    name, request, expected = build_case(_minimal_case(), 0)
    assert name == "case"
    assert expected == ["ACCEPT"]
    assert request.topology == TopologyType.SIMPLE
    assert request.packets[0].dst_port == 80


def test_build_case_gateway_defaults_differ() -> None:
    _, request, _ = build_case(_minimal_case(topology="gateway"), 0)
    assert request.topology == TopologyType.GATEWAY
    assert request.packets[0].src_ip == "10.0.1.1"
    assert request.packets[0].dst_ip == "10.0.2.2"


def test_build_case_reject_normalised_to_drop() -> None:
    """The oracle cannot tell REJECT from DROP; the expectation must say so."""
    case = _minimal_case(packets=[{"protocol": "tcp", "expected_verdict": "REJECT"}])
    _, _, expected = build_case(case, 0)
    assert expected == ["DROP"]


def test_build_case_rejects_unknown_case_key() -> None:
    with pytest.raises(SuiteConfigError, match="unknown key"):
        build_case(_minimal_case(topolgy="simple"), 0)


def test_build_case_rejects_unknown_packet_key() -> None:
    """`expect_verdict` used to be silently absorbed into a default of ACCEPT."""
    case = _minimal_case(packets=[{"protocol": "tcp", "expect_verdict": "DROP"}])
    with pytest.raises(SuiteConfigError, match="unknown key"):
        build_case(case, 0)


def test_build_case_rejects_unknown_verdict() -> None:
    case = _minimal_case(packets=[{"protocol": "tcp", "expected_verdict": "MAYBE"}])
    with pytest.raises(SuiteConfigError, match="unknown verdict"):
        build_case(case, 0)


def test_build_case_rejects_unknown_topology() -> None:
    with pytest.raises(SuiteConfigError, match="unknown topology"):
        build_case(_minimal_case(topology="mesh"), 0)


def test_build_case_rejects_empty_packets() -> None:
    with pytest.raises(SuiteConfigError, match="no packets"):
        build_case(_minimal_case(packets=[]), 0)


def test_build_case_rejects_non_mapping_case() -> None:
    with pytest.raises(SuiteConfigError, match="not a mapping"):
        build_case("nope", 0)  # type: ignore[arg-type]


def test_build_case_rejects_non_mapping_packet() -> None:
    with pytest.raises(SuiteConfigError, match="packet 1 is not a mapping"):
        build_case(_minimal_case(packets=["tcp/80"]), 0)


def test_build_case_invalid_packet_is_a_config_error_not_a_traceback() -> None:
    """PacketSpec construction used to sit outside the try/except."""
    case = _minimal_case(packets=[{"protocol": "tcp", "src_ip": "not-an-ip"}])
    with pytest.raises(SuiteConfigError, match="is invalid"):
        build_case(case, 0)


def test_build_case_invalid_request_is_a_config_error() -> None:
    with pytest.raises(SuiteConfigError, match="invalid test request"):
        build_case(_minimal_case(rules=""), 0)


def test_build_case_uses_positional_default_name() -> None:
    case = {"rules": "x", "packets": [{"protocol": "tcp"}]}
    name, _, _ = build_case(case, 4)
    assert name == "Test case 5"


# ---------------------------------------------------------------------------
# load_suite
# ---------------------------------------------------------------------------


def test_load_suite_reads_yaml(tmp_path: Path) -> None:
    path = tmp_path / "suite.yaml"
    path.write_text("tests:\n  - name: a\n    packets: []\n")
    assert load_suite(str(path)) == [{"name": "a", "packets": []}]


def test_load_suite_reads_json(tmp_path: Path) -> None:
    path = tmp_path / "suite.json"
    path.write_text(json.dumps({"tests": [{"name": "a"}]}))
    assert load_suite(str(path)) == [{"name": "a"}]


def test_load_suite_rejects_missing_tests_key(tmp_path: Path) -> None:
    path = tmp_path / "suite.yaml"
    path.write_text("other: 1\n")
    with pytest.raises(SuiteConfigError, match="no test cases"):
        load_suite(str(path))


def test_load_suite_rejects_non_mapping(tmp_path: Path) -> None:
    path = tmp_path / "suite.yaml"
    path.write_text("- a\n- b\n")
    with pytest.raises(SuiteConfigError, match="must contain a mapping"):
        load_suite(str(path))


def test_load_suite_rejects_non_list_tests(tmp_path: Path) -> None:
    path = tmp_path / "suite.yaml"
    path.write_text("tests: notalist\n")
    with pytest.raises(SuiteConfigError, match="must be a list"):
        load_suite(str(path))
