# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""
YAML/JSON test-suite runner for NSE.

This module decides PASS/FAIL for everyone who wires NSE into CI, so its one
hard requirement is that it must never report success from an absence of
evidence. The previous implementation did exactly that: the count-mismatch
branch printed ``[FAIL] Oracle Error`` without setting the failure flag, and
``zip(..., strict=False)`` truncated the comparison, so a run that observed zero
verdicts printed ``=> SUCCESS`` and exited 0.

The logic is split into pure functions (:func:`reduce_verdicts`,
:func:`build_case`, :func:`evaluate_case`) that take data and return data, and a
thin :func:`main` that does I/O. The pure half is unit-tested without root; the
I/O half has nothing left to get wrong.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

try:
    import yaml
except ImportError:
    yaml = None

from pydantic import ValidationError

from nse.core.netns_controller import NetnsController
from nse.core.pipeline import run_test_pipeline_report
from nse.core.verdicts import reduce_verdicts
from nse.models.artifacts import ArtifactEntry, artifact_entry, write_text_atomic
from nse.models.experiment_report import ExperimentReport
from nse.models.network_config import GatewayNetwork, SimpleNetwork
from nse.models.test_request import PacketSpec, TestRequest, TopologyType
from nse.models.trace_event import TraceEvent

#: Keys a packet entry in a suite file may carry. Anything else is a typo, and a
#: typo used to be silently absorbed into an implicit "expected: ACCEPT".
_PACKET_KEYS = frozenset(
    {
        "expected_verdict",
        "protocol",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "tcp_flags",
    }
)
_CASE_KEYS = frozenset({"name", "topology", "rules", "packets", "network"})
_VALID_VERDICTS = frozenset({"ACCEPT", "DROP", "REJECT"})


class SuiteConfigError(Exception):
    """The suite file is malformed. Distinct from a test that legitimately fails."""


#: What a case ended as, in the JSON report. Every way of not passing is distinct.
CaseStatus = Literal[
    "passed",
    "failed",  # the ruleset gave other verdicts than expected
    "instrument_error",  # the oracle could not observe, or observed the wrong count
    "rules_invalid",
    "setup_error",
    "timeout",
    "teardown_incomplete",  # the verdicts were right, but the run did not clean up
    "invalid_case",  # the suite entry itself is malformed
    "crashed",  # the pipeline raised instead of reporting
]

#: Line labels for outcomes the pipeline reports as error events.
_ERROR_LABELS = {
    "rules_invalid": "[RULES ERROR]",
    "setup_error": "[SETUP ERROR]",
    "timeout": "[TIMEOUT]",
}


@dataclass
class CaseOutcome:
    """The result of evaluating one test case."""

    name: str
    passed: bool
    #: True when the failure is the *instrument's* fault, not the ruleset's.
    oracle_error: bool = False
    lines: list[str] = field(default_factory=list)
    status: CaseStatus | None = None
    #: True when teardown failed or left resources of the run behind.
    teardown_error: bool = False


@dataclass
class SuiteOutcome:
    """Aggregate result of a whole suite."""

    passed: int = 0
    failed: int = 0
    oracle_errors: int = 0
    teardown_errors: int = 0

    @property
    def exit_code(self) -> int:
        return 1 if (self.failed or self.oracle_errors or self.teardown_errors) else 0

    def record(self, outcome: CaseOutcome) -> None:
        if outcome.passed:
            self.passed += 1
        else:
            self.failed += 1
            if outcome.oracle_error:
                self.oracle_errors += 1
        if outcome.teardown_error:
            self.teardown_errors += 1


# ---------------------------------------------------------------------------
# Pure logic
# ---------------------------------------------------------------------------


def collect_oracle_errors(events: Iterable[TraceEvent]) -> list[str]:
    """Return the error messages the pipeline attached to this run."""
    return [
        evt.raw_message or "unspecified pipeline error" for evt in events if evt.type == "error"
    ]


def build_case(raw: dict[str, Any], index: int) -> tuple[str, TestRequest, list[str]]:
    """
    Turn one raw suite entry into (name, request, expected verdicts).

    Raises:
        SuiteConfigError: if the entry is malformed. Every malformed entry is a
            hard error: silently defaulting an unrecognised key is how a typo
            becomes an assertion nobody wrote.
    """
    if not isinstance(raw, dict):
        raise SuiteConfigError(f"test case {index + 1} is not a mapping")

    name = str(raw.get("name", f"Test case {index + 1}"))

    unknown = set(raw) - _CASE_KEYS
    if unknown:
        raise SuiteConfigError(
            f"{name}: unknown key(s) {sorted(unknown)}; expected {sorted(_CASE_KEYS)}"
        )

    topology_str = str(raw.get("topology", "simple")).lower()
    if topology_str not in ("simple", "gateway"):
        raise SuiteConfigError(f"{name}: unknown topology {topology_str!r} (simple|gateway)")
    topology = TopologyType.GATEWAY if topology_str == "gateway" else TopologyType.SIMPLE
    try:
        network = (
            GatewayNetwork if topology == TopologyType.GATEWAY else SimpleNetwork
        ).model_validate(raw.get("network") if raw.get("network") is not None else {})
    except ValidationError as exc:
        raise SuiteConfigError(f"{name}: invalid network configuration:\n{exc}") from exc

    packets_data = raw.get("packets") or []
    if not packets_data:
        raise SuiteConfigError(f"{name}: no packets defined")

    packets: list[PacketSpec] = []
    expected: list[str] = []

    for pkt_index, entry in enumerate(packets_data, start=1):
        if not isinstance(entry, dict):
            raise SuiteConfigError(f"{name}: packet {pkt_index} is not a mapping")
        unknown_pkt = set(entry) - _PACKET_KEYS
        if unknown_pkt:
            raise SuiteConfigError(
                f"{name}: packet {pkt_index} has unknown key(s) {sorted(unknown_pkt)}; "
                f"expected {sorted(_PACKET_KEYS)}"
            )

        verdict = str(entry.get("expected_verdict", "ACCEPT")).upper()
        if verdict not in _VALID_VERDICTS:
            raise SuiteConfigError(
                f"{name}: packet {pkt_index} expects unknown verdict {verdict!r}; "
                f"expected one of {sorted(_VALID_VERDICTS)}"
            )
        # REJECT and DROP are indistinguishable in the reduced stream: both mean
        # the packet did not get through. Normalise so the comparison is honest
        # about what the oracle can actually tell apart.
        expected.append("DROP" if verdict == "REJECT" else verdict)

        default_src = network.host_v4.split("/")[0]
        default_dst = (
            network.server_v4 if isinstance(network, GatewayNetwork) else network.peer_v4
        ).split("/")[0]
        try:
            packets.append(
                PacketSpec(
                    protocol=entry.get("protocol", "tcp"),
                    src_ip=entry.get("src_ip", default_src),
                    dst_ip=entry.get("dst_ip", default_dst),
                    src_port=entry.get("src_port"),
                    dst_port=entry.get("dst_port"),
                    tcp_flags=entry.get("tcp_flags", []),
                )
            )
        except ValidationError as exc:
            raise SuiteConfigError(f"{name}: packet {pkt_index} is invalid:\n{exc}") from exc

    try:
        request = TestRequest(
            rules=raw.get("rules", ""),
            packets=packets,
            topology=topology,
            network=raw.get("network"),
        )
    except ValidationError as exc:
        raise SuiteConfigError(f"{name}: invalid test request:\n{exc}") from exc

    return name, request, expected


def evaluate_case(name: str, expected: Sequence[str], events: Iterable[TraceEvent]) -> CaseOutcome:
    """
    Compare the expected verdicts with what the oracle actually observed.

    Three outcomes, kept distinct on purpose:

    * the pipeline reported an oracle error → failure, blamed on the instrument;
    * the observed verdict count differs from the expected count → failure,
      blamed on the instrument, because a missing verdict is missing evidence
      and not a passing test;
    * counts match → per-packet comparison.
    """
    events = list(events)
    errors = collect_oracle_errors(events)
    if errors:
        return CaseOutcome(
            name=name,
            passed=False,
            oracle_error=True,
            lines=[f"  [ORACLE ERROR] {message}" for message in errors],
        )

    observed = reduce_verdicts(events)
    if len(observed) != len(expected):
        return CaseOutcome(
            name=name,
            passed=False,
            oracle_error=True,
            lines=[
                f"  [ORACLE ERROR] expected {len(expected)} verdict(s), observed "
                f"{len(observed)}: {observed}. A verdict that was not observed is "
                f"missing evidence, not a pass."
            ],
        )

    lines: list[str] = []
    passed = True
    for idx, (exp, act) in enumerate(zip(expected, observed, strict=True), start=1):
        if exp == act:
            lines.append(f"  [OK] Packet {idx}: expected {exp}, got {act}")
        else:
            lines.append(f"  [FAIL] Packet {idx}: expected {exp}, got {act}")
            passed = False

    return CaseOutcome(name=name, passed=passed, lines=lines)


# ---------------------------------------------------------------------------
# I/O
# ---------------------------------------------------------------------------


def check_cli_dependencies() -> None:
    """Verify that CLI extras are installed."""
    if yaml is None:
        print("[FATAL ERROR] Missing dependencies for CLI runner.", file=sys.stderr)
        print("To use the YAML test runner, install the CLI extras:", file=sys.stderr)
        print("    pip install 'network-sandbox-engine[cli]'", file=sys.stderr)
        sys.exit(1)


def load_suite(path: str) -> list[dict[str, Any]]:
    """Read a suite file and return its test-case list."""
    with open(path) as handle:
        if path.endswith(".json"):
            import json

            data = json.load(handle)
        else:
            data = yaml.safe_load(handle)

    if not isinstance(data, dict):
        raise SuiteConfigError("suite file must contain a mapping with a 'tests' key")
    cases = data.get("tests")
    if not cases:
        raise SuiteConfigError("suite file contains no test cases under 'tests'")
    if not isinstance(cases, list):
        raise SuiteConfigError("'tests' must be a list of test cases")
    return cases


def case_status(outcome: CaseOutcome, report: ExperimentReport) -> CaseStatus:
    """Classify a finished case: the experiment's own outcome first, then the verdicts."""
    engine = report.result.outcome
    if engine == "timeout":
        return "timeout"
    if engine == "rules_invalid":
        return "rules_invalid"
    if engine == "setup_failure":
        return "setup_error"
    if engine != "completed" or outcome.oracle_error:
        return "instrument_error"
    if not outcome.passed:
        return "failed"
    if not report.result.teardown_complete:
        return "teardown_incomplete"
    return "passed"


def _judge(name: str, expected: list[str], report: ExperimentReport) -> CaseOutcome:
    result = evaluate_case(name, expected, report.observations.events)
    status = case_status(result, report)  # before teardown can turn a pass into a failure
    if not report.result.teardown_complete:
        # The verdicts may be right, but resources of the run are still on the
        # host (or teardown raised): that must fail the run, not pass silently.
        result.passed = False
        result.teardown_error = True
        problems = [e.message for e in report.result.errors if e.stage == "teardown"]
        problems += [f"left behind: {item}" for item in report.result.residual_resources]
        result.lines += [f"  [TEARDOWN ERROR] {problem}" for problem in problems]
    label = _ERROR_LABELS.get(status)
    if label:
        result.lines = [line.replace("[ORACLE ERROR]", label, 1) for line in result.lines]
    result.status = status
    return result


def run_suite(
    cases: list[dict[str, Any]],
    controller: NetnsController,
    *,
    timeout: float | None = None,
    records: list[dict[str, Any]] | None = None,
) -> SuiteOutcome:
    """Execute every case and return the aggregate outcome.

    *timeout* bounds each case. When *records* is given, one JSON-ready record
    per case (with its full experiment report) is appended as the case ends, so
    an interrupted suite still has every finished case on record.
    """
    outcome = SuiteOutcome()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        for index, raw in enumerate(cases):
            report: ExperimentReport | None = None
            expected: list[str] = []
            try:
                name, request, expected = build_case(raw, index)
            except SuiteConfigError as exc:
                print(f"Running test: (case {index + 1})...")
                result = CaseOutcome(
                    name=f"case {index + 1}",
                    passed=False,
                    lines=[f"  [FAIL] Invalid suite entry: {exc}"],
                    status="invalid_case",
                )
            else:
                print(f"Running test: {name}...")
                try:
                    report = loop.run_until_complete(
                        run_test_pipeline_report(
                            request=request, controller=controller, timeout=timeout
                        )
                    )
                except (RuntimeError, OSError, ValueError) as exc:
                    result = CaseOutcome(
                        name=name,
                        passed=False,
                        oracle_error=True,
                        lines=[f"  [ORACLE ERROR] Pipeline crashed: {exc}"],
                        status="crashed",
                    )
                else:
                    result = _judge(name, expected, report)

            _report(result)
            outcome.record(result)
            if records is not None:
                records.append(_case_record(index, result, expected, report))
    finally:
        loop.close()
    return outcome


# ---------------------------------------------------------------------------
# JSON report
# ---------------------------------------------------------------------------

SUITE_SCHEMA = "nse.suite-report"
MANIFEST_SCHEMA = "nse.artifact-manifest"
REPORT_SCHEMA_VERSION = 1


def _case_record(
    index: int, outcome: CaseOutcome, expected: list[str], report: ExperimentReport | None
) -> dict[str, Any]:
    return {
        "index": index,
        "name": outcome.name,
        "status": outcome.status,
        "passed": outcome.passed,
        "expected": expected,
        "observed": None if report is None else report.result.verdicts,
        "teardown_complete": None if report is None else report.result.teardown_complete,
        "lines": outcome.lines,
        "experiment": None if report is None else report.model_dump(mode="json", by_alias=True),
    }


def _suite_entry(path: str) -> dict[str, Any] | None:
    try:
        return artifact_entry(path).model_dump(mode="json")
    except OSError:
        return None


def write_reports(
    directory: str | os.PathLike[str],
    *,
    suite_path: str,
    records: list[dict[str, Any]],
    outcome: SuiteOutcome | None,
    error: str | None = None,
) -> list[ArtifactEntry]:
    """Write ``report.json`` then ``manifest.json`` into *directory*, atomically.

    Called on every exit, including an unreadable suite or an interruption, so a
    failed run still leaves its evidence. The manifest lists the report and every
    artifact the experiments recorded, each with its SHA-256.
    """
    target = Path(directory)
    summary = (
        None
        if outcome is None
        else {
            "passed": outcome.passed,
            "failed": outcome.failed,
            "oracle_errors": outcome.oracle_errors,
            "teardown_errors": outcome.teardown_errors,
            "exit_code": outcome.exit_code,
        }
    )
    report = {
        "schema": SUITE_SCHEMA,
        "schema_version": REPORT_SCHEMA_VERSION,
        "suite": {"path": os.path.abspath(suite_path), "file": _suite_entry(suite_path)},
        "summary": summary,
        "error": error,
        "cases": records,
    }
    text = json.dumps(report, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    written = write_text_atomic(target / "report.json", text)
    entries = [written]
    for record in records:
        for artifact in (record.get("experiment") or {}).get("artifacts", []):
            entries.append(ArtifactEntry.model_validate(artifact))
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "schema_version": REPORT_SCHEMA_VERSION,
        "artifacts": [entry.model_dump(mode="json") for entry in entries],
    }
    write_text_atomic(
        target / "manifest.json",
        json.dumps(manifest, sort_keys=True, indent=2, ensure_ascii=False) + "\n",
    )
    return entries


def _report(outcome: CaseOutcome) -> None:
    for line in outcome.lines:
        print(line)
    print(f"  => {'SUCCESS' if outcome.passed else 'FAILURE'}: {outcome.name}")


def main() -> None:
    check_cli_dependencies()
    import logging

    parser = argparse.ArgumentParser(
        prog="nse-runner",
        description="Network Sandbox Engine YAML/JSON test runner",
    )
    parser.add_argument(
        "--file",
        required=True,
        help="Path to the test suite YAML or JSON file",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable debug logging from the engine",
    )
    parser.add_argument(
        "--report-dir",
        metavar="DIR",
        help="Write report.json (every case with its full experiment report) and "
        "manifest.json (SHA-256 of each artifact) into DIR, also when the run fails",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        metavar="SECONDS",
        help="Stop and fail a case that runs longer than this (default: no limit)",
    )
    args = parser.parse_args()
    if args.timeout is not None and not args.timeout > 0:
        parser.error("--timeout must be a positive number of seconds")

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        force=True,
    )
    records: list[dict[str, Any]] = []

    def save(outcome: SuiteOutcome | None, error: str | None = None) -> None:
        if args.report_dir is None:
            return
        try:
            write_reports(
                args.report_dir,
                suite_path=args.file,
                records=records,
                outcome=outcome,
                error=error,
            )
        except OSError as exc:
            print(f"Error writing the report to {args.report_dir}: {exc}", file=sys.stderr)
            sys.exit(1)  # a report that was asked for and is missing is a failure
        print(f"[NSE] Report written to {args.report_dir}")

    print(f"[NSE] Loading test suite from: {args.file}")
    try:
        cases = load_suite(args.file)
    except (SuiteConfigError, OSError, ValueError) as exc:
        print(f"Error reading test suite file: {exc}", file=sys.stderr)
        save(None, f"cannot read the suite: {exc}")
        sys.exit(1)

    print(f"Found {len(cases)} test cases.")
    print("-" * 60)

    try:
        outcome = run_suite(cases, NetnsController(), timeout=args.timeout, records=records)
    except BaseException as exc:
        save(None, f"interrupted: {type(exc).__name__}: {exc}")
        raise

    print("-" * 60)
    print(f"Test Suite Summary: {outcome.passed} passed, {outcome.failed} failed.")
    if outcome.oracle_errors:
        print(
            f"{outcome.oracle_errors} of the failures are ORACLE errors: the engine "
            f"could not observe what it needed to. Treat these as a broken "
            f"measurement, not as a firewall defect."
        )
    if outcome.teardown_errors:
        print(
            f"{outcome.teardown_errors} case(s) did not clean up completely. Resources "
            f"of the run may remain on this host; see the [TEARDOWN ERROR] lines."
        )
    save(outcome)
    sys.exit(outcome.exit_code)


if __name__ == "__main__":
    main()
