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
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

try:
    import yaml
except ImportError:
    yaml = None

from pydantic import ValidationError

from nse.core.netns_controller import NetnsController
from nse.core.pipeline import run_test_pipeline
from nse.models.test_request import PacketSpec, TestRequest, TopologyType
from nse.models.trace_event import TraceEvent

#: Trace events from this table are NSE's own tracing scaffolding, not the
#: ruleset under test.
_SCAFFOLD_TABLE = "nse_trace"

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
_CASE_KEYS = frozenset({"name", "topology", "rules", "packets"})
_VALID_VERDICTS = frozenset({"ACCEPT", "DROP", "REJECT"})


class SuiteConfigError(Exception):
    """The suite file is malformed. Distinct from a test that legitimately fails."""


@dataclass
class CaseOutcome:
    """The result of evaluating one test case."""

    name: str
    passed: bool
    #: True when the failure is the *instrument's* fault, not the ruleset's.
    oracle_error: bool = False
    lines: list[str] = field(default_factory=list)


@dataclass
class SuiteOutcome:
    """Aggregate result of a whole suite."""

    passed: int = 0
    failed: int = 0
    oracle_errors: int = 0

    @property
    def exit_code(self) -> int:
        return 1 if (self.failed or self.oracle_errors) else 0

    def record(self, outcome: CaseOutcome) -> None:
        if outcome.passed:
            self.passed += 1
        else:
            self.failed += 1
            if outcome.oracle_error:
                self.oracle_errors += 1


# ---------------------------------------------------------------------------
# Pure logic
# ---------------------------------------------------------------------------


def collect_oracle_errors(events: Iterable[TraceEvent]) -> list[str]:
    """Return the error messages the pipeline attached to this run."""
    return [
        evt.raw_message or "unspecified pipeline error" for evt in events if evt.type == "error"
    ]


def reduce_verdicts(events: Iterable[TraceEvent]) -> list[str]:
    """
    Reduce a trace event stream to one verdict per observed packet.

    A packet traverses several chains and produces several trace lines under a
    single trace id. DROP and REJECT win over ACCEPT, because a packet that was
    accepted by one chain and dropped by another did not get through.

    Events from the ``nse_trace`` scaffolding table are excluded: they exist only
    to switch kernel tracing on, and counting them would inflate the verdict list
    with results the user never asked for.
    """
    order: list[str] = []
    verdicts: dict[str, list[str]] = {}
    reached_user_ruleset: set[str] = set()

    for evt in events:
        if evt.type == "error" or not evt.trace_id:
            continue
        if evt.trace_id not in verdicts:
            verdicts[evt.trace_id] = []
            order.append(evt.trace_id)
        if evt.table and evt.table != _SCAFFOLD_TABLE:
            reached_user_ruleset.add(evt.trace_id)
            if evt.verdict:
                verdicts[evt.trace_id].append(evt.verdict.upper())

    reduced: list[str] = []
    for trace_id in order:
        if trace_id not in reached_user_ruleset:
            continue
        seen = verdicts[trace_id]
        if any(v in ("DROP", "REJECT") for v in seen):
            reduced.append("DROP")
        elif any(v == "ACCEPT" for v in seen):
            reduced.append("ACCEPT")
        # A trace id that reached the user ruleset without producing any verdict
        # is deliberately *not* recorded: it becomes a count mismatch, which is
        # an oracle error, rather than being quietly rounded to a pass.
    return reduced


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

        default_src = "10.0.1.1" if topology == TopologyType.GATEWAY else "10.0.0.1"
        default_dst = "10.0.2.2" if topology == TopologyType.GATEWAY else "10.0.0.2"
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
        request = TestRequest(rules=raw.get("rules", ""), packets=packets, topology=topology)
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


def run_suite(cases: list[dict[str, Any]], controller: NetnsController) -> SuiteOutcome:
    """Execute every case and return the aggregate outcome."""
    outcome = SuiteOutcome()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        for index, raw in enumerate(cases):
            try:
                name, request, expected = build_case(raw, index)
            except SuiteConfigError as exc:
                print(f"Running test: (case {index + 1})...")
                result = CaseOutcome(
                    name=f"case {index + 1}",
                    passed=False,
                    lines=[f"  [FAIL] Invalid suite entry: {exc}"],
                )
                _report(result)
                outcome.record(result)
                continue

            print(f"Running test: {name}...")
            try:
                events = loop.run_until_complete(
                    run_test_pipeline(request=request, controller=controller)
                )
            except (RuntimeError, OSError, ValueError) as exc:
                result = CaseOutcome(
                    name=name,
                    passed=False,
                    oracle_error=True,
                    lines=[f"  [ORACLE ERROR] Pipeline crashed: {exc}"],
                )
            else:
                result = evaluate_case(name, expected, events)

            _report(result)
            outcome.record(result)
    finally:
        loop.close()
    return outcome


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
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        force=True,
    )

    print(f"[NSE] Loading test suite from: {args.file}")
    try:
        cases = load_suite(args.file)
    except (SuiteConfigError, OSError, ValueError) as exc:
        print(f"Error reading test suite file: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(cases)} test cases.")
    print("-" * 60)

    outcome = run_suite(cases, NetnsController())

    print("-" * 60)
    print(f"Test Suite Summary: {outcome.passed} passed, {outcome.failed} failed.")
    if outcome.oracle_errors:
        print(
            f"{outcome.oracle_errors} of the failures are ORACLE errors: the engine "
            f"could not observe what it needed to. Treat these as a broken "
            f"measurement, not as a firewall defect."
        )
    sys.exit(outcome.exit_code)


if __name__ == "__main__":
    main()
