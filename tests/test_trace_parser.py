# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""
Golden-file tests for the `nft monitor trace` parser.

The parser is the narrowest point of the whole oracle: everything downstream
reasons about TraceEvents, and a line the parser does not understand disappears.
It has already broken once across nftables versions, so it is pinned by a corpus
rather than by a single example.

Two guards beyond the golden files themselves:

* an empty corpus is a hard failure. `parametrize` over an empty glob collects
  zero tests and reports success, so deleting the fixtures used to delete the
  parser's coverage without turning anything red;
* every line of every fixture must parse. A fixture whose lines are silently
  skipped would pin nothing.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nse.core.trace_harvester import _parse_line, _unquote

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "nft_trace"

#: Fixtures below this many files mean somebody deleted the corpus.
MIN_FIXTURES = 5


def get_fixture_files() -> list[Path]:
    return sorted(FIXTURE_DIR.glob("*.log"))


def test_corpus_is_not_empty() -> None:
    """
    Without this, `parametrize([])` collects nothing and the suite is green with
    the parser entirely untested.
    """
    files = get_fixture_files()
    assert len(files) >= MIN_FIXTURES, (
        f"expected at least {MIN_FIXTURES} trace fixtures in {FIXTURE_DIR}, found "
        f"{[f.name for f in files]}. See that directory's README before shrinking it."
    )


@pytest.mark.parametrize("log_file", get_fixture_files(), ids=lambda p: p.name)
def test_trace_parser_golden_files(log_file: Path) -> None:
    expected_file = log_file.with_suffix(".expected.json")
    assert expected_file.exists(), f"Missing expected fixture file: {expected_file}"

    with expected_file.open("r", encoding="utf-8") as f:
        expected_data = json.load(f)

    events = []
    unparsed: list[str] = []
    with log_file.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            evt = _parse_line(line)
            if evt is None:
                unparsed.append(line)
            else:
                events.append(evt)

    assert not unparsed, (
        f"{log_file.name}: the parser did not understand {len(unparsed)} line(s), which "
        f"means they would vanish from a real run: {unparsed}"
    )
    assert len(events) == len(expected_data), (
        f"Event count mismatch for {log_file.name}: expected {len(expected_data)}, got {len(events)}"
    )

    # strict=True: the lengths are asserted above, so a mismatch here would be a
    # bug in this test rather than a silently shortened comparison.
    for idx, (evt, exp) in enumerate(zip(events, expected_data, strict=True)):
        for key, val in exp.items():
            actual_val = getattr(evt, key)
            assert actual_val == val, (
                f"Mismatch in {log_file.name} event {idx} [{key}]: expected {val!r}, got {actual_val!r}"
            )


@pytest.mark.parametrize("log_file", get_fixture_files(), ids=lambda p: p.name)
def test_every_fixture_has_expectations(log_file: Path) -> None:
    """A `.log` with no `.expected.json` would be a fixture that asserts nothing."""
    expected_file = log_file.with_suffix(".expected.json")
    assert expected_file.exists()
    data = json.loads(expected_file.read_text())
    assert isinstance(data, list)
    assert data, f"{expected_file.name} is empty"


# ---------------------------------------------------------------------------
# Format variants, asserted directly
# ---------------------------------------------------------------------------


def test_parse_hyphenated_and_dotted_identifiers() -> None:
    r"""`\w+` silently failed on any table name containing '-' or '.'."""
    evt = _parse_line("trace id aa11 inet my-table.v2 fwd-chain packet: iif eth0")
    assert evt is not None
    assert (evt.table, evt.chain, evt.hook) == ("my-table.v2", "fwd-chain", "eth0")


def test_parse_quoted_identifiers_with_spaces() -> None:
    evt = _parse_line('trace id aa11 inet "my table" "in chain" verdict drop')
    assert evt is not None
    assert (evt.table, evt.chain, evt.verdict) == ("my table", "in chain", "DROP")


def test_parse_unquoted_iif() -> None:
    """The variant that broke across kernel versions and was fixed in 1.1.1."""
    evt = _parse_line("trace id aa11 ip filter input packet: iif veth0")
    assert evt is not None
    assert evt.hook == "veth0"


def test_parse_quoted_iif() -> None:
    evt = _parse_line('trace id aa11 ip filter input packet: iif "veth0"')
    assert evt is not None
    assert evt.hook == "veth0"


def test_parse_packet_line_without_iif() -> None:
    evt = _parse_line("trace id aa11 ip filter output packet: oif eth0")
    assert evt is not None
    assert evt.type == "hook"
    assert evt.hook == ""


def test_parse_rule_verdict_is_upper_cased() -> None:
    evt = _parse_line(
        "trace id aa11 ip filter input rule 0x4 (handle 3) tcp dport 80 accept (verdict accept)"
    )
    assert evt is not None
    assert evt.verdict == "ACCEPT"
    assert evt.rule_handle == 3


def test_parse_rule_without_handle() -> None:
    evt = _parse_line("trace id aa11 ip filter input rule tcp dport 80 accept")
    assert evt is not None
    assert evt.rule_handle is None
    assert evt.rule_text is not None
    assert evt.rule_text.startswith("tcp dport 80")


def test_parse_rule_without_verdict_keeps_verdict_none() -> None:
    evt = _parse_line("trace id aa11 ip nat postrouting rule 0x7 (handle 11) masquerade")
    assert evt is not None
    assert evt.verdict is None


def test_parse_policy_line() -> None:
    evt = _parse_line("trace id aa11 ip filter input policy drop")
    assert evt is not None
    assert evt.verdict == "DROP"
    assert evt.type == "verdict"


def test_parse_verdict_continue() -> None:
    evt = _parse_line("trace id aa11 inet nse_trace nse_trace_prerouting verdict continue")
    assert evt is not None
    assert evt.verdict == "CONTINUE"


def test_parse_uppercase_trace_id() -> None:
    evt = _parse_line("trace id AB12CD34 ip filter input verdict accept")
    assert evt is not None
    assert evt.trace_id == "AB12CD34"


@pytest.mark.parametrize(
    "line",
    [
        "this is not a trace line",
        "",
        "trace id",
        "warning: nftables is deprecated in this universe",
    ],
)
def test_parse_returns_none_for_non_trace_lines(line: str) -> None:
    assert _parse_line(line) is None


def test_unquote_helper() -> None:
    assert _unquote('"x"') == "x"
    assert _unquote("x") == "x"
    assert _unquote(None) is None
    assert _unquote('"') == '"'
    assert _unquote('""') == ""
