# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""
Golden-file testing for nft monitor trace parser.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nse.core.trace_harvester import _parse_line

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "nft_trace"


def get_fixture_files() -> list[Path]:
    return list(FIXTURE_DIR.glob("*.log"))


@pytest.mark.parametrize("log_file", get_fixture_files(), ids=lambda p: p.name)
def test_trace_parser_golden_files(log_file: Path) -> None:
    expected_file = log_file.with_suffix(".expected.json")
    assert expected_file.exists(), f"Missing expected fixture file: {expected_file}"

    with expected_file.open("r", encoding="utf-8") as f:
        expected_data = json.load(f)

    events = []
    with log_file.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            evt = _parse_line(line)
            if evt is not None:
                events.append(evt)

    assert len(events) == len(expected_data), (
        f"Event count mismatch for {log_file.name}: expected {len(expected_data)}, got {len(events)}"
    )

    for idx, (evt, exp) in enumerate(zip(events, expected_data, strict=False)):
        for key, val in exp.items():
            actual_val = getattr(evt, key)
            assert actual_val == val, (
                f"Mismatch in {log_file.name} event {idx} [{key}]: expected {val!r}, got {actual_val!r}"
            )
