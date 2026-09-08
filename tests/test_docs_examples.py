# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""
Every YAML suite in the documentation must be valid.

This exists because the README and the tutorials documented a schema the runner
never accepted: a case-level `expected_verdicts:` list and a `mock_listeners:`
key. Nobody noticed, because nothing executed the examples. Now the parser that
users' suites go through is the parser the docs go through.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from nse.cli.runner import build_case

# pyyaml is a dev dependency, but a checkout installed with only the base
# package cannot parse the examples. Skip rather than fail to import: a
# collection error hides every other test in the run.
yaml = pytest.importorskip("yaml", reason="pyyaml is required to validate the documented suites")

REPO_ROOT = Path(__file__).resolve().parent.parent
DOC_FILES = sorted([REPO_ROOT / "README.md", *(REPO_ROOT / "docs").rglob("*.md")])

#: ```yaml fenced blocks
_YAML_BLOCK = re.compile(r"```yaml\n(.*?)```", re.DOTALL)


def _suite_blocks() -> list[tuple[str, int, str]]:
    """Every fenced YAML block in the docs that looks like an NSE test suite."""
    found: list[tuple[str, int, str]] = []
    for path in DOC_FILES:
        text = path.read_text(encoding="utf-8")
        for match in _YAML_BLOCK.finditer(text):
            block = match.group(1)
            if "tests:" not in block or "packets:" not in block:
                continue  # a CI workflow or some other YAML, not a suite
            line_no = text[: match.start()].count("\n") + 1
            found.append((str(path.relative_to(REPO_ROOT)), line_no, block))
    return found


SUITE_BLOCKS = _suite_blocks()


def test_the_docs_contain_suite_examples() -> None:
    """If the extraction stops matching, this file silently tests nothing."""
    assert SUITE_BLOCKS, "no YAML suite examples found in the documentation"


@pytest.mark.parametrize(
    ("source", "line_no", "block"),
    SUITE_BLOCKS,
    ids=[f"{s}:{n}" for s, n, _ in SUITE_BLOCKS],
)
def test_documented_suites_are_valid(source: str, line_no: int, block: str) -> None:
    data = yaml.safe_load(block)
    assert isinstance(data, dict), f"{source}:{line_no}: suite is not a mapping"
    cases = data.get("tests")
    assert cases, f"{source}:{line_no}: suite has no test cases"

    for index, raw in enumerate(cases):
        # build_case raises SuiteConfigError on anything the runner would reject,
        # which is exactly the failure a reader would hit copying this block.
        name, request, expected = build_case(raw, index)
        assert len(expected) == len(request.packets), (
            f"{source}:{line_no}: case {name!r} expects {len(expected)} verdicts "
            f"for {len(request.packets)} packets"
        )
