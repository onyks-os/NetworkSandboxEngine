"""The examples in examples/ are run, not just shipped.

Without privileges: every suite is valid and declares what it expects, and
every script documents its expected output and needs nothing but NSE.
With root: every example runs as its own process in a clean environment, must
exit 0, and must leave the artifacts it promises. The intentionally broken
examples exit 0 only when they fail for the reason they exist to show.
"""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from nse.cli.runner import build_case

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
SUITES = sorted(EXAMPLES.glob("*.yaml"))
SCRIPTS = sorted(EXAMPLES.glob("*.py"))

#: Artifacts each script promises in its --out directory.
ARTIFACTS = {
    "real_application.py": ["wire.pcap", "capture.json", "server.json"],
    "broken_policy.py": ["experiment.json"],
    "broken_observer.py": [
        "blind-experiment.json",
        "capture-wrong-interface.json",
        "capture-right-interface.json",
    ],
}


def test_every_example_is_known() -> None:
    assert {path.name for path in SCRIPTS} == set(ARTIFACTS)
    assert {path.stem for path in SUITES} == {"workstation", "ipv6", "coexistence", "gateway_nat"}


@pytest.mark.parametrize("suite", SUITES, ids=lambda path: path.name)
def test_suites_are_valid_and_declare_their_expectations(suite: Path) -> None:
    text = suite.read_text()
    assert "Expected:" in text, "say what a correct run prints"
    cases = yaml.safe_load(text)["tests"]
    for index, raw in enumerate(cases):
        _, request, expected = build_case(raw, index)
        assert len(expected) == len(request.packets)
        assert all("expected_verdict" in packet for packet in raw["packets"])


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda path: path.name)
def test_scripts_document_their_outcome_and_need_only_nse(script: Path) -> None:
    tree = ast.parse(script.read_text())
    docstring = ast.get_docstring(tree) or ""
    assert "Expected:" in docstring
    assert "Run::" in docstring
    imported = {
        (node.module or "").split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    } | {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    third_party = imported - set(sys.stdlib_module_names) - {"__future__"}
    assert third_party <= {"nse", "scapy"}, third_party  # scapy is an NSE dependency


# --------------------------------------------------------------------------- running them

needs_root = pytest.mark.skipif(os.geteuid() != 0, reason="examples need root and real namespaces")


def _clean_env() -> dict[str, str]:
    """Only what a user's shell would provide: no test fixtures, no overrides."""
    return {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "HOME": "/root"}


def _run(argv: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv, cwd=cwd, env=_clean_env(), capture_output=True, text=True, timeout=600, check=False
    )


@pytest.mark.integration
@needs_root
@pytest.mark.parametrize("suite", SUITES, ids=lambda path: path.name)
def test_suite_example_passes(suite: Path, tmp_path: Path) -> None:
    out = tmp_path / "report"
    done = _run(
        [sys.executable, "-m", "nse.cli.runner", "--file", str(suite), "--report-dir", str(out)],
        tmp_path,
    )
    assert done.returncode == 0, done.stdout + done.stderr
    report = json.loads((out / "report.json").read_text())
    assert {case["status"] for case in report["cases"]} == {"passed"}
    for case in report["cases"]:
        experiment = case["experiment"]
        assert experiment["result"]["oracle"]["readiness"] == "observed"
        assert experiment["result"]["teardown_complete"]
    assert (out / "manifest.json").exists()


@pytest.mark.integration
@needs_root
@pytest.mark.parametrize("script", SCRIPTS, ids=lambda path: path.name)
def test_script_example_ends_as_documented(script: Path, tmp_path: Path) -> None:
    out = tmp_path / "out"
    done = _run([sys.executable, str(script), "--out", str(out)], tmp_path)
    assert done.returncode == 0, done.stdout + done.stderr
    if script.name.startswith("broken_"):
        assert done.stdout.count("FAILED AS EXPECTED") == (2 if "observer" in script.name else 1)
    else:
        assert "[FAIL]" not in done.stdout
        assert "All checks passed." in done.stdout
    for artifact in ARTIFACTS[script.name]:
        path = out / artifact
        assert path.stat().st_size > 0, artifact
        if path.suffix == ".json":
            json.loads(path.read_text())
