"""The 2.1.2 API keeps working: every recorded name, method and parameter.

``tests/data/api-2.1.2.json`` is the surface of the v2.1.2 tag, recorded with
``scripts/api_surface.py dump``. The same checker runs against the installed
wheel and sdist in ``scripts/check-dist.sh``. The tests at the bottom prove the
checker would notice each kind of break, so a green result is not vacuous.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import textwrap
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parent.parent
SNAPSHOT = ROOT / "tests" / "data" / "api-2.1.2.json"


def _load_checker() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "api_surface", ROOT / "scripts" / "api_surface.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("api_surface", module)
    spec.loader.exec_module(module)
    return module


api = _load_checker()


def test_the_checkout_keeps_the_2_1_2_api() -> None:
    old = json.loads(SNAPSHOT.read_text())
    assert api.compare(old, api.surface(ROOT)) == []


def test_every_2_1_2_name_is_importable() -> None:
    assert api.import_check(json.loads(SNAPSHOT.read_text())) == []


def test_the_snapshot_covers_what_ttp_uses() -> None:
    old = json.loads(SNAPSHOT.read_text())
    assert {"NetnsController", "PCAPAsserter"} <= set(old["nse"])
    assert "start_mock_listener" in old["nse.core.mock_listener"]
    assert "_get_mac_address" in old["nse.core.scapy_injector"]
    assert {"arm_event_signal", "wait_for_event", "aclose"} <= set(
        old["nse.core.trace_harvester"]["TraceHarvester"]["methods"]
    )
    sandbox = old["nse.core.netns_controller"]["NamespaceSandbox"]
    assert {"name", "ext_iface", "peer_iface"} <= set(sandbox["attributes"])


def test_main_reports_problems_through_the_exit_code(capsys: pytest.CaptureFixture[str]) -> None:
    assert api.main(["check", str(SNAPSHOT), str(ROOT)]) == 0
    assert "0 problems" in capsys.readouterr().out


# --------------------------------------------------------------------------- the checker itself

BASE = """
from .core import helper as helper

LIMIT = 3

def run(request, controller=None, *, timeout=None) -> list[str]:
    return []

async def start(name, port=0):
    pass

class Box:
    size: int = 0

    def __init__(self, name):
        self.name = name

    @property
    def label(self):
        return self.name

    async def stop(self, timeout=1.0) -> list[str]:
        return []
"""

BREAKS = {
    "module function removed": ("def run(", "def run_renamed("),
    "positional renamed": ("def run(request,", "def run(req,"),
    "default lost": ("controller=None, *", "controller, *"),
    "required positional added": ("def __init__(self, name):", "def __init__(self, name, size):"),
    "required keyword added": ("*, timeout=None)", "*, timeout=None, mode)"),
    "keyword removed": (", *, timeout=None)", ")"),
    "sync became async": ("def run(", "async def run("),
    "async became sync": ("async def start(", "def start("),
    "return type changed": (
        "-> list[str]:\n    return []\n\nasync",
        "-> dict:\n    return {}\n\nasync",
    ),
    "method removed": ("async def stop(", "async def halt("),
    "instance attribute removed": ("self.name = name", "self._name = name"),
    "class attribute removed": ("size: int = 0", "_size: int = 0"),
    "property removed": ("def label(self)", "def _label(self)"),
    "constant removed": ("LIMIT = 3", "_LIMIT = 3"),
    "class became function": ("class Box:", "def Box(): pass\nclass _Box:"),
    "package re-export removed": ("from .core import helper as helper", ""),
}

COMPATIBLE = {
    "unchanged": ("", ""),
    "optional keyword added": ("*, timeout=None)", "*, timeout=None, mode='x')"),
    "optional positional added": ("controller=None, *", "controller=None, retries=0, *"),
    "new method": ("    @property", "    def extra(self):\n        pass\n\n    @property"),
    "attribute became property": (
        "        self.name = name",
        "        self._n = name\n\n    @property\n    def name(self):\n        return self._n",
    ),
}


def _tree(tmp_path: Path, source: str) -> Path:
    package = tmp_path / "nse"
    (package / "core").mkdir(parents=True)
    (package / "core" / "__init__.py").write_text("def helper():\n    pass\n")
    (package / "__init__.py").write_text(textwrap.dedent(source))
    return tmp_path


def _problems(tmp_path: Path, old: str, new: str) -> list[str]:
    before = api.surface(_tree(tmp_path / "old", BASE))
    after = api.surface(_tree(tmp_path / "new", BASE.replace(old, new, 1)))
    assert BASE.replace(old, new, 1) != BASE or old == new
    return list(api.compare(before, after))


@pytest.mark.parametrize("change", BREAKS, ids=list(BREAKS))
def test_the_checker_reports_each_kind_of_break(tmp_path: Path, change: str) -> None:
    assert _problems(tmp_path, *BREAKS[change]), change


@pytest.mark.parametrize("change", COMPATIBLE, ids=list(COMPATIBLE))
def test_the_checker_accepts_compatible_changes(tmp_path: Path, change: str) -> None:
    assert _problems(tmp_path, *COMPATIBLE[change]) == []


def test_a_definition_moved_behind_a_re_export_is_compared_at_its_target(tmp_path: Path) -> None:
    old = _tree(tmp_path / "old", "")
    (old / "nse" / "runner.py").write_text("def reduce(a, b=None):\n    pass\n")
    new = _tree(tmp_path / "new", "")
    (new / "nse" / "verdicts.py").write_text("def reduce(a):\n    pass\n")
    (new / "nse" / "runner.py").write_text("from nse.verdicts import reduce\n")
    assert api.compare(api.surface(old), api.surface(new)) == [
        "nse.runner.reduce: positional parameters ['a', 'b'] -> ['a']",
        "nse.runner.reduce: parameter b removed",
    ]
    (new / "nse" / "runner.py").write_text("from nse.missing import reduce\n")
    assert api.compare(api.surface(old), api.surface(new)) == [
        "nse.runner.reduce: re-exported from nse.missing.reduce, not found"
    ]


def test_an_incidental_import_is_not_part_of_the_api(tmp_path: Path) -> None:
    old = _tree(tmp_path / "old", "")
    (old / "nse" / "pipeline.py").write_text("from nse.core import helper\n")
    new = _tree(tmp_path / "new", "")
    (new / "nse" / "pipeline.py").write_text("")
    assert api.compare(api.surface(old), api.surface(new)) == []


def test_a_removed_module_is_reported(tmp_path: Path) -> None:
    old = _tree(tmp_path / "old", "")
    (old / "nse" / "gone.py").write_text("X = 1\n")
    new = _tree(tmp_path / "new", "")
    assert api.compare(api.surface(old), api.surface(new)) == ["nse.gone: module removed"]
