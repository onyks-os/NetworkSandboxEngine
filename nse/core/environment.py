# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""The software environment of a run, for the experiment report."""

from __future__ import annotations

import platform
import subprocess
from functools import cache
from importlib.metadata import PackageNotFoundError, version

from nse.core.paths import resolve_optional
from nse.core.utils import is_in_container
from nse.models.experiment_report import Environment

#: Python packages whose behaviour shapes a run.
DEPENDENCIES = ("network-sandbox-engine", "scapy", "pydantic", "pydantic-core", "pyyaml")

#: External tools and the argument that prints their version.
TOOLS = {
    "nft": "--version",
    "ip": "-V",
    "nsenter": "--version",
    "setpriv": "--version",
    "conntrack": "--version",
}


def _package_version(name: str) -> str | None:
    try:
        return version(name)
    except PackageNotFoundError:
        return None


@cache
def tool_version(name: str) -> str | None:
    """First line of ``<tool> <flag>``, or None if the tool is absent or silent."""
    try:
        path = resolve_optional(name)
        if path is None:
            return None
        result = subprocess.run(
            [path, TOOLS[name]], capture_output=True, text=True, timeout=5, check=False
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
    output = (result.stdout or result.stderr).strip()
    return output.splitlines()[0] if output else None


def collect_environment(use_nsenter: bool) -> Environment:
    """Describe where this run executes. Nothing is guessed: unknown is ``None``."""
    packages = {name: _package_version(name) for name in DEPENDENCIES}
    return Environment(
        nse=packages.pop("network-sandbox-engine") or "unknown",
        python=platform.python_version(),
        python_implementation=platform.python_implementation(),
        dependencies=packages,
        kernel=platform.release(),
        machine=platform.machine(),
        tools={name: tool_version(name) for name in TOOLS},
        use_nsenter=use_nsenter,
        in_container=is_in_container(),
    )
