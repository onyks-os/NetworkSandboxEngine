# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""Programs NSE runs *inside* a namespace, as the identity under test.

Each module here is a self-contained script: standard library only, no import
of ``nse``. NSE passes its source to an interpreter with ``python -I -c``, so it
runs with whatever UID, GID and capabilities the caller asked for, without the
package (or a virtual environment) having to be readable by that identity.
"""

from __future__ import annotations

from importlib import resources


def source(name: str) -> str:
    """The source of agent *name*, to be run with ``python -I -c``."""
    return resources.files(__name__).joinpath(f"{name}.py").read_text(encoding="utf-8")
