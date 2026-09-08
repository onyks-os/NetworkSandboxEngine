# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""Network Sandbox Engine: deterministic nftables testing in ephemeral netns."""

from importlib.metadata import PackageNotFoundError, version as _version

from .core.netns_controller import NetnsController
from .core.sniffer import PCAPAsserter

try:
    # Read the version from installed metadata rather than restating it here.
    # A hardcoded literal drifts from pyproject.toml silently: this constant
    # still said 2.0.0 while the package was being built as 2.1.0.
    __version__ = _version("network-sandbox-engine")
except PackageNotFoundError:  # pragma: no cover - running from a bare checkout
    __version__ = "0.0.0.dev0"

__all__ = ["NetnsController", "PCAPAsserter", "__version__"]
