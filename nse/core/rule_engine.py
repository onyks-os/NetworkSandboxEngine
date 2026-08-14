# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""
RuleEngine: inject and validate nftables rulesets inside a netns.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger("nse.core.rule_engine")

_NFT_ERROR_RE = re.compile(
    r"^(?P<file>[^:]+):(?P<line>\d+):(?P<col_range>[\d-]+):\s*(?P<level>\w+):\s*(?P<msg>.+)$"
)

_TRACE_INIT_RULESET = """
table inet nse_trace {
  chain nse_trace_prerouting {
    type filter hook prerouting priority -300; policy accept;
    meta nftrace set 1
  }
}
"""


@dataclass
class NftError:
    line: int
    column_range: str
    level: str
    message: str


class RuleValidationError(Exception):
    """Raised when `nft -f` rejects the supplied ruleset."""

    def __init__(self, errors: list[dict[str, Any]]) -> None:
        self.errors = errors
        super().__init__(f"nftables validation failed: {errors}")


class RuleEngine:
    """
    Validates and loads nftables rules into a network namespace.
    """

    def __init__(self, use_nsenter: bool = False) -> None:
        self.use_nsenter = use_nsenter

    def exec_prefix(self, name: str) -> list[str]:
        if self.use_nsenter:
            return ["nsenter", f"--net=/var/run/netns/{name}", "--"]
        else:
            return ["ip", "netns", "exec", name]

    def validate(self, rules: str) -> None:
        """
        Dry-run validation using ``nft --check``.
        """
        with _temp_rules_file(rules) as path:
            result = subprocess.run(
                ["nft", "--check", "-f", path],
                capture_output=True,
                text=True,
                check=False,
                timeout=10.0,
            )
            if result.returncode != 0:
                errors = _parse_nft_errors(result.stderr, path)
                raise RuleValidationError(errors)

    def load(self, rules: str, netns_name: str) -> None:
        """
        Write rules to a temp file and load them inside *netns_name*.
        Automatically prepends tracing enablement (meta trace set 1).
        """
        if not netns_name:
            raise ValueError("netns_name must be provided, refusing to inject into init_net.")

        logger.info("Loading rules into netns %s", netns_name)

        full_ruleset = f"{_TRACE_INIT_RULESET}\n{rules}"

        with _temp_rules_file(full_ruleset) as path:
            cmd = [*self.exec_prefix(netns_name), "nft", "-f", path]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=30.0,
            )
            if result.returncode != 0:
                errors = _parse_nft_errors(result.stderr, path)
                raise RuleValidationError(errors)

    def flush(self, netns_name: str) -> None:
        """Remove all nftables rules from a namespace (safe cleanup)."""
        cmd = [*self.exec_prefix(netns_name), "nft", "flush", "ruleset"]
        subprocess.run(
            cmd,
            capture_output=True,
            check=False,
            timeout=10.0,
        )


class _temp_rules_file:
    """Context manager that writes rules to a named temp file."""

    def __init__(self, rules: str) -> None:
        self._rules = rules
        self._path: str | None = None

    def __enter__(self) -> str:
        fd, path = tempfile.mkstemp(prefix="nse_rules_", suffix=".nft")
        self._path = path
        with os.fdopen(fd, "w") as f:
            f.write(self._rules)
        return path

    def __exit__(self, *_: Any) -> None:
        if self._path and os.path.exists(self._path):
            os.unlink(self._path)


def _parse_nft_errors(stderr: str, rules_path: str) -> list[dict[str, Any]]:
    """
    Parse nft stderr into a list of structured error dicts.
    """
    errors: list[dict[str, Any]] = []
    for raw_line in stderr.splitlines():
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        m = _NFT_ERROR_RE.match(raw_line)
        if m:
            errors.append(
                {
                    "line": int(m.group("line")),
                    "column_range": m.group("col_range"),
                    "level": m.group("level"),
                    "message": m.group("msg"),
                }
            )
        else:
            if errors:
                errors[-1].setdefault("context", []).append(raw_line)
            else:
                errors.append({"raw": raw_line})
    return errors
