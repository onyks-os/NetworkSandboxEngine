"""
RuleEngine — inject and validate nftables rulesets inside a netns.

Key design decisions (from ARCHITECTURE.md)
--------------------------------------------
* **No intermediate parser.**  Rules are passed verbatim to `nft -f`.
  The kernel's own C parser validates syntax; we only capture its stderr.
* **Namespace safety guard.**  The engine refuses to inject rules unless
  a valid netns name is supplied, preventing accidental pollution of the
  host's `init_net`.
* **Error mapping.**  nft stderr lines of the form
      ``/tmp/rules_XXXX.nft:12:5-10: Error: …``
  are parsed to extract the line number and surfaced to the API caller.
"""

from __future__ import annotations

import logging
import re
import subprocess
import tempfile
import os
from dataclasses import dataclass

logger = logging.getLogger("nse.core.rule_engine")

# Regex to extract line number from nft error output
# Example: "/tmp/rules_abc.nft:12:5-10: Error: No such table: filter"
_NFT_ERROR_RE = re.compile(
    r"^(?P<file>[^:]+):(?P<line>\d+):(?P<col_range>[\d-]+):\s*(?P<level>\w+):\s*(?P<msg>.+)$"
)


@dataclass
class NftError:
    line: int
    column_range: str
    level: str
    message: str


class RuleValidationError(Exception):
    """Raised when `nft -f` rejects the supplied ruleset."""

    def __init__(self, errors: list[dict]) -> None:
        self.errors = errors
        super().__init__(f"nftables validation failed: {errors}")


class RuleEngine:
    """
    Validates and loads nftables rules into a network namespace.

    Usage (validation only, no namespace needed):
        engine = RuleEngine()
        engine.validate(raw_rules_text)   # raises RuleValidationError on bad syntax

    Usage (load into namespace):
        engine.load(raw_rules_text, netns_name="nse_abc123")
    """

    def validate(self, rules: str) -> None:
        """
        Dry-run validation using ``nft --check``.

        This does **not** require a namespace — it only checks syntax.
        Raises RuleValidationError with structured error info on failure.
        """
        with _temp_rules_file(rules) as path:
            result = subprocess.run(
                ["nft", "--check", "-f", path],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                errors = _parse_nft_errors(result.stderr, path)
                raise RuleValidationError(errors)

    def load(self, rules: str, netns_name: str) -> None:
        """
        Write rules to a temp file and load them inside *netns_name*.

        Safety: refuses to operate without a netns name (never touches init_net).
        """
        if not netns_name:
            raise ValueError("netns_name must be provided — refusing to inject into init_net.")

        logger.info("Loading rules into netns %s", netns_name)

        with _temp_rules_file(rules) as path:
            result = subprocess.run(
                ["ip", "netns", "exec", netns_name, "nft", "-f", path],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                errors = _parse_nft_errors(result.stderr, path)
                raise RuleValidationError(errors)

    def flush(self, netns_name: str) -> None:
        """Remove all nftables rules from a namespace (safe cleanup)."""
        subprocess.run(
            ["ip", "netns", "exec", netns_name, "nft", "flush", "ruleset"],
            capture_output=True,
            check=False,  # Ignore errors — namespace may already be gone
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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

    def __exit__(self, *_) -> None:
        if self._path and os.path.exists(self._path):
            os.unlink(self._path)


def _parse_nft_errors(stderr: str, rules_path: str) -> list[dict]:
    """
    Parse nft stderr into a list of structured error dicts.

    Each dict has: ``{line, column_range, level, message}``.
    Unknown lines are appended as raw strings under ``{raw}``.
    """
    errors: list[dict] = []
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
            # Context lines (showing the offending source) — attach as raw
            if errors:
                errors[-1].setdefault("context", []).append(raw_line)
            else:
                errors.append({"raw": raw_line})
    return errors
