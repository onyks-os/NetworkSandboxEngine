# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""
Detect a host firewall that can filter traffic from a sandbox to its host endpoint.

In the simple topology the host end of the veth pair, with ``host_ip``, lives in
the namespace NSE runs in. Traffic from the sandbox to ``host_ip`` is therefore
local input for that namespace and crosses its firewall (firewalld, ufw, a
hand-written nftables ruleset). A test server listening on ``host_ip`` then
never sees a request the host dropped, and the test reads the silence as the
rules under test blocking it.

The check reads the ruleset once per process with ``nft -j list ruleset`` and
reports the ``input`` hooks that drop by policy or reach an unconditional
``drop``/``reject``. It cannot know which port a test uses, nor whether an
earlier ``accept`` already admits it, so it can only say *may filter*; it never
fails a setup. ``iptables-legacy`` rules are invisible to ``nft`` and are not
inspected.
"""

from __future__ import annotations

import json
import logging
import subprocess
from typing import Any

from nse.core.paths import resolve_optional

logger = logging.getLogger("nse.core.netns")

#: Statements that do not make a rule conditional.
_UNCONDITIONAL = {"counter", "log", "comment", "limit"}
_TERMINAL = {"drop", "reject"}
_INPUT_FAMILIES = {"ip", "ip6", "inet"}

_findings: list[str] | None = None
_warned = False


def input_filters(ruleset: Any) -> list[str]:
    """Describe the input hooks in an ``nft -j list ruleset`` document that filter.

    Each finding names the base chain and why it filters: its policy is
    ``drop``, or it reaches (directly, or through ``jump``/``goto``) a rule that
    drops or rejects everything that gets that far.
    """
    items = ruleset.get("nftables", []) if isinstance(ruleset, dict) else []
    chains: dict[tuple[str, str, str], dict[str, Any]] = {}
    rules: dict[tuple[str, str, str], list[list[dict[str, Any]]]] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        if isinstance(chain := item.get("chain"), dict):
            key = (chain.get("family"), chain.get("table"), chain.get("name"))
            chains[key] = chain  # type: ignore[index]
        elif isinstance(rule := item.get("rule"), dict):
            key = (rule.get("family"), rule.get("table"), rule.get("chain"))
            expr = rule.get("expr")
            if isinstance(expr, list):
                rules.setdefault(key, []).append(expr)  # type: ignore[arg-type]

    def terminal(key: tuple[str, str, str], seen: set[tuple[str, str, str]]) -> str | None:
        if key in seen:
            return None
        seen.add(key)
        for expr in rules.get(key, []):
            statements = [next(iter(s)) for s in expr if isinstance(s, dict) and s]
            verdicts = [s for s in statements if s in _TERMINAL]
            if verdicts and all(s in _UNCONDITIONAL or s in _TERMINAL for s in statements):
                return f"{verdicts[0]} in chain {key[2]}"
            for statement in expr:
                for kind in ("jump", "goto"):
                    target = statement.get(kind) if isinstance(statement, dict) else None
                    if isinstance(target, dict) and isinstance(target.get("target"), str):
                        found = terminal((key[0], key[1], target["target"]), seen)
                        if found:
                            return found
        return None

    findings = []
    for key, chain in chains.items():
        if chain.get("hook") != "input" or key[0] not in _INPUT_FAMILIES:
            continue
        name = f"{key[0]} {key[1]} {key[2]}"
        if chain.get("policy") == "drop":
            findings.append(f"{name}: policy drop")
        elif reason := terminal(key, set()):
            findings.append(f"{name}: {reason}")
    return sorted(findings)


def host_input_filters() -> list[str]:
    """The filtering input hooks of the host's ruleset, read once per process.

    Empty when nothing filters, and also when the ruleset cannot be read (no
    ``nft``, no permission): this is a diagnostic, not a guarantee.
    """
    global _findings
    if _findings is None:
        try:
            nft = resolve_optional("nft")
            if nft is None:
                _findings = []
                return _findings
            result = subprocess.run(
                [nft, "-j", "list", "ruleset"],
                capture_output=True,
                text=True,
                check=True,
                timeout=5.0,
            )
            _findings = input_filters(json.loads(result.stdout or "{}"))
        except Exception as exc:  # a diagnostic must never break a setup
            logger.debug("Host firewall not inspected: %s", exc)
            _findings = []
    return _findings


def warn_if_filtered(namespace: str, host_addresses: list[str]) -> bool:
    """Log, once per process, that the host firewall may filter *host_addresses*.

    Returns True when a warning was (or had already been) issued.
    """
    global _warned
    findings = host_input_filters()
    if not findings:
        return False
    if not _warned:
        _warned = True
        logger.warning(
            "The host firewall may filter traffic from namespace %s to its host endpoint "
            "%s (%s). A server bound there can miss requests the host dropped, which a "
            "test would attribute to the rules under test. Pass isolated_host=True to "
            "create_namespace() to keep the host endpoint out of the host's firewall.",
            namespace,
            ", ".join(host_addresses),
            "; ".join(findings),
        )
    return True
