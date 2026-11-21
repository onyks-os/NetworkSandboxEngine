"""Host firewall diagnostic: which input hooks can filter traffic to host_ip."""

from __future__ import annotations

import errno
import logging
import os
import subprocess
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from nse.core import host_firewall, utils
from nse.core.host_firewall import input_filters, warn_if_filtered


def _chain(name: str, hook: str | None = None, policy: str = "accept", **kw: Any) -> dict:
    chain = {"family": kw.get("family", "inet"), "table": kw.get("table", "t"), "name": name}
    if hook:
        chain.update(type="filter", hook=hook, prio=0, policy=policy)
    return {"chain": chain}


def _rule(chain: str, *expr: dict, **kw: Any) -> dict:
    return {
        "rule": {
            "family": kw.get("family", "inet"),
            "table": kw.get("table", "t"),
            "chain": chain,
            "expr": list(expr),
        }
    }


MATCH = {"match": {"op": "==", "left": {"ct": {"key": "state"}}, "right": "invalid"}}


def _ruleset(*items: dict) -> dict:
    return {"nftables": [{"metainfo": {"json_schema_version": 1}}, *items]}


@pytest.fixture(autouse=True)
def fresh_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(host_firewall, "_findings", None)
    monkeypatch.setattr(host_firewall, "_warned", False)


def test_firewalld_final_reject_is_found_through_its_zone_jumps() -> None:
    ruleset = _ruleset(
        _chain("filter_INPUT", "input", table="firewalld"),
        _chain("filter_INPUT_ZONES", table="firewalld"),
        _chain("filter_IN_public", table="firewalld"),
        _rule("filter_INPUT", MATCH, {"accept": None}, table="firewalld"),
        _rule("filter_INPUT", MATCH, {"drop": None}, table="firewalld"),  # conditional
        _rule("filter_INPUT", {"jump": {"target": "filter_INPUT_ZONES"}}, table="firewalld"),
        _rule("filter_INPUT_ZONES", {"goto": {"target": "filter_IN_public"}}, table="firewalld"),
        _rule("filter_IN_public", MATCH, {"accept": None}, table="firewalld"),
        _rule(
            "filter_INPUT",
            {"reject": {"type": "icmpx", "expr": "admin-prohibited"}},
            table="firewalld",
        ),
    )
    assert input_filters(ruleset) == ["inet firewalld filter_INPUT: reject in chain filter_INPUT"]


def test_a_drop_policy_is_found() -> None:
    ruleset = _ruleset(_chain("INPUT", "input", "drop", family="ip", table="filter"))
    assert input_filters(ruleset) == ["ip filter INPUT: policy drop"]


def test_an_unconditional_drop_in_a_jumped_chain_is_found() -> None:
    ruleset = _ruleset(
        _chain("input", "input"),
        _chain("zone"),
        _rule("input", MATCH, {"jump": {"target": "zone"}}),
        _rule("zone", {"counter": {"packets": 0, "bytes": 0}}, {"drop": None}),
    )
    assert input_filters(ruleset) == ["inet t input: drop in chain zone"]


def test_a_permissive_host_with_only_conditional_drops_is_not_reported() -> None:
    ruleset = _ruleset(
        _chain("input", "input"),
        _chain("forward", "forward", "drop"),  # not on the path to host_ip
        _chain("ingress", "ingress", "drop", family="netdev"),
        _rule("input", MATCH, {"drop": None}),
    )
    assert input_filters(ruleset) == []


def test_jump_cycles_and_malformed_documents_do_not_break_the_check() -> None:
    cyclic = _ruleset(
        _chain("input", "input"),
        _chain("a"),
        _rule("input", {"jump": {"target": "a"}}),
        _rule("a", {"jump": {"target": "input"}}),
    )
    assert input_filters(cyclic) == []
    for document in (None, [], {"nftables": "x"}, {"nftables": [1, "x", {"rule": 3}]}):
        assert input_filters(document) == []


def test_the_host_ruleset_is_read_once_per_process() -> None:
    document = '{"nftables": [{"chain": {"family": "ip", "table": "f", "name": "I", "hook": "input", "policy": "drop"}}]}'
    run = MagicMock(return_value=subprocess.CompletedProcess([], 0, document, ""))
    with (
        patch.object(host_firewall, "resolve_optional", return_value="/usr/sbin/nft"),
        patch("subprocess.run", run),
    ):
        assert host_firewall.host_input_filters() == ["ip f I: policy drop"]
        assert host_firewall.host_input_filters() == ["ip f I: policy drop"]
    assert run.call_count == 1
    assert run.call_args.args[0] == ["/usr/sbin/nft", "-j", "list", "ruleset"]


@pytest.mark.parametrize(
    "failure",
    [
        subprocess.CalledProcessError(1, "nft", stderr="Operation not permitted"),
        subprocess.TimeoutExpired("nft", 5),
        PermissionError("unsafe binary"),
    ],
)
def test_an_unreadable_ruleset_is_never_an_error(failure: BaseException) -> None:
    with (
        patch.object(host_firewall, "resolve_optional", return_value="/usr/sbin/nft"),
        patch("subprocess.run", side_effect=failure),
    ):
        assert host_firewall.host_input_filters() == []


def test_without_nft_there_is_nothing_to_inspect() -> None:
    with (
        patch.object(host_firewall, "resolve_optional", return_value=None),
        patch("subprocess.run") as run,
    ):
        assert host_firewall.host_input_filters() == []
    run.assert_not_called()


def test_the_warning_names_the_cause_and_the_remedy_once(caplog: pytest.LogCaptureFixture) -> None:
    host_firewall._findings = ["inet firewalld filter_INPUT: reject in chain filter_INPUT"]
    with caplog.at_level(logging.WARNING, logger="nse.core.netns"):
        assert warn_if_filtered("nse_a", ["10.0.1.1/24"]) is True
        assert warn_if_filtered("nse_b", ["10.0.1.1/24"]) is True
    warnings = [r.getMessage() for r in caplog.records]
    assert len(warnings) == 1
    assert "10.0.1.1/24" in warnings[0]
    assert "filter_INPUT" in warnings[0]
    assert "isolated_host=True" in warnings[0]


def test_no_warning_when_nothing_filters(caplog: pytest.LogCaptureFixture) -> None:
    host_firewall._findings = []
    with caplog.at_level(logging.WARNING, logger="nse.core.netns"):
        assert warn_if_filtered("nse_a", ["10.0.1.1/24"]) is False
    assert not caplog.records


# ---------------------------------------------------------------------------
# enter_netns: the per-thread namespace switch behind PCAPAsserter(netns=...)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["", ".", "..", "a/b", "../x"])
def test_enter_netns_rejects_names_that_are_not_a_namespace(name: str) -> None:
    with pytest.raises(ValueError):
        utils.enter_netns(name)


def test_enter_netns_reports_a_missing_namespace_as_enodev() -> None:
    with (
        patch("os.open", side_effect=FileNotFoundError(2, "No such file")),
        pytest.raises(OSError) as info,
    ):
        utils.enter_netns("nsh_missing")
    assert info.value.errno == errno.ENODEV
    assert "nsh_missing" in str(info.value)


def test_enter_netns_uses_os_setns_when_available(monkeypatch: pytest.MonkeyPatch) -> None:
    read, write = os.pipe()
    os.close(write)
    calls = []
    monkeypatch.setattr(os, "setns", lambda fd, kind: calls.append(kind), raising=False)
    with patch("os.open", return_value=read) as opened:
        utils.enter_netns("nsh_x")
    assert opened.call_args.args[0] == "/var/run/netns/nsh_x"
    assert calls == [0x40000000]
    with pytest.raises(OSError):
        os.fstat(read)  # closed after use


def test_enter_netns_falls_back_to_libc_and_reports_its_errno(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    read, write = os.pipe()
    os.close(write)
    monkeypatch.delattr(os, "setns", raising=False)
    libc = MagicMock()
    libc.setns.return_value = -1
    with (
        patch("os.open", return_value=read),
        patch("ctypes.CDLL", return_value=libc),
        patch("ctypes.get_errno", return_value=errno.EPERM),
        pytest.raises(PermissionError),
    ):
        utils.enter_netns("nsh_x")
    libc.setns.assert_called_once_with(read, 0x40000000)
    with pytest.raises(OSError):
        os.fstat(read)
