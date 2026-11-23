"""Stimuli, controlled receivers and observe() on a real kernel (root only).

The sandbox uses ``isolated_host=True``: receivers run on ``sandbox.host``, the
capture is on the host end of the veth, and the stimuli come from a process
inside the sandbox with a non-root identity, which is what an output-hook
firewall filters on. Each positive check has a broken or blind counterpart that
must fail visibly rather than read as "clean".
"""

from __future__ import annotations

import errno
import os
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio

from nse import receivers, stimuli
from nse.core.netns_controller import NamespaceSandbox, NetnsController
from nse.core.rule_engine import RuleEngine
from nse.core.utils import is_in_container
from nse.models.process import ProcessIdentity

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(os.geteuid() != 0, reason="requires root and real network namespaces"),
]

NOBODY = ProcessIdentity(uid=65534, gid=65534)
NOBODY_RAW = ProcessIdentity(uid=65534, gid=65534, capabilities={"net_raw"})
OTHER = ProcessIdentity(uid=1000, gid=1000)
HOST = {4: "10.0.1.1", 6: "fd00::1"}  # the simple topology's defaults
PEER = {4: "10.0.1.2", 6: "fd00::2"}


@pytest_asyncio.fixture
async def sandbox(runtime_registry: Path) -> AsyncIterator[NamespaceSandbox]:
    controller = NetnsController(use_nsenter=True if is_in_container() else None)
    async with controller.create_namespace("nse_stim", isolated_host=True) as ns:
        yield ns


def _engine() -> RuleEngine:
    return RuleEngine(use_nsenter=True if is_in_container() else None)


def _output_rule(rule: str) -> str:
    return (
        "table inet nse_stim {\n"
        "  chain out {\n"
        "    type filter hook output priority 0; policy accept;\n"
        f"    {rule}\n"
        "  }\n"
        "}\n"
    )


def _assert_all_seen(seen: stimuli.Observation, *, receipt: bool = True) -> None:
    assert seen.sent, seen.describe()
    assert seen.on_wire is True, seen.describe()
    if receipt:
        assert seen.received is True, seen.describe()
    assert seen.reply_on_wire is True, seen.describe()
    assert seen.contradictions() == [], seen.describe()
    assert seen.result.identity is not None
    assert set(seen.result.identity.uids) == {65534}


CASES: list[tuple[str, Any, Any]] = [
    ("udp", lambda h: receivers.udp_echo(h, 9999), lambda h: stimuli.udp_round_trip(h, 9999)),
    ("tcp", lambda h: receivers.tcp_echo(h, 9998), lambda h: stimuli.tcp_round_trip(h, 9998)),
    ("syn", lambda h: receivers.tcp_echo(h, 9997), lambda h: stimuli.tcp_connect(h, 9997)),
    ("dns-udp", lambda h: receivers.dns(h), lambda h: stimuli.dns_query(h)),
    ("dns-tcp", lambda h: receivers.dns(h), lambda h: stimuli.dns_query(h, transport="tcp")),
    ("stun", lambda h: receivers.stun(h), lambda h: stimuli.stun_binding(h)),
    ("quic", lambda h: receivers.udp_echo(h, 443), lambda h: stimuli.quic_initial(h, timeout=2)),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("family", [4, 6])
@pytest.mark.parametrize(("label", "receiver", "stimulus"), CASES, ids=[c[0] for c in CASES])
async def test_each_stimulus_is_sent_seen_received_and_answered(
    sandbox: NamespaceSandbox, family: int, label: str, receiver: Any, stimulus: Any
) -> None:
    assert sandbox.host is not None
    host = HOST[family]
    async with await receiver(host).start(sandbox.host) as server:
        seen = await stimuli.observe(sandbox, stimulus(host), identity=NOBODY, receiver=server)
    _assert_all_seen(seen)
    result = seen.result
    assert result.outcome == "answered"
    assert result.source is not None
    assert result.source.address == PEER[family]
    if label.startswith("dns"):
        assert result.dns is not None
        assert result.dns.rcode_name == "NOERROR"
        assert result.dns.addresses == ("192.0.2.53",)  # an A query on either family
    if label == "stun":
        assert result.mapped_address == result.source  # what the server saw
    [first, *_] = seen.receipts or ()
    assert first.source.address == PEER[family]


@pytest.mark.asyncio
@pytest.mark.parametrize("family", [4, 6])
async def test_icmp_echo_from_an_identity_with_cap_net_raw(
    sandbox: NamespaceSandbox, family: int
) -> None:
    seen = await stimuli.observe(
        sandbox, stimuli.icmp_echo(HOST[family], timeout=2), identity=NOBODY_RAW
    )
    _assert_all_seen(seen, receipt=False)
    assert seen.received is None  # no receiver: unknown, not False


@pytest.mark.asyncio
async def test_without_cap_net_raw_an_icmp_echo_could_not_run_not_refused(
    sandbox: NamespaceSandbox,
) -> None:
    seen = await stimuli.observe(sandbox, stimuli.icmp_echo(HOST[4]), identity=NOBODY)
    assert seen.result.outcome == "could_not_run", seen.describe()
    assert seen.result.stage == "socket"
    assert seen.result.errno == errno.EPERM
    assert seen.on_wire is False


@pytest.mark.asyncio
@pytest.mark.parametrize("family", [4, 6])
async def test_a_uid_drop_is_refused_with_eperm_and_never_on_the_wire(
    sandbox: NamespaceSandbox, family: int
) -> None:
    """The firewall working: nothing on the wire, nothing received.

    The same rule spares another UID, which is the positive control: the probe,
    the capture and the receiver all work, so the absences are the firewall's.
    """
    assert sandbox.host is not None
    _engine().load(_output_rule("meta skuid 65534 drop"), sandbox.name)
    host = HOST[family]
    async with await receivers.udp_echo(host, 9999).start(sandbox.host) as echo:
        control = await stimuli.observe(
            sandbox, stimuli.udp_round_trip(host, 9999), identity=OTHER, receiver=echo
        )
        blocked = await stimuli.observe(
            sandbox, stimuli.udp_round_trip(host, 9999), identity=NOBODY, receiver=echo
        )
        syn = await stimuli.observe(
            sandbox, stimuli.tcp_connect(host, 9999), identity=NOBODY, receiver=echo
        )
    assert control.on_wire is True, control.describe()
    assert control.received is True, control.describe()
    assert blocked.result.outcome == "refused", blocked.describe()
    assert blocked.result.stage == "send"
    assert blocked.result.errno == errno.EPERM
    # The kernel retransmits a SYN dropped on output instead of failing connect(),
    # so the probe sees a timeout. Only the complete capture says it never left.
    assert syn.result.outcome == "no_reply", syn.describe()
    assert syn.result.stage == "connect"
    for seen in (blocked, syn):
        assert seen.on_wire is False, seen.describe()
        assert seen.received is False, seen.describe()
        assert seen.contradictions() == []


@pytest.mark.asyncio
async def test_a_tcp_reset_reject_is_refused_at_connect(sandbox: NamespaceSandbox) -> None:
    _engine().load(
        _output_rule("meta skuid 65534 tcp dport 80 reject with tcp reset"), sandbox.name
    )
    seen = await stimuli.observe(sandbox, stimuli.tcp_connect(HOST[4], 80), identity=NOBODY)
    assert seen.result.outcome == "refused", seen.describe()
    assert seen.result.stage == "connect"
    assert seen.on_wire is False


@pytest.mark.asyncio
async def test_a_blind_capture_is_contradicted_by_the_receiver(sandbox: NamespaceSandbox) -> None:
    """The deliberately blind instrument: a filter that excludes the probe.

    The window is complete and saw nothing, so on its own it would read as
    "not on the wire". The receiver's log contradicts it, and observe() says so.
    """
    assert sandbox.host is not None
    async with await receivers.udp_echo(HOST[4], 9999).start(sandbox.host) as echo:
        seen = await stimuli.observe(
            sandbox,
            stimuli.udp_round_trip(HOST[4], 9999),
            identity=NOBODY,
            receiver=echo,
            capture_filter="udp port 1",
        )
    assert seen.on_wire is False
    assert seen.received is True
    assert any("blind to this path" in p for p in seen.contradictions())
    assert "CONTRADICTION" in seen.describe()


@pytest.mark.asyncio
async def test_nothing_listening_is_not_received_and_the_icmp_error_is_refused(
    sandbox: NamespaceSandbox,
) -> None:
    assert sandbox.host is not None
    async with await receivers.udp_echo(HOST[4], 9999).start(sandbox.host) as echo:
        seen = await stimuli.observe(
            sandbox, stimuli.udp_round_trip(HOST[4], 9996), identity=NOBODY, receiver=echo
        )
    assert seen.on_wire is True, seen.describe()
    assert seen.received is False  # the receiver's complete log does not have it
    assert seen.result.outcome == "refused"
    assert seen.result.stage == "receive"
    assert seen.result.errno == errno.ECONNREFUSED


@pytest.mark.asyncio
async def test_dns_failure_modes_through_the_namespace(sandbox: NamespaceSandbox) -> None:
    assert sandbox.host is not None
    async with await receivers.dns(HOST[6], mode="servfail").start(sandbox.host) as server:
        seen = await stimuli.observe(
            sandbox, stimuli.dns_query(HOST[6], transport="tcp"), identity=NOBODY, receiver=server
        )
    assert seen.result.dns is not None
    assert seen.result.dns.rcode_name == "SERVFAIL"
    assert seen.received is True
    assert seen.reply_on_wire is True
    async with await receivers.dns(HOST[4], mode="drop").start(sandbox.host) as server:
        dropped = await stimuli.observe(
            sandbox, stimuli.dns_query(HOST[4], timeout=0.5), identity=NOBODY, receiver=server
        )
    assert dropped.result.outcome == "no_reply"
    assert dropped.received is True
    assert dropped.reply_on_wire is False


@pytest.mark.asyncio
async def test_a_receiver_that_cannot_bind_in_the_namespace_does_not_start(
    sandbox: NamespaceSandbox,
) -> None:
    assert sandbox.host is not None
    with pytest.raises(receivers.ReceiverStartError, match="bind failed"):
        await receivers.udp_echo("10.9.9.9", 9).start(sandbox.host)  # not its address
