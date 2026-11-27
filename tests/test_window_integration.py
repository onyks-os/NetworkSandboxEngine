"""NAT-aware matching, one window with a canary, and tracing local traffic (root only).

Each positive check has its blind counterpart: a strict match after a DNAT
contradicts the receiver, a capture that cannot see the canary vouches for no
absence, and a trace monitor without an output-hook trace chain is never
proven ready by a locally sent canary.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio

from nse import receivers, stimuli
from nse.core.netns_controller import NamespaceSandbox, NetnsController
from nse.core.paths import resolve
from nse.core.rule_engine import RuleEngine
from nse.core.trace_harvester import HarvestState, TraceHarvester, TraceReadiness
from nse.core.utils import is_in_container
from nse.models.process import ProcessIdentity
from nse.models.trace_event import TraceEvent

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(os.geteuid() != 0, reason="requires root and real network namespaces"),
]

NOBODY = ProcessIdentity(uid=65534, gid=65534)
OTHER = ProcessIdentity(uid=1000, gid=1000)
HOST = "10.0.1.1"
NSENTER = True if is_in_container() else None

REDIRECT = """
table ip nse_win {
  chain nat_out {
    type nat hook output priority -100; policy accept;
    udp dport 5353 dnat to 10.0.1.1:9999
  }
}
"""

DROP_NOBODY_SYN = """
table inet nse_win {
  chain out {
    type filter hook output priority 0; policy accept;
    meta skuid 65534 tcp dport 8080 drop
  }
}
"""

DROP_NOBODY_UDP = """
table inet nse_win {
  chain out {
    type filter hook output priority 0; policy accept;
    meta skuid 65534 udp dport 9999 drop
  }
}
"""


@pytest_asyncio.fixture
async def sandbox(runtime_registry: Path) -> AsyncIterator[NamespaceSandbox]:
    controller = NetnsController(use_nsenter=NSENTER)
    async with controller.create_namespace("nse_win", isolated_host=True) as ns:
        yield ns


# --------------------------------------------------------------------------- NAT


@pytest.mark.asyncio
async def test_a_probe_redirected_by_dnat_is_followed_only_with_nat(
    sandbox: NamespaceSandbox,
) -> None:
    assert sandbox.host is not None
    RuleEngine(use_nsenter=bool(NSENTER)).load(REDIRECT, sandbox.name)
    probe = stimuli.udp_round_trip(HOST, 5353)
    async with await receivers.udp_echo(HOST, 9999).start(sandbox.host) as server:
        followed = await stimuli.observe(sandbox, probe, identity=NOBODY, receiver=server, nat=True)
        strict = await stimuli.observe(sandbox, probe, identity=NOBODY, receiver=server)
    assert followed.result.outcome == "answered", followed.describe()
    assert followed.on_wire is True, followed.describe()
    assert followed.received is True
    assert followed.reply_on_wire is True
    assert followed.contradictions() == []
    assert {int(p.dport) for p in (r.payload.payload for r in followed.requests)} == {9999}
    # Without nat the probe is not recognised on the wire, and the receiver's
    # log exposes that blind spot instead of letting it read as "not sent".
    assert strict.on_wire is False
    assert strict.received is True
    assert "blind" in strict.contradictions()[0]


# --------------------------------------------------------------------------- canary


@pytest.mark.asyncio
async def test_a_seen_canary_vouches_for_an_absence_in_the_same_window(
    sandbox: NamespaceSandbox,
) -> None:
    RuleEngine(use_nsenter=bool(NSENTER)).load(DROP_NOBODY_SYN, sandbox.name)
    window = await stimuli.observe_window(
        sandbox,
        [stimuli.tcp_connect(HOST, 8080, timeout=0.3), stimuli.udp(HOST, 9000)],
        identity=NOBODY,
        canary=stimuli.udp(HOST, 7777),
        canary_identity=OTHER,
    )
    assert window.canary_seen is True, window.describe()
    assert window.conclusive, window.describe()
    syn, udp = window
    assert syn.result.outcome == "no_reply"
    assert syn.on_wire is False, syn.describe()  # dropped, and the capture can vouch for it
    assert udp.on_wire is True


@pytest.mark.asyncio
async def test_a_capture_that_cannot_see_the_canary_vouches_for_nothing(
    sandbox: NamespaceSandbox,
) -> None:
    RuleEngine(use_nsenter=bool(NSENTER)).load(DROP_NOBODY_SYN, sandbox.name)
    seen = await stimuli.observe(
        sandbox,
        stimuli.tcp_connect(HOST, 8080, timeout=0.3),
        identity=NOBODY,
        capture_filter="tcp",  # blind to the canary's path
        canary=stimuli.udp(HOST, 7777),
        canary_identity=OTHER,
    )
    assert seen.canary is not None
    assert seen.canary.on_wire is False
    assert seen.on_wire is None, seen.describe()  # never "not sent"
    assert "canary: NOT seen" in seen.describe()


# --------------------------------------------------------------------------- trace


async def _trace(
    sandbox: NamespaceSandbox,
    engine: RuleEngine,
    subject: stimuli.Stimulus,
    rules: str = DROP_NOBODY_UDP,
) -> tuple[TraceReadiness, HarvestState, list[TraceEvent]]:
    engine.load(rules, sandbox.name)
    harvester = TraceHarvester()
    events: list[TraceEvent] = []
    queue: asyncio.Queue[TraceEvent | None] = asyncio.Queue()
    await harvester.start(
        netns_name=sandbox.name,
        queue=queue,
        timeout=20.0,
        use_nsenter=bool(NSENTER),
        on_event=events.append,
    )
    try:
        await harvester.wait_ready(timeout=2.0)
        readiness = await stimuli.trace_ready(
            harvester, sandbox, stimuli.udp(HOST, 7777), identity=OTHER, attempts=3
        )
        harvester.arm_event_signal()
        await subject.run(sandbox, identity=NOBODY)
        await asyncio.sleep(0.5)
    finally:
        state = await harvester.aclose()
    return readiness, state, readiness.without(events)


@pytest.mark.asyncio
async def test_a_local_drop_is_traced_once_output_tracing_is_on(
    sandbox: NamespaceSandbox,
) -> None:
    engine = RuleEngine(use_nsenter=bool(NSENTER), trace_output=True)
    readiness, state, events = await _trace(sandbox, engine, stimuli.udp(HOST, 9999))
    assert readiness.ready, readiness.describe()
    assert state in (HarvestState.STOPPED, HarvestState.CLEAN_EOF)
    drops = [e for e in events if e.type == "match" and e.rule_text and "drop" in e.rule_text]
    assert drops, events
    assert all(e.packet_dst_port != 7777 for e in events)  # the canary's traces are gone


@pytest.mark.asyncio
async def test_without_output_tracing_a_local_canary_never_proves_readiness(
    sandbox: NamespaceSandbox,
) -> None:
    engine = RuleEngine(use_nsenter=bool(NSENTER))
    readiness, _, events = await _trace(sandbox, engine, stimuli.udp(HOST, 9999))
    assert not readiness.ready, readiness.describe()
    assert any("no output chain" in p for p in readiness.problems), readiness.problems
    assert not [e for e in events if e.type == "match" and "drop" in (e.rule_text or "")]


# --------------------------------------------------------------------------- trace table


def _trace_table(sandbox: NamespaceSandbox, engine: RuleEngine) -> str:
    cmd = [*engine.exec_prefix(sandbox.name), resolve("nft"), "list", "table", "inet", "nse_trace"]
    return subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=10).stdout


def test_loading_again_replaces_the_trace_table(sandbox: NamespaceSandbox) -> None:
    traced = RuleEngine(use_nsenter=bool(NSENTER), trace_output=True)
    for _ in range(3):
        traced.load(DROP_NOBODY_UDP, sandbox.name)
    table = _trace_table(sandbox, traced)
    assert table.count("meta nftrace set 1") == 2, table  # one per chain, not three
    assert "nse_trace_output" in table
    plain = RuleEngine(use_nsenter=bool(NSENTER))
    plain.load(DROP_NOBODY_UDP, sandbox.name)
    table = _trace_table(sandbox, plain)
    assert "nse_trace_output" not in table, table  # trace_output=False means no output chain
    assert table.count("meta nftrace set 1") == 1


@pytest.mark.asyncio
async def test_after_several_loads_each_packet_is_traced_by_nse_once(
    sandbox: NamespaceSandbox,
) -> None:
    engine = RuleEngine(use_nsenter=bool(NSENTER), trace_output=True)
    for _ in range(2):  # _trace() loads a third time
        engine.load(DROP_NOBODY_UDP, sandbox.name)
    readiness, _, events = await _trace(sandbox, engine, stimuli.udp(HOST, 9999))
    assert readiness.ready, readiness.describe()
    nse_rules: dict[str, int] = {}
    for e in events:
        if e.type == "match" and e.table == "nse_trace" and e.trace_id:
            nse_rules[e.trace_id] = nse_rules.get(e.trace_id, 0) + 1
    assert nse_rules, events
    assert set(nse_rules.values()) == {1}, nse_rules


@pytest.mark.asyncio
async def test_a_ruleset_that_flushes_explains_why_nothing_is_traced(
    sandbox: NamespaceSandbox,
) -> None:
    engine = RuleEngine(use_nsenter=bool(NSENTER), trace_output=True)
    flushing = "flush ruleset\n" + DROP_NOBODY_UDP
    readiness, _, _ = await _trace(sandbox, engine, stimuli.udp(HOST, 9999), flushing)
    assert not readiness.ready, readiness.describe()
    assert any("flush ruleset" in p and "not loaded" in p for p in readiness.problems), (
        readiness.problems
    )
