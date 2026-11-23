"""Beacons, stimulus streams and correlate() on a real kernel (root only).

Every positive check has a broken counterpart that must come out incomplete or
inconclusive, never clean: a beacon the filter excludes, a beacon sent on a
link the capture does not watch, a stream frozen mid-window, a stream whose
attempts cannot run.
"""

from __future__ import annotations

import asyncio
import os
import signal
import time
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio

from nse import PCAPAsserter, StimulusStream, correlate, receivers, stimuli
from nse.core import beacons
from nse.core.netns_controller import NamespaceSandbox, NetnsController
from nse.core.rule_engine import RuleEngine
from nse.core.sniffer import CaptureStateError
from nse.core.utils import is_in_container
from nse.models.process import ProcessIdentity

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(os.geteuid() != 0, reason="requires root and real network namespaces"),
]

NOBODY = ProcessIdentity(uid=65534, gid=65534)
HOST = "10.0.1.1"
PORT = 9999
PERIOD = 0.02

DROP_NOBODY = """
table inet nse_strm {
  chain out {
    type filter hook output priority 0; policy accept;
    meta skuid 65534 udp dport 9999 drop
  }
}
"""


@pytest_asyncio.fixture
async def sandbox(runtime_registry: Path) -> AsyncIterator[NamespaceSandbox]:
    controller = NetnsController(use_nsenter=True if is_in_container() else None)
    async with controller.create_namespace("nse_strm", isolated_host=True) as ns:
        yield ns


def _capture(sandbox: NamespaceSandbox, **options: object) -> PCAPAsserter:
    return PCAPAsserter(iface=sandbox.ext_iface, netns=sandbox.ext_netns, **options)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- beacons


@pytest.mark.asyncio
async def test_beacons_from_both_ends_are_seen_and_vouch_for_the_window(
    sandbox: NamespaceSandbox,
) -> None:
    asserter = _capture(sandbox, required_bytes=1514)
    await asserter.start()
    await asserter.mark("start")
    await asserter.mark("from-sandbox", via=sandbox)
    await asserter.mark("end")
    packets = await asserter.stop()
    report = await asserter.stop_report()
    assert report.beacons_missing == [], report
    assert [s.label for s in report.beacons_seen] == ["start", "from-sandbox", "end"]
    assert not any(beacons.parse(bytes(p)) for p in packets)  # never in the packet list
    assert report.hardware_type == 1
    assert report.link_type == 1
    assert report.snaplen == 65535
    assert report.snaplen_sufficient is True
    assert report.window_complete is True


@pytest.mark.asyncio
async def test_a_beacon_the_filter_excludes_leaves_the_window_incomplete(
    sandbox: NamespaceSandbox,
) -> None:
    asserter = _capture(sandbox, filter="udp")
    await asserter.start()
    with pytest.raises(CaptureStateError, match="beacons=True"):
        await asserter.mark("refused")  # NSE will not mark through a filter that may drop it
    asserter.expect(await sandbox.beacon("excluded"))  # sent anyway: the filter drops it
    await asserter.stop()
    report = await asserter.stop_report()
    assert report.instrument_healthy
    assert report.beacons_missing == ["excluded"]
    assert report.window_complete is False


@pytest.mark.asyncio
async def test_a_beacon_on_a_link_the_capture_does_not_watch_is_missing(
    sandbox: NamespaceSandbox,
) -> None:
    asserter = _capture(sandbox)
    await asserter.start()
    asserter.expect(await beacons.send("lo", sandbox.name, "elsewhere"))
    await asserter.mark("here")
    await asserter.stop()
    report = await asserter.stop_report()
    assert report.beacons_missing == ["elsewhere"]
    assert report.window_complete is False


# --------------------------------------------------------------------------- streams


@pytest.mark.asyncio
async def test_a_stream_is_received_end_to_end_and_the_window_is_conclusive(
    sandbox: NamespaceSandbox,
) -> None:
    assert sandbox.host is not None
    async with await receivers.udp_echo(HOST, PORT).start(sandbox.host) as server:
        asserter = _capture(sandbox)
        await asserter.start()
        await asserter.mark("start")
        stream = StimulusStream(stimuli.udp(HOST, PORT), period=PERIOD)
        async with await stream.start(sandbox, identity=NOBODY) as running:
            await asyncio.sleep(0.4)
        await asserter.mark("end")
        packets = await asserter.stop()
        report = await asserter.stop_report()
        receipts = await server.stop()
    log = running.log()
    assert log.complete, log.problems
    joined = correlate(log, packets, receipts, capture=report)
    assert joined.conclusive, joined.describe()
    assert len(joined.fates) >= 10
    assert set(joined.counts()) == {"received"}, joined.describe()
    assert all(fate.conclusive for fate in joined.fates)


@pytest.mark.asyncio
async def test_a_rule_loaded_mid_stream_shows_as_a_clean_switch(
    sandbox: NamespaceSandbox,
) -> None:
    assert sandbox.host is not None
    engine = RuleEngine(use_nsenter=True if is_in_container() else None)
    async with await receivers.udp_echo(HOST, PORT).start(sandbox.host) as server:
        asserter = _capture(sandbox)
        await asserter.start()
        await asserter.mark("start")
        stream = StimulusStream(stimuli.udp(HOST, PORT), period=PERIOD)
        async with await stream.start(sandbox, identity=NOBODY) as running:
            await asyncio.sleep(0.3)
            load_started = time.monotonic()
            await asyncio.to_thread(engine.load, DROP_NOBODY, sandbox.name)
            load_done = time.monotonic()
            await asyncio.sleep(0.3)
        await asserter.mark("end")
        packets = await asserter.stop()
        report = await asserter.stop_report()
        receipts = await server.stop()
    joined = correlate(running.log(), packets, receipts, capture=report)
    assert joined.conclusive, joined.describe()
    window_start, window_end = joined.window_start, joined.window_end
    assert window_start is not None
    assert window_end is not None
    before = joined.between(window_start, load_started)
    after = joined.between(load_done, window_end)
    assert before.conclusive, before.describe()
    assert after.conclusive, after.describe()
    assert set(before.counts()) == {"received"}, before.describe()
    assert set(after.counts()) == {"refused"}, after.describe()
    for fate in after.fates:
        assert fate.attempt is not None
        assert fate.attempt.result.stage == "send"


@pytest.mark.asyncio
async def test_a_frozen_stream_makes_its_window_inconclusive(sandbox: NamespaceSandbox) -> None:
    assert sandbox.host is not None
    async with await receivers.udp_echo(HOST, PORT).start(sandbox.host) as server:
        asserter = _capture(sandbox)
        await asserter.start()
        stream = StimulusStream(stimuli.udp(HOST, PORT), period=PERIOD)
        async with await stream.start(sandbox, identity=NOBODY) as running:
            await asyncio.sleep(0.2)
            os.killpg(running.process.pid, signal.SIGSTOP)  # the stream stops sending
            frozen = time.monotonic()
            await asyncio.sleep(0.3)
            os.killpg(running.process.pid, signal.SIGCONT)
            await asyncio.sleep(0.2)
        packets = await asserter.stop()
        report = await asserter.stop_report()
        receipts = await server.stop()
    joined = correlate(running.log(), packets, receipts, capture=report)
    assert not joined.conclusive, joined.describe()
    assert len(joined.gaps) == 1, joined.describe()
    gap = joined.gaps[0]
    assert gap.start <= frozen <= gap.end
    assert gap.seconds >= 0.25
    assert set(joined.counts()) == {"received"}  # every attempt made it: only the gap is unknown


@pytest.mark.asyncio
async def test_a_stream_that_cannot_send_tested_nothing(sandbox: NamespaceSandbox) -> None:
    asserter = _capture(sandbox)
    await asserter.start()
    stream = StimulusStream(stimuli.icmp_echo(HOST), period=PERIOD, count=5)
    log = await (await stream.start(sandbox, identity=NOBODY)).wait(20)  # no CAP_NET_RAW
    packets = await asserter.stop()
    report = await asserter.stop_report()
    assert log.complete, log.problems
    joined = correlate(log, packets, capture=report)
    assert set(joined.counts()) == {"not_sent"}
    assert not joined.conclusive
    assert any("nothing was tested" in p for p in joined.problems), joined.describe()
