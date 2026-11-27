"""A stream and clocked beacons run as if on another machine (root only).

The stream agent and the beacon agent run from their command lines, as they
would over ssh in a VM; the capture is read back from its pcap file with
``CaptureReport.from_pcap``, as a file written by QEMU would be. The positive
check places every attempt on the capture's clock; its broken counterpart, the
same file cut short, must come out inconclusive.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio

from nse import CaptureReport, ClockMap, PCAPAsserter, StimulusStream, StreamLog, correlate, stimuli
from nse.core import beacons
from nse.core.netns_controller import NamespaceSandbox, NetnsController
from nse.core.utils import is_in_container
from nse.models.capture_report import Beacon
from nse.models.process import ProcessIdentity
from nse.stimuli import default_python

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(os.geteuid() != 0, reason="requires root and real network namespaces"),
]

NOBODY = ProcessIdentity(uid=65534, gid=65534)


@pytest_asyncio.fixture
async def sandbox(runtime_registry: Path) -> AsyncIterator[NamespaceSandbox]:
    controller = NetnsController(use_nsenter=True if is_in_container() else None)
    async with controller.create_namespace("nse_rmt", isolated_host=True) as ns:
        yield ns


async def _beacon(sandbox: NamespaceSandbox, label: str) -> Beacon:
    argv, token = beacons.agent_command(sandbox.peer_iface, label, python=default_python())
    done = await sandbox.exec_argv(argv)
    assert done.returncode == 0, done.stdout + done.stderr
    beacon = beacons.agent_report(done.stdout)
    assert beacon.token == token
    return beacon


@pytest.mark.asyncio
async def test_a_stream_run_elsewhere_is_placed_on_the_capture_clock(
    sandbox: NamespaceSandbox, tmp_path: Path
) -> None:
    path = tmp_path / "vm.pcap"
    capture = PCAPAsserter(iface=sandbox.ext_iface, netns=sandbox.ext_netns, output=path)
    await capture.start()
    start = await _beacon(sandbox, "start")
    stream = StimulusStream(stimuli.udp("10.0.1.1", 9999), period=0.02, count=15)
    argv, stream_id = stream.command(python=default_python())
    process = await sandbox.start_process(argv, identity=NOBODY)
    result = await process.wait(timeout=30)
    assert result.returncode == 0
    end = await _beacon(sandbox, "end")
    live = await capture.stop()
    live_report = await capture.stop_report()

    log = StreamLog.parse(process.output("stdout"), stream_id, final=True, stream=stream)
    assert log.complete, log.problems
    assert log.boot_id == Path("/proc/sys/kernel/random/boot_id").read_text().strip()

    report, packets = CaptureReport.from_pcap(path, expected_beacons=[start, end])
    assert report.window_complete is True, report
    assert report.packets_observed == live_report.packets_observed
    assert live == []  # file mode: the record is the file, read back here
    assert [s.token for s in report.beacons_seen] == [s.token for s in live_report.beacons_seen]
    assert all(s.clock is not None and s.clock.bracketed for s in report.beacons_seen)

    clock = ClockMap.from_beacons(report.beacons_seen)
    assert clock.problems == ()
    (boot,) = clock.boots
    assert boot.boot_id == log.boot_id
    assert boot.uncertainty < 0.5, boot

    joined = correlate(log, packets, capture=report, clock=clock)
    assert joined.conclusive, joined.describe()
    assert set(joined.counts()) == {"on_wire"}, joined.describe()
    assert joined.clock == "capture"
    assert joined.window_start is not None
    assert joined.window_end is not None
    assert start.sent_at - 1 < joined.window_start < joined.window_end < end.sent_at + 1
    phase = joined.between(
        joined.window_start - boot.uncertainty, joined.window_end + boot.uncertainty
    )
    assert phase.conclusive, phase.describe()
    assert len(phase.fates) == 15

    # The broken counterpart: the same file, cut as if the machine had stopped.
    cut = tmp_path / "cut.pcap"
    cut.write_bytes(path.read_bytes()[:-5])
    cut_report, cut_packets = CaptureReport.from_pcap(cut, expected_beacons=[start, end])
    assert cut_report.window_complete is False
    blind = correlate(
        log, cut_packets, capture=cut_report, clock=ClockMap.from_beacons(cut_report.beacons_seen)
    )
    assert not blind.conclusive
    assert all(fate.on_wire is not False for fate in blind.fates)  # never "not sent"
