"""Observing outside the sandbox: portable streams and beacons, and the clock map.

No privileges: the stream agent runs as a plain subprocess, the beacon agent
sends through a fake socket, and logs and sightings are built by hand so that
every broken instrument (a reboot, a suspend, a single beacon, an attempt
across a phase edge) is reached on purpose and comes out inconclusive.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any, ClassVar

import pytest
from scapy.layers.inet import IP, UDP
from scapy.packet import Raw

from nse import (
    BeaconSighting,
    ClockMap,
    SenderClock,
    StimulusStream,
    StreamLog,
    correlate,
    stimuli,
)
from nse._agents import beacon as agent
from nse._agents import stimulus as stream_agent
from nse.core import beacons, probe_packets
from nse.formats import beacon as beacon_format
from nse.models.stream import Fate

BOOT = "6f1c2b3a-4d5e-4f60-8a9b-0c1d2e3f4a5b"
OTHER_BOOT = "00000000-0000-4000-8000-000000000000"
TOKEN = "ab" * 16
DEST, PORT = "10.0.1.1", 9999
STREAM = StimulusStream(stimuli.udp(DEST, PORT), period=0.1)
PREFIX = "0123456789abcdef"


# --------------------------------------------------------------------------- beacon frames


def test_a_clocked_beacon_and_its_follow_up_round_trip() -> None:
    raw = beacon_format.clocked_frame("phase", TOKEN, BOOT, 1_500_000_000, 2_500_000_000)
    decoded = beacon_format.decode(raw)
    assert decoded == beacon_format.BeaconFrame(
        token=TOKEN, label="phase", follow_up=False, boot_id=BOOT, monotonic=1.5, boottime=2.5
    )
    assert beacon_format.parse(raw) == (TOKEN, "phase")
    follow = beacon_format.clocked_frame("ignored", TOKEN, BOOT, 3, 4, follow_up=True)
    assert beacon_format.decode(follow) is not None
    assert beacon_format.decode(follow).follow_up  # type: ignore[union-attr]
    assert beacon_format.decode(follow).label == ""  # type: ignore[union-attr]
    assert beacon_format.parse(follow) is None  # a follow-up is not a beacon of its own


def _corrupt(raw: bytes, at: int, value: int) -> bytes:
    data = bytearray(raw)
    data[at] = value
    return bytes(data)


def test_frames_that_are_not_beacons_are_not_decoded() -> None:
    clocked = beacon_format.clocked_frame("p", TOKEN, BOOT, 1, 2)
    version_at = beacon_format.HEADER + len(beacon_format.MAGIC)
    v1 = beacon_format.frame("label", TOKEN)
    assert beacon_format.decode(_corrupt(clocked, 12, 0x08)) is None  # EtherType
    assert beacon_format.decode(clocked[: beacon_format.HEADER + 10]) is None  # magic only
    assert beacon_format.decode(_corrupt(clocked, version_at, 9)) is None  # unknown version
    assert beacon_format.decode(_corrupt(clocked, version_at + 1, 7)) is None  # unknown kind
    assert beacon_format.decode(clocked[: version_at + 20]) is None  # cut fixed part
    assert beacon_format.decode(_corrupt(clocked, version_at + 2, 60)) is None  # cut label
    assert beacon_format.decode(v1[: version_at + 5]) is None  # cut version 1
    assert beacon_format.decode(_corrupt(v1, version_at + 1, 60)) is None


def test_the_core_module_still_offers_the_frame_format() -> None:
    assert beacons.frame is beacon_format.frame
    assert beacons.parse is beacon_format.parse
    assert beacons.ETHERTYPE == 0x88B5


# --------------------------------------------------------------------------- the beacon agent


def test_the_agent_builds_exactly_the_frames_nse_decodes() -> None:
    mac = bytes.fromhex("020000000001")
    for follow_up in (False, True):
        mine = agent.clocked_frame("lbl", TOKEN, BOOT, 11, 22, follow_up, mac)
        assert mine == beacon_format.clocked_frame(
            "lbl", TOKEN, BOOT, 11, 22, follow_up=follow_up, source_mac=mac
        )
    with pytest.raises(ValueError, match="64 bytes"):
        agent.clocked_frame("x" * 65, TOKEN, BOOT, 1, 2, False, mac)
    with pytest.raises(ValueError, match="32 hex"):
        agent.clocked_frame("x", "ab", BOOT, 1, 2, False, mac)


class _FakeSocket:
    sent: ClassVar[list[bytes]] = []

    def __init__(self, *args: Any) -> None:
        type(self).sent = []

    def __enter__(self) -> _FakeSocket:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def bind(self, address: Any) -> None:
        self.address = address

    def getsockname(self) -> tuple[Any, ...]:
        return ("eth0", 0, 0, 1, bytes.fromhex("020000000002"))

    def send(self, data: bytes) -> int:
        type(self).sent.append(data)
        return len(data)


def test_the_agent_sends_a_beacon_then_its_follow_up(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(agent.socket, "socket", _FakeSocket)
    monkeypatch.setattr(agent, "boot_id", lambda: BOOT)
    code = agent.main(["x", json.dumps({"iface": "eth0", "label": "go", "token": TOKEN})])
    assert code == 0
    first, second = (beacon_format.decode(frame) for frame in _FakeSocket.sent)
    assert first is not None
    assert second is not None
    assert (first.label, first.follow_up, second.follow_up) == ("go", False, True)
    assert first.boot_id == second.boot_id == BOOT
    assert first.boottime is not None
    assert second.boottime is not None
    assert first.boottime <= second.boottime
    beacon = beacons.agent_report(capsys.readouterr().out)
    assert beacon.token == TOKEN
    assert beacon.iface == "eth0"
    assert beacon.clock is not None
    assert beacon.clock.bracketed
    assert beacon.clock.boottime_before == pytest.approx(first.boottime, abs=1e-6)


def test_an_agent_that_cannot_send_says_so(capsys: pytest.CaptureFixture[str]) -> None:
    assert agent.main(["x", "{not json"]) == 1
    with pytest.raises(ValueError, match="could not send"):
        beacons.agent_report(capsys.readouterr().out.encode())


def test_the_agent_reads_this_machines_boot_id() -> None:
    assert agent.boot_id() == Path("/proc/sys/kernel/random/boot_id").read_text().strip()


def test_the_stream_agent_reports_no_clock_it_cannot_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert stream_agent._boot_id() == Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    monkeypatch.delattr(stream_agent.time, "CLOCK_BOOTTIME")
    assert stream_agent._boottime() is None

    def unreadable(*args: Any, **kwargs: Any) -> Any:
        raise PermissionError("no /proc")

    monkeypatch.setattr("builtins.open", unreadable)
    assert stream_agent._boot_id() is None


def test_agent_command_and_report() -> None:
    argv, token = beacons.agent_command("eth0", "phase", python="/usr/bin/python3")
    assert argv[:4] == ["/usr/bin/python3", "-I", "-S", "-c"]
    assert json.loads(argv[-1]) == {"iface": "eth0", "label": "phase", "token": token}
    assert len(token) == 32
    with pytest.raises(ValueError, match="64 bytes"):
        beacons.agent_command("eth0", "x" * 65)
    for output, message in (
        ("", "printed nothing"),
        ('{"event": "attempt"}\n', "not a beacon agent report"),
        ('{"event": "beacon"}\n', "unreadable"),
        ("garbage\n", "unreadable"),
    ):
        with pytest.raises(ValueError, match=message):
            beacons.agent_report(output)


# --------------------------------------------------------------------------- the clock map


def _sighting(
    seen_at: float,
    boottime: float,
    *,
    fork: float = 0.001,
    boot: str = BOOT,
    label: str = "b",
    bracketed: bool = True,
) -> BeaconSighting:
    return BeaconSighting(
        label=label,
        token=TOKEN,
        seen_at=seen_at,
        index=0,
        clock=SenderClock(
            boot_id=boot,
            monotonic_before=boottime,
            boottime_before=boottime,
            monotonic_after=boottime + fork if bracketed else None,
            boottime_after=boottime + fork if bracketed else None,
        ),
    )


def test_two_beacons_map_their_boot_with_an_honest_uncertainty() -> None:
    # Offsets 1000.0 and 1000.002: the spread and the widest fork both count.
    clock = ClockMap.from_beacons(
        [_sighting(1010.0005, 10.0), _sighting(1020.0025, 20.0, fork=0.001)]
    )
    assert clock.problems == ()
    (boot,) = clock.boots
    assert boot.beacons == 2
    assert boot.offset == pytest.approx(1000.001)
    assert boot.uncertainty == pytest.approx(0.003)
    mapped = clock.to_capture(BOOT, 15.0)
    assert mapped is not None
    assert mapped.time == pytest.approx(1015.001)
    assert mapped.uncertainty == pytest.approx(0.003)
    assert clock.to_capture(BOOT, 9.0) is None  # before the first beacon: never extrapolated
    assert clock.to_capture(BOOT, 21.0) is None
    assert clock.to_capture(OTHER_BOOT, 15.0) is None
    assert clock.to_capture(BOOT, None) is None


def test_a_single_beacon_maps_only_its_own_instant() -> None:
    clock = ClockMap.from_beacons([_sighting(1010.0, 10.0)])
    assert "a single beacon" in clock.problems[0]
    assert clock.to_capture(BOOT, 10.0005) is not None
    assert clock.to_capture(BOOT, 10.5) is None


def test_beacons_of_another_boot_never_map_this_one() -> None:
    clock = ClockMap.from_beacons(
        [_sighting(1010.0, 10.0), _sighting(1020.0, 20.0), _sighting(2000.0, 1.0, boot=OTHER_BOOT)]
    )
    assert {b.boot_id: b.beacons for b in clock.boots} == {BOOT: 2, OTHER_BOOT: 1}
    assert clock.to_capture(OTHER_BOOT, 15.0) is None


def test_beacons_that_cannot_be_used_are_listed() -> None:
    plain = BeaconSighting(label="v1", token=TOKEN, seen_at=1.0, index=0)
    backwards = _sighting(1.0, 10.0, fork=-1.0, label="back")
    clock = ClockMap.from_beacons(
        [plain, _sighting(1.0, 10.0, bracketed=False, label="half"), backwards]
    )
    assert clock.boots == ()
    text = " | ".join(clock.problems)
    assert "'v1' carries no clock" in text
    assert "'half': its follow-up was not seen" in text
    assert "'back': its clock ran backwards" in text


# --------------------------------------------------------------------------- stream logs


def _line(**event: Any) -> bytes:
    return (json.dumps(event) + "\n").encode()


def _attempt_line(seq: int, mono: float, boot: float | None) -> bytes:
    return _line(
        event="attempt",
        seq=seq,
        probe_id=f"{PREFIX}{seq:08x}",
        started_monotonic=mono,
        started_boottime=boot,
        outcome="sent",
        stage=None,
    )


def _run(boot_id: str = BOOT, attempts: int = 3, end: bool = True, base: float = 100.0) -> bytes:
    out = _line(event="started", monotonic=base, boottime=base + 50, boot_id=boot_id)
    for seq in range(1, attempts + 1):
        out += _attempt_line(seq, base + 0.1 * seq, base + 50 + 0.1 * seq)
    if end:
        out += _line(event="end", attempts=attempts, reason="stopped")
    return out


def _parse(output: bytes, final: bool = True) -> StreamLog:
    return StreamLog.parse(output, PREFIX, final=final, stream=STREAM)


def test_a_stream_run_elsewhere_is_parsed_with_its_clocks() -> None:
    log = _parse(_run())
    assert log.complete, log.problems
    assert log.boot_id == BOOT
    assert log.started_boottime == 150.0
    assert [a.started_boottime for a in log.attempts] == pytest.approx([150.1, 150.2, 150.3])
    assert log.period == STREAM.period


def test_a_reboot_in_the_middle_of_the_stream_is_never_complete() -> None:
    log = _parse(_run(BOOT, end=False) + _run(OTHER_BOOT))
    assert not log.complete
    text = " | ".join(log.problems)
    assert "spans 2 boots" in text
    assert "rebooted" in text
    assert "appear more than once" in text


def test_two_runs_on_one_boot_are_not_one_stream() -> None:
    log = _parse(_run() + _run())
    assert not log.complete
    assert any("2 runs of the stream" in p for p in log.problems)


def test_a_log_cut_because_the_machine_stopped_is_incomplete() -> None:
    output = _run(end=False) + b'{"event": "attempt", "se'
    assert _parse(output, final=False).problems == ()
    log = _parse(output)
    assert not log.complete
    assert "the stream's last line was cut off" in log.problems
    assert any("shut down or rebooted" in p for p in log.problems)


def test_command_runs_the_agent_anywhere_and_parse_reads_it() -> None:
    stream = StimulusStream(stimuli.udp("127.0.0.1", 9), period=0.01, count=3)
    argv, stream_id = stream.command(python=sys.executable)
    assert argv[0] == sys.executable
    assert len(stream_id) == 16
    output = subprocess.run(argv, capture_output=True, check=True, timeout=30).stdout
    log = StreamLog.parse(output, stream_id, final=True, stream=stream)
    assert log.complete, log.problems
    assert log.ended == "count"
    assert log.boot_id == Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    assert all(a.started_boottime is not None for a in log.attempts)
    assert [a.result.probe_id[:16] for a in log.attempts] == [stream_id] * 3


# --------------------------------------------------------------------------- suspend


def _log(times: list[tuple[float, float | None]], boot_id: str | None = BOOT) -> StreamLog:
    output = _line(event="started", monotonic=99.0, boottime=149.0, boot_id=boot_id)
    for seq, (mono, boot) in enumerate(times, 1):
        output += _attempt_line(seq, mono, boot)
    output += _line(event="end", attempts=len(times), reason="stopped")
    log = _parse(output)
    assert log.complete, log.problems
    return log


def test_a_suspend_is_a_gap_although_the_monotonic_clock_shows_none() -> None:
    # MONOTONIC advances 0.1s between seq 2 and 3, BOOTTIME 30.1s: 30s suspended.
    log = _log([(100.1, 150.1), (100.2, 150.2), (100.3, 180.3), (100.4, 180.4)])
    joined = correlate(log, None)
    (gap,) = joined.gaps
    assert (gap.after_seq, gap.before_seq) == (2, 3)
    assert gap.suspended == pytest.approx(30.0)
    assert gap.seconds == pytest.approx(30.1)
    assert not joined.conclusive
    assert "30.000s suspended" in joined.describe()
    during = joined.between(100.0, 100.5)
    assert during.gaps
    assert not during.conclusive


def test_clock_noise_is_not_a_suspend() -> None:
    log = _log([(100.1, 150.1), (100.2, 150.2000004), (100.3, None)])
    assert correlate(log, None).gaps == ()


# --------------------------------------------------------------------------- capture clock


def _two_beacon_map(boot: str = BOOT) -> ClockMap:
    # Both beacons give offset 1000 (no spread) with a 1 ms fork: uncertainty 0.001.
    return ClockMap.from_beacons(
        [_sighting(1150.0005, 150.0, boot=boot), _sighting(1151.0005, 151.0, boot=boot)]
    )


def _packet(seq: int) -> Any:
    marker = probe_packets.marker(f"{PREFIX}{seq:08x}")
    return IP(dst=DEST) / UDP(sport=40000, dport=PORT) / Raw(marker)


def _stream_log() -> StreamLog:
    return _log([(100.0 + 0.1 * s, 150.0 + 0.1 * s) for s in range(1, 10)])


def test_attempts_are_placed_on_the_capture_clock() -> None:
    joined = correlate(_stream_log(), [_packet(s) for s in range(1, 10)], clock=_two_beacon_map())
    assert joined.clock == "capture"
    assert [f.capture_time for f in joined.fates] == pytest.approx(
        [1150.0 + 0.1 * s for s in range(1, 10)]
    )
    assert joined.fates[0].capture_uncertainty == pytest.approx(0.001)
    assert joined.window_start == pytest.approx(1150.1)
    assert joined.window_end == pytest.approx(1150.9)
    assert not joined.problems[1:]  # only the missing capture report
    phase = joined.between(1150.25, 1150.75)
    assert [f.seq for f in phase.fates] == [3, 4, 5, 6, 7]
    assert phase.gaps == ()


def test_an_attempt_across_the_phase_edge_is_inconclusive() -> None:
    joined = correlate(_stream_log(), None, clock=_two_beacon_map())
    phase = joined.between(1150.3005, 1150.65)  # seq 3 at 1150.3 +- 0.001 crosses the start
    assert 3 not in [f.seq for f in phase.fates]
    assert any("seq 3" in p and "across the edge 1150.300500" in p for p in phase.problems)
    assert not phase.conclusive
    late = joined.between(1150.25, 1150.6995)  # seq 7 at 1150.7 crosses the end
    assert any("seq 7" in p and "across the edge 1150.699500" in p for p in late.problems)


def test_a_phase_the_stream_did_not_cover_on_the_capture_clock_has_gaps() -> None:
    joined = correlate(_stream_log(), None, clock=_two_beacon_map())
    assert joined.between(1140.0, 1141.0).gaps[0].after_seq is None  # nothing in it
    edges = joined.between(1149.0, 1152.0)
    assert [(g.after_seq, g.before_seq) for g in edges.gaps] == [(None, 1), (9, None)]
    sparse = _log([(100.1, 150.1), (100.9, 150.9)])
    inner = correlate(sparse, None, clock=_two_beacon_map()).between(1150.05, 1150.95)
    assert [(g.after_seq, g.before_seq) for g in inner.gaps] == [(1, 2)]


def test_a_map_from_a_single_beacon_leaves_the_window_inconclusive() -> None:
    single = ClockMap.from_beacons([_sighting(1150.0005, 150.0)])
    joined = correlate(_stream_log(), [_packet(s) for s in range(1, 10)], clock=single)
    assert all(f.capture_time is None for f in joined.fates)
    assert any("9 attempt(s) cannot be placed" in p for p in joined.problems)
    assert not joined.conclusive
    assert joined.window_start is None
    assert joined.between(1150.0, 1151.0).gaps  # nothing placed in it


def test_a_stream_from_a_boot_the_map_does_not_know_is_inconclusive() -> None:
    joined = correlate(_stream_log(), None, clock=_two_beacon_map(OTHER_BOOT))
    assert any("no mapping for the stream's boot 6f1c2b3a" in p for p in joined.problems)
    weak = ClockMap.from_beacons([_sighting(1.0, 1.0, boot=OTHER_BOOT, bracketed=False)])
    joined = correlate(_stream_log(), None, clock=weak)
    assert any("follow-up was not seen" in p for p in joined.problems)


def test_a_log_without_a_boot_id_cannot_be_placed() -> None:
    joined = correlate(_log([(100.1, 150.1)], boot_id=None), None, clock=_two_beacon_map())
    assert any("has no boot_id" in p for p in joined.problems)


def test_a_missing_attempt_stays_unplaced_on_the_capture_clock() -> None:
    log = _stream_log()
    holed = log.model_copy(update={"attempts": log.attempts[:2] + log.attempts[3:]})
    joined = correlate(holed, None, clock=_two_beacon_map())
    missing: Fate = joined.fates[2]
    assert missing.attempt is None
    assert missing.capture_time is None


def test_on_the_capture_clock_the_gaps_are_in_capture_time() -> None:
    log = _log([(100.1, 150.1), (100.2, 150.2), (100.3, 150.8), (100.4, 150.9)])  # 0.5s suspended
    joined = correlate(log, None, clock=_two_beacon_map())
    (gap,) = joined.gaps
    assert (gap.after_seq, gap.before_seq) == (2, 3)
    assert gap.start == pytest.approx(1150.2 - 0.001)
    assert gap.end == pytest.approx(1150.8 + 0.001)
    assert gap.suspended == 0.0  # the capture clock ran through the suspend
