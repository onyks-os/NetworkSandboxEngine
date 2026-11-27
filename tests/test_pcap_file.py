"""Reading pcap files NSE did not capture: every damage refused, never a clean window.

Files are built byte by byte, so each refusal of ``nse.formats.pcap.read`` and
each completeness rule of ``CaptureReport.from_pcap`` is reached on purpose.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

import pytest
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from nse import Beacon, CaptureReport, StimulusStream, correlate, stimuli
from nse.core import probe_packets
from nse.formats import beacon as beacon_format
from nse.formats import pcap

BOOT = "6f1c2b3a-4d5e-4f60-8a9b-0c1d2e3f4a5b"
START, END = "a" * 32, "b" * 32


def _udp(payload: bytes = b"x", dst: str = "10.0.1.1") -> bytes:
    return bytes(Ether() / IP(dst=dst) / UDP(sport=40000, dport=9999) / Raw(payload))


def _beacon(label: str, token: str, boottime: float) -> list[bytes]:
    before = beacon_format.clocked_frame(label, token, BOOT, int(5e9), int(boottime * 1e9))
    after = beacon_format.clocked_frame(
        label, token, BOOT, int(5e9) + 1000, int(boottime * 1e9) + 1000, follow_up=True
    )
    return [before, after]


def _expected(label: str, token: str) -> Beacon:
    return Beacon(label=label, token=token, iface="eth0", netns=None, sent_at=0, sent_monotonic=0)


def _write(path: Path, frames: list[bytes], **kw: Any) -> Path:
    pcap.write(path, [(1000.0 + i * 0.01, frame) for i, frame in enumerate(frames)], **kw)
    return path


# --------------------------------------------------------------------------- the reader


def _header(
    magic: int = 0xA1B2C3D4, version: tuple[int, int] = (2, 4), snaplen: int = 128
) -> bytes:
    return struct.pack("<IHHiIII", magic, *version, 0, 0, snaplen, 1)


def _record(incl: int, orig: int, data: bytes | None = None, frac: int = 0) -> bytes:
    body = b"\x00" * incl if data is None else data
    return struct.pack("<IIII", 1000, frac, incl, orig) + body


@pytest.mark.parametrize(
    ("raw", "error"),
    [
        (b"", "empty file header (0 of 24 bytes)"),
        (_header()[:10], "truncated file header (10 of 24 bytes)"),
        (struct.pack("<I", 0x0A0D0D0A) + b"\x00" * 20, "a pcapng file"),
        (struct.pack("<I", 0xDEADBEEF) + b"\x00" * 20, "not a pcap file (magic 0xdeadbeef)"),
        (_header(version=(2, 3)), "unsupported pcap version 2.3"),
        (_header() + _record(60, 60)[:10], "record 1 header cut short (10 of 16 bytes)"),
        (_header() + _record(60, 60, b"\x00" * 20), "record 1 frame cut short (20 of 60 bytes)"),
        (_header() + _record(60, 50), "record 1 claims 60 bytes of 50"),
        (_header(snaplen=40) + _record(60, 60), "record 1 claims 60 bytes of 60 (snap length 40)"),
        (_header() + _record(10, 10, frac=1_000_000), "invalid timestamp fraction"),
    ],
)
def test_every_structural_damage_is_refused(tmp_path: Path, raw: bytes, error: str) -> None:
    path = tmp_path / "x.pcap"
    path.write_bytes(raw)
    contents = pcap.read(path)
    assert contents.error is not None
    assert error in contents.error


def test_records_before_the_damage_are_kept(tmp_path: Path) -> None:
    path = tmp_path / "x.pcap"
    path.write_bytes(_header() + _record(10, 10) + _record(10, 30) + _record(60, 60)[:20])
    contents = pcap.read(path)
    assert [r.index for r in contents.records] == [1, 2]
    assert contents.records[1].truncated
    assert "record 3" in (contents.error or "")


def test_every_byte_order_and_resolution_is_read(tmp_path: Path) -> None:
    for magic, order, units in (
        (0xA1B2C3D4, "<", 1e6),
        (0xA1B2C3D4, ">", 1e6),
        (0xA1B23C4D, "<", 1e9),
        (0xA1B23C4D, ">", 1e9),
    ):
        path = tmp_path / "x.pcap"
        header = struct.pack(order + "IHHiIII", magic, 2, 4, 0, 0, 65535, 0x10000001)
        record = struct.pack(order + "IIII", 7, int(units // 2), 3, 3) + b"abc"
        path.write_bytes(header + record)
        contents = pcap.read(path)
        assert contents.error is None
        assert contents.link_type == 1  # FCS flag bits removed
        assert contents.nanosecond is (units == 1e9)
        assert contents.records[0].timestamp == pytest.approx(7.5)
        assert contents.records[0].data == b"abc"


def test_an_unreadable_file_is_reported_not_raised(tmp_path: Path) -> None:
    contents = pcap.read(tmp_path / "missing.pcap")
    assert "cannot be read" in (contents.error or "")


def test_written_records_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "x.pcap"
    pcap.write(path, [(1.9999999, b"a" * 10), (2.5, b"b" * 300)], snaplen=128)
    contents = pcap.read(path)
    assert contents.error is None
    assert [r.timestamp for r in contents.records] == [2.0, 2.5]
    assert len(contents.records[1].data) == 128
    assert contents.records[1].original_length == 300


# --------------------------------------------------------------------------- from_pcap


def test_an_intact_file_with_every_beacon_is_complete(tmp_path: Path) -> None:
    frames = [*_beacon("start", START, 10.0), _udp(), _udp(), *_beacon("end", END, 11.0)]
    path = _write(tmp_path / "x.pcap", frames, snaplen=128)
    report, packets = CaptureReport.from_pcap(
        path, required_bytes=96, expected_beacons=[_expected("start", START), _expected("end", END)]
    )
    assert report.source == "pcap_file"
    assert report.window_complete is True, report
    assert report.kernel_drops is None
    assert report.link_type == 1
    assert report.snaplen == 128
    assert report.snaplen_sufficient is True
    assert report.packets_observed == 6
    assert report.packets_stored == 2
    assert [bytes(p) for p in packets] == [_udp(), _udp()]  # beacons never in the packets
    assert packets[0].time == pytest.approx(1000.02)
    start = report.beacons_seen[0]
    assert (start.label, start.token, start.index) == ("start", START, 0)
    assert start.clock is not None
    assert start.clock.bracketed
    assert start.clock.boot_id == BOOT
    assert start.clock.boottime_before == pytest.approx(10.0)
    assert start.clock.boottime_after == pytest.approx(10.000001)


def test_a_missing_closing_beacon_makes_the_window_incomplete(tmp_path: Path) -> None:
    path = _write(tmp_path / "x.pcap", [*_beacon("start", START, 10.0), _udp()])
    report, _ = CaptureReport.from_pcap(
        path, expected_beacons=[_expected("start", START), _expected("end", END)]
    )
    assert report.beacons_missing == ["end"]
    assert report.window_complete is False


def test_without_expected_beacons_nothing_shows_the_window_is_covered(tmp_path: Path) -> None:
    report, _ = CaptureReport.from_pcap(_write(tmp_path / "x.pcap", [_udp()]))
    assert report.instrument_healthy
    assert report.window_complete is None


def test_a_truncated_file_is_never_complete(tmp_path: Path) -> None:
    path = _write(tmp_path / "x.pcap", [*_beacon("start", START, 10.0), _udp(), _udp()])
    path.write_bytes(path.read_bytes()[:-7])  # the machine stopped mid-record
    report, packets = CaptureReport.from_pcap(path, expected_beacons=[_expected("start", START)])
    assert report.artifact_complete is False
    assert not report.instrument_healthy
    assert report.window_complete is False
    assert "frame cut short" in report.errors[0]
    assert len(packets) == 1  # what was read before the damage still counts


def test_a_snap_length_below_the_required_bytes_is_incomplete(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "x.pcap", [*_beacon("start", START, 10.0), _udp(b"y" * 200)], snaplen=128
    )
    report, _ = CaptureReport.from_pcap(
        path, required_bytes=256, expected_beacons=[_expected("start", START)]
    )
    assert report.packets_truncated == 1
    assert report.snaplen_sufficient is False
    assert report.window_complete is False


def test_a_link_type_scapy_cannot_decode_is_an_error(tmp_path: Path) -> None:
    path = _write(tmp_path / "x.pcap", [b"abc"], link_type=147)  # LINKTYPE_USER0
    report, packets = CaptureReport.from_pcap(path)
    assert packets == []
    assert "link type 147 cannot be decoded" in report.errors[0]
    assert report.window_complete is False


def test_a_raw_ip_file_is_decoded_without_beacons(tmp_path: Path) -> None:
    raw = bytes(IP(dst="10.0.1.1") / UDP(dport=9999))
    report, packets = CaptureReport.from_pcap(_write(tmp_path / "x.pcap", [raw], link_type=101))
    assert report.link_type == 101
    assert packets[0][UDP].dport == 9999


def test_a_record_scapy_fails_on_is_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from nse.models import _pcap_report

    def broken(link_type: int | None) -> Any:
        def decode(data: bytes) -> Any:
            raise ValueError("bad")

        return decode

    monkeypatch.setattr(_pcap_report, "_decoder", broken)
    report, packets = CaptureReport.from_pcap(_write(tmp_path / "x.pcap", [_udp()]))
    assert packets == []
    assert "record 1 cannot be decoded" in report.errors[0]


def test_follow_ups_complete_only_their_own_beacon(tmp_path: Path) -> None:
    before = beacon_format.clocked_frame("s", START, BOOT, 1, 2)
    stray = beacon_format.clocked_frame("", END, BOOT, 3, 4, follow_up=True)  # no such beacon
    other_boot = beacon_format.clocked_frame(
        "", START, "00000000-0000-4000-8000-000000000000", 3, 4, follow_up=True
    )
    v1 = beacon_format.frame("old", "c" * 32)
    path = _write(tmp_path / "x.pcap", [before, stray, other_boot, v1])
    report, packets = CaptureReport.from_pcap(path)
    assert packets == []
    first, old = report.beacons_seen
    assert first.clock is not None
    assert not first.clock.bracketed
    assert old.clock is None


def test_an_empty_intact_file_takes_its_time_from_the_file(tmp_path: Path) -> None:
    path = _write(tmp_path / "x.pcap", [])
    report, _ = CaptureReport.from_pcap(path, expected_beacons=[_expected("start", START)])
    assert report.started_at == pytest.approx(path.stat().st_mtime)
    assert report.window_complete is False
    missing, _ = CaptureReport.from_pcap(tmp_path / "none.pcap")
    assert missing.started_at is None
    assert missing.start_requested_at == 0.0


def test_correlate_accepts_an_absence_only_from_a_complete_file(tmp_path: Path) -> None:
    from nse.models.stream import StreamAttempt, StreamLog

    stream = StimulusStream(stimuli.udp("10.0.1.1", 9999), period=0.1)
    stimulus = stream.stimulus
    prefix = "0123456789abcdef"

    def attempt(seq: int) -> StreamAttempt:
        probe = f"{prefix}{seq:08x}"
        return StreamAttempt(
            seq=seq,
            started_monotonic=0.1 * seq,
            result=stimulus._from_report(probe, {"outcome": "sent", "stage": None}, None),
        )

    log = StreamLog(
        stream_id=prefix,
        period=0.1,
        attempts=(attempt(1), attempt(2)),
        ended="stopped",
        complete=True,
    )
    seen = _udp(probe_packets.marker(f"{prefix}{1:08x}"))
    expected = [_expected("start", START), _expected("end", END)]
    frames = [*_beacon("start", START, 10.0), seen, *_beacon("end", END, 11.0)]
    report, packets = CaptureReport.from_pcap(
        _write(tmp_path / "a.pcap", frames), expected_beacons=expected
    )
    joined = correlate(log, packets, capture=report)
    assert joined.conclusive, joined.describe()
    assert [f.status for f in joined.fates] == ["on_wire", "sent_not_seen"]

    cut, cut_packets = CaptureReport.from_pcap(
        _write(tmp_path / "b.pcap", frames[:-2]), expected_beacons=expected
    )
    blind = correlate(log, cut_packets, capture=cut)
    assert not blind.conclusive
    assert blind.fates[1].on_wire is None  # never "not sent"
