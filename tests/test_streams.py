"""Stimulus streams and correlate(), without privileges.

Streams run on loopback through the real launch chain (``local_sandbox``);
correlate() is fed hand-built logs, packets and capture reports so every
status, gap and contradiction is reached deliberately, including the blind
setups that must come out inconclusive.
"""

from __future__ import annotations

import asyncio
import socket
import stat
from pathlib import Path
from typing import Any

import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Raw

from nse import (
    CaptureReport,
    Endpoint,
    Receipt,
    ReceiptLog,
    StimulusStream,
    StreamAttempt,
    StreamLog,
    StreamStartError,
    correlate,
    stimuli,
)
from nse.core import probe_packets
from nse.models.process import EffectiveIdentity, ProcessResult
from nse.models.stream import Fate, Gap
from nse.streams import RunningStream

PREFIX = "0123456789abcdef"
DEST = "10.9.9.9"
PORT = 9999


# --------------------------------------------------------------------------- helpers


def _probe(seq: int) -> str:
    return f"{PREFIX}{seq:08x}"


def _attempt(
    seq: int,
    started: float,
    outcome: str = "sent",
    stage: str | None = None,
    stimulus: stimuli.Stimulus | None = None,
    source_port: int | None = None,
) -> StreamAttempt:
    stimulus = stimulus or stimuli.udp(DEST, PORT)
    report: dict[str, Any] = {"outcome": outcome, "stage": stage}
    if source_port is not None:
        report["source"] = ["10.9.9.1", source_port]
    return StreamAttempt(
        seq=seq,
        started_monotonic=started,
        result=stimulus._from_report(_probe(seq), report, None),
    )


def _log(
    *attempts: StreamAttempt, complete: bool = True, problems: tuple[str, ...] = ()
) -> StreamLog:
    return StreamLog(
        stream_id=PREFIX,
        period=0.1,
        started_monotonic=0.0,
        attempts=attempts,
        ended="stopped",
        complete=complete,
        problems=problems,
    )


def _even(count: int, outcome: str = "sent") -> list[StreamAttempt]:
    return [_attempt(seq, 100.0 + 0.1 * seq, outcome) for seq in range(1, count + 1)]


def _packet(seq: int, dest: str = DEST) -> Any:
    return IP(dst=dest) / UDP(sport=40000, dport=PORT) / Raw(probe_packets.marker(_probe(seq)))


def _capture(**overrides: Any) -> CaptureReport:
    fields: dict[str, Any] = {
        "iface": "veth0",
        "netns": None,
        "requested_filter": None,
        "effective_filter": "x",
        "default_filter_replaced": False,
        "backend": "scapy",
        "backend_version": "2.6",
        "output_mode": "memory",
        "termination": "stopped",
        "start_requested_at": 1.0,
        "started_at": 1.0,
        "stopped_at": 2.0,
        "packets_observed": 0,
        "bytes_observed": 0,
        "packets_stored": 0,
        "kernel_packets": 0,
        "kernel_drops": 0,
    }
    fields.update(overrides)
    return CaptureReport(**fields)


def _receipt(index: int, probe_id: str | None, source_port: int = 40000) -> Receipt:
    return Receipt(
        seq=index,
        transport="udp",
        kind="datagram",
        family=4,
        source=Endpoint(address="10.9.9.1", port=source_port),
        destination=Endpoint(address=DEST, port=PORT),
        monotonic=1.0,
        wall=1.0,
        size=10,
        data=b"",
        response="none",
        probe_id=probe_id,
    )


# --------------------------------------------------------------------------- the stream


def test_stream_arguments_are_validated() -> None:
    probe = stimuli.udp(DEST, PORT)
    for bad in ({"period": 0}, {"period": 1, "count": 0}, {"period": 1, "duration": 0}):
        with pytest.raises(ValueError):
            StimulusStream(probe, **bad)
    with pytest.raises(ValueError):
        StimulusStream(probe, period=1, max_in_flight=0)


def test_the_plan_is_the_stimulus_plan_plus_a_schedule() -> None:
    plan = StimulusStream(stimuli.udp(DEST, PORT), period=0.5, count=3).plan(PREFIX)
    assert plan["stream"] == {
        "prefix": PREFIX,
        "template_id": PREFIX + "00000000",
        "period": 0.5,
        "count": 3,
        "duration": None,
        "max_in_flight": 256,
    }
    assert bytes.fromhex(plan["payload"]) == probe_packets.marker(PREFIX + "00000000")


def _udp_sink() -> socket.socket:
    sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sink.bind(("127.0.0.1", 0))
    sink.setblocking(False)
    return sink


def _drain(sink: socket.socket) -> list[bytes]:
    data = []
    while True:
        try:
            data.append(sink.recv(2048))
        except BlockingIOError:
            return data


@pytest.mark.asyncio
async def test_a_counted_stream_numbers_every_attempt_and_ends_by_itself(
    local_sandbox: Any,
) -> None:
    with _udp_sink() as sink:
        stream = StimulusStream(
            stimuli.udp("127.0.0.1", sink.getsockname()[1]), period=0.01, count=5
        )
        running = await stream.start(local_sandbox)
        log = await running.wait(10)
        datagrams = _drain(sink)
    assert log.complete, log.problems
    assert log.ended == "count"
    assert [a.seq for a in log.attempts] == [1, 2, 3, 4, 5]
    assert all(a.result.outcome == "sent" for a in log.attempts)
    ids = [a.result.probe_id for a in log.attempts]
    assert ids == [f"{running.stream_id}{seq:08x}" for seq in range(1, 6)]
    assert sorted(datagrams) == sorted(probe_packets.marker(i) for i in ids)
    starts = [a.started_monotonic for a in log.attempts]
    assert starts == sorted(starts)
    assert log.started_monotonic is not None
    assert log.started_monotonic <= starts[0]
    assert await running.stop() is log  # final, and stop() after the end is harmless
    assert running.log() is log


@pytest.mark.asyncio
async def test_a_stopped_stream_reports_a_complete_log(local_sandbox: Any) -> None:
    with _udp_sink() as sink:
        stream = StimulusStream(stimuli.udp("127.0.0.1", sink.getsockname()[1]), period=0.01)
        async with await stream.start(local_sandbox) as running:
            await asyncio.sleep(0.2)
            partial = running.log()
        log = running.log()
    assert not partial.complete  # still running: not final
    assert log.complete, log.problems
    assert log.ended == "stopped"
    assert len(log.attempts) >= len(partial.attempts) >= 1
    joined = correlate(partial, None)
    assert not joined.conclusive
    assert any("not final" in problem for problem in joined.problems)


@pytest.mark.asyncio
async def test_a_stream_with_a_duration_ends_by_itself(local_sandbox: Any) -> None:
    with _udp_sink() as sink:
        stream = StimulusStream(
            stimuli.udp("127.0.0.1", sink.getsockname()[1]), period=0.05, duration=0.2
        )
        log = await (await stream.start(local_sandbox)).wait(10)
    assert log.complete, log.problems
    assert log.ended == "duration"
    assert 1 <= len(log.attempts) <= 4


@pytest.mark.asyncio
async def test_bare_syns_of_a_stream_leave_from_distinct_source_ports(
    local_sandbox: Any,
) -> None:
    with socket.socket() as closed:
        closed.bind(("127.0.0.1", 0))
        port = closed.getsockname()[1]  # bound, not listening: every SYN is reset
        stream = StimulusStream(stimuli.tcp_connect("127.0.0.1", port), period=0.01, count=4)
        log = await (await stream.start(local_sandbox)).wait(20)
    assert log.complete, log.problems
    ports = [a.result.source.port for a in log.attempts if a.result.source]
    assert len(ports) == 4
    assert ports == list(range(ports[0], ports[0] + 4))
    assert {a.result.outcome for a in log.attempts} == {"refused"}


@pytest.mark.asyncio
async def test_a_stream_whose_interpreter_is_missing_does_not_start(
    local_sandbox: Any,
) -> None:
    stream = StimulusStream(stimuli.udp("127.0.0.1", 9), period=0.1)
    with pytest.raises(StreamStartError, match="could not start"):
        await stream.start(local_sandbox, python="/nonexistent/python3")


@pytest.mark.asyncio
async def test_a_stream_program_that_exits_at_once_did_not_start(local_sandbox: Any) -> None:
    stream = StimulusStream(stimuli.udp("127.0.0.1", 9), period=0.1)
    with pytest.raises(StreamStartError, match="did not start") as caught:
        await stream.start(local_sandbox, python="/bin/false")
    assert caught.value.result is not None


@pytest.mark.asyncio
async def test_a_stream_that_never_says_it_started_is_stopped(
    local_sandbox: Any, tmp_path: Path
) -> None:
    silent = tmp_path / "silent"
    silent.write_text("#!/bin/sh\nexec sleep 30\n")
    silent.chmod(silent.stat().st_mode | stat.S_IXUSR)
    stream = StimulusStream(stimuli.udp("127.0.0.1", 9), period=0.1)
    with pytest.raises(StreamStartError, match=r"within 0\.3s") as caught:
        await stream.start(local_sandbox, python=str(silent), ready_timeout=0.3)
    assert caught.value.result is not None
    assert caught.value.result.termination != "exited"


# --------------------------------------------------------------------------- reading the log


class FakeProcess:
    def __init__(self, stdout: bytes, dropped: bool = False) -> None:
        self.stdout = stdout
        self.dropped = dropped

    def output(self, stream: str) -> bytes:
        return self.stdout

    def output_dropped(self, stream: str) -> bool:
        return self.dropped


def _running(stdout: bytes, dropped: bool = False) -> RunningStream:
    stream = StimulusStream(stimuli.udp(DEST, PORT), period=0.1)
    return RunningStream(stream, FakeProcess(stdout, dropped), PREFIX)  # type: ignore[arg-type]


def _line(seq: int, **extra: Any) -> bytes:
    import json

    event = {
        "event": "attempt",
        "seq": seq,
        "probe_id": _probe(seq),
        "started_monotonic": 10.0 + seq,
        "outcome": "sent",
        "stage": None,
    }
    event.update(extra)
    return json.dumps(event).encode() + b"\n"


START = b'{"event": "started", "monotonic": 10.0}\n'
STATUS = "Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nGroups:\t\nCapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapBnd:\t0\nCapAmb:\t0\n"


def _result(termination: str = "exited", returncode: int = 0) -> ProcessResult:
    return ProcessResult(
        argv=["python"],
        command=["python"],
        pid=1000,
        identity=EffectiveIdentity.from_status(STATUS),
        termination=termination,  # type: ignore[arg-type]
        returncode=returncode,
        stdout=b"",
        stderr=b"boom",
        started_at=0,
        ended_at=1,
    )


def test_a_full_log_is_complete() -> None:
    end = b'{"event": "end", "attempts": 2, "reason": "count"}\n'
    log = _running(START + _line(1) + _line(2) + end)._parse(
        START + _line(1) + _line(2) + end, final=True, result=_result()
    )
    assert log.complete
    assert log.ended == "count"
    assert log.attempt(2) is not None
    assert log.attempt(3) is None


@pytest.mark.parametrize(
    ("stdout", "dropped", "result", "problem"),
    [
        (START + _line(1) + b'{"event": "att', False, _result(), "cut off"),
        (START + b"not json\n" + _line(1), False, _result(), "unreadable line"),
        (START + b'{"event": "other"}\n', False, _result(), "unknown event"),
        (START + _line(1) + b'{"event": "end", "attempts": 3}\n', False, _result(), "missing"),
        (START + _line(2), False, _result(), "missing from the log, first seq 1"),
        (START + _line(1), True, _result(), "exceeded the limit"),
        (START + _line(1), False, _result("terminated", -9), "without reporting its end"),
        (START + _line(1), False, None, "was killed"),
        (
            START + _line(1) + b'{"event": "end", "attempts": 1}\n',
            False,
            _result(returncode=3),
            "exited with status 3",
        ),
        (START + _line(1, outcome="bogus"), False, _result(), "unknown outcome"),
    ],
)
def test_a_damaged_log_is_never_complete(
    stdout: bytes, dropped: bool, result: ProcessResult | None, problem: str
) -> None:
    log = _running(stdout, dropped)._parse(stdout, final=True, result=result)
    assert not log.complete
    assert any(problem in p for p in log.problems), log.problems


def test_an_unfinished_line_is_not_a_problem_while_the_stream_runs() -> None:
    log = _running(b"")._parse(START + _line(1) + b'{"ev', final=False, result=None)
    assert log.problems == ()
    assert not log.complete


# --------------------------------------------------------------------------- correlate


def test_every_status_is_reached_and_a_complete_window_is_conclusive() -> None:
    attempts = [
        _attempt(1, 100.0),  # received
        _attempt(2, 100.1),  # on the wire only
        _attempt(3, 100.2),  # sent, not seen
        _attempt(4, 100.3, "refused", "send"),
        _attempt(5, 100.4),
    ]
    receipts = ReceiptLog(receipts=(_receipt(1, _probe(1)),), complete=True)
    packets = [_packet(1), _packet(2), _packet(5), _packet(99, dest="10.0.0.1")]
    joined = correlate(_log(*attempts), packets, receipts, capture=_capture())
    assert [f.status for f in joined.fates] == [
        "received",
        "on_wire",
        "sent_not_seen",
        "refused",
        "on_wire",
    ]
    assert joined.conclusive, joined.describe()
    assert all(f.conclusive for f in joined.fates)
    assert joined.counts() == {"received": 1, "on_wire": 2, "sent_not_seen": 1, "refused": 1}
    assert [f.seq for f in joined.with_status("refused", "sent_not_seen")] == [3, 4]
    assert joined.window_start == 100.0
    assert joined.window_end == 100.4
    assert "received: 1" in joined.describe()


def test_without_a_capture_nothing_is_said_about_the_wire() -> None:
    joined = correlate(_log(*_even(3)), None)
    assert {f.on_wire for f in joined.fates} == {None}
    assert {f.received for f in joined.fates} == {None}
    assert not joined.conclusive
    assert not any(f.conclusive for f in joined.fates)
    assert "INCONCLUSIVE: no capture" in joined.describe()


@pytest.mark.parametrize(
    "capture",
    [
        None,
        _capture(termination="backend_terminated", errors=["backend died"]),
        _capture(kernel_drops=3),
        _capture(kernel_packets=None, kernel_drops=None),
    ],
)
def test_a_capture_that_cannot_vouch_leaves_absences_unknown(
    capture: CaptureReport | None,
) -> None:
    joined = correlate(_log(*_even(2)), [_packet(1)], capture=capture)
    assert [f.on_wire for f in joined.fates] == [True, None]
    assert [f.status for f in joined.fates] == ["on_wire", "sent_not_seen"]
    assert not joined.fates[1].conclusive
    assert not joined.conclusive
    assert any("vouch" in p for p in joined.problems)


def test_a_missing_beacon_makes_the_correlation_inconclusive() -> None:
    from nse import Beacon

    blind = _capture(
        beacons_expected=[
            Beacon(
                label="start", token="0" * 32, iface="v", netns=None, sent_at=1, sent_monotonic=1
            )
        ]
    )
    assert blind.window_complete is False
    joined = correlate(_log(*_even(2)), [], capture=blind)
    assert not joined.conclusive
    assert [f.on_wire for f in joined.fates] == [None, None]


def test_an_incomplete_receiver_log_proves_no_absence() -> None:
    receipts = ReceiptLog(complete=False, problems=("output cut",))
    joined = correlate(_log(*_even(1)), [_packet(1)], receipts, capture=_capture())
    assert joined.fates[0].received is None
    assert joined.fates[0].status == "on_wire"
    assert not joined.fates[0].conclusive
    assert any("output cut" in p for p in joined.problems)


def test_receipts_without_a_probe_id_match_by_source_port() -> None:
    probe = stimuli.tcp_connect(DEST, PORT)
    attempts = [_attempt(1, 1.0, "answered", stimulus=probe, source_port=41001)]
    receipts = ReceiptLog(receipts=(_receipt(1, None, source_port=41001),), complete=True)
    receipts = ReceiptLog(
        receipts=(receipts.receipts[0].model_copy(update={"transport": "tcp"}),), complete=True
    )
    syn = IP(dst=DEST) / TCP(sport=41001, dport=PORT, flags="S")
    joined = correlate(_log(*attempts), [syn], receipts, capture=_capture())
    assert joined.fates[0].status == "received"
    assert joined.fates[0].on_wire is True


def test_a_capture_blind_to_the_path_is_a_contradiction() -> None:
    receipts = ReceiptLog(receipts=(_receipt(1, _probe(1)),), complete=True)
    joined = correlate(_log(*_even(1)), [], receipts, capture=_capture())
    assert joined.fates[0].status == "received"
    assert not joined.conclusive
    assert "blind to this path" in joined.contradictions[0]
    assert "CONTRADICTION" in joined.describe()


@pytest.mark.parametrize(("outcome", "stage"), [("could_not_run", "socket"), ("refused", "send")])
def test_a_packet_the_process_says_never_left_is_a_contradiction(outcome: str, stage: str) -> None:
    attempts = [_attempt(1, 1.0), _attempt(2, 1.1, outcome, stage)]
    joined = correlate(_log(*attempts), [_packet(2)], capture=_capture())
    assert "the probe's report is wrong" in joined.contradictions[0]


def test_attempts_missing_from_the_log_are_not_sent_and_inconclusive() -> None:
    attempts = [_attempt(1, 1.0), _attempt(3, 1.2)]
    log = _log(*attempts, complete=False, problems=("1 attempt(s) missing from the log",))
    joined = correlate(log, [_packet(1), _packet(3)], capture=_capture())
    assert [f.status for f in joined.fates] == ["on_wire", "not_sent", "on_wire"]
    missing = joined.fates[1]
    assert missing.attempt is None
    assert missing.started_monotonic is None
    assert not missing.conclusive
    assert not joined.conclusive
    assert any("missing from the log" in p for p in joined.problems)


def test_a_pause_longer_than_the_allowed_periods_is_a_gap() -> None:
    attempts = [_attempt(1, 1.0), _attempt(2, 1.1), _attempt(3, 1.6), _attempt(4, 1.7)]
    joined = correlate(_log(*attempts), [], capture=_capture())
    assert joined.gaps == (Gap(start=1.1, end=1.6, after_seq=2, before_seq=3),)
    assert joined.gaps[0].seconds == pytest.approx(0.5)
    assert not joined.conclusive
    assert "gaps: 0.500s after seq 2" in joined.describe()
    assert correlate(_log(*attempts), [], capture=_capture(), max_gap_periods=6).conclusive


def test_attempts_that_could_not_run_cover_no_time() -> None:
    attempts = [
        _attempt(1, 1.0),
        _attempt(2, 1.1, "could_not_run", "socket"),
        _attempt(3, 1.2, "could_not_run", "socket"),
        _attempt(4, 1.3, "could_not_run", "socket"),
        _attempt(5, 1.4),
    ]
    joined = correlate(_log(*attempts), [], capture=_capture())
    assert [f.status for f in joined.fates][1:4] == ["not_sent"] * 3
    assert len(joined.gaps) == 1
    assert not joined.conclusive


def test_a_stream_that_never_ran_tested_nothing() -> None:
    joined = correlate(_log(*_even(3, "could_not_run")), [], capture=_capture())
    assert not joined.conclusive
    assert any("nothing was tested" in p for p in joined.problems)
    assert joined.window_start is None
    empty = correlate(_log(), [], capture=_capture())
    assert empty.fates == ()
    assert not empty.conclusive


def test_max_gap_periods_is_validated() -> None:
    with pytest.raises(ValueError):
        correlate(_log(), None, max_gap_periods=0.5)


def test_a_slice_reports_the_gaps_at_its_edges() -> None:
    joined = correlate(_log(*_even(10)), [], capture=_capture())  # 100.1 .. 101.0
    assert joined.conclusive
    inside = joined.between(100.25, 100.75)
    assert [f.seq for f in inside.fates] == [3, 4, 5, 6, 7]
    assert inside.conclusive
    assert (inside.window_start, inside.window_end) == (100.25, 100.75)
    late = joined.between(100.5, 102.0)
    assert late.gaps[-1].after_seq == 10
    assert late.gaps[-1].before_seq is None
    assert not late.conclusive
    early = joined.between(99.0, 100.5)
    assert early.gaps[0].after_seq is None
    assert early.gaps[0].before_seq == 1
    nothing = joined.between(200.0, 201.0)
    assert nothing.fates == ()
    assert nothing.gaps == (Gap(start=200.0, end=201.0, after_seq=None, before_seq=None),)
    with pytest.raises(ValueError):
        joined.between(2.0, 1.0)


def test_a_slice_keeps_the_problems_of_the_whole() -> None:
    joined = correlate(_log(*_even(5)), None)
    assert not joined.between(100.1, 100.5).conclusive


@pytest.mark.parametrize(
    ("status", "on_wire", "received", "conclusive"),
    [
        ("received", None, True, True),
        ("on_wire", True, False, True),
        ("on_wire", True, None, False),
        ("sent_not_seen", False, False, True),
        ("sent_not_seen", False, None, True),
        ("sent_not_seen", None, None, False),
        ("refused", False, None, True),
    ],
)
def test_a_fate_is_conclusive_only_on_vouched_facts(
    status: str, on_wire: bool | None, received: bool | None, conclusive: bool
) -> None:
    fate = Fate(
        seq=1,
        status=status,  # type: ignore[arg-type]
        attempt=_attempt(1, 1.0),
        on_wire=on_wire,
        received=received,
    )
    assert fate.conclusive is conclusive
    assert fate.covers


def test_the_index_matches_exactly_what_request_packets_matches() -> None:
    for probe, packets in (
        (
            stimuli.udp("fd00::2", PORT),
            [
                IPv6(dst="fd00::2")
                / UDP(sport=1, dport=PORT)
                / Raw(probe_packets.marker(_probe(1))),
                IPv6(dst="fd00::2")
                / UDP(sport=1, dport=PORT + 1)
                / Raw(probe_packets.marker(_probe(1))),
                IPv6(dst="fd00::2")
                / TCP(sport=1, dport=PORT)
                / Raw(probe_packets.marker(_probe(1))),
            ],
        ),
        (
            stimuli.icmp_echo(DEST),
            [
                Raw(b"not ip"),
                IP(bytes(IP(dst=DEST, proto=1) / Raw(probe_packets.icmp_echo(_probe(1), 4)))),
                IP(dst=DEST) / UDP(),
            ],
        ),
    ):
        attempt = _attempt(1, 1.0, stimulus=probe)
        index = probe_packets.RequestIndex(attempt.result, packets)
        found = index.requests(attempt.result)
        assert found == probe_packets.request_packets(attempt.result, packets)
        assert len(found) == 1, probe.kind


def test_correlate_with_nat_follows_a_rewritten_destination() -> None:
    attempts = [_attempt(1, 1.0, source_port=40001), _attempt(2, 1.1, source_port=40002)]
    rewritten = [
        IP(src="10.9.9.1", dst="192.0.2.9")
        / UDP(sport=40000 + seq, dport=5353)
        / Raw(probe_packets.marker(_probe(seq)))
        for seq in (1, 2)
    ]
    strict = correlate(_log(*attempts), rewritten, capture=_capture())
    assert strict.counts() == {"sent_not_seen": 2}
    followed = correlate(_log(*attempts), rewritten, capture=_capture(), nat=True)
    assert followed.counts() == {"on_wire": 2}


@pytest.mark.asyncio
async def test_a_stream_that_cannot_find_setpriv_does_not_start(
    local_sandbox: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    import os

    from nse.core import paths
    from nse.models.process import ProcessIdentity
    from nse.streams import StimulusStream, StreamStartError

    paths.clear_cache()
    monkeypatch.setattr(paths, "TRUSTED_DIRS", (str(tmp_path),))
    try:
        stream = StimulusStream(stimuli.udp("127.0.0.1", 9), period=0.05, count=1)
        with pytest.raises(StreamStartError, match="Install util-linux"):
            await stream.start(
                local_sandbox, identity=ProcessIdentity(uid=os.getuid(), gid=os.getgid())
            )
    finally:
        paths.clear_cache()
