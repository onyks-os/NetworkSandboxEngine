"""The stimulus agent, run in-process: every way a socket call can end.

The same program runs inside namespaces through ``python -I -c``; here its
branches are driven directly, on loopback or against a socket that fails on
cue, so a change in how an outcome is classified shows up as a failure.
"""

from __future__ import annotations

import errno
import json
import socket
from typing import Any

import pytest

from nse import _agents
from nse._agents import stimulus as agent


def _plan(**fields: Any) -> dict[str, Any]:
    plan: dict[str, Any] = {
        "transport": "udp",
        "family": 4,
        "host": "127.0.0.1",
        "port": 9,
        "payload": b"nse-probe:".hex(),
        "source_port": None,
        "port_attempts": 1,
        "connect_timeout": 1.0,
        "reply_timeout": None,
        "socket": "raw",
        "framing": None,
    }
    plan.update(fields)
    return plan


class Failing:
    """A socket whose named method raises *error*; everything else is a no-op."""

    def __init__(self, failures: dict[str, BaseException], replies: list[Any] | None = None):
        self.failures = failures
        self.replies = list(replies or [])

    def __call__(self, *args: Any) -> Failing:
        if "socket" in self.failures:
            raise self.failures["socket"]
        return self

    def __enter__(self) -> Failing:
        return self

    def __exit__(self, *exc: object) -> None:
        pass

    def _maybe(self, name: str) -> None:
        if name in self.failures:
            raise self.failures[name]

    def bind(self, address: Any) -> None:
        self._maybe("bind")

    def connect(self, address: Any) -> None:
        self._maybe("connect")

    def send(self, data: bytes) -> int:
        self._maybe("send")
        return len(data)

    def sendall(self, data: bytes) -> None:
        self._maybe("send")

    def sendto(self, data: bytes, address: Any) -> int:
        self._maybe("send")
        return len(data)

    def settimeout(self, value: float) -> None:
        pass

    def getsockname(self) -> Any:
        return ("127.0.0.1", 40000)

    def recv(self, size: int) -> bytes:
        self._maybe("recv")
        return self.replies.pop(0) if self.replies else b""

    def recvfrom(self, size: int) -> Any:
        self._maybe("recv")
        return self.replies.pop(0)


def _run(monkeypatch: pytest.MonkeyPatch, plan: dict[str, Any], fake: Failing) -> dict[str, Any]:
    monkeypatch.setattr(agent.socket, "socket", fake)
    return agent.Probe(plan).run()


@pytest.mark.parametrize(
    ("plan", "failures", "outcome", "stage"),
    [
        (_plan(), {"socket": OSError(errno.EAFNOSUPPORT, "no")}, "could_not_run", "socket"),
        (_plan(), {"connect": OSError(errno.ENETUNREACH, "no")}, "refused", "connect"),
        (_plan(), {"send": OSError(errno.EPERM, "no")}, "refused", "send"),
        (_plan(reply_timeout=1), {"recv": TimeoutError()}, "no_reply", "receive"),
        (_plan(reply_timeout=1), {"recv": OSError(errno.ECONNREFUSED, "x")}, "refused", "receive"),
        (_plan(transport="tcp"), {"connect": TimeoutError()}, "no_reply", "connect"),
        (_plan(transport="tcp"), {"connect": OSError(errno.EPERM, "no")}, "refused", "connect"),
        (_plan(transport="tcp"), {"send": OSError(errno.EPIPE, "no")}, "refused", "send"),
        (_plan(transport="tcp", payload=""), {}, "answered", None),
        (_plan(transport="icmp"), {"send": OSError(errno.EPERM, "no")}, "refused", "send"),
        (_plan(transport="icmp", reply_timeout=1), {"recv": TimeoutError()}, "no_reply", "receive"),
        (
            _plan(transport="icmp", reply_timeout=1),
            {"recv": OSError(errno.EHOSTUNREACH, "x")},
            "refused",
            "receive",
        ),
    ],
)
def test_each_failure_lands_in_its_own_outcome(
    monkeypatch: pytest.MonkeyPatch, plan: dict[str, Any], failures: Any, outcome: str, stage: Any
) -> None:
    report = _run(monkeypatch, plan, Failing(failures))
    assert (report["outcome"], report["stage"]) == (outcome, stage)
    if any(not isinstance(f, TimeoutError) for f in failures.values()):
        assert report["errno"] is not None
        assert report["error"]
    assert report["ended_monotonic"] is not None


def test_a_peer_that_closes_without_answering_is_no_reply(monkeypatch: pytest.MonkeyPatch) -> None:
    report = _run(monkeypatch, _plan(transport="tcp", reply_timeout=1), Failing({}, [b""]))
    assert report["outcome"] == "no_reply"
    assert "closed" in report["error"]


def test_a_framed_dns_reply_is_read_in_full(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = Failing({}, [b"\x00\x05", b"ab", b"cde"])
    plan = _plan(transport="tcp", reply_timeout=1, framing="dns-tcp")
    report = _run(monkeypatch, plan, fake)
    assert report["outcome"] == "answered"
    assert report["reply"] == b"abcde".hex()
    short = _run(monkeypatch, plan, Failing({}, [b"\x00"]))
    assert short["outcome"] == "no_reply"


def test_a_raw_socket_waits_for_its_own_echo_reply(monkeypatch: pytest.MonkeyPatch) -> None:
    data = b"nse-probe:x"
    request = bytes([8, 0, 0, 0, 0, 1, 0, 1]) + data
    ip_header = bytes([0x45]) + bytes(19)
    replies = [
        (ip_header + bytes([3, 3]) + bytes(6) + data, ("127.0.0.1", 0)),  # an error
        (ip_header + bytes([0, 0]) + bytes(6) + b"other", ("127.0.0.1", 0)),  # not ours
        (ip_header + bytes([0, 0]) + bytes(6) + data, ("192.0.2.9", 0)),  # wrong peer
        (ip_header + bytes([0, 0]) + bytes(6) + data, ("127.0.0.1", 0)),
    ]
    plan = _plan(transport="icmp", reply_timeout=2, payload=request.hex())
    report = _run(monkeypatch, plan, Failing({}, replies))
    assert report["outcome"] == "answered"
    assert report["reply_source"] == ["127.0.0.1", 0]


def test_an_icmp_wait_that_runs_out_is_no_reply(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = iter([0.0, 0.0, 0.0, 10.0, 10.0])
    monkeypatch.setattr(agent.time, "monotonic", lambda: next(clock, 10.0))
    replies = [(bytes([0x45]) + bytes(19) + bytes([3, 3]) + bytes(6), ("127.0.0.1", 0))]
    plan = _plan(transport="icmp", reply_timeout=1)
    report = _run(monkeypatch, plan, Failing({}, replies))
    assert report["outcome"] == "no_reply"


def test_source_ports_in_use_are_skipped_and_other_bind_errors_stop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts: list[int] = []

    class Busy(Failing):
        def bind(self, address: Any) -> None:
            attempts.append(address[1])
            if len(attempts) < 3:
                raise OSError(errno.EADDRINUSE, "in use")

    report = _run(monkeypatch, _plan(source_port=65535, port_attempts=5), Busy({}))
    assert report["outcome"] == "sent"
    assert attempts == [65535, 1024, 1025]
    attempts.clear()
    report = _run(
        monkeypatch,
        _plan(source_port=2000, port_attempts=5),
        Failing({"bind": OSError(errno.EACCES, "no")}),
    )
    assert (report["outcome"], report["stage"]) == ("could_not_run", "bind")
    exhausted = _run(
        monkeypatch,
        _plan(source_port=2000, port_attempts=2),
        Failing({"bind": OSError(errno.EADDRINUSE, "in use")}),
    )
    assert exhausted["outcome"] == "could_not_run"
    assert exhausted["errno"] == errno.EADDRINUSE


def test_an_unknown_transport_is_a_bug(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValueError):
        _run(monkeypatch, _plan(transport="sctp"), Failing({}))


def test_main_prints_one_json_report_on_real_loopback(capsys: pytest.CaptureFixture[str]) -> None:
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as server:
        server.bind(("::1", 0))
        plan = _plan(family=6, host="::1", port=server.getsockname()[1], source_port=None)
        assert agent.main(["-c", json.dumps(plan)]) == 0
        assert server.recv(100) == b"nse-probe:"
    [line] = capsys.readouterr().out.splitlines()
    report = json.loads(line)
    assert report["outcome"] == "sent"
    assert report["source"][0] == "::1"


def test_agent_sources_are_shipped_with_the_package() -> None:
    assert "class Probe" in _agents.source("stimulus")
    assert "class Receiver" in _agents.source("receiver")


def test_icmpv6_one_way_and_an_empty_address(monkeypatch: pytest.MonkeyPatch) -> None:
    report = _run(monkeypatch, _plan(transport="icmp", family=6, host="::1"), Failing({}))
    assert report["outcome"] == "sent"
    assert agent._endpoint(None) is None
    assert agent._endpoint(("::1", 5, 0, 0)) == ["::1", 5]


@pytest.mark.parametrize("transport", ["udp", "tcp"])
def test_a_bind_failure_stops_udp_and_tcp_before_any_packet(
    monkeypatch: pytest.MonkeyPatch, transport: str
) -> None:
    plan = _plan(transport=transport, source_port=2000)
    report = _run(monkeypatch, plan, Failing({"bind": OSError(errno.EACCES, "no")}))
    assert (report["outcome"], report["stage"]) == ("could_not_run", "bind")
    assert report["sent_at"] is None


def test_a_tcp_socket_that_cannot_be_created_could_not_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _plan(transport="tcp")
    report = _run(monkeypatch, plan, Failing({"socket": OSError(errno.EMFILE, "no")}))
    assert report["outcome"] == "could_not_run"
    icmp = _run(monkeypatch, _plan(transport="icmp"), Failing({"socket": PermissionError(1, "x")}))
    assert icmp["stage"] == "socket"


# --------------------------------------------------------------------------- stream mode

TEMPLATE = "0123456789abcdef00000000"


def _stream_plan(stimulus: Any, **schedule: Any) -> dict[str, Any]:
    plan: dict[str, Any] = stimulus.plan(TEMPLATE)
    plan["stream"] = {
        "prefix": TEMPLATE[:16],
        "template_id": TEMPLATE,
        "period": 0.01,
        "count": None,
        "duration": None,
        "max_in_flight": 256,
    }
    plan["stream"].update(schedule)
    return plan


def test_each_attempt_carries_its_own_probe_id_in_every_form() -> None:
    from nse import stimuli

    for probe in (
        stimuli.udp("127.0.0.1", 9),
        stimuli.dns_query("127.0.0.1"),
        stimuli.stun_binding("127.0.0.1"),
        stimuli.quic_initial("127.0.0.1"),
        stimuli.icmp_echo("::1"),
    ):
        stream = agent.Stream(_stream_plan(probe))
        probe_id = stream.probe_id(7)
        assert probe_id == TEMPLATE[:16] + "00000007"
        assert stream.payload(probe_id) == probe.payload(probe_id), probe.kind


def test_an_icmpv4_attempt_gets_a_valid_checksum() -> None:
    from nse import stimuli
    from nse.core import probe_packets

    stream = agent.Stream(_stream_plan(stimuli.icmp_echo("127.0.0.1")))
    probe_id = stream.probe_id(3)
    assert stream.payload(probe_id) == probe_packets.icmp_echo(probe_id, 4)
    assert agent._checksum(b"\x01") == probe_packets.checksum(b"\x01")


def test_attempt_source_ports_are_claimed_from_one_counter_and_wrap() -> None:
    from nse import stimuli

    plan = _stream_plan(stimuli.tcp_connect("127.0.0.1", 9))
    plan["source_port"] = 65535
    stream = agent.Stream(plan)
    ports = [
        stream.attempt_plan(stream.probe_id(1), stream.claim_port())["source_port"]
        for _ in range(3)
    ]
    assert ports == [65535, 1024, 1025]
    assert "stream" not in stream.attempt_plan(stream.probe_id(1), None)
    assert stream.attempt_plan(stream.probe_id(1), 2000)["port_attempts"] == 1
    plan["source_port"] = None
    unbound = agent.Stream(plan)
    assert unbound.claim_port() is None
    assert unbound.attempt_plan(unbound.probe_id(1), None).get("source_port") is None


def test_a_busy_port_is_never_shared_with_the_next_attempt() -> None:
    """Attempt 2's port is taken: it moves on, and attempt 3 gets a port of its own."""
    import socket

    from nse import stimuli

    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        target = listener.getsockname()[1]
        with socket.socket() as squatter:
            squatter.bind(("0.0.0.0", 0))
            busy = squatter.getsockname()[1]
            plan = _stream_plan(stimuli.tcp_connect("127.0.0.1", target, timeout=0.5))
            plan["source_port"] = busy - 1 if busy > 1024 else 65535
            stream = agent.Stream(plan)
            reports = [stream.probe(stream.probe_id(seq)) for seq in (1, 2, 3)]
    ports = [r["source"][1] for r in reports]
    assert busy not in ports
    assert len(set(ports)) == 3, ports
    assert all(r["outcome"] == "answered" for r in reports), reports


def test_a_stream_gives_up_after_port_attempts_busy_ports() -> None:
    import socket

    from nse import stimuli

    with socket.socket() as squatter:
        squatter.bind(("0.0.0.0", 0))
        busy = squatter.getsockname()[1]
        plan = _stream_plan(stimuli.tcp_connect("127.0.0.1", 9))
        plan["source_port"] = busy
        plan["port_attempts"] = 1
        stream = agent.Stream(plan)
        report = stream.probe(stream.probe_id(1))
    assert report["outcome"] == "could_not_run"
    assert report["stage"] == "bind"


def _events(capsys: pytest.CaptureFixture[str]) -> list[dict[str, Any]]:
    return [json.loads(line) for line in capsys.readouterr().out.splitlines()]


def test_a_counted_stream_prints_started_attempts_and_end(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from nse import stimuli

    monkeypatch.setattr(agent.signal, "signal", lambda *args: None)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sink:
        sink.bind(("127.0.0.1", 0))
        plan = _stream_plan(stimuli.udp("127.0.0.1", sink.getsockname()[1]), count=3)
        assert agent.main(["agent", json.dumps(plan)]) == 0
    events = _events(capsys)
    assert events[0]["event"] == "started"
    assert events[-1] == {"event": "end", "attempts": 3, "reason": "count"}
    attempts = sorted((e for e in events if e["event"] == "attempt"), key=lambda e: e["seq"])
    assert [(e["seq"], e["outcome"]) for e in attempts] == [(1, "sent"), (2, "sent"), (3, "sent")]


def test_a_broken_attempt_is_reported_and_the_stream_goes_on(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from nse import stimuli

    def explode(self: Any) -> dict[str, Any]:
        raise RuntimeError("bug")

    monkeypatch.setattr(agent.signal, "signal", lambda *args: None)
    monkeypatch.setattr(agent.Probe, "run", explode)
    plan = _stream_plan(stimuli.udp("127.0.0.1", 9), count=2)
    assert agent.Stream(plan).run() == 0
    attempts = [e for e in _events(capsys) if e["event"] == "attempt"]
    assert {e["outcome"] for e in attempts} == {"could_not_run"}
    assert "bug" in attempts[0]["error"]


def test_a_stopped_stream_waits_for_attempts_in_flight(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import threading
    import time

    from nse import stimuli

    handlers: list[Any] = []
    monkeypatch.setattr(agent.signal, "signal", lambda signum, handler: handlers.append(handler))
    release = threading.Event()
    in_flight = threading.Semaphore(0)

    def slow(self: Any) -> dict[str, Any]:
        in_flight.release()
        release.wait(5)
        return {"outcome": "sent", "stage": None}

    monkeypatch.setattr(agent.Probe, "run", slow)
    stream = agent.Stream(_stream_plan(stimuli.udp("127.0.0.1", 9), max_in_flight=2))
    runner = threading.Thread(target=stream.run)
    runner.start()
    assert in_flight.acquire(timeout=5)
    assert in_flight.acquire(timeout=5)  # two attempts in flight
    time.sleep(0.05)  # later slots are skipped
    handlers[0]()  # SIGTERM
    release.set()
    runner.join(5)
    events = _events(capsys)
    assert events[-1] == {"event": "end", "attempts": 2, "reason": "stopped"}
    assert len([e for e in events if e["event"] == "attempt"]) == 2


def test_a_late_scheduler_skips_the_missed_slots(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from nse import stimuli

    clock = iter([100.0, 100.0, 100.0, 105.0, 105.0, 105.0, 105.0, 105.0, 105.0])
    monkeypatch.setattr(agent.time, "monotonic", lambda: next(clock, 200.0))
    monkeypatch.setattr(agent.signal, "signal", lambda *args: None)
    monkeypatch.setattr(agent.Probe, "run", lambda self: {"outcome": "sent", "stage": None})
    plan = _stream_plan(stimuli.udp("127.0.0.1", 9), period=1.0, count=2)
    assert agent.Stream(plan).run() == 0
    attempts = sorted(
        (e for e in _events(capsys) if e["event"] == "attempt"), key=lambda e: e["seq"]
    )
    assert [e["seq"] for e in attempts] == [1, 2]
    assert attempts[1]["started_monotonic"] - attempts[0]["started_monotonic"] > 3.0


def test_a_stream_with_a_duration_stops_scheduling_at_its_end(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from nse import stimuli

    monkeypatch.setattr(agent.signal, "signal", lambda *args: None)
    monkeypatch.setattr(agent.Probe, "run", lambda self: {"outcome": "sent", "stage": None})
    plan = _stream_plan(stimuli.udp("127.0.0.1", 9), period=0.01, duration=0.03)
    assert agent.Stream(plan).run() == 0
    assert _events(capsys)[-1] == {"event": "end", "attempts": 3, "reason": "duration"}
