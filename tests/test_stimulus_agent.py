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
