"""Controlled receivers: readiness, receipts, and a log that admits when it is incomplete."""

from __future__ import annotations

import asyncio
import json
import os
import signal
import socket
import stat
import time
from pathlib import Path
from typing import Any

import pytest

from nse import receivers, stimuli
from nse._agents import receiver as agent
from nse.models.stimulus import Endpoint, ReceiptLog
from nse.receivers import ReceiverStartError, _parse


def _fake_python(tmp_path: Path, body: str) -> str:
    path = tmp_path / "python"
    path.write_text(f"#!/bin/sh\n{body}\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return str(path)


def _line(seq: int, **fields: Any) -> bytes:
    record = {
        "event": "receipt",
        "seq": seq,
        "transport": "udp",
        "kind": "datagram",
        "family": 4,
        "source": ["10.0.1.2", 40000],
        "destination": ["10.0.1.1", 9999],
        "monotonic": 1.0,
        "wall": 2.0,
        "size": 3,
        "data": b"abc".hex(),
        "response": "echo",
    }
    record.update(fields)
    return json.dumps(record).encode() + b"\n"


# --------------------------------------------------------------------------- starting


@pytest.mark.asyncio
async def test_a_dns_receiver_binds_one_port_for_both_transports(local_sandbox: Any) -> None:
    server = await receivers.dns("127.0.0.1", 0).start(local_sandbox)
    try:
        assert [b.port for b in server.bound] == [server.port, server.port]
        assert server.address == "127.0.0.1"
    finally:
        log = await server.stop()
    assert log.complete
    assert log.receipts == ()
    assert await server.stop() is log  # the same final log on every call
    assert server.log() is log


@pytest.mark.asyncio
async def test_a_receiver_that_cannot_bind_does_not_start(local_sandbox: Any) -> None:
    with pytest.raises(ReceiverStartError, match="bind failed") as info:
        await receivers.udp_echo("192.0.2.1", 9).start(local_sandbox)
    assert info.value.result is not None
    assert info.value.result.returncode == 1


@pytest.mark.asyncio
async def test_a_port_in_use_is_a_start_error(local_sandbox: Any) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as taken:
        taken.bind(("127.0.0.1", 0))
        with pytest.raises(ReceiverStartError, match="Address already in use"):
            await receivers.udp_echo("127.0.0.1", taken.getsockname()[1]).start(local_sandbox)


@pytest.mark.asyncio
async def test_a_receiver_that_never_says_ready_is_stopped(
    local_sandbox: Any, tmp_path: Path
) -> None:
    python = _fake_python(tmp_path, "echo starting; exec sleep 30")
    with pytest.raises(ReceiverStartError, match="not ready within") as info:
        await receivers.udp_echo("127.0.0.1").start(local_sandbox, python=python, ready_timeout=0.3)
    assert info.value.result is not None
    assert info.value.result.termination == "terminated"


@pytest.mark.asyncio
async def test_a_receiver_that_dies_says_why(local_sandbox: Any, tmp_path: Path) -> None:
    python = _fake_python(tmp_path, "echo broken >&2; exit 2")
    with pytest.raises(ReceiverStartError, match="exit status 2: broken"):
        await receivers.udp_echo("127.0.0.1").start(local_sandbox, python=python)


# --------------------------------------------------------------------------- the log


@pytest.mark.asyncio
async def test_a_receiver_killed_from_outside_has_an_incomplete_log(local_sandbox: Any) -> None:
    echo = await receivers.udp_echo("127.0.0.1").start(local_sandbox)
    await stimuli.udp("127.0.0.1", echo.port).run(local_sandbox)
    await asyncio.sleep(0.1)
    os.kill(echo.process.pid, signal.SIGKILL)
    await echo.process.wait(5)
    live = echo.log()
    assert not live.complete
    assert "exited on its own" in live.problems[0]
    assert len(live.receipts) == 1  # what was logged before is still there
    final = await echo.stop()
    assert not final.complete
    assert "exited on its own" in final.problems[0]


@pytest.mark.asyncio
async def test_a_log_over_the_output_limit_is_incomplete(
    local_sandbox: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(receivers, "_OUTPUT_LIMIT", 600)
    echo = await receivers.udp_echo("127.0.0.1").start(local_sandbox)
    for _ in range(3):
        await stimuli.udp("127.0.0.1", echo.port).run(local_sandbox)
    await asyncio.sleep(0.2)
    live = echo.log()
    assert not live.complete
    assert any("output limit" in p for p in live.problems)
    final = await echo.stop()
    assert not final.complete
    assert any("output limit" in p for p in final.problems)


def test_the_log_parser_reports_gaps_unreadable_lines_and_cut_lines() -> None:
    clean = _parse(_line(1) + b'{"event": "ready", "bound": []}\n' + _line(2), [], final=True)
    assert clean.complete
    assert [r.seq for r in clean.receipts] == [1, 2]
    gap = _parse(_line(1) + _line(3), [], final=True)
    assert not gap.complete
    assert "receipt 2 is missing" in gap.problems[0]
    garbage = _parse(_line(1) + b"{not json\n" + _line(2, source="x"), [], final=True)
    assert not garbage.complete
    assert len(garbage.problems) == 2
    assert [r.seq for r in garbage.receipts] == [1]
    running = _parse(_line(1) + _line(2)[:20], [], final=False)
    assert running.complete
    assert len(running.receipts) == 1
    cut = _parse(_line(1) + _line(2)[:20], [], final=True)
    assert not cut.complete
    assert "incomplete line" in cut.problems[0]
    blank = _parse(b"\n" + _line(1), [], final=True)
    assert blank.complete


def test_receipt_log_lookups() -> None:
    from nse.core import probe_packets
    from nse.models.stimulus import StimulusResult

    probe = probe_packets.new_probe_id()
    log = _parse(
        _line(1, data=probe_packets.marker(probe).hex())
        + _line(2, transport="tcp", kind="connection", data="", source=["10.0.1.2", 40001])
        + _line(3, data=b"other".hex(), source=["10.0.1.2", 40001]),
        [],
        final=True,
    )
    assert [r.seq for r in log.for_probe(probe)] == [1]
    source = Endpoint(address="10.0.1.2", port=40001)
    assert [r.seq for r in log.from_source(source)] == [2, 3]
    assert [r.seq for r in log.from_source(source, "tcp")] == [2]

    def result(**fields: Any) -> StimulusResult:
        base: dict[str, Any] = {
            "kind": "tcp_connect",
            "transport": "tcp",
            "family": 4,
            "probe_id": "f" * 24,
            "destination": Endpoint(address="10.0.1.1", port=9999),
            "source": source,
            "payload": b"",
            "outcome": "answered",
        }
        base.update(fields)
        return StimulusResult(**base)

    assert [r.seq for r in log.matching(result())] == [2]
    wildcard = result(source=Endpoint(address="0.0.0.0", port=40001))
    assert [r.seq for r in log.matching(wildcard)] == [2]
    assert log.matching(result(source=None)) == []
    assert [r.seq for r in log.matching(result(probe_id=probe, transport="udp"))] == [1, 3]
    assert ReceiptLog(complete=True).receipts == ()


@pytest.mark.parametrize(
    "build",
    [
        lambda: receivers.udp_echo("localhost"),
        lambda: receivers.udp_echo("127.0.0.1", 70000),
        lambda: receivers.ReceiverSpec("udp_echo", "127.0.0.1", 0, ()),
        lambda: receivers.dns("127.0.0.1", a=("2001:db8::1",)),
        lambda: receivers.ReceiverSpec("udp_echo", "127.0.0.1", 0, ("udp",), record_bytes=10),
    ],
)
def test_invalid_receivers_are_refused(build: Any) -> None:
    with pytest.raises(ValueError):
        build()


# --------------------------------------------------------------------------- the agent itself


def _query(qtype: int, name: bytes = b"\x03nse\x04test\x00", flags: bytes = b"\x01\x00") -> bytes:
    return (
        b"\x12\x34"
        + flags
        + b"\x00\x01\x00\x00\x00\x00\x00\x00"
        + name
        + qtype.to_bytes(2, "big")
        + b"\x00\x01"
    )


def test_dns_responses_by_mode_and_type() -> None:
    from nse.core.probe_packets import parse_dns

    config = {"mode": "answer", "a": ["192.0.2.1", "192.0.2.2"], "aaaa": ["2001:db8::1"]}
    reply, label = agent.dns_response(_query(1), config)
    assert label == "answer"
    assert reply is not None
    parsed = parse_dns(reply)
    assert parsed.id == 0x1234
    assert parsed.addresses == ("192.0.2.1", "192.0.2.2")
    assert reply[2] & 0x81 == 0x81  # QR and RD (copied from the query)
    reply, _ = agent.dns_response(_query(16), config)  # TXT: empty NOERROR
    assert reply is not None
    assert parse_dns(reply).addresses == ()
    assert agent.dns_response(_query(1), {"mode": "drop"}) == (None, "drop")


@pytest.mark.parametrize(
    "query",
    [
        b"\x00" * 4,
        _query(1, flags=b"\x81\x00"),  # a response, not a query
        _query(1, name=b"\xc0\x0c"),  # compression in a question
        _query(1, name=b"\x05ab"),  # runs off the end
        _query(1)[:-3],  # truncated type and class
    ],
)
def test_malformed_dns_queries_are_logged_not_answered(query: bytes) -> None:
    assert agent.dns_response(query, {"mode": "answer"}) == (None, "malformed")


def test_stun_ignores_what_is_not_a_binding_request() -> None:
    assert agent.stun_response(b"\x00\x01", ("127.0.0.1", 1)) == (None, "none")


def test_the_receiver_closes_idle_connections() -> None:
    plan = {"kind": "tcp_echo", "family": 4, "address": "127.0.0.1", "port": 0}
    plan |= {"transports": ["tcp"], "idle_timeout": 0.2}
    server = agent.Receiver(plan)
    [bound] = server.bind()
    with socket.create_connection(("127.0.0.1", bound["port"]), timeout=2) as client:
        server.serve(rounds=1)  # accept
        assert len(server.connections) == 1
        time.sleep(0.3)
        server.serve(rounds=1)  # idle for longer than idle_timeout: closed
        assert server.connections == {}
        assert client.recv(10) == b""


def test_dns_over_tcp_reassembles_a_query_split_across_segments(
    capsys: pytest.CaptureFixture[str],
) -> None:
    plan = {"kind": "dns", "family": 4, "address": "127.0.0.1", "port": 0}
    plan |= {"transports": ["tcp"], "dns": {"mode": "answer", "a": ["192.0.2.9"]}}
    server = agent.Receiver(plan)
    [bound] = server.bind()
    query = _query(1)
    framed = len(query).to_bytes(2, "big") + query
    with socket.create_connection(("127.0.0.1", bound["port"]), timeout=2) as client:
        server.serve(rounds=1)
        client.sendall(framed[:5])
        server.serve(rounds=1)
        client.sendall(framed[5:] + framed)  # the rest, and a second query at once
        server.serve(rounds=1)
        size = int.from_bytes(client.recv(2), "big")
        assert client.recv(size)[:2] == b"\x12\x34"
    records = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [r["kind"] for r in records] == ["connection", "data", "data"]
    assert [r["seq"] for r in records] == [1, 2, 3]


def test_the_agent_reports_a_bind_failure_as_an_event(capsys: pytest.CaptureFixture[str]) -> None:
    plan = {"kind": "udp_echo", "family": 4, "address": "192.0.2.1", "port": 9}
    assert agent.main(["-c", json.dumps(plan | {"transports": ["udp"]})]) == 1
    event = json.loads(capsys.readouterr().out)
    assert event["event"] == "error"
    assert event["stage"] == "bind"


def test_an_unknown_kind_is_a_bug_not_a_receipt() -> None:
    server = agent.Receiver({"kind": "nope", "family": 4, "address": "127.0.0.1"})
    with pytest.raises(ValueError):
        server._answer(b"", ("127.0.0.1", 1))


# --------------------------------------------------------------------------- serving, in-process


def _serving(kind: str, address: str = "127.0.0.1", **plan: Any) -> tuple[Any, int]:
    family = 6 if ":" in address else 4
    base = {"kind": kind, "family": family, "address": address, "port": 0}
    base |= {"transports": ["udp"]} | plan
    server = agent.Receiver(base)
    [bound, *_] = server.bind()
    return server, bound["port"]


@pytest.mark.parametrize(("kind", "address"), [("udp_echo", "127.0.0.1"), ("stun", "::1")])
def test_datagrams_are_logged_then_answered(
    kind: str, address: str, capsys: pytest.CaptureFixture[str]
) -> None:
    from nse.core import probe_packets

    server, port = _serving(kind, address)
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    request = probe_packets.stun_binding_request("a" * 24) if kind == "stun" else b"hello"
    with socket.socket(family, socket.SOCK_DGRAM) as client:
        client.settimeout(2)
        client.sendto(request, (address, port))
        server.serve(rounds=1)
        reply = client.recv(100)
        source = client.getsockname()
    if kind == "stun":
        mapped = probe_packets.parse_stun_mapped_address(reply)
        assert mapped is not None
        assert (mapped.address, mapped.port) == (address, source[1])
    else:
        assert reply == b"hello"
    [record] = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert record["response"] == ("binding" if kind == "stun" else "echo")


def test_a_queued_icmp_error_is_not_a_receipt(capsys: pytest.CaptureFixture[str]) -> None:
    server, _ = _serving("udp_echo")
    [key] = list(server.selector.get_map().values())
    sock = key.fileobj
    # Make the socket report an error the way a queued ICMP unreachable does.
    sock.connect(("127.0.0.1", 9))  # type: ignore[union-attr]
    sock.send(b"x")  # type: ignore[union-attr]
    time.sleep(0.05)
    server._datagram(sock)  # type: ignore[arg-type]
    assert capsys.readouterr().out == ""


def test_tcp_echo_data_and_a_failing_peer(capsys: pytest.CaptureFixture[str]) -> None:
    server, port = _serving("tcp_echo", transports=["tcp"])
    with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
        server.serve(rounds=1)
        client.sendall(b"ping")
        server.serve(rounds=1)
        assert client.recv(10) == b"ping"
    server.serve(rounds=1)  # the close: the connection is dropped
    assert server.connections == {}
    records = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [r["kind"] for r in records] == ["connection", "data"]


def test_a_reply_that_cannot_be_sent_closes_the_connection() -> None:
    class Broken:
        def recv(self, size: int) -> bytes:
            return b"ping"

        def getsockname(self) -> Any:
            return ("127.0.0.1", 1)

        def sendall(self, data: bytes) -> None:
            raise OSError("gone")

    server, _ = _serving("tcp_echo", transports=["tcp"])
    broken = Broken()
    closed = []
    server.connections[broken] = {"source": ("127.0.0.1", 2), "buffer": b"", "last": 0.0}  # type: ignore[index]
    server._close = closed.append  # type: ignore[method-assign]
    server._stream(broken)  # type: ignore[arg-type]
    assert closed == [broken]


def test_a_connection_reset_is_a_close() -> None:
    class Reset:
        def recv(self, size: int) -> bytes:
            raise ConnectionResetError

    server, _ = _serving("tcp_echo", transports=["tcp"])
    reset = Reset()
    closed = []
    server.connections[reset] = {"source": ("127.0.0.1", 2), "buffer": b"", "last": 0.0}  # type: ignore[index]
    server._close = closed.append  # type: ignore[method-assign]
    server._stream(reset)  # type: ignore[arg-type]
    assert closed == [reset]


def test_a_dropped_dns_query_over_tcp_gets_no_answer(capsys: pytest.CaptureFixture[str]) -> None:
    server, port = _serving("dns", transports=["tcp"], dns={"mode": "drop"})
    query = _query(1)
    with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
        server.serve(rounds=1)
        client.sendall(len(query).to_bytes(2, "big") + query)
        server.serve(rounds=1)
    records = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert records[-1]["response"] == "drop"


def test_main_serves_after_saying_ready(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(agent.Receiver, "serve", lambda self: None)
    plan = {"kind": "udp_echo", "family": 6, "address": "::1", "port": 0, "transports": ["udp"]}
    agent.main(["-c", json.dumps(plan)])
    assert json.loads(capsys.readouterr().out)["event"] == "ready"


@pytest.mark.asyncio
async def test_output_that_could_not_be_read_to_the_end_makes_the_log_incomplete(
    local_sandbox: Any,
) -> None:
    echo = await receivers.udp_echo("127.0.0.1").start(local_sandbox)
    real = echo.process.terminate

    async def terminate() -> Any:
        result = await real()
        return result.model_copy(update={"output_complete": False})

    echo.process.terminate = terminate  # type: ignore[method-assign]
    log = await echo.stop()
    assert not log.complete
    assert "read to the end" in log.problems[0]
