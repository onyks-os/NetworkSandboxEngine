"""Stimuli on loopback, through the real launch chain, without privileges.

Each outcome is produced for real and must come back as itself: a refused send
is never "could not run", a probe that could not run is never "refused", and
only a stimulus that waited for a reply can be "no_reply".
"""

from __future__ import annotations

import asyncio
import errno
import os
import socket
import stat
import sys
from pathlib import Path
from typing import Any

import pytest

from nse import receivers, stimuli
from nse.core import probe_packets
from nse.models.process import ProcessIdentity

LOOPBACKS = ["127.0.0.1", "::1"]


def _fake_python(tmp_path: Path, body: str) -> str:
    """An "interpreter" that ignores its arguments and does *body* instead."""
    path = tmp_path / "python"
    path.write_text(f"#!/bin/sh\n{body}\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return str(path)


@pytest.mark.asyncio
@pytest.mark.parametrize("host", LOOPBACKS)
async def test_udp_round_trip_is_answered_and_logged_by_its_probe_id(
    local_sandbox: Any, host: str
) -> None:
    async with await receivers.udp_echo(host).start(local_sandbox) as echo:
        result = await stimuli.udp_round_trip(host, echo.port).run(local_sandbox)
        log = await echo.stop()
    assert result.outcome == "answered", result.describe()
    assert result.left_socket
    assert result.answered
    assert result.reply == probe_packets.marker(result.probe_id)
    assert result.family == (6 if ":" in host else 4)
    assert result.source is not None
    assert result.source.address == host
    assert result.reply_source is not None
    assert result.reply_source.port == echo.port
    assert log.complete
    [receipt] = log.matching(result)
    assert receipt.probe_id == result.probe_id
    assert receipt.source == result.source
    assert receipt.response == "echo"
    assert result.sent_monotonic is not None
    assert result.sent_monotonic <= receipt.monotonic  # one clock for both sides
    assert result.identity is not None
    assert result.identity.uids[0] == os.getuid()


@pytest.mark.asyncio
async def test_a_one_way_udp_send_is_sent_not_answered(local_sandbox: Any) -> None:
    async with await receivers.udp_echo("127.0.0.1").start(local_sandbox) as echo:
        result = await stimuli.udp("127.0.0.1", echo.port).run(local_sandbox)
        await asyncio.sleep(0.1)
        assert echo.log().for_probe(result.probe_id)
    assert result.outcome == "sent"
    assert result.reply is None


@pytest.mark.asyncio
@pytest.mark.parametrize("host", LOOPBACKS)
async def test_tcp_round_trip_and_bare_handshake(local_sandbox: Any, host: str) -> None:
    async with await receivers.tcp_echo(host).start(local_sandbox) as echo:
        talk = await stimuli.tcp_round_trip(host, echo.port).run(local_sandbox)
        bare = await stimuli.tcp_connect(host, echo.port).run(local_sandbox)
        await asyncio.sleep(0.2)
        log = await echo.stop()
    assert talk.outcome == "answered"
    assert talk.connected
    assert talk.reply == probe_packets.marker(talk.probe_id)
    assert bare.outcome == "answered"
    assert bare.connected
    assert bare.payload == b""
    # The bare SYN carries no ID: its explicitly bound source port is the ID.
    assert bare.source is not None
    assert bare.source.port != talk.source.port
    [accepted] = log.matching(bare)
    assert accepted.kind == "connection"
    assert accepted.probe_id is None
    kinds = sorted(r.kind for r in log.matching(talk))
    assert kinds == ["connection", "data"]


@pytest.mark.asyncio
async def test_tcp_probes_bind_distinct_source_ports_or_the_one_requested(
    local_sandbox: Any,
) -> None:
    async with await receivers.tcp_echo("127.0.0.1").start(local_sandbox) as echo:
        results = [
            await stimuli.tcp_connect("127.0.0.1", echo.port).run(local_sandbox) for _ in range(3)
        ]
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            free = probe.getsockname()[1]
        chosen = await stimuli.tcp_connect("127.0.0.1", echo.port, source_port=free).run(
            local_sandbox
        )
    ports = [r.source.port for r in results if r.source]
    assert len(set(ports)) == 3
    assert chosen.source is not None
    assert chosen.source.port == free


@pytest.mark.asyncio
@pytest.mark.parametrize("transport", ["udp", "tcp"])
@pytest.mark.parametrize("host", LOOPBACKS)
async def test_dns_answers_a_and_aaaa_over_both_transports(
    local_sandbox: Any, host: str, transport: Any
) -> None:
    async with await receivers.dns(host, 0, a=("192.0.2.7",), aaaa=("2001:db8::7",)).start(
        local_sandbox
    ) as server:
        a = await stimuli.dns_query(host, port=server.port, transport=transport).run(local_sandbox)
        aaaa = await stimuli.dns_query(
            host, port=server.port, transport=transport, qtype="AAAA"
        ).run(local_sandbox)
        log = await server.stop()
    assert a.dns is not None
    assert a.dns.addresses == ("192.0.2.7",)
    assert aaaa.dns is not None
    assert aaaa.dns.addresses == ("2001:db8::7",)
    assert a.dns.qname == f"nse-{a.probe_id}.nse.test"
    assert a.dns.rcode_name == "NOERROR"
    assert [r.response for r in log.matching(a) if r.kind != "connection"] == ["answer"]


@pytest.mark.asyncio
@pytest.mark.parametrize(("mode", "rcode"), [("servfail", "SERVFAIL"), ("refused", "REFUSED")])
async def test_dns_failure_modes_are_answers_with_their_rcode(
    local_sandbox: Any, mode: Any, rcode: str
) -> None:
    async with await receivers.dns("127.0.0.1", 0, mode=mode).start(local_sandbox) as server:
        result = await stimuli.dns_query("127.0.0.1", port=server.port).run(local_sandbox)
    assert result.outcome == "answered"
    assert result.dns is not None
    assert result.dns.rcode_name == rcode
    assert result.dns.addresses == ()


@pytest.mark.asyncio
async def test_a_dropped_dns_query_is_received_but_not_answered(local_sandbox: Any) -> None:
    async with await receivers.dns("127.0.0.1", 0, mode="drop").start(local_sandbox) as server:
        result = await stimuli.dns_query("127.0.0.1", port=server.port, timeout=0.3).run(
            local_sandbox
        )
        log = await server.stop()
    assert result.outcome == "no_reply"
    assert result.stage == "receive"
    assert [r.response for r in log.matching(result)] == ["drop"]


@pytest.mark.asyncio
@pytest.mark.parametrize("host", LOOPBACKS)
async def test_stun_reports_the_source_the_server_saw(local_sandbox: Any, host: str) -> None:
    async with await receivers.stun(host, 0).start(local_sandbox) as server:
        result = await stimuli.stun_binding(host, server.port).run(local_sandbox)
        log = await server.stop()
    assert result.outcome == "answered"
    assert result.mapped_address == result.source
    [receipt] = log.matching(result)
    assert receipt.probe_id == result.probe_id
    assert receipt.response == "binding"


@pytest.mark.asyncio
async def test_quic_initial_has_the_shape_and_carries_the_probe(local_sandbox: Any) -> None:
    async with await receivers.udp_echo("127.0.0.1").start(local_sandbox) as echo:
        result = await stimuli.quic_initial("127.0.0.1", echo.port).run(local_sandbox)
        await asyncio.sleep(0.1)
        [receipt] = echo.log().for_probe(result.probe_id)
    assert result.outcome == "sent"
    assert len(result.payload) == 1200
    assert receipt.size == 1200
    assert result.payload[0] & 0xC0 == 0xC0
    assert result.payload[1:5] == b"\x00\x00\x00\x01"


# --------------------------------------------------------------------------- outcomes kept apart


@pytest.mark.asyncio
async def test_a_closed_tcp_port_is_refused_at_connect(local_sandbox: Any) -> None:
    with socket.socket() as closed:
        closed.bind(("127.0.0.1", 0))
        port = closed.getsockname()[1]  # bound, never listening: RST
        result = await stimuli.tcp_connect("127.0.0.1", port).run(local_sandbox)
    assert result.outcome == "refused"
    assert result.stage == "connect"
    assert result.errno == errno.ECONNREFUSED
    assert result.connected is False
    assert not result.left_socket


@pytest.mark.asyncio
async def test_an_icmp_error_is_refused_at_receive_not_folded_into_no_reply(
    local_sandbox: Any,
) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as closed:
        closed.bind(("127.0.0.1", 0))
        port = closed.getsockname()[1]
    result = await stimuli.udp_round_trip("127.0.0.1", port, timeout=1).run(local_sandbox)
    assert result.outcome == "refused"
    assert result.stage == "receive"
    assert result.errno == errno.ECONNREFUSED


@pytest.mark.asyncio
async def test_silence_is_no_reply(local_sandbox: Any) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as silent:
        silent.bind(("127.0.0.1", 0))
        result = await stimuli.udp_round_trip(
            "127.0.0.1", silent.getsockname()[1], timeout=0.2
        ).run(local_sandbox)
        assert probe_packets.extract_probe_id(silent.recv(100)) == result.probe_id
    assert result.outcome == "no_reply"
    assert result.stage == "receive"
    assert result.left_socket
    assert not result.answered


@pytest.mark.asyncio
@pytest.mark.skipif(os.geteuid() == 0, reason="root may open raw sockets")
async def test_a_raw_socket_without_cap_net_raw_could_not_run(local_sandbox: Any) -> None:
    result = await stimuli.icmp_echo("127.0.0.1").run(local_sandbox)
    assert result.outcome == "could_not_run"
    assert result.stage == "socket"
    assert result.errno == errno.EPERM
    assert result.reason is not None
    assert "no packet" in result.reason


def _ping_allowed() -> bool:
    low, high = Path("/proc/sys/net/ipv4/ping_group_range").read_text().split()
    return int(low) <= os.getgid() <= int(high)


@pytest.mark.asyncio
@pytest.mark.parametrize("host", LOOPBACKS)
async def test_icmp_echo_through_a_ping_socket(local_sandbox: Any, host: str) -> None:
    result = await stimuli.icmp_echo(host, timeout=1.0, socket="dgram").run(local_sandbox)
    if _ping_allowed():
        assert result.outcome == "answered", result.describe()
        assert result.reply is not None
        assert result.reply[0] in (0, 129)
    else:
        assert result.outcome == "could_not_run"
        assert result.stage == "socket"


@pytest.mark.asyncio
@pytest.mark.skipif(os.geteuid() != 0, reason="raw sockets need root here")
@pytest.mark.parametrize("host", LOOPBACKS)
async def test_icmp_echo_through_a_raw_socket(local_sandbox: Any, host: str) -> None:
    result = await stimuli.icmp_echo(host, timeout=1.0).run(local_sandbox)
    assert result.outcome == "answered", result.describe()


@pytest.mark.asyncio
async def test_a_missing_interpreter_could_not_run_at_launch(local_sandbox: Any) -> None:
    result = await stimuli.udp("127.0.0.1", 9).run(local_sandbox, python="/nonexistent/python3")
    assert result.outcome == "could_not_run"
    assert result.stage == "launch"
    assert result.reason is not None
    assert "not found" in result.reason
    assert not result.left_socket


@pytest.mark.asyncio
@pytest.mark.skipif(os.geteuid() == 0, reason="root can change its UID")
async def test_an_identity_that_cannot_be_applied_could_not_run(local_sandbox: Any) -> None:
    other = 0 if os.getuid() else 1
    result = await stimuli.udp("127.0.0.1", 9).run(
        local_sandbox, identity=ProcessIdentity(uid=other, gid=other)
    )
    assert result.outcome == "could_not_run"
    assert result.stage == "launch"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("echo boom >&2; exit 3", "exited with status 3: boom"),
        ("echo not-json", "report is unreadable"),
        ("true", "report is unreadable"),
        ('echo \'{"outcome": "leaked", "stage": null}\'', "unknown outcome"),
    ],
)
async def test_a_broken_probe_could_not_run_and_says_why(
    local_sandbox: Any, tmp_path: Path, body: str, expected: str
) -> None:
    python = _fake_python(tmp_path, body)
    result = await stimuli.udp("127.0.0.1", 9).run(local_sandbox, python=python)
    assert result.outcome == "could_not_run"
    assert result.stage == "output"
    assert result.reason is not None
    assert expected in result.reason


@pytest.mark.asyncio
async def test_a_probe_that_hangs_could_not_run(local_sandbox: Any, tmp_path: Path) -> None:
    python = _fake_python(tmp_path, "sleep 30")
    result = await stimuli.udp("127.0.0.1", 9).run(local_sandbox, python=python, timeout=0.3)
    assert result.outcome == "could_not_run"
    assert result.reason is not None
    assert "timeout" in result.reason


@pytest.mark.asyncio
async def test_an_unparseable_dns_reply_is_answered_with_the_error(local_sandbox: Any) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as junk:
        junk.bind(("127.0.0.1", 0))
        port = junk.getsockname()[1]
        task = asyncio.ensure_future(
            stimuli.dns_query("127.0.0.1", port=port, timeout=3).run(local_sandbox)
        )
        junk.settimeout(5)
        _, peer = await asyncio.to_thread(junk.recvfrom, 512)  # sock_recvfrom is 3.11+
        junk.sendto(b"\x00\x01", peer)
        broken = await task
    assert broken.outcome == "answered"
    assert broken.dns is None
    assert broken.error is not None
    assert "unparseable DNS reply" in broken.error


# --------------------------------------------------------------------------- the plan


def test_every_run_gets_a_new_probe_id_and_the_payload_carries_it() -> None:
    stimulus = stimuli.udp("192.0.2.1", 9)
    first, second = probe_packets.new_probe_id(), probe_packets.new_probe_id()
    assert first != second
    assert len(first) == 24
    plan = stimulus.plan(first)
    assert bytes.fromhex(plan["payload"]) == probe_packets.marker(first)
    assert plan["source_port"] is None  # UDP: the kernel's port, recorded after connect
    assert stimuli.tcp_connect("192.0.2.1", 9).plan(first)["source_port"] is not None


def test_dns_over_tcp_is_length_framed() -> None:
    probe = probe_packets.new_probe_id()
    udp = stimuli.dns_query("192.0.2.1").payload(probe)
    tcp = stimuli.dns_query("192.0.2.1", transport="tcp").payload(probe)
    assert tcp == len(udp).to_bytes(2, "big") + udp
    assert stimuli.dns_query("192.0.2.1", transport="tcp").plan(probe)["framing"] == "dns-tcp"


@pytest.mark.parametrize(
    "build",
    [
        lambda: stimuli.udp("example.com", 53),
        lambda: stimuli.udp("192.0.2.1", 0),
        lambda: stimuli.udp("192.0.2.1", 70000),
        lambda: stimuli.udp_round_trip("192.0.2.1", 9, timeout=0),
        lambda: stimuli.tcp_connect("192.0.2.1", 9, source_port=80),
        lambda: stimuli.dns_query("192.0.2.1", zone="a..b"),
    ],
)
def test_invalid_stimuli_are_refused_before_anything_runs(build: Any) -> None:
    with pytest.raises(ValueError):
        build().payload(probe_packets.new_probe_id())


def test_with_reply_changes_only_the_wait() -> None:
    stimulus = stimuli.icmp_echo("192.0.2.1")
    waiting = stimulus.with_reply(1.5)
    assert waiting.reply_timeout == 1.5
    assert stimulus.reply_timeout is None
    assert waiting.kind == stimulus.kind
    assert waiting.host == stimulus.host


def test_the_default_interpreter_is_this_one_resolved() -> None:
    assert os.path.samefile(stimuli.default_python(), sys.executable)
    assert not os.path.islink(stimuli.default_python())


@pytest.fixture
def without_setpriv(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> Any:
    """A minimal image: no trusted directory holds setpriv (or anything else)."""
    from nse.core import paths

    paths.clear_cache()
    monkeypatch.setattr(paths, "TRUSTED_DIRS", (str(tmp_path),))
    yield
    paths.clear_cache()


@pytest.mark.asyncio
@pytest.mark.usefixtures("without_setpriv")
async def test_a_missing_setpriv_could_not_run_and_names_the_package(local_sandbox: Any) -> None:
    import os

    from nse.models.process import ProcessIdentity

    result = await stimuli.udp("127.0.0.1", 9).run(
        local_sandbox, identity=ProcessIdentity(uid=os.getuid(), gid=os.getgid())
    )
    assert result.outcome == "could_not_run"
    assert result.stage == "launch"
    assert "setpriv" in (result.reason or "")
    assert "Install util-linux" in (result.reason or "")
