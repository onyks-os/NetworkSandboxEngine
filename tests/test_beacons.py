"""Beacon frames, without privileges: their bytes, and how they are sent.

The raw socket is replaced; that the kernel delivers the frame across a veth
to a real capture is shown by the integration tests.
"""

from __future__ import annotations

import errno
import threading
from typing import Any

import pytest

from nse.core import beacons
from nse.core.netns_controller import NamespaceSandbox

TOKEN = "00112233445566778899aabbccddeeff"


def test_a_frame_is_a_padded_broadcast_with_the_experimental_ethertype() -> None:
    data = beacons.frame("start", TOKEN)
    assert len(data) == 60
    assert data[:6] == b"\xff" * 6
    assert data[12:14] == b"\x88\xb5"
    assert beacons.parse(data) == (TOKEN, "start")
    long_label = "é" * 32  # 64 bytes: the most a label may take
    assert beacons.parse(beacons.frame(long_label, TOKEN)) == (TOKEN, long_label)


@pytest.mark.parametrize(("label", "token"), [("x" * 65, TOKEN), ("ok", "abcd"), ("ok", "zz" * 16)])
def test_a_frame_refuses_a_bad_label_or_token(label: str, token: str) -> None:
    with pytest.raises(ValueError):
        beacons.frame(label, token)


def _mutate(position: int, value: int) -> bytes:
    data = bytearray(beacons.frame("label", TOKEN))
    data[position] = value
    return bytes(data)


@pytest.mark.parametrize(
    "data",
    [
        b"",
        beacons.frame("x", TOKEN)[:30],
        _mutate(13, 0x00),  # another EtherType
        _mutate(14, ord("X")),  # another magic
        _mutate(24, 2),  # another version
        _mutate(25, 200),  # a label longer than the frame
    ],
)
def test_parse_ignores_anything_but_a_beacon(data: bytes) -> None:
    assert beacons.parse(data) is None


def test_a_beacon_is_sent_from_a_thread_that_enters_the_namespace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, Any]] = []
    main = threading.get_ident()

    def enter(name: str) -> None:
        assert threading.get_ident() != main  # never the caller's own thread
        calls.append(("enter", name))

    monkeypatch.setattr(beacons, "enter_netns", enter)
    monkeypatch.setattr(beacons, "_send_here", lambda iface, data: calls.append((iface, data)))
    beacon = beacons.send_blocking("vrh-x", "nse_x", "start")
    assert calls[0] == ("enter", "nse_x")
    assert calls[1][0] == "vrh-x"
    assert beacons.parse(calls[1][1]) == (beacon.token, "start")
    assert (beacon.label, beacon.iface, beacon.netns) == ("start", "vrh-x", "nse_x")
    assert beacon.sent_at > 0


def test_a_beacon_in_nses_own_namespace_enters_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(beacons, "enter_netns", lambda name: pytest.fail("entered"))
    monkeypatch.setattr(beacons, "_send_here", lambda iface, data: b"")
    assert beacons.send_blocking("veth0", None, "here").netns is None


def test_a_beacon_that_cannot_be_sent_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(iface: str, data: bytes) -> bytes:
        raise PermissionError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr(beacons, "_send_here", refuse)
    with pytest.raises(PermissionError):
        beacons.send_blocking("veth0", None, "x")
    with pytest.raises(ValueError):
        beacons.send_blocking("veth0", None, "x" * 100)


def test_the_frame_leaves_with_the_interfaces_own_source_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent: list[Any] = []

    class Packet:
        def __init__(self, *args: Any) -> None:
            assert args[0] == beacons.socket.AF_PACKET

        def __enter__(self) -> Packet:
            return self

        def __exit__(self, *exc: object) -> None:
            pass

        def bind(self, address: Any) -> None:
            sent.append(address)

        def getsockname(self) -> tuple[Any, ...]:
            return ("veth0", 0, 0, 1, b"\x02\x00\x00\x00\x00\x01")

        def send(self, data: bytes) -> None:
            sent.append(data)

    monkeypatch.setattr(beacons.socket, "socket", Packet)
    mac = beacons._send_here("veth0", beacons.frame("m", TOKEN))
    assert mac == b"\x02\x00\x00\x00\x00\x01"
    assert sent[0] == ("veth0", 0)
    assert sent[1][6:12] == mac
    assert beacons.parse(sent[1]) == (TOKEN, "m")


@pytest.mark.asyncio
async def test_a_sandbox_beacon_leaves_from_its_own_end_of_the_link(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[tuple[str, str | None, str]] = []

    async def send(iface: str, netns: str | None, label: str) -> Any:
        seen.append((iface, netns, label))
        return "beacon"

    monkeypatch.setattr(beacons, "send", send)

    class Controller:
        use_nsenter = False

    sandbox = NamespaceSandbox(Controller(), "nse_b")  # type: ignore[arg-type]
    assert await sandbox.beacon("go") == "beacon"
    assert seen == [(sandbox.peer_iface, "nse_b", "go")]


@pytest.mark.asyncio
async def test_send_runs_off_the_event_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(beacons, "_send_here", lambda iface, data: b"")
    beacon = await beacons.send("veth0", None, "async")
    assert beacon.label == "async"
