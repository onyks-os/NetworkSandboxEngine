# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""
Beacon frames: markers a capture is expected to see.

A beacon is an Ethernet frame with EtherType 0x88B5 (IEEE 802 local
experimental, never routed and never IP), broadcast on one interface. Its
payload is ``NSE-BEACON``, a version byte, a 16-byte random token and a UTF-8
label. A capture recognises beacon frames, records them as sightings and keeps
them out of its packet list (:class:`~nse.core.sniffer.PCAPAsserter`).

The frame is sent from a thread created for the purpose, which enters the
interface's network namespace and ends with it, so nothing else in the process
changes namespace. Sending needs ``CAP_NET_RAW`` there, as capturing does.
"""

from __future__ import annotations

import json
import secrets
import socket
import threading
import time

from nse import _agents
from nse.core.async_work import run_blocking
from nse.core.utils import enter_netns

# The frame format lives in nse.formats.beacon, a leaf the models can use too.
from nse.formats.beacon import (
    CLOCKED_VERSION,
    ETHERTYPE,
    FILTER,
    MAGIC,
    MAX_LABEL_BYTES,
    VERSION,
    BeaconFrame,
    clocked_frame,
    decode,
    frame,
    parse,
)
from nse.formats.beacon import TOKEN_BYTES as _TOKEN_BYTES
from nse.models.capture_report import Beacon, SenderClock

__all__ = [
    "CLOCKED_VERSION",
    "ETHERTYPE",
    "FILTER",
    "MAGIC",
    "MAX_LABEL_BYTES",
    "VERSION",
    "BeaconFrame",
    "agent_command",
    "agent_report",
    "clocked_frame",
    "decode",
    "frame",
    "parse",
    "send",
    "send_blocking",
]


def _send_here(iface: str, data: bytes) -> bytes:
    """Send *data* on *iface* in the calling thread's namespace; return the source MAC used."""
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0) as sock:
        sock.bind((iface, 0))
        mac = bytes(sock.getsockname()[4])[:6]
        sock.send(data[:6] + mac + data[12:])
        return mac


def send_blocking(iface: str, netns: str | None, label: str) -> Beacon:
    """Send one beacon on *iface* in *netns*; raise ``OSError`` if it cannot be sent."""
    token = secrets.token_hex(_TOKEN_BYTES)
    data = frame(label, token)  # validates the label before any thread is started
    times: list[float] = []
    errors: list[BaseException] = []

    def run() -> None:
        try:
            if netns is not None:
                enter_netns(netns)
            sent_at, sent_monotonic = time.time(), time.monotonic()
            _send_here(iface, data)
            times.extend((sent_at, sent_monotonic))
        except BaseException as exc:  # handed to the caller below
            errors.append(exc)

    thread = threading.Thread(target=run, name=f"nse-beacon-{iface}", daemon=True)
    thread.start()
    thread.join()
    if errors:
        raise errors[0]
    sent_at, sent_monotonic = times
    return Beacon(
        label=label,
        token=token,
        iface=iface,
        netns=netns,
        sent_at=sent_at,
        sent_monotonic=sent_monotonic,
    )


async def send(iface: str, netns: str | None, label: str) -> Beacon:
    """Send one beacon without blocking the event loop."""
    return await run_blocking(send_blocking, iface, netns, label)


def agent_command(iface: str, label: str, *, python: str = "python3") -> tuple[list[str], str]:
    """The command line of the portable beacon agent, and the token its beacon will carry.

    Run it as root wherever *iface* is, a VM over ssh for instance: it sends a
    clocked beacon and its follow-up, and prints what it sent. Hand that output
    to :func:`agent_report` to get the :class:`Beacon` a capture should expect.
    """
    frame(label, "0" * 32)  # validates the label here rather than on the far side
    token = secrets.token_hex(_TOKEN_BYTES)
    plan = json.dumps({"iface": iface, "label": label, "token": token})
    return [python, "-I", "-S", "-c", _agents.source("beacon"), plan], token


def agent_report(output: bytes | str) -> Beacon:
    """The beacon the agent says it sent; ``ValueError`` if it did not send one."""
    text = output.decode(errors="replace") if isinstance(output, bytes) else output
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        raise ValueError("the beacon agent printed nothing")
    try:
        event = json.loads(lines[-1])
        if event.get("event") == "error":
            raise ValueError(f"the beacon agent could not send: {event.get('error')}")
        if event.get("event") != "beacon":
            raise ValueError(f"not a beacon agent report: {lines[-1][:200]!r}")
        return Beacon(
            label=str(event["label"]),
            token=str(event["token"]),
            iface=str(event["iface"]),
            netns=None,
            sent_at=float(event["sent_at"]),
            sent_monotonic=float(event["monotonic_before"]),
            clock=SenderClock(
                boot_id=str(event["boot_id"]),
                monotonic_before=float(event["monotonic_before"]),
                boottime_before=float(event["boottime_before"]),
                monotonic_after=float(event["monotonic_after"]),
                boottime_after=float(event["boottime_after"]),
            ),
        )
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ValueError(f"unreadable beacon agent report ({exc}): {lines[-1][:200]!r}") from None
