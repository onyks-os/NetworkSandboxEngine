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

import secrets
import socket
import threading
import time

from nse.core.async_work import run_blocking
from nse.core.utils import enter_netns
from nse.models.capture_report import Beacon

ETHERTYPE = 0x88B5
MAGIC = b"NSE-BEACON"
VERSION = 1
#: A BPF expression that admits beacon frames; OR it into a custom filter.
FILTER = f"ether proto 0x{ETHERTYPE:04x}"
MAX_LABEL_BYTES = 64

_HEADER = 14
_MIN_FRAME = 60  # Ethernet minimum without the FCS
_TOKEN_BYTES = 16


def frame(label: str, token: str, source_mac: bytes = bytes(6)) -> bytes:
    """The bytes of a beacon frame for *label* and *token* (32 hex digits)."""
    encoded = label.encode()
    if len(encoded) > MAX_LABEL_BYTES:
        raise ValueError(f"a beacon label is at most {MAX_LABEL_BYTES} bytes")
    raw_token = bytes.fromhex(token)
    if len(raw_token) != _TOKEN_BYTES:
        raise ValueError("a beacon token is 32 hex digits")
    body = MAGIC + bytes([VERSION, len(encoded)]) + raw_token + encoded
    data = b"\xff" * 6 + source_mac + ETHERTYPE.to_bytes(2, "big") + body
    return data.ljust(_MIN_FRAME, b"\x00")


def parse(raw: bytes) -> tuple[str, str] | None:
    """``(token, label)`` if *raw* is a beacon frame, else None."""
    if len(raw) < _HEADER + len(MAGIC) + 2 + _TOKEN_BYTES:
        return None
    if raw[12:14] != ETHERTYPE.to_bytes(2, "big"):
        return None
    body = raw[_HEADER:]
    if not body.startswith(MAGIC) or body[len(MAGIC)] != VERSION:
        return None
    size = body[len(MAGIC) + 1]
    start = len(MAGIC) + 2
    token = body[start : start + _TOKEN_BYTES]
    label = body[start + _TOKEN_BYTES : start + _TOKEN_BYTES + size]
    if len(label) != size:
        return None
    return token.hex(), label.decode(errors="replace")


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
