# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""
The bytes of a beacon frame.

A beacon is an Ethernet broadcast with EtherType 0x88B5 (IEEE 802 local
experimental, never routed and never IP). Its payload starts with
``NSE-BEACON`` and a version byte.

- **Version 1**: a label-length byte, a 16-byte random token, the UTF-8 label.
- **Version 2** (clocked): a kind byte, a label-length byte, the token, the
  sender's 16-byte ``boot_id``, then ``CLOCK_MONOTONIC`` and ``CLOCK_BOOTTIME``
  in nanoseconds (two big-endian unsigned 64-bit integers), then the label. A
  *beacon* (kind 0) carries the clocks read just before it was sent; its
  *follow-up* (kind 1, same token, no label) carries those read just after,
  which cannot be in the frame they time.
"""

from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass

ETHERTYPE = 0x88B5
MAGIC = b"NSE-BEACON"
VERSION = 1
CLOCKED_VERSION = 2
#: A BPF expression that admits beacon frames; OR it into a custom filter.
FILTER = f"ether proto 0x{ETHERTYPE:04x}"
MAX_LABEL_BYTES = 64

HEADER = 14
MIN_FRAME = 60  # Ethernet minimum without the FCS
TOKEN_BYTES = 16
_BOOT_ID_BYTES = 16
_CLOCKS = struct.Struct(">QQ")
_KIND_BEACON, _KIND_FOLLOW_UP = 0, 1


@dataclass(frozen=True)
class BeaconFrame:
    """A decoded beacon frame. The clock fields are None in a version 1 frame."""

    token: str
    label: str
    follow_up: bool = False
    boot_id: str | None = None
    monotonic: float | None = None  # seconds
    boottime: float | None = None  # seconds


def _encode_label(label: str) -> bytes:
    encoded = label.encode()
    if len(encoded) > MAX_LABEL_BYTES:
        raise ValueError(f"a beacon label is at most {MAX_LABEL_BYTES} bytes")
    return encoded


def _encode_token(token: str) -> bytes:
    raw = bytes.fromhex(token)
    if len(raw) != TOKEN_BYTES:
        raise ValueError("a beacon token is 32 hex digits")
    return raw


def _ethernet(body: bytes, source_mac: bytes) -> bytes:
    data = b"\xff" * 6 + source_mac + ETHERTYPE.to_bytes(2, "big") + body
    return data.ljust(MIN_FRAME, b"\x00")


def frame(label: str, token: str, source_mac: bytes = bytes(6)) -> bytes:
    """The bytes of a version 1 beacon frame for *label* and *token* (32 hex digits)."""
    encoded = _encode_label(label)
    body = MAGIC + bytes([VERSION, len(encoded)]) + _encode_token(token) + encoded
    return _ethernet(body, source_mac)


def clocked_frame(
    label: str,
    token: str,
    boot_id: str,
    monotonic_ns: int,
    boottime_ns: int,
    *,
    follow_up: bool = False,
    source_mac: bytes = bytes(6),
) -> bytes:
    """The bytes of a version 2 beacon (or, with *follow_up*, of its follow-up)."""
    encoded = b"" if follow_up else _encode_label(label)
    kind = _KIND_FOLLOW_UP if follow_up else _KIND_BEACON
    body = (
        MAGIC
        + bytes([CLOCKED_VERSION, kind, len(encoded)])
        + _encode_token(token)
        + uuid.UUID(boot_id).bytes
        + _CLOCKS.pack(monotonic_ns, boottime_ns)
        + encoded
    )
    return _ethernet(body, source_mac)


def decode(raw: bytes) -> BeaconFrame | None:
    """The beacon (or follow-up) *raw* carries, or None if it is not a beacon frame."""
    if raw[12:14] != ETHERTYPE.to_bytes(2, "big"):
        return None
    body = raw[HEADER:]
    if not body.startswith(MAGIC) or len(body) <= len(MAGIC):
        return None
    version = body[len(MAGIC)]
    at = len(MAGIC) + 1
    if version == VERSION:
        if len(body) < at + 1 + TOKEN_BYTES:
            return None
        size = body[at]
        token = body[at + 1 : at + 1 + TOKEN_BYTES]
        label = body[at + 1 + TOKEN_BYTES : at + 1 + TOKEN_BYTES + size]
        if len(label) != size:
            return None
        return BeaconFrame(token=token.hex(), label=label.decode(errors="replace"))
    if version != CLOCKED_VERSION:
        return None
    fixed = 2 + TOKEN_BYTES + _BOOT_ID_BYTES + _CLOCKS.size
    if len(body) < at + fixed:
        return None
    kind, size = body[at], body[at + 1]
    if kind not in (_KIND_BEACON, _KIND_FOLLOW_UP):
        return None
    at += 2
    token = body[at : at + TOKEN_BYTES]
    at += TOKEN_BYTES
    boot_id = str(uuid.UUID(bytes=body[at : at + _BOOT_ID_BYTES]))
    at += _BOOT_ID_BYTES
    monotonic_ns, boottime_ns = _CLOCKS.unpack(body[at : at + _CLOCKS.size])
    at += _CLOCKS.size
    label = body[at : at + size]
    if len(label) != size:
        return None
    return BeaconFrame(
        token=token.hex(),
        label=label.decode(errors="replace"),
        follow_up=kind == _KIND_FOLLOW_UP,
        boot_id=boot_id,
        monotonic=monotonic_ns / 1e9,
        boottime=boottime_ns / 1e9,
    )


def parse(raw: bytes) -> tuple[str, str] | None:
    """``(token, label)`` if *raw* is a beacon (version 1 or 2, not a follow-up), else None."""
    decoded = decode(raw)
    if decoded is None or decoded.follow_up:
        return None
    return decoded.token, decoded.label
