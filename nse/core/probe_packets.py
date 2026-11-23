# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""
The bytes of NSE's stimuli, and how to recognise them again.

Every stimulus carries a **probe ID** (24 hex digits, 96 random bits):

* UDP, TCP and ICMP payloads contain the marker ``nse-probe:<id>``;
* a DNS query's name starts with the label ``nse-<id>``;
* a STUN Binding Request's transaction ID *is* the ID (12 bytes);
* a QUIC-shaped Initial carries the marker in its (unencrypted) payload.

A bare TCP SYN has no payload: it is identified by the source port the probe
bound, recorded with the result. :func:`extract_probe_id` finds the ID in data a
receiver logged; :func:`request_packets` and :func:`reply_packets` find a
stimulus and its reply in a capture.
"""

from __future__ import annotations

import ipaddress
import re
import secrets
from collections.abc import Iterable
from typing import Any

from nse.models.stimulus import DnsAnswer, Endpoint, StimulusResult

MARKER = b"nse-probe:"
STUN_COOKIE = 0x2112A442
QUIC_INITIAL_SIZE = 1200  # RFC 9000 14.1: a client Initial is padded to 1200 bytes

_MARKER_RE = re.compile(rb"nse-probe:([0-9a-f]{24})")
_DNS_LABEL_RE = re.compile(rb"\x1cnse-([0-9a-f]{24})")
_RCODE_NAMES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}
QTYPES = {"A": 1, "AAAA": 28}


def new_probe_id() -> str:
    return secrets.token_hex(12)


def marker(probe_id: str) -> bytes:
    return MARKER + probe_id.encode("ascii")


def family_of(address: str) -> int:
    """4 or 6 for an IP literal; ``ValueError`` for anything else (no name lookup)."""
    return ipaddress.ip_address(address).version


def extract_probe_id(data: bytes) -> str | None:
    """The probe ID carried by *data*, wherever this module puts one."""
    found = _MARKER_RE.search(data)
    if found:
        return found.group(1).decode("ascii")
    if (
        len(data) >= 20
        and int.from_bytes(data[0:2], "big") in (0x0001, 0x0101)
        and int.from_bytes(data[4:8], "big") == STUN_COOKIE
    ):
        return data[8:20].hex()
    found = _DNS_LABEL_RE.search(data)
    if found:
        return found.group(1).decode("ascii")
    return None


# --------------------------------------------------------------------------- ICMP


def checksum(data: bytes) -> int:
    """The Internet checksum (RFC 1071)."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(int.from_bytes(data[i : i + 2], "big") for i in range(0, len(data), 2))
    while total >> 16:
        total = (total >> 16) + (total & 0xFFFF)
    return ~total & 0xFFFF


def icmp_echo(probe_id: str, family: int) -> bytes:
    """An echo request whose data is the probe marker.

    For ICMPv6 the kernel fills in the checksum (it covers a pseudo-header the
    socket cannot see); for ICMPv4 it is computed here.
    """
    identifier = int(probe_id[:4], 16)
    data = marker(probe_id)
    kind = 128 if family == 6 else 8
    header = bytes([kind, 0]) + b"\x00\x00" + identifier.to_bytes(2, "big") + b"\x00\x01"
    if family == 6:
        return header + data
    total = checksum(header + data)
    return header[:2] + total.to_bytes(2, "big") + header[4:] + data


# --------------------------------------------------------------------------- DNS


def _encode_name(name: str) -> bytes:
    encoded = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("ascii")
        if not 0 < len(raw) < 64:
            raise ValueError(f"invalid DNS label {label!r} in {name!r}")
        encoded += bytes([len(raw)]) + raw
    return encoded + b"\x00"


def dns_qname(probe_id: str, zone: str) -> str:
    return f"nse-{probe_id}.{zone.strip('.')}"


def dns_query(probe_id: str, qname: str, qtype: str) -> bytes:
    """A recursive query for *qname*; the ID is taken from the probe ID."""
    header = bytes.fromhex(probe_id[:4]) + b"\x01\x00" + b"\x00\x01" + b"\x00" * 6
    return header + _encode_name(qname) + QTYPES[qtype].to_bytes(2, "big") + b"\x00\x01"


def _read_name(message: bytes, offset: int) -> tuple[str, int]:
    """A possibly compressed name at *offset*; returns it and the offset after it."""
    labels: list[str] = []
    end: int | None = None
    for _ in range(128):  # bounded: a pointer loop is a malformed message
        length = message[offset]
        if length & 0xC0 == 0xC0:
            if end is None:
                end = offset + 2
            offset = ((length & 0x3F) << 8) | message[offset + 1]
            continue
        if length == 0:
            return ".".join(labels), (end if end is not None else offset + 1)
        labels.append(message[offset + 1 : offset + 1 + length].decode("ascii", "replace"))
        offset += 1 + length
    raise ValueError("DNS name compression loop")


def parse_dns(message: bytes) -> DnsAnswer:
    """The rcode, question and A/AAAA answers of *message*; ``ValueError`` if malformed."""
    try:
        if len(message) < 12:
            raise ValueError("shorter than a DNS header")
        rcode = message[3] & 0x0F
        qdcount = int.from_bytes(message[4:6], "big")
        ancount = int.from_bytes(message[6:8], "big")
        offset = 12
        qname = None
        for _ in range(qdcount):
            qname, offset = _read_name(message, offset)
            offset += 4
        addresses = []
        for _ in range(ancount):
            _, offset = _read_name(message, offset)
            rtype = int.from_bytes(message[offset : offset + 2], "big")
            length = int.from_bytes(message[offset + 8 : offset + 10], "big")
            rdata = message[offset + 10 : offset + 10 + length]
            if len(rdata) != length:
                raise ValueError("truncated resource record")
            if rtype in (1, 28) and length in (4, 16):
                addresses.append(str(ipaddress.ip_address(rdata)))
            offset += 10 + length
    except IndexError:
        raise ValueError("truncated DNS message") from None
    return DnsAnswer(
        id=int.from_bytes(message[0:2], "big"),
        rcode=rcode,
        rcode_name=_RCODE_NAMES.get(rcode, f"RCODE{rcode}"),
        qname=qname,
        addresses=tuple(addresses),
    )


# --------------------------------------------------------------------------- STUN and QUIC


def stun_binding_request(probe_id: str) -> bytes:
    """A Binding Request (RFC 8489) with no attributes; transaction ID = probe ID."""
    return b"\x00\x01\x00\x00" + STUN_COOKIE.to_bytes(4, "big") + bytes.fromhex(probe_id)


def parse_stun_mapped_address(message: bytes) -> Endpoint | None:
    """XOR-MAPPED-ADDRESS from a Binding Success Response, if there is one."""
    if len(message) < 20 or int.from_bytes(message[0:2], "big") != 0x0101:
        return None
    transaction = message[8:20]
    offset = 20
    end = 20 + int.from_bytes(message[2:4], "big")
    while offset + 4 <= min(end, len(message)):
        kind = int.from_bytes(message[offset : offset + 2], "big")
        length = int.from_bytes(message[offset + 2 : offset + 4], "big")
        value = message[offset + 4 : offset + 4 + length]
        if kind == 0x0020 and len(value) >= 8:
            port = int.from_bytes(value[2:4], "big") ^ (STUN_COOKIE >> 16)
            size = 16 if value[1] == 0x02 else 4
            mask = STUN_COOKIE.to_bytes(4, "big") + (transaction if size == 16 else b"")
            raw = bytes(a ^ b for a, b in zip(value[4 : 4 + size], mask, strict=False))
            if len(raw) == size:
                return Endpoint(address=str(ipaddress.ip_address(raw)), port=port)
        offset += 4 + length + (-length % 4)
    return None


def quic_initial(probe_id: str) -> bytes:
    """A datagram shaped like a QUIC v1 client Initial (RFC 9000 17.2.2).

    Long header, version 1, an 8-byte destination connection ID, padded to 1200
    bytes. The payload is *not* encrypted: this is the shape a middlebox
    recognises QUIC by, not a connection attempt a server could accept.
    """
    dcid = bytes.fromhex(probe_id[:16])
    body = marker(probe_id)
    header_fixed = b"\xc3" + (1).to_bytes(4, "big") + b"\x08" + dcid + b"\x00" + b"\x00"
    # Length (2-byte varint) covers the 4-byte packet number and the payload.
    length = QUIC_INITIAL_SIZE - len(header_fixed) - 2
    payload = body + b"\x00" * (length - 4 - len(body))
    return header_fixed + (0x4000 | length).to_bytes(2, "big") + b"\x00\x00\x00\x00" + payload


# --------------------------------------------------------------------------- captures


def _layers(packet: Any) -> tuple[Any, Any] | None:
    """(network layer, layer above it) of a captured packet, or None."""
    from scapy.layers.inet import IP
    from scapy.layers.inet6 import IPv6

    for network in (IP, IPv6):
        if packet.haslayer(network):
            layer = packet.getlayer(network)
            return layer, layer.payload
    return None


def _transport_matches(result: StimulusResult, upper: Any) -> bool:
    from scapy.layers.inet import ICMP, TCP, UDP

    name = {"udp": UDP, "tcp": TCP}.get(result.transport)
    if name is not None:
        return isinstance(upper, name)
    if result.family == 4:
        return isinstance(upper, ICMP)
    return bool(upper.name.startswith("ICMPv6"))


def _carries_probe(result: StimulusResult, upper: Any) -> bool:
    # Scapy keeps an ICMPv6 echo's data in a field, not a payload layer, so for
    # ICMP the whole message is searched (the type is checked by the caller).
    data = bytes(upper) if result.transport == "icmp" else bytes(upper.payload)
    return extract_probe_id(data) == result.probe_id


def request_packets(result: StimulusResult, packets: Iterable[Any]) -> list[Any]:
    """The captured packets that are *result*'s stimulus, travelling to its destination.

    A packet counts when it goes to the destination's address (and port) and
    carries the probe ID, or, for TCP without a payload, leaves from the source
    port the probe bound.
    """
    found = []
    for packet in packets:
        layers = _layers(packet)
        if layers is None:
            continue
        network, upper = layers
        if network.dst != result.destination.address or not _transport_matches(result, upper):
            continue
        if result.transport == "icmp":
            if upper.type in (8, 128) and _carries_probe(result, upper):
                found.append(packet)
            continue
        if upper.dport != result.destination.port:
            continue
        if _carries_probe(result, upper) or (
            result.source is not None and upper.sport == result.source.port
        ):
            found.append(packet)
    return found


def reply_packets(result: StimulusResult, packets: Iterable[Any]) -> list[Any]:
    """The captured packets that answer *result*'s stimulus, travelling back to it."""
    found = []
    for packet in packets:
        layers = _layers(packet)
        if layers is None:
            continue
        network, upper = layers
        if network.src != result.destination.address or not _transport_matches(result, upper):
            continue
        if result.transport == "icmp":
            if upper.type in (0, 129) and _carries_probe(result, upper):
                found.append(packet)
            continue
        if upper.sport != result.destination.port:
            continue
        if (result.source is not None and upper.dport == result.source.port) or _carries_probe(
            result, upper
        ):
            found.append(packet)
    return found
