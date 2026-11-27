# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""
Reading a classic pcap file, refusing any structural damage.

:func:`read` never trusts a file it cannot account for byte by byte. The
records before the first damage are kept, and the damage is described in
:attr:`PcapContents.error`. It covers an empty or cut file header, an unknown
magic (pcapng included), a version other than 2.4, a record header or frame
cut short, and a record that claims more bytes than the packet had
(``incl > orig``) or than the snap length allows (``incl > snaplen``).
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field

#: Size of the global header and of each record header.
FILE_HEADER = 24
RECORD_HEADER = 16

#: magic -> (byte order, timestamp fraction units per second)
_MAGIC = {
    0xA1B2C3D4: ("<", 1_000_000),
    0xD4C3B2A1: (">", 1_000_000),
    0xA1B23C4D: ("<", 1_000_000_000),
    0x4D3CB2A1: (">", 1_000_000_000),
}
_PCAPNG = 0x0A0D0D0A


@dataclass(frozen=True)
class PcapRecord:
    """One packet record: its capture time, the bytes kept and the packet's length."""

    index: int  # from 1, in file order
    timestamp: float  # seconds since the epoch, on the capturing machine's clock
    data: bytes
    original_length: int

    @property
    def truncated(self) -> bool:
        """The record holds fewer bytes than the packet had."""
        return len(self.data) < self.original_length


@dataclass
class PcapContents:
    """What a pcap file holds, up to the first damage."""

    path: str
    link_type: int | None = None
    snaplen: int | None = None
    nanosecond: bool = False
    records: list[PcapRecord] = field(default_factory=list)
    error: str | None = None  # None: the file was read to its end without damage


def read(path: str | os.PathLike[str]) -> PcapContents:
    """Every record of *path*; never raises for a damaged or unreadable file."""
    name = os.fspath(path)
    contents = PcapContents(path=name)
    try:
        with open(name, "rb") as f:
            _read_into(contents, f.read())
    except OSError as exc:
        contents.error = f"{name}: cannot be read ({exc.strerror or exc})"
    return contents


def _read_into(contents: PcapContents, data: bytes) -> None:
    name = contents.path
    if len(data) < FILE_HEADER:
        state = "empty" if not data else "truncated"
        contents.error = f"{name}: {state} file header ({len(data)} of {FILE_HEADER} bytes)"
        return
    magic = struct.unpack("<I", data[:4])[0]
    if magic == _PCAPNG:
        contents.error = f"{name}: a pcapng file, not a classic pcap file"
        return
    if magic not in _MAGIC:
        contents.error = f"{name}: not a pcap file (magic {magic:#010x})"
        return
    order, units = _MAGIC[magic]
    major, minor, _zone, _sigfigs, snaplen, link_type = struct.unpack(
        order + "HHiIII", data[4:FILE_HEADER]
    )
    if (major, minor) != (2, 4):
        contents.error = f"{name}: unsupported pcap version {major}.{minor}"
        return
    contents.link_type = link_type & 0x0FFFFFFF  # the top bits carry FCS flags
    contents.snaplen = snaplen
    contents.nanosecond = units == 1_000_000_000
    offset, index = FILE_HEADER, 0
    while offset < len(data):
        index += 1
        header = data[offset : offset + RECORD_HEADER]
        if len(header) < RECORD_HEADER:
            contents.error = (
                f"{name}: record {index} header cut short ({len(header)} of {RECORD_HEADER} bytes)"
            )
            return
        sec, frac, incl, orig = struct.unpack(order + "IIII", header)
        if incl > orig or (snaplen and incl > snaplen):
            contents.error = (
                f"{name}: record {index} claims {incl} bytes of {orig} (snap length {snaplen})"
            )
            return
        if frac >= units:
            contents.error = f"{name}: record {index} has an invalid timestamp fraction {frac}"
            return
        offset += RECORD_HEADER
        frame = data[offset : offset + incl]
        if len(frame) < incl:
            contents.error = (
                f"{name}: record {index} frame cut short ({len(frame)} of {incl} bytes)"
            )
            return
        offset += incl
        contents.records.append(
            PcapRecord(index=index, timestamp=sec + frac / units, data=frame, original_length=orig)
        )


def write(
    path: str | os.PathLike[str],
    records: list[tuple[float, bytes]],
    *,
    link_type: int = 1,
    snaplen: int = 262144,
) -> None:
    """Write *records* (timestamp, frame) as a microsecond pcap file; for tests and fixtures."""
    out = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, link_type)]
    for timestamp, frame in records:
        sec = int(timestamp)
        usec = round((timestamp - sec) * 1_000_000)
        if usec == 1_000_000:
            sec, usec = sec + 1, 0
        kept = frame[:snaplen]
        out.append(struct.pack("<IIII", sec, usec, len(kept), len(frame)) + kept)
    with open(path, "wb") as f:
        f.write(b"".join(out))
