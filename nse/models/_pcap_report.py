# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""
A :class:`~nse.models.capture_report.CaptureReport` for a pcap file NSE did not capture.

Used by :meth:`CaptureReport.from_pcap`. The file is checked structurally by
:func:`nse.formats.pcap.read`, every record is decoded with Scapy according to
the file's link type, and beacon frames (and their follow-ups) become
sightings instead of packets, as in a live capture.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterable
from typing import Any

from nse.formats import beacon as beacon_format
from nse.formats import pcap
from nse.models.capture_report import (
    Beacon,
    BeaconSighting,
    CaptureLimits,
    CaptureReport,
    record_sighting,
)

_LINKTYPE_ETHERNET = 1
_NO_COUNTERS = (
    "read from a pcap file NSE did not capture: the capturing side's drop counters are unknown"
)


def _decoder(link_type: int | None) -> Callable[[bytes], Any] | None:
    """The Scapy layer for *link_type*, or None if Scapy does not know it."""
    if link_type is None:
        return None
    import scapy.layers.inet6
    import scapy.layers.l2  # noqa: F401 - registering the link types
    from scapy.config import conf

    layer = conf.l2types.get(link_type)
    return layer if isinstance(layer, type) else None


def _mtime(path: str) -> float:
    try:
        return os.stat(path).st_mtime
    except OSError:
        return 0.0


def report_from_pcap(
    path: str | os.PathLike[str],
    *,
    required_bytes: int | None = None,
    expected_beacons: Iterable[Beacon] = (),
) -> tuple[CaptureReport, list[Any]]:
    contents = pcap.read(path)
    errors = [contents.error] if contents.error else []
    decode = _decoder(contents.link_type)
    if contents.link_type is not None and decode is None:
        errors.append(f"{contents.path}: link type {contents.link_type} cannot be decoded")
    ethernet = contents.link_type == _LINKTYPE_ETHERNET

    packets: list[Any] = []
    sightings: list[BeaconSighting] = []
    stored_bytes = observed_bytes = truncated = 0
    for position, record in enumerate(contents.records):
        observed_bytes += len(record.data)
        truncated += record.truncated
        frame = beacon_format.decode(record.data) if ethernet else None
        if frame is not None:
            record_sighting(sightings, frame, record.timestamp, position)
            continue
        if decode is None:
            continue
        try:
            packet = decode(record.data)
        except Exception as exc:
            errors.append(f"{contents.path}: record {record.index} cannot be decoded ({exc!r})")
            continue
        packet.time = record.timestamp
        packets.append(packet)
        stored_bytes += len(record.data)

    readable = contents.link_type is not None
    times = [record.timestamp for record in contents.records]
    first = times[0] if times else _mtime(contents.path)
    report = CaptureReport(
        source="pcap_file",
        iface=contents.path,
        netns=None,
        requested_filter=None,
        effective_filter="",
        default_filter_replaced=False,
        backend="pcap-file",
        backend_version="2.4",
        output_mode="file",
        limits=CaptureLimits(),
        termination="stopped",
        errors=errors,
        start_requested_at=first,
        started_at=first if readable else None,
        stop_requested_at=times[-1] if times else first,
        stopped_at=times[-1] if times else first,
        packets_observed=len(contents.records),
        bytes_observed=observed_bytes,
        packets_stored=len(packets),
        bytes_stored=stored_bytes,
        packets_written=len(contents.records),
        bytes_written=observed_bytes,
        artifacts=[contents.path],
        artifact_complete=not errors,
        kernel_packets=None,
        kernel_drops=None,
        stats_unavailable_reason=_NO_COUNTERS,
        link_type=contents.link_type,
        snaplen=contents.snaplen or None,
        required_bytes=required_bytes,
        packets_truncated=truncated,
        beacons_expected=list(expected_beacons),
        beacons_seen=sightings,
    )
    return report, packets
