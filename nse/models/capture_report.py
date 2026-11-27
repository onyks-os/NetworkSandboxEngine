# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""
CaptureReport: what a packet capture could see, what it saw, and how it ended.

An empty packet list cannot tell "nothing matched" apart from "the instrument was
not working". The report carries the evidence needed to tell them apart. It
describes the **instrument**; whether that evidence is sufficient for a given
assertion (for example a positive control on the same path) is decided by the
test, never by the report.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, computed_field

from nse.formats.beacon import BeaconFrame

Termination = Literal[
    "stopped",  # stop requested and the capture loop drained and exited in time
    "limit_reached",  # the capture ended itself at max_packets or max_duration
    "start_failed",  # the backend could not be armed; see start_failure
    "start_timeout",  # the backend did not confirm readiness before the deadline
    "start_cancelled",  # the caller cancelled start(); resources were released
    "backend_terminated",  # the capture loop ended before stop was requested
    "stop_timeout",  # the capture loop did not exit before the stop deadline
]

StartFailure = Literal[
    "interface_missing",
    "filter_invalid",
    "permission_denied",
    "backend_unavailable",
    "backend_error",
    "output_unavailable",  # the PCAP file could not be created (exists, no permission, ...)
]

OutputMode = Literal["memory", "file"]

CaptureSource = Literal["live", "pcap_file"]

LimitName = Literal[
    "max_packets",
    "max_duration",
    "max_file_bytes",
    "max_stored_packets",
    "max_stored_bytes",
]

#: Size of the PCAP global header; a PCAP file is never smaller.
PCAP_HEADER_BYTES = 24
#: Size of each PCAP record header, written before the packet bytes.
PCAP_RECORD_HEADER_BYTES = 16

#: Limits that only bound the in-memory sample when the record is the file.
_SAMPLE_LIMITS: frozenset[str] = frozenset({"max_stored_packets", "max_stored_bytes"})


class CaptureLimits(BaseModel):
    """Bounds on how long a capture runs and how much it keeps.

    Every limit is optional; ``None`` means unbounded. Reaching a limit is never
    silent: it is listed in :attr:`CaptureReport.limits_reached` and, unless it
    only bounds the in-memory sample of a file capture, it makes
    :attr:`CaptureReport.window_complete` ``False``.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    max_packets: int | None = Field(
        default=None,
        gt=0,
        description="The capture ends itself after reading this many packets "
        "(termination 'limit_reached'); later packets are not read.",
    )
    max_duration: float | None = Field(
        default=None,
        gt=0,
        allow_inf_nan=False,
        description="The capture ends itself this many seconds after readiness, after "
        "draining what was already queued (termination 'limit_reached').",
    )
    max_file_bytes: int | None = Field(
        default=None,
        ge=PCAP_HEADER_BYTES,
        description="File mode only. The first packet that would grow the PCAP file past "
        "this size, and every packet after it, is counted but not written: the file "
        "stays a readable prefix of the capture.",
    )
    max_stored_packets: int | None = Field(
        default=None,
        ge=0,
        description="Keep at most this many packets in memory. Later packets are counted "
        "(and written, in file mode) but not kept.",
    )
    max_stored_bytes: int | None = Field(
        default=None,
        ge=0,
        description="Keep at most this many bytes of packet data in memory. The first "
        "packet that would exceed it, and every packet after it, is not kept.",
    )


class SenderClock(BaseModel):
    """The sender's clocks around one clocked (version 2) beacon.

    The beacon frame carries the values read just before it was sent; its
    follow-up frame carries those read just after. Until the follow-up is seen
    the ``*_after`` fields are None, and the sending time is not bracketed.
    """

    model_config = ConfigDict(frozen=True)

    boot_id: str = Field(description="The sender's /proc/sys/kernel/random/boot_id.")
    monotonic_before: float = Field(description="CLOCK_MONOTONIC just before sending, seconds.")
    boottime_before: float = Field(description="CLOCK_BOOTTIME just before sending, seconds.")
    monotonic_after: float | None = Field(
        default=None, description="CLOCK_MONOTONIC just after sending; None without a follow-up."
    )
    boottime_after: float | None = Field(
        default=None, description="CLOCK_BOOTTIME just after sending; None without a follow-up."
    )

    @property
    def bracketed(self) -> bool:
        """Both sides of the send are known."""
        return self.monotonic_after is not None and self.boottime_after is not None


class Beacon(BaseModel):
    """A beacon frame that was sent: a marker the capture is expected to see.

    A beacon is a non-IP Ethernet frame (EtherType 0x88B5, IEEE 802 local
    experimental) carrying a random token and a label. No firewall rule for IP
    traffic touches it, so seeing it proves only that the capture was reading
    that link at that moment. Two beacons around a window, both seen, prove the
    capture was open for all of it.
    """

    model_config = ConfigDict(frozen=True)

    label: str
    token: str = Field(description="32 hex digits, unique to this beacon.")
    iface: str = Field(description="Interface the frame was sent from.")
    netns: str | None = Field(description="Namespace of that interface; None for NSE's own.")
    sent_at: float = Field(description="Unix time the frame was sent.")
    sent_monotonic: float = Field(description="time.monotonic() when the frame was sent.")
    clock: SenderClock | None = Field(
        default=None, description="The sender's clocks, for a clocked beacon; None otherwise."
    )


class BeaconSighting(BaseModel):
    """A beacon frame the capture read."""

    model_config = ConfigDict(frozen=True)

    label: str
    token: str
    seen_at: float = Field(description="Unix time the capture read it.")
    index: int = Field(description="How many frames the capture had read before it.")
    clock: SenderClock | None = Field(
        default=None,
        description="The sender's clocks a clocked beacon carried (and its follow-up, "
        "if seen); None for a version 1 beacon.",
    )


class CaptureReport(BaseModel):
    """Result of one capture session, produced once and shared by stop()/stop_report()."""

    model_config = ConfigDict(frozen=True)

    source: CaptureSource = Field(
        default="live",
        description="'live' for a capture NSE ran; 'pcap_file' for a file it only read "
        "(CaptureReport.from_pcap), whose kernel counters are unknown.",
    )
    iface: str = Field(description="Interface the capture was armed on.")
    netns: str | None = Field(
        default=None,
        description="Network namespace holding the interface; None for the namespace NSE runs in.",
    )
    requested_filter: str | None = Field(description="Filter passed by the caller, if any.")
    effective_filter: str = Field(description="BPF expression actually attached in the kernel.")
    default_filter_replaced: bool = Field(
        description="True when the caller's filter replaced DEFAULT_FILTER instead of narrowing it."
    )
    backend: str = Field(description="Capture backend, e.g. 'scapy-l2listen'.")
    backend_version: str = Field(description="Version of the backend library.")
    output_mode: OutputMode = Field(
        default="memory",
        description="'memory': the record is the packet list returned by stop(). 'file': "
        "the record is the PCAP artifact; memory only holds a bounded sample.",
    )
    limits: CaptureLimits = Field(
        default_factory=CaptureLimits,
        description="Limits in force, including the defaults applied by file mode.",
    )

    termination: Termination
    start_failure: StartFailure | None = Field(
        default=None, description="Classified cause when the capture could not start."
    )
    errors: list[str] = Field(
        default_factory=list, description="Backend errors, in the order they occurred."
    )

    start_requested_at: float = Field(description="Unix time start() was called.")
    started_at: float | None = Field(
        default=None,
        description="Unix time the kernel socket was bound with its filter: from here on, "
        "matching packets are queued for the capture.",
    )
    stop_requested_at: float | None = None
    stopped_at: float | None = Field(
        default=None, description="Unix time the capture loop exited (None if it did not)."
    )

    packets_observed: int = Field(description="Packets read from the kernel socket.")
    bytes_observed: int = Field(description="Bytes of the packets read from the kernel socket.")
    packets_stored: int = Field(description="Packets kept in memory and returned by stop().")
    bytes_stored: int = Field(default=0, description="Bytes of the packets kept in memory.")
    packets_written: int | None = Field(
        default=None, description="Packets written to the PCAP file; None when no file output."
    )
    bytes_written: int | None = Field(
        default=None,
        description="Size of the PCAP file as written, headers included; None when no file output.",
    )
    artifacts: list[str] = Field(
        default_factory=list,
        description="Paths of files produced by the capture, including partial ones.",
    )
    artifact_complete: bool | None = Field(
        default=None,
        description="File mode: every packet read was written and the file was flushed and "
        "closed without error. None in memory mode.",
    )
    limits_reached: list[LimitName] = Field(
        default_factory=list, description="Limits that were reached, in the order they were hit."
    )

    kernel_packets: int | None = Field(
        default=None,
        description="Packets that passed the BPF filter after readiness, including dropped ones "
        "(PACKET_STATISTICS tp_packets). None when unavailable.",
    )
    kernel_drops: int | None = Field(
        default=None,
        description="Packets the kernel dropped because the socket buffer was full "
        "(PACKET_STATISTICS tp_drops). None when unavailable - never a guessed zero.",
    )
    stats_unavailable_reason: str | None = Field(
        default=None, description="Why kernel_packets/kernel_drops are None."
    )

    hardware_type: int | None = Field(
        default=None, description="Linux ARPHRD_* type of the interface; None if never opened."
    )
    link_type: int | None = Field(
        default=None,
        description="PCAP LINKTYPE_* of the frames read (1: Ethernet, 101: raw IP); None "
        "when the hardware type has no known mapping.",
    )
    snaplen: int | None = Field(
        default=None, description="Most bytes of one frame the capture reads; None if never opened."
    )
    required_bytes: int | None = Field(
        default=None,
        description="Bytes of each frame the caller said it needs (PCAPAsserter(required_bytes=)).",
    )
    packets_truncated: int = Field(
        default=0,
        description="Frames read at exactly snaplen bytes: possibly cut short. For a pcap "
        "file, the records holding fewer bytes than the packet had.",
    )
    beacons_expected: list[Beacon] = Field(
        default_factory=list, description="Beacons sent for this capture, in order."
    )
    beacons_seen: list[BeaconSighting] = Field(
        default_factory=list,
        description="Beacon frames the capture read, in order. They count in "
        "packets_observed but are never in the list stop() returns.",
    )

    @classmethod
    def from_pcap(
        cls,
        path: str | os.PathLike[str],
        *,
        required_bytes: int | None = None,
        expected_beacons: Iterable[Beacon] = (),
    ) -> tuple[CaptureReport, list[Any]]:
        """The report and the packets of a pcap file NSE did not capture.

        The file is refused, record by record, on any structural damage: an
        empty or cut file header, a wrong magic or version, a record header or
        frame cut short, or a record claiming more bytes than the packet had or
        than the snap length allows. The records before the damage are
        returned, and the damage is in ``errors``, so the window is not
        complete. Beacon frames become ``beacons_seen``, never packets.

        Kernel drops are unknown (``kernel_drops`` is None). See
        :attr:`window_complete` for when such a window counts as complete.
        """
        from nse.models._pcap_report import report_from_pcap

        return report_from_pcap(
            path, required_bytes=required_bytes, expected_beacons=expected_beacons
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def beacons_missing(self) -> list[str]:
        """Labels of the expected beacons the capture did not read."""
        seen = {sighting.token for sighting in self.beacons_seen}
        return [beacon.label for beacon in self.beacons_expected if beacon.token not in seen]

    @computed_field  # type: ignore[prop-decorator]
    @property
    def snaplen_sufficient(self) -> bool | None:
        """Whether every frame was read in full up to required_bytes; None if none was required."""
        if self.required_bytes is None:
            return None
        return self.snaplen is not None and self.snaplen >= self.required_bytes

    @computed_field  # type: ignore[prop-decorator]
    @property
    def instrument_healthy(self) -> bool:
        """The capture was armed, ran until asked to stop or until a declared limit ended
        it, and reported no backend or file error."""
        return (
            self.started_at is not None
            and self.termination in ("stopped", "limit_reached")
            and not self.errors
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def window_complete(self) -> bool | None:
        """Whether every packet matching the filter between start and stop was read
        and kept in the record: the PCAP file in file mode, the list otherwise.

        ``False`` if the instrument was unhealthy, a limit truncated the window or
        the record, the file is incomplete, the kernel dropped packets, packets
        remained unread, an expected beacon was not seen, or the snaplen is below
        the bytes the caller required; ``None`` when the drop counters are
        unavailable, because completeness then cannot be shown either way. In
        file mode the in-memory sample is not the record, so its limits do not
        count here.

        A report read from a pcap file NSE did not capture (``source`` is
        ``"pcap_file"``) has no drop counters. Its beacons stand in for them:
        it is ``True`` only when the file is intact, the snap length covers
        ``required_bytes``, and at least one beacon was expected and every
        expected beacon is in the file. Without expected beacons it is
        ``None``: nothing shows the file covers the window.
        """
        if not self.instrument_healthy:
            return False
        if self.artifact_complete is False:
            return False
        if self.beacons_missing or self.snaplen_sufficient is False:
            return False
        if any(
            not (self.output_mode == "file" and name in _SAMPLE_LIMITS)
            for name in self.limits_reached
        ):
            return False
        if self.source == "pcap_file":
            return True if self.beacons_expected else None
        if self.kernel_packets is None or self.kernel_drops is None:
            return None
        if self.kernel_drops:
            return False
        return self.packets_observed >= self.kernel_packets


def record_sighting(
    sightings: list[BeaconSighting], frame: BeaconFrame, seen_at: float, index: int
) -> None:
    """Add the beacon *frame* to *sightings*, or complete the clock of the beacon it follows.

    A follow-up only fills the ``*_after`` clocks of the latest sighting with
    its token, and only once and from the same boot; any other follow-up is
    ignored, so the sending time of that beacon stays unbracketed.
    """
    if frame.follow_up:
        for at in range(len(sightings) - 1, -1, -1):
            if sightings[at].token != frame.token:
                continue
            clock = sightings[at].clock
            if clock is not None and clock.boot_id == frame.boot_id and not clock.bracketed:
                after = {"monotonic_after": frame.monotonic, "boottime_after": frame.boottime}
                sightings[at] = sightings[at].model_copy(
                    update={"clock": clock.model_copy(update=after)}
                )
            return
        return
    clock = None
    if frame.boot_id is not None and frame.monotonic is not None and frame.boottime is not None:
        clock = SenderClock(
            boot_id=frame.boot_id,
            monotonic_before=frame.monotonic,
            boottime_before=frame.boottime,
        )
    sightings.append(
        BeaconSighting(
            label=frame.label, token=frame.token, seen_at=seen_at, index=index, clock=clock
        )
    )
