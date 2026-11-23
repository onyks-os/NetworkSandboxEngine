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

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, computed_field

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


class BeaconSighting(BaseModel):
    """A beacon frame the capture read."""

    model_config = ConfigDict(frozen=True)

    label: str
    token: str
    seen_at: float = Field(description="Unix time the capture read it.")
    index: int = Field(description="How many frames the capture had read before it.")


class CaptureReport(BaseModel):
    """Result of one capture session, produced once and shared by stop()/stop_report()."""

    model_config = ConfigDict(frozen=True)

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
        default=0, description="Frames read at exactly snaplen bytes: possibly cut short."
    )
    beacons_expected: list[Beacon] = Field(
        default_factory=list, description="Beacons sent for this capture, in order."
    )
    beacons_seen: list[BeaconSighting] = Field(
        default_factory=list,
        description="Beacon frames the capture read, in order. They count in "
        "packets_observed but are never in the list stop() returns.",
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
        if self.kernel_packets is None or self.kernel_drops is None:
            return None
        if self.kernel_drops:
            return False
        return self.packets_observed >= self.kernel_packets
