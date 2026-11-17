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
]


class CaptureReport(BaseModel):
    """Result of one capture session, produced once and shared by stop()/stop_report()."""

    model_config = ConfigDict(frozen=True)

    iface: str = Field(description="Interface the capture was armed on.")
    requested_filter: str | None = Field(description="Filter passed by the caller, if any.")
    effective_filter: str = Field(description="BPF expression actually attached in the kernel.")
    default_filter_replaced: bool = Field(
        description="True when the caller's filter replaced DEFAULT_FILTER instead of narrowing it."
    )
    backend: str = Field(description="Capture backend, e.g. 'scapy-l2listen'.")
    backend_version: str = Field(description="Version of the backend library.")

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
    packets_written: int | None = Field(
        default=None, description="Packets written to an artifact; None when no file output."
    )
    artifacts: list[str] = Field(
        default_factory=list, description="Paths of files produced by the capture."
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

    @computed_field  # type: ignore[prop-decorator]
    @property
    def instrument_healthy(self) -> bool:
        """The capture was armed, ran until asked to stop, and reported no backend error."""
        return self.started_at is not None and self.termination == "stopped" and not self.errors

    @computed_field  # type: ignore[prop-decorator]
    @property
    def window_complete(self) -> bool | None:
        """Whether every packet matching the filter between start and stop was read.

        ``False`` if the instrument was unhealthy, the kernel dropped packets, or
        packets remained unread; ``None`` when the drop counters are unavailable,
        because completeness then cannot be shown either way.
        """
        if not self.instrument_healthy:
            return False
        if self.kernel_packets is None or self.kernel_drops is None:
            return None
        if self.kernel_drops:
            return False
        return self.packets_observed >= self.kernel_packets
