# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""
What a stimulus did, and what a controlled receiver saw.

:class:`StimulusResult` is the account of one stimulus sent by a process inside
a namespace (:mod:`nse.stimuli`). :class:`Receipt` is one arrival logged by a
controlled receiver (:mod:`nse.receivers`), and :class:`ReceiptLog` is the
receiver's whole log together with whether it can vouch for being complete.

The outcome of a stimulus is never folded into another one: a send the kernel
refused (``refused``, with its errno) is the firewall working, a probe that
could not run (``could_not_run``) is the instrument failing, and only a
stimulus that asked for a reply can end ``no_reply``.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from nse.models.process import EffectiveIdentity

Outcome = Literal["sent", "answered", "no_reply", "refused", "could_not_run"]

#: Where a stimulus stopped. ``launch`` and ``output`` are NSE's own steps
#: (starting the program, reading its report); the others are socket calls.
Stage = Literal["launch", "socket", "bind", "connect", "send", "receive", "output"]

Transport = Literal["udp", "tcp", "icmp"]

StimulusKind = Literal[
    "udp",
    "udp_round_trip",
    "tcp_connect",
    "tcp_round_trip",
    "icmp_echo",
    "dns_query",
    "quic_initial",
    "stun_binding",
]

#: The outcomes in which the packet left the socket.
LEFT_THE_SOCKET: frozenset[str] = frozenset({"sent", "answered", "no_reply"})


class Endpoint(BaseModel):
    """An IP address and a port (0 where the protocol has none)."""

    model_config = ConfigDict(frozen=True)

    address: str
    port: int = Field(ge=0, le=65535)

    def __str__(self) -> str:
        return (
            f"[{self.address}]:{self.port}"
            if ":" in self.address
            else f"{self.address}:{self.port}"
        )


class DnsAnswer(BaseModel):
    """The parts of a DNS response a test asserts on."""

    model_config = ConfigDict(frozen=True)

    id: int
    rcode: int
    rcode_name: str = Field(description="NOERROR, SERVFAIL, NXDOMAIN, REFUSED, ...")
    qname: str | None = Field(description="The question's name, if the response echoed it.")
    addresses: tuple[str, ...] = Field(description="A and AAAA addresses in the answer section.")


class StimulusResult(BaseModel):
    """What one stimulus did, as reported by the process that sent it."""

    model_config = ConfigDict(frozen=True, ser_json_bytes="base64")

    kind: StimulusKind
    transport: Transport
    family: Literal[4, 6]
    probe_id: str = Field(
        description="Identifies this stimulus: in its payload where there is one, and "
        "in the receipts of a controlled receiver that got it."
    )
    destination: Endpoint
    source: Endpoint | None = Field(
        default=None,
        description="The socket's local address and port, as the kernel chose or "
        "bound them; for a bare TCP SYN this is what identifies the probe.",
    )
    payload: bytes = Field(description="The bytes handed to the socket.")
    outcome: Outcome
    stage: Stage | None = Field(
        default=None, description="The step that ended a refused, unanswered or failed stimulus."
    )
    errno: int | None = Field(default=None, description="The errno of a failed socket call.")
    error: str | None = Field(default=None, description="The error, as text.")
    reason: str | None = Field(
        default=None, description="Why a could_not_run stimulus could not run."
    )
    reply: bytes | None = Field(default=None, description="The reply, for an answered stimulus.")
    reply_source: Endpoint | None = None
    connected: bool | None = Field(
        default=None, description="TCP only: whether the handshake completed."
    )
    dns: DnsAnswer | None = Field(default=None, description="The parsed reply of a DNS query.")
    mapped_address: Endpoint | None = Field(
        default=None, description="STUN only: the XOR-MAPPED-ADDRESS the server reported."
    )
    sent_at: float | None = Field(default=None, description="Unix time of the send call.")
    sent_monotonic: float | None = Field(
        default=None, description="CLOCK_MONOTONIC of the send call, comparable with receipts."
    )
    ended_monotonic: float | None = None
    identity: EffectiveIdentity | None = Field(
        default=None, description="The identity the kernel reported for the sending process."
    )

    @property
    def left_socket(self) -> bool:
        """True when the send call succeeded (``sent``, ``answered`` or ``no_reply``).

        This is the process's account. Whether the packet then reached the wire
        is a separate fact: see :func:`nse.stimuli.observe`.
        """
        return self.outcome in LEFT_THE_SOCKET

    @property
    def answered(self) -> bool:
        return self.outcome == "answered"

    def describe(self) -> str:
        """One line for an assertion message."""
        text = f"{self.kind} {self.destination} probe {self.probe_id}: {self.outcome}"
        if self.stage:
            text += f" at {self.stage}"
        if self.error:
            text += f" ({self.error})"
        if self.reason:
            text += f": {self.reason}"
        return text


ReceiptKind = Literal["datagram", "connection", "data"]


class Receipt(BaseModel):
    """One arrival at a controlled receiver, logged before it was answered."""

    model_config = ConfigDict(frozen=True, ser_json_bytes="base64")

    seq: int = Field(ge=1, description="Position in the receiver's log, from 1, without gaps.")
    transport: Literal["udp", "tcp"]
    kind: ReceiptKind = Field(
        description="A UDP datagram; an accepted TCP connection; data on one."
    )
    family: Literal[4, 6]
    source: Endpoint = Field(description="Where the traffic came from, as the receiver saw it.")
    destination: Endpoint = Field(description="The receiver's own address and port.")
    monotonic: float = Field(description="CLOCK_MONOTONIC on arrival.")
    wall: float = Field(description="Unix time on arrival.")
    size: int = Field(ge=0, description="Bytes that arrived.")
    data: bytes = Field(description="The first bytes that arrived (see record_bytes).")
    response: str = Field(
        description="What the receiver did: echo, accepted, answer, servfail, refused, "
        "drop, binding, malformed or none."
    )
    probe_id: str | None = Field(
        default=None, description="The probe ID found in the data, if any."
    )


class ReceiptLog(BaseModel):
    """A receiver's log, and whether it can vouch for having recorded everything."""

    model_config = ConfigDict(frozen=True)

    receipts: tuple[Receipt, ...] = ()
    complete: bool = Field(
        description="False when lines may be missing (output limit reached, a gap in "
        "the sequence, an unreadable line, or the receiver died on its own). An "
        "absence in an incomplete log proves nothing."
    )
    problems: tuple[str, ...] = Field(default=(), description="Why the log is incomplete.")

    def for_probe(self, probe_id: str) -> list[Receipt]:
        return [r for r in self.receipts if r.probe_id == probe_id]

    def from_source(self, source: Endpoint, transport: str | None = None) -> list[Receipt]:
        return [
            r
            for r in self.receipts
            if r.source == source and (transport is None or r.transport == transport)
        ]

    def matching(self, result: StimulusResult) -> list[Receipt]:
        """Receipts of *result*: its probe ID, or (with no ID in the data) its source."""
        seen = []
        for receipt in self.receipts:
            if receipt.probe_id is not None:
                if receipt.probe_id == result.probe_id:
                    seen.append(receipt)
            elif (
                result.source is not None
                and receipt.transport == result.transport
                and receipt.source.port == result.source.port
                and (result.source.address in ("0.0.0.0", "::") or receipt.source == result.source)
            ):
                seen.append(receipt)
        return seen
