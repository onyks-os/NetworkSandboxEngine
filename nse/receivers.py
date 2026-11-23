# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""
Controlled receivers: known servers that log every arrival.

A capture says a packet was *on the wire*; a receiver says it *arrived*. The
difference matters: a packet can be captured on the veth and still be dropped
by the destination's input path, and a reply can only come from something that
received the request. Run receivers on the host endpoint of an isolated sandbox
(``create_namespace(..., isolated_host=True)``, then ``sandbox.host``), where
no firewall of NSE's own machine sits in the path::

    from nse import receivers, stimuli

    async with await receivers.udp_echo("10.0.1.1", 9999).start(sandbox.host) as echo:
        result = await stimuli.udp_round_trip("10.0.1.1", 9999).run(sandbox)
        log = echo.log()
    assert log.complete and log.matching(result)

:meth:`ReceiverSpec.start` returns only once every socket is bound (the
program says so explicitly), and raises :class:`ReceiverStartError` if binding
fails. Each arrival is logged as a :class:`~nse.models.stimulus.Receipt`
*before* it is answered. :meth:`Receiver.log` says whether the log is complete:
an absence in an incomplete log proves nothing.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Literal

from nse import _agents
from nse.core import probe_packets
from nse.core.process import ManagedProcess, ProcessExitedError
from nse.models.process import ProcessIdentity, ProcessResult
from nse.models.stimulus import Endpoint, Receipt, ReceiptLog

__all__ = [
    "Receiver",
    "ReceiverSpec",
    "ReceiverStartError",
    "dns",
    "stun",
    "tcp_echo",
    "udp_echo",
]

ReceiverKind = Literal["udp_echo", "tcp_echo", "dns", "stun"]
DnsMode = Literal["answer", "drop", "servfail", "refused"]

_READY = b'"event": "ready"'
_OUTPUT_LIMIT = 16 * 1024 * 1024


class ReceiverStartError(RuntimeError):
    """The receiver could not bind or did not become ready; nothing is left running."""

    def __init__(self, message: str, result: ProcessResult | None = None) -> None:
        super().__init__(message)
        self.result = result


@dataclass(frozen=True)
class ReceiverSpec:
    """What to run: build one with :func:`udp_echo`, :func:`tcp_echo`, :func:`dns` or :func:`stun`."""

    kind: ReceiverKind
    address: str
    port: int
    transports: tuple[Literal["udp", "tcp"], ...]
    dns_mode: DnsMode = "answer"
    dns_a: tuple[str, ...] = ()
    dns_aaaa: tuple[str, ...] = ()
    dns_ttl: int = 60
    record_bytes: int = 512
    idle_timeout: float = 5.0

    def __post_init__(self) -> None:
        try:
            probe_packets.family_of(self.address)
        except ValueError:
            raise ValueError(f"{self.address!r} is not an IP address") from None
        if not 0 <= self.port <= 65535:
            raise ValueError(f"invalid port {self.port}")
        if not self.transports or set(self.transports) - {"udp", "tcp"}:
            raise ValueError(f"invalid transports {self.transports!r}")
        for address in (*self.dns_a, *self.dns_aaaa):
            probe_packets.family_of(address)
        if any(probe_packets.family_of(a) != 4 for a in self.dns_a) or any(
            probe_packets.family_of(a) != 6 for a in self.dns_aaaa
        ):
            raise ValueError("A answers must be IPv4 and AAAA answers IPv6")
        if self.record_bytes < 64:
            raise ValueError("record_bytes must be at least 64, to keep the probe ID")

    def plan(self) -> dict[str, Any]:
        """What the agent is told to do (see :mod:`nse._agents.receiver`)."""
        return {
            "kind": self.kind,
            "family": probe_packets.family_of(self.address),
            "address": self.address,
            "port": self.port,
            "transports": list(self.transports),
            "record_bytes": self.record_bytes,
            "idle_timeout": self.idle_timeout,
            "dns": {
                "mode": self.dns_mode,
                "a": list(self.dns_a),
                "aaaa": list(self.dns_aaaa),
                "ttl": self.dns_ttl,
            },
        }

    async def start(
        self,
        sandbox: Any,
        *,
        identity: ProcessIdentity | None = None,
        python: str | None = None,
        ready_timeout: float = 10.0,
    ) -> Receiver:
        """Start the receiver in *sandbox* and return once it is bound and serving."""
        from nse.stimuli import default_python

        argv = [python or default_python(), "-I", "-S", "-c", _agents.source("receiver")]
        argv.append(json.dumps(self.plan()))
        process = await sandbox.start_process(
            argv, identity=identity, max_output_bytes=_OUTPUT_LIMIT
        )
        try:
            await process.wait_for_output(_READY, timeout=ready_timeout)
        except ProcessExitedError as exc:
            raise ReceiverStartError(
                f"{self.kind} receiver on {self.address}:{self.port} did not start: "
                f"{_failure(exc.result)}",
                exc.result,
            ) from None
        except TimeoutError:
            result = await process.terminate()
            raise ReceiverStartError(
                f"{self.kind} receiver on {self.address}:{self.port} was not ready within "
                f"{ready_timeout}s: {_failure(result)}",
                result,
            ) from None
        ready = json.loads(
            next(
                line
                for line in process.output().splitlines()
                if line.startswith(b"{") and _READY in line
            )
        )
        bound = tuple(Endpoint(address=b["address"], port=b["port"]) for b in ready["bound"])
        return Receiver(self, process, bound)


def _failure(result: ProcessResult) -> str:
    for line in (result.stdout or b"").splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if isinstance(event, dict) and event.get("event") == "error":
            return f"{event.get('stage')} failed: {event.get('error')}"
    stderr = (result.stderr or b"").decode(errors="replace").strip()
    return f"exit status {result.returncode}" + (f": {stderr[-400:]}" if stderr else "")


class Receiver:
    """A running receiver. Stop it with :meth:`stop` or ``async with``."""

    def __init__(self, spec: ReceiverSpec, process: ManagedProcess, bound: tuple[Endpoint, ...]):
        self.spec = spec
        self.process = process
        #: What the receiver is bound to: one endpoint per transport, same port.
        self.bound = bound
        self._final: ReceiptLog | None = None

    @property
    def address(self) -> str:
        return self.bound[0].address

    @property
    def port(self) -> int:
        """The bound port (the one the kernel chose, when the spec asked for 0)."""
        return self.bound[0].port

    def log(self) -> ReceiptLog:
        """Every receipt so far, and whether the log can vouch for being complete."""
        if self._final is not None:
            return self._final
        problems = []
        if self.process.returncode is not None:
            problems.append(f"the receiver exited on its own with status {self.process.returncode}")
        dropped = self.process.output_dropped()
        if dropped:
            problems.append(f"{dropped} byte(s) of the log were over the output limit")
        return _parse(self.process.output(), problems, final=False)

    async def stop(self) -> ReceiptLog:
        """Stop the receiver and return its final log (the same on every call)."""
        if self._final is None:
            exited_already = self.process.returncode is not None
            result = await self.process.terminate()
            problems = []
            if exited_already:
                problems.append(f"the receiver exited on its own with status {result.returncode}")
            if result.stdout_dropped:
                problems.append(
                    f"{result.stdout_dropped} byte(s) of the log were over the output limit"
                )
            if not result.output_complete:
                problems.append("the receiver's output could not be read to the end")
            self._final = _parse(result.stdout or b"", problems, final=True)
        return self._final

    async def __aenter__(self) -> Receiver:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.stop()


def _parse(output: bytes, problems: list[str], *, final: bool) -> ReceiptLog:
    lines = output.split(b"\n")
    # A last line without its newline is still being written while the receiver
    # runs; after it ended, the line was cut off.
    if lines and lines[-1] and final:
        problems.append("the log ends with an incomplete line")
    lines = lines[:-1]
    receipts = []
    expected = 1
    for line in lines:
        if not line.strip():
            continue
        try:
            event = json.loads(line)
            if event.get("event") != "receipt":
                continue
            receipt = Receipt(
                seq=event["seq"],
                transport=event["transport"],
                kind=event["kind"],
                family=event["family"],
                source=Endpoint(address=event["source"][0], port=event["source"][1]),
                destination=Endpoint(address=event["destination"][0], port=event["destination"][1]),
                monotonic=event["monotonic"],
                wall=event["wall"],
                size=event["size"],
                data=bytes.fromhex(event["data"]),
                response=event["response"],
                probe_id=probe_packets.extract_probe_id(bytes.fromhex(event["data"])),
            )
        except (ValueError, KeyError, TypeError, AttributeError, IndexError) as exc:
            problems.append(f"unreadable log line {line[:80]!r}: {exc}")
            continue
        if receipt.seq != expected:
            problems.append(f"receipt {expected} is missing (next was {receipt.seq})")
        expected = receipt.seq + 1
        receipts.append(receipt)
    return ReceiptLog(receipts=tuple(receipts), complete=not problems, problems=tuple(problems))


# --------------------------------------------------------------------------- constructors


def udp_echo(address: str, port: int = 0) -> ReceiverSpec:
    """Echo every UDP datagram back unchanged. Port 0: the kernel picks one."""
    return ReceiverSpec("udp_echo", address, port, ("udp",))


def tcp_echo(address: str, port: int = 0, *, idle_timeout: float = 5.0) -> ReceiverSpec:
    """Accept TCP connections and echo what arrives; each accept is a receipt too,
    so a bare handshake is logged by its source port."""
    return ReceiverSpec("tcp_echo", address, port, ("tcp",), idle_timeout=idle_timeout)


def dns(
    address: str,
    port: int = 53,
    *,
    a: tuple[str, ...] = ("192.0.2.53",),
    aaaa: tuple[str, ...] = ("2001:db8::53",),
    mode: DnsMode = "answer",
    ttl: int = 60,
    transports: tuple[Literal["udp", "tcp"], ...] = ("udp", "tcp"),
) -> ReceiverSpec:
    """A DNS responder on UDP and TCP (same port).

    ``mode="answer"``: every A query gets *a*, every AAAA query *aaaa*, other
    types an empty NOERROR. ``"servfail"`` and ``"refused"`` answer with that
    RCODE; ``"drop"`` logs the query and sends nothing. The defaults are
    documentation addresses (RFC 5737, RFC 3849).
    """
    return ReceiverSpec(
        "dns",
        address,
        port,
        transports,
        dns_mode=mode,
        dns_a=tuple(a),
        dns_aaaa=tuple(aaaa),
        dns_ttl=ttl,
    )


def stun(address: str, port: int = 3478) -> ReceiverSpec:
    """A STUN server: a Binding Request is answered with XOR-MAPPED-ADDRESS set to
    the source address and port it arrived from."""
    return ReceiverSpec("stun", address, port, ("udp",))
