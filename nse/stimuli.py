# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""
Stimuli: real sockets opened by a process inside the sandbox, as a chosen identity.

A firewall filters locally generated traffic by UID, GID or cgroup in its
output hook, so the traffic under test has to come from a process with that
identity, not from packet injection. Each stimulus here runs a small
standard-library program through :meth:`~nse.core.netns_controller.NamespaceSandbox.run_process`
with an optional :class:`~nse.models.process.ProcessIdentity`, and returns a
:class:`~nse.models.stimulus.StimulusResult`::

    from nse import stimuli
    from nse.models.process import ProcessIdentity

    result = await stimuli.udp("8.8.8.8", 53).run(sandbox, identity=ProcessIdentity(uid=1000, gid=1000))
    assert result.outcome == "refused" and result.errno == errno.EPERM  # the firewall working

The outcomes are never folded into one another: ``sent``, ``answered``,
``no_reply`` (only for a stimulus that waits for a reply), ``refused`` (a socket
call failed, with its errno) and ``could_not_run`` (no packet can have been
produced: the interpreter, the identity, or the socket itself failed).

A process's own account has limits. A UDP datagram dropped by an output-hook
rule fails ``send()`` with ``EPERM``, but a TCP SYN dropped the same way does
not fail ``connect()``: the kernel retransmits it until the stimulus gives up,
so the result is ``no_reply`` at ``connect``. Only a capture can tell that the
SYN never left, which is what :func:`observe` is for.

Every stimulus carries a probe ID (see :mod:`nse.core.probe_packets`).
:func:`observe` pairs one with a capture and, optionally, a controlled receiver
(:mod:`nse.receivers`), and keeps each fact separate: sent, seen on the wire,
received, reply seen.

Raw shapes need ``CAP_NET_RAW`` on the identity (``capabilities={"net_raw"}``):
only :func:`icmp_echo` with ``socket="raw"`` (the default) uses one.
"""

from __future__ import annotations

import asyncio
import ipaddress
import itertools
import json
import os
import random
import sys
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any, Literal, Protocol

from nse import _agents
from nse.core import probe_packets
from nse.core.paths import BinaryNotFoundError
from nse.core.process import ProcessStartError
from nse.models.process import ProcessIdentity, ProcessResult
from nse.models.stimulus import (
    Endpoint,
    Outcome,
    Stage,
    StimulusKind,
    StimulusResult,
    Transport,
)

if TYPE_CHECKING:
    from nse.core.trace_harvester import TraceHarvester, TraceReadiness
    from nse.models.capture_report import CaptureReport
    from nse.models.stimulus import Receipt, ReceiptLog
    from nse.models.trace_event import TraceEvent
    from nse.receivers import Receiver

__all__ = [
    "Observation",
    "Stimulus",
    "Window",
    "default_python",
    "dns_query",
    "icmp_echo",
    "observe",
    "observe_window",
    "quic_initial",
    "replies_in",
    "requests_in",
    "stun_binding",
    "tcp_connect",
    "tcp_round_trip",
    "trace_matches",
    "trace_ready",
    "udp",
    "udp_round_trip",
]

_OUTCOMES: frozenset[str] = frozenset({"sent", "answered", "no_reply", "refused", "could_not_run"})
_STAGES: frozenset[str] = frozenset({"socket", "bind", "connect", "send", "receive"})
_SETUP_FAILURES = {
    "socket": "the socket could not be created, so no packet was produced",
    "bind": "the socket could not be bound, so no packet was produced",
}
_STDERR_TAIL = 400
_MARGIN = 10.0  # seconds a probe gets beyond its own timeouts, for interpreter start-up

# Source ports for TCP stimuli: one counter per process from a random start, so
# successive probes bind distinct ports and a bare SYN is identified by its own.
_PORT_LOW, _PORT_HIGH = 20000, 60000
_ports = itertools.count(random.randrange(_PORT_LOW, _PORT_HIGH))
_PORT_ATTEMPTS = 64


def _next_source_port() -> int:
    return _PORT_LOW + next(_ports) % (_PORT_HIGH - _PORT_LOW)


def default_python() -> str:
    """The interpreter stimuli and receivers run with: this one, symlinks resolved.

    The agents use the standard library only and run with ``-I -S``, so a
    virtual environment's interpreter works through its base installation.
    The identity under test must be able to execute it: if it cannot (an
    interpreter under a private home directory, say) the stimulus ends
    ``could_not_run`` and says so. Pass ``python=`` to use another one.
    """
    return os.path.realpath(sys.executable)


class Sandbox(Protocol):
    """What a stimulus needs from a sandbox: a way to run a program in it."""

    async def run_process(self, argv: Any, **options: Any) -> ProcessResult: ...


@dataclass(frozen=True)
class Stimulus:
    """One kind of traffic to one destination. Run it as often as needed:
    every :meth:`run` gets a new probe ID."""

    kind: StimulusKind
    host: str
    port: int
    transport: Transport
    reply_timeout: float | None = None
    connect_timeout: float = 1.0
    source_port: int | None = None
    icmp_socket: Literal["raw", "dgram"] = "raw"
    dns_zone: str = "nse.test"
    dns_qtype: Literal["A", "AAAA"] = "A"
    family: int = field(init=False)

    def __post_init__(self) -> None:
        try:
            object.__setattr__(self, "family", probe_packets.family_of(self.host))
        except ValueError:
            raise ValueError(f"{self.host!r} is not an IP address (no name is resolved)") from None
        if not 0 <= self.port <= 65535 or (self.transport != "icmp" and self.port == 0):
            raise ValueError(f"invalid port {self.port}")
        if self.source_port is not None and not 1024 <= self.source_port <= 65535:
            raise ValueError(f"source_port must be in 1024-65535, got {self.source_port}")
        for name in ("reply_timeout", "connect_timeout"):
            value = getattr(self, name)
            if value is not None and value <= 0:
                raise ValueError(f"{name} must be positive")

    # ----------------------------------------------------------------- the plan

    def payload(self, probe_id: str) -> bytes:
        """The exact bytes this stimulus hands to the socket for *probe_id*."""
        if self.kind == "icmp_echo":
            return probe_packets.icmp_echo(probe_id, self.family)
        if self.kind == "dns_query":
            query = probe_packets.dns_query(
                probe_id, probe_packets.dns_qname(probe_id, self.dns_zone), self.dns_qtype
            )
            if self.transport == "tcp":
                return len(query).to_bytes(2, "big") + query
            return query
        if self.kind == "quic_initial":
            return probe_packets.quic_initial(probe_id)
        if self.kind == "stun_binding":
            return probe_packets.stun_binding_request(probe_id)
        if self.kind == "tcp_connect":
            return b""  # a bare handshake: the bound source port identifies it
        return probe_packets.marker(probe_id)

    def plan(self, probe_id: str) -> dict[str, Any]:
        """What the agent is told to do (see :mod:`nse._agents.stimulus`)."""
        source_port = self.source_port
        attempts = 1
        if self.transport == "tcp" and source_port is None:
            source_port, attempts = _next_source_port(), _PORT_ATTEMPTS
        return {
            "transport": self.transport,
            "family": self.family,
            "host": self.host,
            "port": self.port,
            "payload": self.payload(probe_id).hex(),
            "source_port": source_port,
            "port_attempts": attempts,
            "connect_timeout": self.connect_timeout,
            "reply_timeout": self.reply_timeout,
            "socket": self.icmp_socket,
            "framing": "dns-tcp" if self.kind == "dns_query" and self.transport == "tcp" else None,
        }

    def _budget(self) -> float:
        return self.connect_timeout + (self.reply_timeout or 0.0) + _MARGIN

    # ----------------------------------------------------------------- running

    async def run(
        self,
        sandbox: Sandbox,
        *,
        identity: ProcessIdentity | None = None,
        python: str | None = None,
        timeout: float | None = None,
    ) -> StimulusResult:
        """Send the stimulus from inside *sandbox* as *identity*; return what happened.

        Never raises for a failure of the stimulus itself: a program that cannot
        start, exits non-zero or prints no report is ``could_not_run``, with the
        reason. *timeout* bounds the whole program (default: the stimulus's own
        timeouts plus 10 s).
        """
        probe_id = probe_packets.new_probe_id()
        plan = self.plan(probe_id)
        argv = [python or default_python(), "-I", "-S", "-c", _agents.source("stimulus")]
        argv.append(json.dumps(plan))
        try:
            process = await sandbox.run_process(
                argv, identity=identity, timeout=timeout or self._budget()
            )
        except ProcessStartError as exc:
            detail = exc.stderr.decode(errors="replace").strip()[-_STDERR_TAIL:]
            return self._failed(probe_id, "launch", f"{exc}" + (f": {detail}" if detail else ""))
        except BinaryNotFoundError as exc:  # setpriv on a minimal image, for instance
            return self._failed(probe_id, "launch", str(exc))
        return self._result(probe_id, process)

    def _base(self, probe_id: str) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "transport": self.transport,
            "family": self.family,
            "probe_id": probe_id,
            "destination": Endpoint(address=self.host, port=self.port),
            "payload": self.payload(probe_id),
        }

    def _failed(
        self,
        probe_id: str,
        stage: Stage,
        reason: str,
        identity: Any = None,
    ) -> StimulusResult:
        return StimulusResult(
            **self._base(probe_id),
            outcome="could_not_run",
            stage=stage,
            reason=reason,
            identity=identity,
        )

    def _result(self, probe_id: str, process: ProcessResult) -> StimulusResult:
        stderr = (process.stderr or b"").decode(errors="replace").strip()[-_STDERR_TAIL:]
        if process.termination != "exited":
            return self._failed(
                probe_id,
                "output",
                f"the probe did not finish ({process.termination})",
                process.identity,
            )
        if process.returncode != 0:
            return self._failed(
                probe_id,
                "output",
                f"the probe exited with status {process.returncode}: {stderr or '<no stderr>'}",
                process.identity,
            )
        lines = (process.stdout or b"").decode(errors="replace").strip().splitlines()
        try:
            return self._from_report(probe_id, json.loads(lines[-1]), process.identity)
        except (IndexError, KeyError, TypeError, ValueError) as exc:
            return self._failed(
                probe_id,
                "output",
                f"the probe's report is unreadable ({exc}); stderr: {stderr or '<none>'}",
                process.identity,
            )

    def _from_report(self, probe_id: str, report: dict[str, Any], identity: Any) -> StimulusResult:
        """The agent's JSON report as a result; ``ValueError``/``KeyError`` if it is not one."""
        outcome: Outcome = report["outcome"]
        if outcome not in _OUTCOMES or (
            report["stage"] is not None and report["stage"] not in _STAGES
        ):
            raise ValueError(f"unknown outcome or stage in {report!r}")
        reply = bytes.fromhex(report["reply"]) if report.get("reply") else None
        error = report.get("error")
        dns = mapped = None
        if reply is not None and self.kind == "dns_query":
            try:
                dns = probe_packets.parse_dns(reply)
            except ValueError as exc:
                error = f"unparseable DNS reply: {exc}"
        if reply is not None and self.kind == "stun_binding":
            mapped = probe_packets.parse_stun_mapped_address(reply)
        return StimulusResult(
            **self._base(probe_id),
            outcome=outcome,
            stage=report.get("stage"),
            errno=report.get("errno"),
            error=error,
            reason=_SETUP_FAILURES.get(report["stage"]) if outcome == "could_not_run" else None,
            source=_endpoint(report.get("source")),
            reply=reply,
            reply_source=_endpoint(report.get("reply_source")),
            connected=report.get("connected"),
            dns=dns,
            mapped_address=mapped,
            sent_at=report.get("sent_at"),
            sent_monotonic=report.get("sent_monotonic"),
            ended_monotonic=report.get("ended_monotonic"),
            identity=identity,
        )

    def with_reply(self, timeout: float | None) -> Stimulus:
        """This stimulus, waiting *timeout* seconds for a reply (None: not at all)."""
        return replace(self, reply_timeout=timeout)


def _endpoint(value: Any) -> Endpoint | None:
    if not value:
        return None
    return Endpoint(address=str(value[0]), port=int(value[1]))


# --------------------------------------------------------------------------- constructors


def udp(host: str, port: int, *, source_port: int | None = None) -> Stimulus:
    """One UDP datagram carrying the probe marker. Does not wait for a reply."""
    return Stimulus("udp", host, port, "udp", source_port=source_port)


def udp_round_trip(
    host: str, port: int, *, timeout: float = 2.0, source_port: int | None = None
) -> Stimulus:
    """A UDP datagram, then a wait of *timeout* seconds for one reply.

    ``no_reply`` when nothing comes back; ``refused`` at ``receive`` when an
    ICMP error came back instead (ECONNREFUSED for port unreachable).
    """
    return Stimulus(
        "udp_round_trip", host, port, "udp", reply_timeout=timeout, source_port=source_port
    )


def tcp_connect(
    host: str, port: int, *, timeout: float = 1.0, source_port: int | None = None
) -> Stimulus:
    """A TCP handshake and nothing else: the SYN is what matters.

    The socket is bound to an explicit source port before connecting (one NSE
    picks, distinct for each probe, unless *source_port* is given), and the
    result records it: that 5-tuple identifies a SYN that carries no payload.
    ``answered`` when the handshake completes, ``no_reply`` when *timeout*
    expires first, ``refused`` (with the errno) when connect fails.
    """
    return Stimulus(
        "tcp_connect", host, port, "tcp", connect_timeout=timeout, source_port=source_port
    )


def tcp_round_trip(
    host: str,
    port: int,
    *,
    timeout: float = 2.0,
    connect_timeout: float = 1.0,
    source_port: int | None = None,
) -> Stimulus:
    """Connect, send the probe marker, and wait *timeout* seconds for an answer."""
    return Stimulus(
        "tcp_round_trip",
        host,
        port,
        "tcp",
        reply_timeout=timeout,
        connect_timeout=connect_timeout,
        source_port=source_port,
    )


def icmp_echo(
    host: str, *, timeout: float | None = None, socket: Literal["raw", "dgram"] = "raw"
) -> Stimulus:
    """An ICMP (IPv4) or ICMPv6 echo request whose data is the probe marker.

    ``socket="raw"`` needs CAP_NET_RAW (root has it; for another UID pass
    ``capabilities={"net_raw"}`` in the identity). ``socket="dgram"`` uses a
    ping socket instead, which needs no capability but a GID inside the
    namespace's ``net.ipv4.ping_group_range`` (closed by default in a new
    namespace); the kernel then chooses the echo identifier. Either way a
    socket that cannot be opened is ``could_not_run``, never ``refused``.
    With *timeout*, wait that long for the echo reply.
    """
    return Stimulus("icmp_echo", host, 0, "icmp", reply_timeout=timeout, icmp_socket=socket)


def dns_query(
    server: str,
    *,
    port: int = 53,
    transport: Literal["udp", "tcp"] = "udp",
    qtype: Literal["A", "AAAA"] = "A",
    zone: str = "nse.test",
    timeout: float | None = 2.0,
    connect_timeout: float = 1.0,
) -> Stimulus:
    """A DNS query for ``nse-<probe id>.<zone>``: a name no cache has seen before.

    Waits *timeout* seconds for the response (None: do not wait) and parses it
    into :attr:`~nse.models.stimulus.StimulusResult.dns`. Over TCP the query is
    length-framed as RFC 1035 requires.
    """
    return Stimulus(
        "dns_query",
        server,
        port,
        transport,
        reply_timeout=timeout,
        connect_timeout=connect_timeout,
        dns_zone=zone,
        dns_qtype=qtype,
    )


def quic_initial(host: str, port: int = 443, *, timeout: float | None = None) -> Stimulus:
    """A UDP datagram shaped like a QUIC v1 client Initial: what a QUIC filter must catch.

    See :func:`nse.core.probe_packets.quic_initial` for the exact shape.
    """
    return Stimulus("quic_initial", host, port, "udp", reply_timeout=timeout)


def stun_binding(host: str, port: int = 3478, *, timeout: float | None = 2.0) -> Stimulus:
    """A STUN Binding Request whose transaction ID is the probe ID.

    With a reply, :attr:`~nse.models.stimulus.StimulusResult.mapped_address`
    is the address the server saw the request come from: exactly what WebRTC
    leaks.
    """
    return Stimulus("stun_binding", host, port, "udp", reply_timeout=timeout)


# --------------------------------------------------------------------------- observation


def requests_in(result: StimulusResult, packets: Iterable[Any], *, nat: bool = False) -> list[Any]:
    """The packets in *packets* that are *result*'s request.

    A packet matches by the probe ID it carries, or, for a bare SYN, by the
    source port the probe bound, on its way to the stimulus's destination. Use
    it when one capture holds several stimuli, for instance a probe and a later
    control in the same window.

    With *nat*, the destination is not compared, so a probe whose destination
    a DNAT or a redirect rewrote is still recognised; read where it went from
    the packets' own addresses. A NAT that rewrites the source port of a bare
    SYN still hides it.
    """
    return probe_packets.request_packets(result, packets, nat=nat)


def replies_in(result: StimulusResult, packets: Iterable[Any], *, nat: bool = False) -> list[Any]:
    """The packets in *packets* that answer *result*'s request (ICMP errors excluded).

    With *nat*, a reply counts from whatever source answered.
    """
    return probe_packets.reply_packets(result, packets, nat=nat)


@dataclass(frozen=True)
class Observation:
    """One stimulus, its capture and its receiver, with every fact kept apart.

    ``True`` and ``False`` are findings; ``None`` means the instrument cannot
    say: the capture was not complete (or not healthy) and nothing matching was
    in it, or there was no receiver, or the receiver's log was incomplete and
    the probe was not in it. A test must never read ``None`` as ``False``.
    """

    result: StimulusResult
    capture: CaptureReport
    requests: tuple[Any, ...]
    replies: tuple[Any, ...]
    receipts: tuple[Receipt, ...] | None
    on_wire: bool | None
    received: bool | None
    reply_on_wire: bool | None
    canary: Observation | None = None
    """The canary sent after the stimulus in the same window, if one was asked for.
    Unless it was seen on the wire, no absence above is ``False``."""

    @property
    def sent(self) -> bool:
        """The sending process's account: the send call succeeded."""
        return self.result.left_socket

    def contradictions(self) -> list[str]:
        """Facts that cannot all be true: each one means an instrument is blind.

        Something that arrived at the receiver, or was answered, must have been
        on the wire; a packet on the wire must have left a socket. When the
        capture missed what the receiver logged, the capture is not looking at
        the path the traffic took, and its silence elsewhere proves nothing.
        """
        problems = []
        if self.received and self.on_wire is False:
            problems.append(
                "the receiver logged the probe but the capture did not see it: "
                "the capture is blind to this path"
            )
        if self.result.answered and self.reply_on_wire is False and self.result.reply_source:
            problems.append(
                "the probe got its reply but the capture did not see it: "
                "the capture is blind to the return path"
            )
        # A refused connect or receive can follow a packet that did leave (a TCP
        # RST, an ICMP error); a socket never created or a refused send cannot.
        if self.on_wire and (
            self.result.outcome == "could_not_run"
            or (self.result.outcome == "refused" and self.result.stage == "send")
        ):
            problems.append(
                f"the capture saw the probe although the process reported "
                f"{self.result.outcome}: the probe's report is wrong"
            )
        return problems

    def describe(self) -> str:
        """The four facts in one line, for an assertion message."""

        def fact(value: bool | None) -> str:
            return "unknown" if value is None else ("yes" if value else "no")

        return (
            f"{self.result.describe()}; on the wire: {fact(self.on_wire)} "
            f"({len(self.requests)} packet(s)); received: {fact(self.received)}; "
            f"reply on the wire: {fact(self.reply_on_wire)} ({len(self.replies)} packet(s)); "
            f"capture on {self.capture.iface}: {self.capture.packets_observed} packet(s), "
            f"window complete: {self.capture.window_complete}"
            + _canary_note(self.canary)
            + "".join(f"; CONTRADICTION: {problem}" for problem in self.contradictions())
        )


def _canary_note(canary: Observation | None) -> str:
    if canary is None:
        return ""
    if canary.on_wire is True:
        return "; canary: seen"
    return f"; canary: NOT seen ({canary.result.describe()}): no absence is vouched for"


@dataclass(frozen=True)
class Window:
    """Several stimuli, and optionally a canary, observed in one capture window.

    The canary is sent after every stimulus, inside the same window, and must
    be traffic the rules under test let through. Seeing it on the wire proves
    the capture was open and looking at the right link across all of them; a
    capture that silently stopped, or watches another link, does not see it,
    and then no stimulus's absence is ``False``.
    """

    observations: tuple[Observation, ...]
    canary: Observation | None
    capture: CaptureReport
    packets: tuple[Any, ...]

    @property
    def canary_seen(self) -> bool | None:
        """Whether the canary was on the wire; None when no canary was sent."""
        return None if self.canary is None else self.canary.on_wire is True

    @property
    def vouched(self) -> bool:
        """The capture can vouch for an absence: healthy, complete, canary seen."""
        return _vouched(self.capture, self.canary)

    def contradictions(self) -> list[str]:
        """Every observation's contradictions, the canary's included, named by probe."""
        found = []
        for observation in (*self.observations, *(o for o in (self.canary,) if o is not None)):
            found += [
                f"{observation.result.kind} {observation.result.probe_id}: {problem}"
                for problem in observation.contradictions()
            ]
        return found

    @property
    def conclusive(self) -> bool:
        return self.vouched and not self.contradictions()

    def __iter__(self) -> Iterator[Observation]:
        return iter(self.observations)

    def __len__(self) -> int:
        return len(self.observations)

    def __getitem__(self, index: int) -> Observation:
        return self.observations[index]

    def describe(self) -> str:
        lines = [observation.describe() for observation in self.observations]
        if self.canary is not None:
            lines.append("canary: " + self.canary.describe())
        lines.append(
            f"window: vouched {self.vouched}, conclusive {self.conclusive}, "
            f"{len(self.packets)} packet(s)"
        )
        return "\n".join(lines)


def _vouched(capture: CaptureReport, canary: Observation | None) -> bool:
    return (
        capture.instrument_healthy
        and capture.window_complete is True
        and (canary is None or canary.on_wire is True)
    )


class _Unset:
    pass


_UNSET = _Unset()


async def observe(
    sandbox: Any,
    stimulus: Stimulus,
    *,
    identity: ProcessIdentity | None = None,
    receiver: Receiver | None = None,
    iface: str | None = None,
    netns: str | _Unset | None = _UNSET,
    capture_filter: str | None = None,
    settle: float = 0.3,
    python: str | None = None,
    canary: Stimulus | None = None,
    canary_identity: ProcessIdentity | _Unset | None = _UNSET,
    nat: bool = False,
) -> Observation:
    """Run *stimulus* in *sandbox* with a capture armed, and report each fact separately.

    The capture is on *iface* in *netns* (default: the sandbox's host end,
    ``sandbox.ext_iface`` in ``sandbox.ext_netns``), started before the
    stimulus and stopped *settle* seconds after it returns. With a *receiver*
    its log is read after the same delay.

    A capture that was not healthy, or whose window is not known to be complete
    (kernel drops, limits, or counters unavailable), cannot turn "not seen"
    into ``False``: the fact is ``None``. A capture on the wrong interface is
    still a complete window that saw nothing: pass a *canary*, a stimulus the
    rules let through, sent after *stimulus* in the same window (as
    *canary_identity*, by default *identity*). Unless the canary is seen, no
    absence is ``False``. *nat* recognises the probe after its destination was
    rewritten (see :func:`requests_in`).
    """
    window = await observe_window(
        sandbox,
        [stimulus],
        identity=identity,
        receiver=receiver,
        iface=iface,
        netns=netns,
        capture_filter=capture_filter,
        settle=settle,
        python=python,
        canary=canary,
        canary_identity=canary_identity,
        nat=nat,
    )
    return window.observations[0]


async def observe_window(
    sandbox: Any,
    stimuli: Sequence[Stimulus],
    *,
    identity: ProcessIdentity | None = None,
    receiver: Receiver | None = None,
    iface: str | None = None,
    netns: str | _Unset | None = _UNSET,
    capture_filter: str | None = None,
    settle: float = 0.3,
    python: str | None = None,
    canary: Stimulus | None = None,
    canary_identity: ProcessIdentity | _Unset | None = _UNSET,
    nat: bool = False,
) -> Window:
    """Run several stimuli, then an optional *canary*, inside **one** capture window.

    The stimuli run in order as *identity*; the canary runs last, as
    *canary_identity* (by default *identity*), and must be traffic the rules
    under test allow. Each stimulus gets its own :class:`Observation`, matched
    by its probe ID, with the canary attached; the :class:`Window` holds them
    all. The other arguments are those of :func:`observe`.
    """
    from nse.core.sniffer import PCAPAsserter

    if not stimuli:
        raise ValueError("observe_window needs at least one stimulus")
    asserter = PCAPAsserter(
        iface=iface or sandbox.ext_iface,
        filter=capture_filter,
        netns=sandbox.ext_netns if isinstance(netns, _Unset) else netns,
    )
    await asserter.start()
    canary_result: StimulusResult | None = None
    try:
        results = [
            await stimulus.run(sandbox, identity=identity, python=python) for stimulus in stimuli
        ]
        if canary is not None:
            canary_result = await canary.run(
                sandbox,
                identity=identity if isinstance(canary_identity, _Unset) else canary_identity,
                python=python,
            )
        await asyncio.sleep(settle)
    finally:
        report = await asserter.stop_report()
    packets = await asserter.stop() if report.instrument_healthy else []
    log = receiver.log() if receiver is not None else None
    base = _vouched(report, None)
    canary_seen = None
    if canary_result is not None:
        canary_seen = _observation(canary_result, report, packets, log, base, nat, None)
    vouched = _vouched(report, canary_seen)
    observations = tuple(
        _observation(result, report, packets, log, vouched, nat, canary_seen) for result in results
    )
    return Window(
        observations=observations, canary=canary_seen, capture=report, packets=tuple(packets)
    )


def _observation(
    result: StimulusResult,
    report: CaptureReport,
    packets: list[Any],
    log: ReceiptLog | None,
    conclusive: bool,
    nat: bool,
    canary: Observation | None,
) -> Observation:
    def fact(found: list[Any]) -> bool | None:
        if found:
            return True
        return False if conclusive else None

    requests = requests_in(result, packets, nat=nat)
    replies = replies_in(result, packets, nat=nat)
    receipts: tuple[Receipt, ...] | None = None
    received: bool | None = None
    if log is not None:
        receipts = tuple(log.matching(result))
        received = True if receipts else (False if log.complete else None)
    return Observation(
        result=result,
        capture=report,
        requests=tuple(requests),
        replies=tuple(replies),
        receipts=receipts,
        on_wire=fact(requests),
        received=received,
        reply_on_wire=fact(replies),
        canary=canary,
    )


def trace_matches(stimulus: Stimulus) -> Callable[[TraceEvent], bool]:
    """A predicate for trace events of packets toward *stimulus*'s destination.

    It compares the destination address, the transport and (for UDP and TCP)
    the port, which is what ``nft monitor trace`` prints; a probe ID is not in
    the trace. Give a canary a destination nothing else in the test uses.
    """
    host = ipaddress.ip_address(stimulus.host)
    protocol = stimulus.transport

    def matches(event: TraceEvent) -> bool:
        if event.packet_dst_ip is None or event.packet_protocol != protocol:
            return False
        try:
            if ipaddress.ip_address(event.packet_dst_ip) != host:
                return False
        except ValueError:
            return False
        return protocol == "icmp" or event.packet_dst_port == stimulus.port

    return matches


async def trace_ready(
    harvester: TraceHarvester,
    sandbox: Any,
    canary: Stimulus,
    *,
    identity: ProcessIdentity | None = None,
    attempts: int = 5,
    timeout: float = 1.0,
    python: str | None = None,
) -> TraceReadiness:
    """Prove a running *harvester* sees traces, by sending *canary* until its trace returns.

    The canary runs in *sandbox* as *identity*. For traffic a process
    generates, the rules must be loaded with ``RuleEngine(trace_output=True)``,
    or no output-path packet is traced. An attempt that ``could_not_run`` is
    not a canary and is reported in ``problems``. Drop the canary's traces with
    :meth:`TraceReadiness.without` before reading the subject's.
    """

    async def send() -> str | None:
        result = await canary.run(sandbox, identity=identity, python=python)
        return result.describe() if result.outcome == "could_not_run" else None

    return await harvester.prove_ready(
        send, trace_matches(canary), attempts=attempts, timeout=timeout
    )
