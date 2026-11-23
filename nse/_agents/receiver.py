# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""A controlled receiver: answer known traffic and log every arrival.

Run as ``python -I -c <this source> <json plan>``. It binds what the plan
asks for, prints a ``ready`` line once every socket is bound, then serves
until it is stopped, printing one JSON ``receipt`` line per arrival *before*
answering it. Lines carry a sequence number, so a reader can tell a complete
log from one that lost lines.

Kinds:

``udp_echo``  echo each datagram back unchanged;
``tcp_echo``  accept, then echo what arrives on each connection;
``dns``       answer A and AAAA queries with fixed addresses, or answer every
              query with SERVFAIL or REFUSED, or log and drop it (``mode``);
``stun``      answer a Binding Request with XOR-MAPPED-ADDRESS set to the
              source address and port the request arrived from.

Standard library only: this runs as the identity under test.
"""

from __future__ import annotations

import contextlib
import ipaddress
import json
import selectors
import socket
import sys
import time
from typing import Any

_MAX_DATAGRAM = 65535
_STUN_COOKIE = 0x2112A442
_RCODES = {"answer": 0, "servfail": 2, "refused": 5}


def _emit(record: dict[str, Any]) -> None:
    print(json.dumps(record), flush=True)


# --------------------------------------------------------------------------- DNS


def _parse_question(query: bytes) -> tuple[int, int, int] | None:
    """(end of question, qtype, flags) for a one-question query, else None."""
    if len(query) < 12 or int.from_bytes(query[4:6], "big") != 1:
        return None
    if query[2] & 0x80:  # a response, not a query
        return None
    offset = 12
    while True:
        if offset >= len(query):
            return None
        length = query[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0:  # compression has no place in a question we sent
            return None
        offset += 1 + length
    if offset + 4 > len(query):
        return None
    qtype = int.from_bytes(query[offset : offset + 2], "big")
    return offset + 4, qtype, int.from_bytes(query[2:4], "big")


def dns_response(query: bytes, config: dict[str, Any]) -> tuple[bytes | None, str]:
    """The answer to *query* under *config*, and what was done with it."""
    mode = config.get("mode", "answer")
    parsed = _parse_question(query)
    if parsed is None:
        return None, "malformed"
    if mode == "drop":
        return None, "drop"
    end, qtype, flags = parsed
    answers = b""
    count = 0
    if mode == "answer":
        ttl = int(config.get("ttl", 60))
        family = {1: "a", 28: "aaaa"}.get(qtype)
        for address in config.get(family, []) if family else []:
            rdata = ipaddress.ip_address(address).packed
            answers += (
                b"\xc0\x0c"
                + qtype.to_bytes(2, "big")
                + b"\x00\x01"
                + ttl.to_bytes(4, "big")
                + len(rdata).to_bytes(2, "big")
                + rdata
            )
            count += 1
    # QR, the query's opcode and RD, RA, and the mode's RCODE.
    reply_flags = 0x8000 | (flags & 0x7900) | 0x0080 | _RCODES[mode]
    header = (
        query[0:2]
        + reply_flags.to_bytes(2, "big")
        + b"\x00\x01"
        + count.to_bytes(2, "big")
        + b"\x00\x00\x00\x00"
    )
    return header + query[12:end] + answers, mode


# --------------------------------------------------------------------------- STUN


def stun_response(request: bytes, source: tuple[Any, ...]) -> tuple[bytes | None, str]:
    """A Binding Success Response reporting *source*, or None if not a request."""
    if (
        len(request) < 20
        or int.from_bytes(request[0:2], "big") != 0x0001
        or int.from_bytes(request[4:8], "big") != _STUN_COOKIE
    ):
        return None, "none"
    transaction = request[8:20]
    address = ipaddress.ip_address(source[0])
    port = int(source[1]) ^ (_STUN_COOKIE >> 16)
    mask = _STUN_COOKIE.to_bytes(4, "big") + (transaction if address.version == 6 else b"")
    xored = bytes(a ^ b for a, b in zip(address.packed, mask, strict=True))
    value = b"\x00" + (b"\x02" if address.version == 6 else b"\x01") + port.to_bytes(2, "big")
    value += xored
    attribute = b"\x00\x20" + len(value).to_bytes(2, "big") + value
    header = b"\x01\x01" + len(attribute).to_bytes(2, "big") + request[4:8] + transaction
    return header + attribute, "binding"


# --------------------------------------------------------------------------- serving


class Receiver:
    """Serve the plan's sockets until killed."""

    def __init__(self, plan: dict[str, Any]) -> None:
        self.plan = plan
        self.kind = plan["kind"]
        self.family = socket.AF_INET6 if plan["family"] == 6 else socket.AF_INET
        self.record_bytes = int(plan.get("record_bytes", 512))
        self.idle_timeout = float(plan.get("idle_timeout", 5.0))
        self.selector = selectors.DefaultSelector()
        self.sequence = 0
        self.connections: dict[socket.socket, dict[str, Any]] = {}

    def _socket(self, kind: int) -> socket.socket:
        sock = socket.socket(self.family, kind)
        if self.family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        if kind == socket.SOCK_STREAM:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return sock

    def bind(self) -> list[dict[str, Any]]:
        bound = []
        port = int(self.plan["port"])
        for transport in self.plan["transports"]:
            kind = socket.SOCK_DGRAM if transport == "udp" else socket.SOCK_STREAM
            sock = self._socket(kind)
            try:
                sock.bind((self.plan["address"], port))
            except OSError:
                sock.close()
                raise
            if transport == "tcp":
                sock.listen(64)
            sock.setblocking(False)
            port = sock.getsockname()[1]  # a second transport shares the first's port
            self.selector.register(sock, selectors.EVENT_READ, transport)
            bound.append({"transport": transport, "address": self.plan["address"], "port": port})
        return bound

    def _receipt(
        self, transport: str, kind: str, source: Any, destination: Any, data: bytes, response: str
    ) -> None:
        self.sequence += 1
        _emit(
            {
                "event": "receipt",
                "seq": self.sequence,
                "transport": transport,
                "kind": kind,
                "family": self.plan["family"],
                "source": [source[0], source[1]],
                "destination": [destination[0], destination[1]],
                "monotonic": time.monotonic(),
                "wall": time.time(),
                "size": len(data),
                "data": data[: self.record_bytes].hex(),
                "response": response,
            }
        )

    def _answer(self, data: bytes, source: Any) -> tuple[bytes | None, str]:
        if self.kind in ("udp_echo", "tcp_echo"):
            return data, "echo"
        if self.kind == "dns":
            return dns_response(data, self.plan.get("dns", {}))
        if self.kind == "stun":
            return stun_response(data, source)
        raise ValueError(f"unknown receiver kind {self.kind!r}")

    def _datagram(self, sock: socket.socket) -> None:
        try:
            data, source = sock.recvfrom(_MAX_DATAGRAM)
        except (BlockingIOError, InterruptedError):  # pragma: no cover - spurious wakeup
            return
        except OSError:  # an ICMP error queued on the socket: nothing arrived
            return
        reply, response = self._answer(data, source)
        self._receipt("udp", "datagram", source, sock.getsockname(), data, response)
        if reply is not None:
            with contextlib.suppress(OSError):  # best effort: the receipt is the record
                sock.sendto(reply, source)

    def _accept(self, listener: socket.socket) -> None:
        try:
            conn, source = listener.accept()
        except (BlockingIOError, InterruptedError):  # pragma: no cover - spurious wakeup
            return
        conn.settimeout(2.0)
        state = {"source": source, "buffer": b"", "last": time.monotonic()}
        self.connections[conn] = state
        self.selector.register(conn, selectors.EVENT_READ, "conn")
        self._receipt("tcp", "connection", source, conn.getsockname(), b"", "accepted")

    def _close(self, conn: socket.socket) -> None:
        self.selector.unregister(conn)
        self.connections.pop(conn, None)
        conn.close()

    def _stream(self, conn: socket.socket) -> None:
        state = self.connections[conn]
        try:
            data = conn.recv(_MAX_DATAGRAM)
        except OSError:
            data = b""
        if not data:
            self._close(conn)
            return
        state["last"] = time.monotonic()
        messages = [data]
        if self.kind == "dns":  # DNS over TCP: two-byte length framing
            state["buffer"] += data
            messages = []
            buffer = state["buffer"]
            while len(buffer) >= 2 and len(buffer) >= 2 + int.from_bytes(buffer[:2], "big"):
                size = int.from_bytes(buffer[:2], "big")
                messages.append(buffer[2 : 2 + size])
                buffer = buffer[2 + size :]
            state["buffer"] = buffer
        for message in messages:
            reply, response = self._answer(message, state["source"])
            self._receipt("tcp", "data", state["source"], conn.getsockname(), message, response)
            if reply is None:
                continue
            if self.kind == "dns":
                reply = len(reply).to_bytes(2, "big") + reply
            try:
                conn.sendall(reply)
            except OSError:
                self._close(conn)
                return

    def _expire(self) -> None:
        now = time.monotonic()
        for conn, state in list(self.connections.items()):
            if now - state["last"] > self.idle_timeout:
                self._close(conn)

    def serve(self, rounds: int | None = None) -> None:
        """Serve forever, or for *rounds* selector wakeups (for tests)."""
        while rounds is None or rounds > 0:
            for key, _ in self.selector.select(timeout=0.5):
                sock = key.fileobj
                assert isinstance(sock, socket.socket)
                if key.data == "udp":
                    self._datagram(sock)
                elif key.data == "tcp":
                    self._accept(sock)
                else:
                    self._stream(sock)
            self._expire()
            if rounds is not None:
                rounds -= 1


def main(argv: list[str]) -> int:
    receiver = Receiver(json.loads(argv[1]))
    try:
        bound = receiver.bind()
    except OSError as exc:
        _emit({"event": "error", "stage": "bind", "errno": exc.errno, "error": str(exc)})
        return 1
    _emit({"event": "ready", "bound": bound})
    receiver.serve()
    return 0  # pragma: no cover - serve() only returns when given rounds


if __name__ == "__main__":
    sys.exit(main(sys.argv))
