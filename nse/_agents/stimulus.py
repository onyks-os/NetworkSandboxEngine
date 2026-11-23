# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""Send one stimulus from inside a namespace and say exactly what happened.

Run as ``python -I -c <this source> <json plan>``. The plan (built by
:mod:`nse.stimuli`) names the socket, the destination and the exact bytes to
send; this program performs the socket calls and prints **one** JSON line:

``outcome``
    ``sent``      the send call succeeded and no reply was asked for;
    ``answered``  a reply was asked for and arrived (for TCP: the handshake
                  completed, and the echo arrived if one was asked for);
    ``no_reply``  the send succeeded, and nothing came back in time;
    ``refused``   a connect, send or receive call failed with an errno. EPERM
                  from a firewall's drop or reject is reported here: it is the
                  firewall working, not the instrument failing;
    ``could_not_run``  the socket could not even be created or bound (for
                  example a raw socket without CAP_NET_RAW). No packet can have
                  been produced, and no firewall was involved.

Anything else (a bad plan, a bug) raises and exits non-zero, which NSE reports
as ``could_not_run`` too: a broken probe is never mistaken for a blocked one.

Standard library only: this runs as the identity under test, which may not be
able to read NSE's installation.
"""

from __future__ import annotations

import contextlib
import errno
import json
import socket
import sys
import time
from typing import Any

_MAX_REPLY = 65535


def _error(exc: OSError) -> tuple[int | None, str]:
    code = exc.errno
    name = errno.errorcode.get(code, str(code)) if code is not None else type(exc).__name__
    return code, f"{name}: {exc.strerror or exc}"


def _endpoint(address: Any) -> list[Any] | None:
    if not address:
        return None
    return [address[0], address[1]]


class Probe:
    """One stimulus. :meth:`run` returns the report printed as JSON."""

    def __init__(self, plan: dict[str, Any]) -> None:
        self.plan = plan
        self.family = socket.AF_INET6 if plan["family"] == 6 else socket.AF_INET
        self.payload = bytes.fromhex(plan["payload"])
        self.report: dict[str, Any] = {
            "outcome": None,
            "stage": None,
            "errno": None,
            "error": None,
            "source": None,
            "reply": None,
            "reply_source": None,
            "connected": None,
            "sent_at": None,
            "sent_monotonic": None,
            "ended_monotonic": None,
        }

    # ----------------------------------------------------------------- results

    def _finish(self, outcome: str, stage: str | None = None, exc: OSError | None = None) -> None:
        self.report["outcome"] = outcome
        self.report["stage"] = stage
        if exc is not None:
            self.report["errno"], self.report["error"] = _error(exc)
        self.report["ended_monotonic"] = time.monotonic()

    def _mark_sent(self) -> None:
        self.report["sent_at"] = time.time()
        self.report["sent_monotonic"] = time.monotonic()

    def _source(self, sock: socket.socket) -> None:
        with contextlib.suppress(OSError):  # getsockname on a live socket
            self.report["source"] = _endpoint(sock.getsockname())

    # ----------------------------------------------------------------- sockets

    def _socket(self, kind: int, proto: int = 0) -> socket.socket | None:
        try:
            return socket.socket(self.family, kind, proto)
        except OSError as exc:
            self._finish("could_not_run", "socket", exc)
            return None

    def _bind(self, sock: socket.socket) -> bool:
        start = self.plan.get("source_port")
        if start is None:
            return True
        attempts = int(self.plan.get("port_attempts", 1))
        wildcard = "::" if self.family == socket.AF_INET6 else "0.0.0.0"
        last: OSError | None = None
        for offset in range(attempts):
            port = 1024 + (int(start) - 1024 + offset) % (65536 - 1024)
            try:
                sock.bind((wildcard, port))
                return True
            except OSError as exc:
                last = exc
                if exc.errno != errno.EADDRINUSE:
                    break
        assert last is not None
        self._finish("could_not_run", "bind", last)
        return False

    # ----------------------------------------------------------------- kinds

    def run(self) -> dict[str, Any]:
        transport = self.plan["transport"]
        if transport == "udp":
            self._udp()
        elif transport == "tcp":
            self._tcp()
        elif transport == "icmp":
            self._icmp()
        else:
            raise ValueError(f"unknown transport {transport!r}")
        return self.report

    def _udp(self) -> None:
        sock = self._socket(socket.SOCK_DGRAM)
        if sock is None:
            return
        with sock:
            if not self._bind(sock):
                return
            target = (self.plan["host"], self.plan["port"])
            try:
                # Connecting fixes the source address (recorded below) and lets
                # an ICMP port unreachable surface as ECONNREFUSED on receive.
                sock.connect(target)
            except OSError as exc:
                self._finish("refused", "connect", exc)
                return
            self._source(sock)
            self._mark_sent()
            try:
                sock.send(self.payload)
            except OSError as exc:
                self._finish("refused", "send", exc)
                return
            self._receive(sock, lambda: sock.recv(_MAX_REPLY), target)

    def _tcp(self) -> None:
        sock = self._socket(socket.SOCK_STREAM)
        if sock is None:
            return
        with sock:
            if not self._bind(sock):
                return
            self._source(sock)
            sock.settimeout(float(self.plan["connect_timeout"]))
            target = (self.plan["host"], self.plan["port"])
            self._mark_sent()
            try:
                sock.connect(target)
            except TimeoutError:
                self.report["connected"] = False
                self._finish("no_reply", "connect")
                return
            except OSError as exc:
                self.report["connected"] = False
                self._finish("refused", "connect", exc)
                return
            self.report["connected"] = True
            self._source(sock)
            if self.payload:
                try:
                    sock.sendall(self.payload)
                except OSError as exc:
                    self._finish("refused", "send", exc)
                    return
            if self.plan.get("reply_timeout") is None:
                self._finish("answered")  # the handshake is the answer
                return
            if self.plan.get("framing") == "dns-tcp":
                self._receive(sock, lambda: _read_framed(sock), target)
            else:
                self._receive(sock, lambda: sock.recv(_MAX_REPLY), target)

    def _receive(self, sock: socket.socket, read: Any, peer: Any) -> None:
        timeout = self.plan.get("reply_timeout")
        if timeout is None:
            self._finish("sent")
            return
        sock.settimeout(float(timeout))
        try:
            data = read()
        except TimeoutError:
            self._finish("no_reply", "receive")
            return
        except OSError as exc:
            self._finish("refused", "receive", exc)
            return
        if not data:
            self.report["error"] = "the peer closed the connection without answering"
            self._finish("no_reply", "receive")
            return
        self.report["reply"] = data.hex()
        self.report["reply_source"] = _endpoint(peer)
        self._finish("answered")

    def _icmp(self) -> None:
        raw = self.plan.get("socket", "raw") == "raw"
        if self.family == socket.AF_INET6:
            proto, reply_type = socket.IPPROTO_ICMPV6, 129
        else:
            proto, reply_type = socket.IPPROTO_ICMP, 0
        sock = self._socket(socket.SOCK_RAW if raw else socket.SOCK_DGRAM, proto)
        if sock is None:
            return
        with sock:
            target = (self.plan["host"], 0)
            self._mark_sent()
            try:
                sock.sendto(self.payload, target)
            except OSError as exc:
                self._finish("refused", "send", exc)
                return
            self._source(sock)
            timeout = self.plan.get("reply_timeout")
            if timeout is None:
                self._finish("sent")
                return
            # A raw socket sees every ICMP message: wait for *our* echo reply.
            strip_ip = raw and self.family == socket.AF_INET
            deadline = time.monotonic() + float(timeout)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self._finish("no_reply", "receive")
                    return
                sock.settimeout(remaining)
                try:
                    data, peer = sock.recvfrom(_MAX_REPLY)
                except TimeoutError:
                    self._finish("no_reply", "receive")
                    return
                except OSError as exc:
                    self._finish("refused", "receive", exc)
                    return
                message = data[(data[0] & 0x0F) * 4 :] if strip_ip and data else data
                if (
                    len(message) >= 8
                    and message[0] == reply_type
                    and message[8:] == self.payload[8:]
                    and peer[0] == self.plan["host"]
                ):
                    self.report["reply"] = message.hex()
                    self.report["reply_source"] = [peer[0], 0]
                    self._finish("answered")
                    return


def _read_framed(sock: socket.socket) -> bytes:
    """One DNS-over-TCP message: a two-byte length, then that many bytes."""
    header = _read_exactly(sock, 2)
    if len(header) < 2:
        return b""
    return _read_exactly(sock, int.from_bytes(header, "big"))


def _read_exactly(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            break
        data += chunk
    return data


def main(argv: list[str]) -> int:
    plan = json.loads(argv[1])
    print(json.dumps(Probe(plan).run()), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
