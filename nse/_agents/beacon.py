# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""Send one clocked beacon (version 2) and its follow-up on an interface.

NSE runs this anywhere a capture should be marked from: a sandbox, or a VM
over ssh. It must run as root (or with ``CAP_NET_RAW``). The argument is a
JSON plan: ``{"iface": ..., "label": ..., "token": ...}``.

The beacon frame carries this machine's ``boot_id`` and its CLOCK_MONOTONIC and
CLOCK_BOOTTIME read just before the frame was sent. The follow-up, with the same
token, carries the clocks read just after. It prints one JSON line with
everything it sent (``"event": "beacon"``), or ``"event": "error"`` and exits
non-zero if it could not send.

The frame layout must match ``nse.formats.beacon.clocked_frame``; NSE's tests
check that it does.

Standard library only: this runs where NSE may not be installed.
"""

from __future__ import annotations

import json
import socket
import struct
import sys
import time
import uuid

ETHERTYPE = 0x88B5
MAGIC = b"NSE-BEACON"
CLOCKED_VERSION = 2
MIN_FRAME = 60


def clocked_frame(
    label: str, token: str, boot_id: str, mono_ns: int, boot_ns: int, follow_up: bool, mac: bytes
) -> bytes:
    encoded = b"" if follow_up else label.encode()
    if len(encoded) > 64:
        raise ValueError("a beacon label is at most 64 bytes")
    raw_token = bytes.fromhex(token)
    if len(raw_token) != 16:
        raise ValueError("a beacon token is 32 hex digits")
    body = (
        MAGIC
        + bytes([CLOCKED_VERSION, 1 if follow_up else 0, len(encoded)])
        + raw_token
        + uuid.UUID(boot_id).bytes
        + struct.pack(">QQ", mono_ns, boot_ns)
        + encoded
    )
    data = b"\xff" * 6 + mac + ETHERTYPE.to_bytes(2, "big") + body
    return data.ljust(MIN_FRAME, b"\x00")


def clocks() -> tuple[int, int]:
    return time.clock_gettime_ns(time.CLOCK_MONOTONIC), time.clock_gettime_ns(time.CLOCK_BOOTTIME)


def boot_id() -> str:
    with open("/proc/sys/kernel/random/boot_id") as f:
        return f.read().strip()


def send(plan: dict[str, str]) -> dict[str, object]:
    iface, label, token = plan["iface"], plan["label"], plan["token"]
    boot = boot_id()
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0) as sock:
        sock.bind((iface, 0))
        mac = bytes(sock.getsockname()[4])[:6]
        sent_at = time.time()
        mono_before, boot_before = clocks()
        sock.send(clocked_frame(label, token, boot, mono_before, boot_before, False, mac))
        mono_after, boot_after = clocks()
        sock.send(clocked_frame(label, token, boot, mono_after, boot_after, True, mac))
    return {
        "event": "beacon",
        "iface": iface,
        "label": label,
        "token": token,
        "boot_id": boot,
        "sent_at": sent_at,
        "monotonic_before": mono_before / 1e9,
        "boottime_before": boot_before / 1e9,
        "monotonic_after": mono_after / 1e9,
        "boottime_after": boot_after / 1e9,
    }


def main(argv: list[str]) -> int:
    try:
        report = send(json.loads(argv[1]))
    except (OSError, ValueError, KeyError, IndexError) as exc:
        print(json.dumps({"event": "error", "error": repr(exc)}), flush=True)
        return 1
    print(json.dumps(report), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
