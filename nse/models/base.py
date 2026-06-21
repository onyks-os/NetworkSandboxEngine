from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Literal


class TopologyType(str, Enum):
    SIMPLE = "simple"
    GATEWAY = "gateway"


@dataclass
class PacketSpec:
    """Describes the packet to forge and inject (pure python dataclass)."""

    protocol: Literal["tcp", "udp", "icmp"]
    src_ip: str = "10.0.0.1"
    dst_ip: str = "10.0.0.2"
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: list[str] = field(default_factory=list)
