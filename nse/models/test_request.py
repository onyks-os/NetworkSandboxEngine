"""
Pydantic models for incoming test requests.
"""

from __future__ import annotations

from typing import Literal
from enum import Enum
import ipaddress

try:
    from pydantic import BaseModel, Field, field_validator

    HAS_PYDANTIC = True
except ImportError:
    # Dummy mock classes if pydantic is not installed
    class BaseModel:
        def __init__(self, **kwargs) -> None:
            for k, v in kwargs.items():
                setattr(self, k, v)

    def Field(*args, **kwargs):
        class FieldInfo:
            pass

        return FieldInfo()

    def field_validator(*args, **kwargs):
        return lambda func: func

    HAS_PYDANTIC = False


class TopologyType(str, Enum):
    SIMPLE = "simple"
    GATEWAY = "gateway"


class PacketSpec(BaseModel):
    """Describes the packet to forge and inject."""

    protocol: Literal["tcp", "udp", "icmp"] = Field(
        description="Layer 4 protocol.",
        examples=["tcp"],
    )
    src_ip: str = Field(
        default="10.0.0.1",
        description="Source IP address (IPv4 or IPv6).",
        examples=["192.168.1.10", "fd00::1"],
    )
    dst_ip: str = Field(
        default="10.0.0.2",
        description="Destination IP address (IPv4 or IPv6).",
        examples=["192.168.1.1", "fd00::2"],
    )
    src_port: int | None = Field(
        default=None,
        ge=1,
        le=65535,
        description="Source port (TCP/UDP only).",
        examples=[54321],
    )
    dst_port: int | None = Field(
        default=None,
        ge=1,
        le=65535,
        description="Destination port (TCP/UDP only).",
        examples=[80],
    )
    tcp_flags: list[str] = Field(
        default_factory=list,
        description="List of TCP flag names to set (e.g. ['S'] for SYN).",
        examples=[["S"]],
    )

    if HAS_PYDANTIC:

        @field_validator("src_ip", "dst_ip")
        @classmethod
        def validate_ip(cls, v: str) -> str:
            try:
                ipaddress.ip_address(v)
            except ValueError as exc:
                raise ValueError(f"Invalid IP address (must be IPv4 or IPv6): {v!r}") from exc
            return v

        @field_validator("tcp_flags")
        @classmethod
        def validate_tcp_flags(cls, flags: list[str]) -> list[str]:
            valid = {"F", "S", "R", "P", "A", "U", "E", "C"}
            for f in flags:
                if f.upper() not in valid:
                    raise ValueError(f"Invalid TCP flag: {f!r}. Valid: {valid}")
            return [f.upper() for f in flags]


class TestRequest(BaseModel):
    """Top-level body for POST /api/test."""

    __test__ = False

    rules: str = Field(
        description="Raw nftables ruleset text (passed verbatim to `nft -f`).",
        min_length=1,
        examples=[
            "table ip filter {\n  chain input {\n    type filter hook input priority 0;\n    tcp dport 22 accept\n    drop\n  }\n}"
        ],
    )
    packets: list[PacketSpec] = Field(
        description="Sequence of packets to forge and inject into the sandboxed namespace.",
        min_length=1,
    )
    topology: TopologyType = Field(
        default=TopologyType.SIMPLE,
        description="Sandbox network topology configuration.",
        examples=[TopologyType.SIMPLE],
    )
