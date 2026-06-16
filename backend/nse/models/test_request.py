"""
Pydantic models for incoming test requests.

TestRequest is the top-level body for POST /api/test.
PacketSpec describes the L3/L4 properties of the packet to forge.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, Field, field_validator
import ipaddress


class PacketSpec(BaseModel):
    """Describes the packet to forge and inject."""

    protocol: Literal["tcp", "udp", "icmp"] = Field(
        description="Layer 4 protocol.",
        examples=["tcp"],
    )
    src_ip: str = Field(
        default="10.0.0.1",
        description="Source IP address (IPv4).",
        examples=["192.168.1.10"],
    )
    dst_ip: str = Field(
        default="10.0.0.2",
        description="Destination IP address (IPv4).",
        examples=["192.168.1.1"],
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

    @field_validator("src_ip", "dst_ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ipaddress.IPv4Address(v)
        except ValueError as exc:
            raise ValueError(f"Invalid IPv4 address: {v!r}") from exc
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
    packet: PacketSpec = Field(
        description="The packet to forge and inject into the sandboxed namespace.",
    )
