"""
Pydantic models for trace events streamed over WebSocket.
"""

from __future__ import annotations

from typing import Literal

try:
    from pydantic import BaseModel, Field

    HAS_PYDANTIC = True
except ImportError:

    class BaseModel:
        def __init__(self, **kwargs) -> None:
            for k, v in kwargs.items():
                setattr(self, k, v)

    def Field(*args, **kwargs):
        class FieldInfo:
            pass

        return FieldInfo()

    HAS_PYDANTIC = False


class TraceEvent(BaseModel):
    """A single event emitted by `nft monitor trace` (or the pipeline itself)."""

    type: Literal["hook", "match", "verdict", "error", "ping", "conntrack"] = Field(
        description="Event category."
    )
    trace_id: str | None = Field(
        default=None,
        description="nft internal trace identifier (hex string).",
    )
    family: str | None = Field(
        default=None,
        description="Address family (ip, ip6, inet…).",
    )
    table: str | None = Field(
        default=None,
        description="nftables table name.",
    )
    chain: str | None = Field(
        default=None,
        description="nftables chain name.",
    )
    hook: str | None = Field(
        default=None,
        description="Hook name or incoming interface name (for 'hook' events).",
    )
    rule_handle: int | None = Field(
        default=None,
        description="Rule handle number (for 'match' events).",
    )
    rule_text: str | None = Field(
        default=None,
        description="Partial rule text as printed by nft (for 'match' events).",
    )
    verdict: str | None = Field(
        default=None,
        description="Verdict string: ACCEPT, DROP, REJECT, CONTINUE… (for 'match'/'verdict' events).",
    )
    raw_message: str | None = Field(
        default=None,
        description="Free-form error message (for 'error' events).",
    )
    timestamp: float | None = Field(
        default=None,
        description="Unix timestamp of the event (seconds).",
    )
    # Conntrack table state fields
    ct_proto: str | None = Field(default=None, description="Conntrack layer 4 protocol.")
    ct_state: str | None = Field(default=None, description="Conntrack connection state.")
    ct_src: str | None = Field(default=None, description="Conntrack source IP.")
    ct_dst: str | None = Field(default=None, description="Conntrack destination IP.")
    ct_sport: int | None = Field(default=None, description="Conntrack source port.")
    ct_dport: int | None = Field(default=None, description="Conntrack destination port.")


class TestStatusResponse(BaseModel):
    """Response body for GET /api/test/{test_id}."""

    __test__ = False

    test_id: str
    status: Literal["pending", "running", "done", "error"]


TestStatus = Literal["pending", "running", "done", "error"]
