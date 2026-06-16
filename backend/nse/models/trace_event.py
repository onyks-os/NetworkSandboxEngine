"""
Pydantic models for trace events streamed over WebSocket.

TraceEvent is serialised to JSON and sent to the frontend over the WS
connection.  The frontend uses the `type` discriminator to determine which
visual update to apply to the Pipeline component.

Event types
-----------
* ``hook``    — packet entered a chain (prerouting, input, forward, output…)
* ``match``   — a rule was evaluated (with or without a verdict)
* ``verdict`` — final chain verdict (ACCEPT, DROP, REJECT, CONTINUE…)
* ``error``   — pipeline error (sent before the "done" sentinel)
* ``done``    — signals end of test (sent by the WebSocket handler, not here)
* ``ping``    — keep-alive (no visual effect)
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class TraceEvent(BaseModel):
    """A single event emitted by `nft monitor trace` (or the pipeline itself)."""

    type: Literal["hook", "match", "verdict", "error", "ping"] = Field(
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


class TestStatusResponse(BaseModel):
    """Response body for GET /api/test/{test_id}."""

    __test__ = False

    test_id: str
    status: Literal["pending", "running", "done", "error"]


# Type alias used by the controller for clarity
TestStatus = Literal["pending", "running", "done", "error"]
