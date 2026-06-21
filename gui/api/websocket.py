# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""
WebSocket endpoint.

WS /ws/{test_id}

The client opens this connection immediately after receiving a test_id from
POST /api/test.  The server streams TraceEvent JSON objects as the kernel
emits them via `nft monitor trace` and proxies them through nse-rootd.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect

from gui.api.deps import get_client
from gui.api.rootd_client import RootdClient

logger = logging.getLogger("nse.api.websocket")

router = APIRouter(tags=["websocket"])


@router.websocket("/ws/{test_id}")
async def trace_stream(
    websocket: WebSocket,
    test_id: str,
    client: RootdClient = Depends(get_client),
) -> None:
    """Stream trace events for a running test over WebSocket."""
    await websocket.accept()

    try:
        async for event in client.stream_events(test_id):
            if event is None:
                # Sentinel: test pipeline has finished
                await websocket.send_json({"type": "done"})
                break

            if hasattr(event, "model_dump_json"):
                await websocket.send_text(event.model_dump_json())
            else:
                await websocket.send_text(event.json())

    except WebSocketDisconnect:
        logger.info("Client disconnected from test %s", test_id)
    except Exception as exc:
        logger.exception("Error in WebSocket stream for test %s: %s", test_id, exc)
        await websocket.send_json({"type": "error", "message": str(exc)})
    finally:
        try:
            await websocket.close()
        except RuntimeError:
            pass  # Already closed by the client, this is fine
