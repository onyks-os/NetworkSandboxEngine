"""
WebSocket endpoint.

WS /ws/{test_id}

The client opens this connection immediately after receiving a test_id from
POST /api/test.  The server streams TraceEvent JSON objects as the kernel
emits them via `nft monitor trace`.

Connection lifecycle
--------------------
1. Client connects → server validates test_id.
2. Server starts the test pipeline (netns setup, nft load, scapy inject).
3. TraceEvent objects are pushed to the client as they arrive.
4. A final {"type": "done"} event signals that the test has completed.
5. Server closes the WebSocket; netns is torn down.
"""

from __future__ import annotations

import asyncio
import json
import logging

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect

from nse.core.netns_controller import NetnsController
from nse.deps import get_controller
from nse.models.trace_event import TraceEvent

logger = logging.getLogger("nse.api.websocket")

router = APIRouter(tags=["websocket"])


@router.websocket("/ws/{test_id}")
async def trace_stream(
    websocket: WebSocket,
    test_id: str,
    controller: NetnsController = Depends(get_controller),
) -> None:
    """Stream trace events for a running test over WebSocket."""
    await websocket.accept()

    if not controller.has_test(test_id):
        await websocket.send_json({"type": "error", "message": f"Unknown test_id: {test_id}"})
        await websocket.close(code=4004)
        return

    event_queue: asyncio.Queue[TraceEvent | None] = controller.get_event_queue(test_id)

    try:
        while True:
            try:
                event = await asyncio.wait_for(event_queue.get(), timeout=30.0)
            except asyncio.TimeoutError:
                # Keep-alive ping
                await websocket.send_json({"type": "ping"})
                continue

            if event is None:
                # Sentinel: test pipeline has finished
                await websocket.send_json({"type": "done"})
                break

            await websocket.send_text(event.model_dump_json())

    except WebSocketDisconnect:
        logger.info("Client disconnected from test %s", test_id)
    except Exception as exc:
        logger.exception("Error in WebSocket stream for test %s: %s", test_id, exc)
        await websocket.send_json({"type": "error", "message": str(exc)})
    finally:
        controller.release_test(test_id)
        try:
            await websocket.close()
        except RuntimeError:
            pass  # Already closed by the client — this is fine
