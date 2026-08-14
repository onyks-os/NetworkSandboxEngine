# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""
WebSocket endpoint.

WS /ws/{test_id}

The client opens this connection immediately after receiving a test_id from
POST /api/test.  The server streams TraceEvent JSON objects as the kernel
emits them via `nft monitor trace`.
"""

from __future__ import annotations

import contextlib
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from nse.core.netns_controller import TestRun

logger = logging.getLogger("nse.api.websocket")

router = APIRouter(tags=["websocket"])


@router.websocket("/ws/{test_id}")
async def trace_stream(
    websocket: WebSocket,
    test_id: str,
) -> None:
    """Stream trace events for a running test over WebSocket."""
    await websocket.accept()

    run: TestRun | None = websocket.app.state.runs.get(test_id)
    if run is None:
        await websocket.send_json({"type": "error", "message": f"Test '{test_id}' not found"})
        await websocket.close()
        return

    try:
        while True:
            event = await run.event_queue.get()
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
        logger.exception("Error in WebSocket stream for test %s", test_id)
        await websocket.send_json({"type": "error", "message": str(exc)})
    finally:
        with contextlib.suppress(RuntimeError):
            await websocket.close()
