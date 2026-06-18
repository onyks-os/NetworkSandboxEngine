"""
REST API routes.

Endpoints
---------
GET  /api/health               — liveness probe
POST /api/test                 — submit a new test (ruleset + packet)
GET  /api/test/{test_id}       — query test status
"""

from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, status

from nse.core.netns_controller import NetnsController
from nse.core.rule_engine import RuleEngine, RuleValidationError
from gui.api.deps import get_controller
from nse.models.test_request import TestRequest
from nse.models.trace_event import TestStatusResponse

logger = logging.getLogger("nse.api.routes")

router = APIRouter(tags=["test"])


@router.get("/health")
async def health() -> dict[str, str]:
    """Liveness probe."""
    return {"status": "ok"}


@router.post("/test", status_code=status.HTTP_202_ACCEPTED)
async def submit_test(
    request: TestRequest,
    controller: NetnsController = Depends(get_controller),
) -> dict[str, str]:
    """
    Accept a test request.

    1. Validate the nftables ruleset (nft -f dry-run).
    2. Create an ephemeral netns.
    3. Enqueue the packet injection job (runs async via trace_harvester).

    Returns a ``test_id`` that the client uses to open a WebSocket.
    """
    test_id = uuid.uuid4().hex[:12]

    # --- Rule validation (fast path — raises HTTP 400 on syntax error) ---
    engine = RuleEngine()
    try:
        engine.validate(request.rules)
    except RuleValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "nftables syntax error", "errors": exc.errors},
        ) from exc

    # --- Register & enqueue the test run ---
    controller.enqueue_test(test_id=test_id, request=request)

    logger.info("Accepted test %s", test_id)
    return {"test_id": test_id}


@router.get("/test/{test_id}", response_model=TestStatusResponse)
async def get_test_status(
    test_id: str,
    controller: NetnsController = Depends(get_controller),
) -> TestStatusResponse:
    """Return the current status of a test run."""
    status_info = controller.get_status(test_id)
    if status_info is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Test '{test_id}' not found.",
        )
    return status_info
