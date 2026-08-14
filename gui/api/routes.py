# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""
REST API routes.

Endpoints
---------
GET  /api/health               : liveness probe
POST /api/test                 : submit a new test (ruleset + packet)
GET  /api/test/{test_id}       : query test status
"""

from __future__ import annotations

import asyncio
import logging
import uuid

from fastapi import APIRouter, HTTPException, Request, status

from nse.core.netns_controller import NetnsController, TestRun
from nse.core.pipeline import run_test_pipeline
from nse.core.rule_engine import RuleEngine, RuleValidationError
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
    req: Request,
) -> dict[str, str]:
    """
    Accept a test request.

    1. Validate the nftables ruleset (nft -f dry-run).
    2. Enqueue the packet injection job in-process.

    Returns a ``test_id`` that the client uses to open a WebSocket.
    """
    test_id = uuid.uuid4().hex[:12]
    controller: NetnsController = req.app.state.controller

    # --- Rule validation (fast path: raises HTTP 400 on syntax error) ---
    engine = RuleEngine(use_nsenter=controller.use_nsenter)
    try:
        engine.validate(request.rules)
    except RuleValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "nftables syntax error", "errors": exc.errors},
        ) from exc

    # --- Register & enqueue test run in-process ---
    netns_name = f"nse_{test_id}"
    run = TestRun(test_id=test_id, netns_name=netns_name, request=request)
    req.app.state.runs[test_id] = run

    task = asyncio.create_task(run_test_pipeline(request=request, controller=controller, run=run))
    req.app.state.tasks[test_id] = task

    logger.info("Accepted test %s", test_id)
    return {"test_id": test_id}


@router.get("/test/{test_id}", response_model=TestStatusResponse)
async def get_test_status(
    test_id: str,
    req: Request,
) -> TestStatusResponse:
    """Return the current status of a test run."""
    run: TestRun | None = req.app.state.runs.get(test_id)
    if run is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Test '{test_id}' not found.",
        )
    return TestStatusResponse(test_id=test_id, status=run.status)  # type: ignore[arg-type]
