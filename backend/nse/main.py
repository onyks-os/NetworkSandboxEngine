"""
FastAPI application factory + lifespan.

The application is created via create_app(dev_mode) so the CLI can pass
context before uvicorn starts.  Signal handlers for SIGINT/SIGTERM are
registered here to guarantee namespace cleanup even on forced shutdown.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from nse.api import routes, websocket
from nse.core.netns_controller import NetnsController
from nse.deps import set_controller

logger = logging.getLogger("nse")


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Startup / shutdown lifecycle."""
    logger.info("NSE daemon starting up…")
    controller = NetnsController()
    set_controller(controller)

    yield  # <— server is running

    logger.info("NSE daemon shutting down — cleaning up namespaces…")
    controller.cleanup_all()
    logger.info("Cleanup complete.")


def create_app(dev_mode: bool = False) -> FastAPI:
    """
    Application factory.

    Args:
        dev_mode: When True, enables CORS (Vite dev server on :5173 talks to :8000).
                  In production the frontend is served from the same origin.
    """
    app = FastAPI(
        title="Network Sandbox Engine",
        description="Deterministic nftables rule tester using Linux netns.",
        version="0.1.0",
        lifespan=_lifespan,
    )

    # In dev mode, the Vite dev server (port 5173) is a different origin —
    # even though we also configure the Vite proxy, some tools (curl, Postman)
    # may hit the API directly, so we allow it explicitly.
    if dev_mode:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    # API routers
    app.include_router(routes.router, prefix="/api")
    app.include_router(websocket.router)

    # Try the packaged dist first (nested inside the package for wheel installs)
    dist_path = os.path.join(os.path.dirname(__file__), "dist")
    if not os.path.isdir(dist_path):
        # Fall back to the relative path in the source repo
        dist_path = os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "dist")

    if not dev_mode and os.path.isdir(dist_path):
        app.mount("/", StaticFiles(directory=dist_path, html=True), name="static")

    return app
