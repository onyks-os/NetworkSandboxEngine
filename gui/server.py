"""
NSE Daemon server — starts the FastAPI API + WebSocket server.
"""

from __future__ import annotations

import argparse
import logging
import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from gui.api import routes, websocket
from gui.api.deps import set_controller
from nse.core.netns_controller import NetnsController

logger = logging.getLogger("nse")


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Startup / shutdown lifecycle."""
    logger.info("NSE daemon starting up…")
    controller = NetnsController()
    set_controller(controller)

    yield

    logger.info("NSE daemon shutting down — cleaning up namespaces…")
    controller.cleanup_all()
    logger.info("Cleanup complete.")


def create_app(dev_mode: bool = False) -> FastAPI:
    """Application factory."""
    app = FastAPI(
        title="Network Sandbox Engine",
        description="Deterministic nftables rule tester using Linux netns.",
        version="1.0.0",
        lifespan=_lifespan,
    )

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

    # Look for the compiled Svelte GUI files at gui/gui_svelte/dist/
    dist_path = os.path.join(os.path.dirname(__file__), "gui_svelte", "dist")

    if not dev_mode and os.path.isdir(dist_path):
        app.mount("/", StaticFiles(directory=dist_path, html=True), name="static")

    return app


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="nse-server",
        description="Network Sandbox Engine daemon server",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    serve_parser = subparsers.add_parser("serve", help="Start the NSE daemon")
    serve_parser.add_argument(
        "--dev",
        action="store_true",
        default=False,
        help="Run in development mode: bind to 127.0.0.1:8000 instead of /run/nse.sock",
    )
    serve_parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind to in --dev mode (default: 127.0.0.1)",
    )
    serve_parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to bind to in --dev mode (default: 8000)",
    )
    serve_parser.add_argument(
        "--socket",
        default="/run/nse.sock",
        help="Unix socket path for production mode (default: /run/nse.sock)",
    )
    serve_parser.add_argument(
        "--reload",
        action="store_true",
        default=False,
        help="Enable uvicorn auto-reload (development only)",
    )

    args = parser.parse_args()

    app = create_app(dev_mode=args.dev)

    # Setup standard logger
    logging.basicConfig(level=logging.INFO)

    if args.dev:
        print(f"[NSE] Development mode — binding to http://{args.host}:{args.port}")
        uvicorn.run(
            "gui.server:create_app" if args.reload else app,
            host=args.host,
            port=args.port,
            reload=args.reload,
            factory=True if args.reload else False,
            log_level="debug",
        )
    else:
        socket_path = args.socket
        socket_dir = os.path.dirname(socket_path)
        if socket_dir:
            os.makedirs(socket_dir, exist_ok=True)

        if os.path.exists(socket_path):
            os.unlink(socket_path)

        print(f"[NSE] Production mode — binding to unix:{socket_path}")
        uvicorn.run(
            app,
            uds=socket_path,
            log_level="info",
        )


if __name__ == "__main__":
    main()
