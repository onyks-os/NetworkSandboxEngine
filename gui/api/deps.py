"""
FastAPI dependency providers.

Centralises dependency-injection helpers that need to be shared between
the API routes and the WebSocket endpoint without creating circular imports.
"""

from __future__ import annotations

from nse.core.netns_controller import NetnsController

# Module-level singleton — set by main.py during app startup
_controller: NetnsController | None = None


def set_controller(c: NetnsController) -> None:
    """Called once from the lifespan context manager in main.py."""
    global _controller
    _controller = c


def get_controller() -> NetnsController:
    """FastAPI dependency — returns the singleton NetnsController."""
    if _controller is None:
        raise RuntimeError("NetnsController not initialised — server not started yet.")
    return _controller
