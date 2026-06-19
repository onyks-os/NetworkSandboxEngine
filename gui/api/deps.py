"""
FastAPI dependency providers.

Centralises dependency-injection helpers that need to be shared between
the API routes and the WebSocket endpoint without creating circular imports.
"""

from __future__ import annotations

from gui.api.rootd_client import RootdClient

# Module-level singleton — set by server.py during app startup
_client: RootdClient | None = None


def set_client(c: RootdClient) -> None:
    """Called once from the lifespan context manager in server.py."""
    global _client
    _client = c


def get_client() -> RootdClient:
    """FastAPI dependency — returns the singleton RootdClient."""
    if _client is None:
        raise RuntimeError("RootdClient not initialised — server not started yet.")
    return _client
