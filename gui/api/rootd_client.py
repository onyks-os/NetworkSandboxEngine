"""
RootdClient — client proxy to communicate with nse-rootd over UNIX socket.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import AsyncGenerator

from nse.core.rule_engine import RuleValidationError
from nse.models.test_request import TestRequest
from nse.models.trace_event import TraceEvent, TestStatusResponse

logger = logging.getLogger("nse.api.rootd_client")


class RootdClient:
    """
    Client proxy for communicating with the privileged nse-rootd daemon.
    """

    def __init__(self, socket_path: str = "/var/run/nse-core.sock") -> None:
        self.socket_path = socket_path

    async def validate_rules(self, rules: str) -> None:
        """Ask rootd to validate the given nftables ruleset."""
        reader, writer = await asyncio.open_unix_connection(self.socket_path)
        try:
            payload = {"action": "validate_rules", "rules": rules}
            writer.write(json.dumps(payload).encode("utf-8") + b"\n")
            await writer.drain()

            line_bytes = await reader.readline()
            if not line_bytes:
                raise RuntimeError("Rootd closed connection unexpectedly")

            response = json.loads(line_bytes.decode("utf-8").strip())
            if response.get("status") == "error":
                raise RuleValidationError(response.get("errors", []))
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def submit_test(self, test_id: str, request: TestRequest) -> None:
        """Submit a new test run to rootd."""
        reader, writer = await asyncio.open_unix_connection(self.socket_path)
        try:
            if hasattr(request, "model_dump"):
                request_dict = request.model_dump()
            else:
                request_dict = request.dict()

            payload = {"action": "submit_test", "test_id": test_id, "request": request_dict}
            writer.write(json.dumps(payload).encode("utf-8") + b"\n")
            await writer.drain()

            line_bytes = await reader.readline()
            if not line_bytes:
                raise RuntimeError("Rootd closed connection unexpectedly")

            response = json.loads(line_bytes.decode("utf-8").strip())
            if response.get("status") == "error":
                raise RuntimeError(response.get("message", "Unknown error submitting test"))
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def get_status(self, test_id: str) -> TestStatusResponse | None:
        """Fetch current test status from rootd."""
        reader, writer = await asyncio.open_unix_connection(self.socket_path)
        try:
            payload = {"action": "get_test_status", "test_id": test_id}
            writer.write(json.dumps(payload).encode("utf-8") + b"\n")
            await writer.drain()

            line_bytes = await reader.readline()
            if not line_bytes:
                return None

            response = json.loads(line_bytes.decode("utf-8").strip())
            if response.get("status") == "error":
                return None

            data = response.get("data")
            if data is None:
                return None

            if hasattr(TestStatusResponse, "model_validate"):
                return TestStatusResponse.model_validate(data)
            return TestStatusResponse.parse_obj(data)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def stream_events(self, test_id: str) -> AsyncGenerator[TraceEvent | None, None]:
        """Stream TraceEvents from rootd for the given test."""
        reader, writer = await asyncio.open_unix_connection(self.socket_path)
        try:
            payload = {"action": "stream_events", "test_id": test_id}
            writer.write(json.dumps(payload).encode("utf-8") + b"\n")
            await writer.drain()

            while True:
                line_bytes = await reader.readline()
                if not line_bytes:
                    break
                line = line_bytes.decode("utf-8").strip()
                if not line:
                    continue

                data = json.loads(line)
                if data.get("type") == "done":
                    yield None
                    break
                elif data.get("type") == "error":
                    raise RuntimeError(data.get("message", "Error streaming events"))
                else:
                    if hasattr(TraceEvent, "model_validate"):
                        yield TraceEvent.model_validate(data)
                    else:
                        yield TraceEvent.parse_obj(data)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
