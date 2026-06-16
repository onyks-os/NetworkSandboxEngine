"""
NetnsController — manages ephemeral Linux network namespaces.

Responsibilities
----------------
* Create / destroy netns (ip netns add / del).
* Create veth pairs inside a namespace.
* Maintain an in-memory registry of active namespaces for crash recovery.
* Track test runs: their status, event queues, and enqueued requests.

All subprocess calls use iproute2 (`ip`) and must be run as root.
"""

from __future__ import annotations

import asyncio
import logging
import subprocess
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from nse.models.test_request import TestRequest
    from nse.models.trace_event import TestStatus, TestStatusResponse, TraceEvent

logger = logging.getLogger("nse.core.netns")


# ---------------------------------------------------------------------------
# Internal data structures
# ---------------------------------------------------------------------------

@dataclass
class TestRun:
    __test__ = False

    test_id: str
    netns_name: str
    request: "TestRequest"
    status: str = "running" if False else "pending"  # pending | running | done | error
    event_queue: asyncio.Queue = field(default_factory=lambda: asyncio.Queue(maxsize=512))


class NetnsController:
    """
    Central orchestrator for network namespace lifecycle and test management.

    Thread / async safety: all public methods are called from the asyncio
    event loop (FastAPI / uvicorn).  Subprocess calls are blocking and should
    be wrapped with ``loop.run_in_executor`` in future iterations; for the
    initial scaffold they run synchronously (acceptable for low concurrency).
    """

    def __init__(self) -> None:
        self._active_ns: set[str] = set()       # namespace names
        self._tests: dict[str, TestRun] = {}     # test_id → TestRun

    # ------------------------------------------------------------------
    # Namespace lifecycle
    # ------------------------------------------------------------------

    def create_netns(self, name: str) -> None:
        """Create a new network namespace. Raises on failure."""
        logger.debug("Creating netns: %s", name)
        _run(["ip", "netns", "add", name])
        self._active_ns.add(name)

    def destroy_netns(self, name: str) -> None:
        """Delete a network namespace. Idempotent (ignores 'not found' errors)."""
        logger.debug("Destroying netns: %s", name)
        try:
            _run(["ip", "netns", "del", name])
        except subprocess.CalledProcessError:
            logger.warning("netns %s may already be gone — ignoring.", name)
        self._active_ns.discard(name)

    def create_veth_pair(
        self,
        netns_name: str,
        veth_host: str,
        veth_peer: str,
        host_ip: str = "10.0.0.1/24",
        peer_ip: str = "10.0.0.2/24",
    ) -> None:
        """
        Create a veth pair, move one end into *netns_name*, and assign IPs.

        After this call:
          - ``veth_host`` lives on the root namespace with IP ``host_ip``.
          - ``veth_peer`` lives inside ``netns_name`` with IP ``peer_ip``.

        Assigning IPs is essential: without them, packets destined for
        ``peer_ip`` inside the namespace are not delivered to the ``input``
        hook (the kernel can't identify a local recipient), so nftables
        trace events for the ``input`` chain would never be generated.
        """
        logger.debug(
            "Creating veth pair %s (%s) <-> %s (%s) in netns %s",
            veth_host, host_ip, veth_peer, peer_ip, netns_name,
        )
        # Create veth pair in the root namespace
        _run(["ip", "link", "add", veth_host, "type", "veth", "peer", "name", veth_peer])
        # Move the peer end into the target namespace
        _run(["ip", "link", "set", veth_peer, "netns", netns_name])

        # --- Host side ---
        _run(["ip", "addr", "add", host_ip, "dev", veth_host])
        _run(["ip", "link", "set", veth_host, "up"])

        # --- Namespace side ---
        _run(["ip", "netns", "exec", netns_name, "ip", "addr", "add", peer_ip, "dev", veth_peer])
        _run(["ip", "netns", "exec", netns_name, "ip", "link", "set", veth_peer, "up"])
        _run(["ip", "netns", "exec", netns_name, "ip", "link", "set", "lo", "up"])

    def cleanup_all(self) -> None:
        """
        Destroy all known namespaces.  Called on SIGINT/SIGTERM.
        Safe to call multiple times.
        """
        logger.info("Cleaning up %d namespace(s)…", len(self._active_ns))
        for name in list(self._active_ns):
            self.destroy_netns(name)

    # ------------------------------------------------------------------
    # Test run management
    # ------------------------------------------------------------------

    def enqueue_test(self, test_id: str, request: "TestRequest") -> None:
        """Register a new test and schedule its pipeline for execution."""
        from nse.core.pipeline import run_test_pipeline  # local import avoids cycles

        netns_name = f"nse_{test_id}"
        run = TestRun(test_id=test_id, netns_name=netns_name, request=request)
        self._tests[test_id] = run

        # Schedule the async pipeline without blocking the request handler
        asyncio.ensure_future(run_test_pipeline(controller=self, run=run))

    def has_test(self, test_id: str) -> bool:
        return test_id in self._tests

    def get_status(self, test_id: str) -> "TestStatusResponse | None":
        from nse.models.trace_event import TestStatusResponse

        run = self._tests.get(test_id)
        if run is None:
            return None
        return TestStatusResponse(test_id=test_id, status=run.status)

    def get_event_queue(self, test_id: str) -> "asyncio.Queue[TraceEvent | None]":
        return self._tests[test_id].event_queue

    def release_test(self, test_id: str) -> None:
        """Called by the WebSocket handler after the connection closes."""
        # Keep the record for status queries but free heavy resources if any.
        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    """Run a subprocess command, raising on non-zero exit."""
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=True,
    )
    return result
