"""
NetnsController — manages ephemeral Linux network namespaces.

All subprocess calls use iproute2 (`ip`) and must be run as root.
"""

from __future__ import annotations

import asyncio
import logging
import subprocess
from dataclasses import dataclass, field
import contextlib
from typing import TYPE_CHECKING, AsyncIterator

if TYPE_CHECKING:
    from nse.models.test_request import TestRequest
    from nse.models.trace_event import TestStatusResponse, TraceEvent

logger = logging.getLogger("nse.core.netns")


@dataclass
class TestRun:
    __test__ = False

    test_id: str
    netns_name: str
    request: "TestRequest"
    status: str = "running" if False else "pending"  # pending | running | done | error
    event_queue: asyncio.Queue = field(default_factory=lambda: asyncio.Queue(maxsize=512))


class NamespaceSandbox:
    """
    Represents an active isolated network namespace sandbox.
    Provides utility methods to execute commands and inject packets inside the sandbox context.
    """

    def __init__(self, controller: NetnsController, name: str) -> None:
        self.controller = controller
        self.name = name
        # We derive interface names from the sandbox name
        self.ext_iface = f"vhr-{name[:8]}"
        self.peer_iface = f"vrh-{name[:8]}"

    async def exec(self, command: str) -> subprocess.CompletedProcess[bytes]:
        """
        Execute a shell command inside the network namespace context asynchronously.
        """
        cmd = ["ip", "netns", "exec", self.name] + command.split()
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            raise subprocess.CalledProcessError(
                proc.returncode,
                cmd,
                output=stdout,
                stderr=stderr,
            )
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=proc.returncode,
            stdout=stdout,
            stderr=stderr,
        )

    async def inject_packet(
        self,
        protocol: str,
        dst_port: int,
        dst_ip: str,
        src_ip: str | None = None,
    ) -> None:
        """
        Inject a layer 3/4 packet on the host side of the veth link targeting this namespace.
        """
        from nse.core.scapy_injector import ScapyInjector
        from nse.models.base import PacketSpec

        injector = ScapyInjector()
        packet = PacketSpec(
            protocol=protocol,
            dst_port=dst_port,
            dst_ip=dst_ip,
            src_ip=src_ip or ("10.0.1.1" if "." in dst_ip else "fd00:1::1"),
        )

        loop = asyncio.get_running_loop()
        # Sniffing/injection scapy operations can be blocking, run in executor
        await loop.run_in_executor(
            None,
            injector.inject,
            packet,
            self.name,
            self.ext_iface,
            self.peer_iface,
        )


class NetnsController:
    """
    Central orchestrator for network namespace lifecycle and test management.
    """

    def __init__(self) -> None:
        self._active_ns: set[str] = set()  # namespace names
        self._tests: dict[str, TestRun] = {}  # test_id → TestRun

    # ------------------------------------------------------------------
    # Namespace lifecycle
    # ------------------------------------------------------------------

    def create_netns(self, name: str) -> None:
        """Create a new network namespace. Raises on failure."""
        logger.debug("Creating netns: %s", name)
        _run(["ip", "netns", "add", name])
        self._active_ns.add(name)
        # Disable DAD inside the netns to speed up IPv6 interface readiness
        try:
            _run(
                [
                    "ip",
                    "netns",
                    "exec",
                    name,
                    "sysctl",
                    "-w",
                    "net.ipv6.conf.all.accept_dad=0",
                ]
            )
            _run(
                [
                    "ip",
                    "netns",
                    "exec",
                    name,
                    "sysctl",
                    "-w",
                    "net.ipv6.conf.default.accept_dad=0",
                ]
            )
        except subprocess.CalledProcessError as e:
            logger.warning("Could not set accept_dad sysctls inside netns %s: %s", name, e)

    def destroy_netns(self, name: str) -> None:
        """Delete a network namespace. Idempotent (ignores 'not found' errors)."""
        logger.debug("Destroying netns: %s", name)
        try:
            _run(["ip", "netns", "del", name])
        except subprocess.CalledProcessError:
            logger.warning("netns %s may already be gone — ignoring.", name)
        self._active_ns.discard(name)

    @contextlib.asynccontextmanager
    async def create_namespace(
        self,
        name: str,
        host_ip: str | list[str] = "10.0.1.1/24",
        peer_ip: str | list[str] = "10.0.1.2/24",
    ) -> AsyncIterator[NamespaceSandbox]:
        """
        Context manager to safely construct and teardown an isolated namespace.
        """
        sandbox = NamespaceSandbox(self, name)

        # Setup
        self.create_netns(name)

        # Bring loopback interface up
        _run(["ip", "netns", "exec", name, "ip", "link", "set", "lo", "up"])

        # Setup links
        self.create_veth_pair(
            netns_name=name,
            veth_host=sandbox.ext_iface,
            veth_peer=sandbox.peer_iface,
            host_ip=host_ip,
            peer_ip=peer_ip,
        )

        try:
            yield sandbox
        finally:
            # Cleanup links
            try:
                _run(["ip", "link", "del", sandbox.ext_iface])
            except Exception:
                pass

            # Cleanup netns
            self.destroy_netns(name)

    def create_veth_pair(
        self,
        netns_name: str,
        veth_host: str,
        veth_peer: str,
        host_ip: str | list[str] = "10.0.0.1/24",
        peer_ip: str | list[str] = "10.0.0.2/24",
    ) -> None:
        """
        Create a veth pair, move one end into *netns_name*, and assign IPs.
        """
        logger.debug(
            "Creating veth pair %s <-> %s in netns %s",
            veth_host,
            veth_peer,
            netns_name,
        )

        # Parse host and peer IPs (which could be single strings or list of strings)
        host_ips = [host_ip] if isinstance(host_ip, str) else list(host_ip)
        peer_ips = [peer_ip] if isinstance(peer_ip, str) else list(peer_ip)

        v4_host, v6_host = None, None
        v4_peer, v6_peer = None, None

        for ip in host_ips:
            if ":" in ip:
                v6_host = ip
            else:
                v4_host = ip
        for ip in peer_ips:
            if ":" in ip:
                v6_peer = ip
            else:
                v4_peer = ip

        # Inject defaults if missing to support hybrid/both tests easily
        if not v4_host:
            v4_host = "10.0.0.1/24"
        if not v4_peer:
            v4_peer = "10.0.0.2/24"
        if not v6_host:
            v6_host = "fd00::1/64"
        if not v6_peer:
            v6_peer = "fd00::2/64"

        # Create veth pair in the root namespace
        _run(["ip", "link", "add", veth_host, "type", "veth", "peer", "name", veth_peer])
        # Move the peer end into the target namespace
        _run(["ip", "link", "set", veth_peer, "netns", netns_name])

        # --- Host side ---
        if v4_host:
            _run(["ip", "addr", "add", v4_host, "dev", veth_host])
        if v6_host:
            _run(["ip", "addr", "add", v6_host, "dev", veth_host])
        _run(["ip", "link", "set", veth_host, "up"])

        # --- Namespace side ---
        if v4_peer:
            _run(
                [
                    "ip",
                    "netns",
                    "exec",
                    netns_name,
                    "ip",
                    "addr",
                    "add",
                    v4_peer,
                    "dev",
                    veth_peer,
                ]
            )
        if v6_peer:
            _run(
                [
                    "ip",
                    "netns",
                    "exec",
                    netns_name,
                    "ip",
                    "addr",
                    "add",
                    v6_peer,
                    "dev",
                    veth_peer,
                ]
            )
        _run(["ip", "netns", "exec", netns_name, "ip", "link", "set", veth_peer, "up"])
        _run(["ip", "netns", "exec", netns_name, "ip", "link", "set", "lo", "up"])

    def create_gateway_topology(
        self,
        router_ns: str,
        server_ns: str,
        veth_host: str,
        veth_router_host: str,
        veth_router_server: str,
        veth_server: str,
        host_v4: str = "10.0.1.1/24",
        router_host_v4: str = "10.0.1.2/24",
        router_server_v4: str = "10.0.2.1/24",
        server_v4: str = "10.0.2.2/24",
        host_v6: str = "fd00:1::1/64",
        router_host_v6: str = "fd00:1::2/64",
        router_server_v6: str = "fd00:2::1/64",
        server_v6: str = "fd00:2::2/64",
    ) -> None:
        """
        Create router and server namespaces, build double veth links,
        enable IPv4/IPv6 forwarding inside the router, and add transit routes.
        """
        logger.info("Setting up gateway topology: %s <-> %s", router_ns, server_ns)
        # Create namespaces
        self.create_netns(router_ns)
        self.create_netns(server_ns)

        # Enable IPv4/IPv6 forwarding on router namespace
        _run(["ip", "netns", "exec", router_ns, "sysctl", "-w", "net.ipv4.ip_forward=1"])
        _run(
            [
                "ip",
                "netns",
                "exec",
                router_ns,
                "sysctl",
                "-w",
                "net.ipv6.conf.all.forwarding=1",
            ]
        )

        # 1. Create Host <-> Router veth pair
        _run(
            [
                "ip",
                "link",
                "add",
                veth_host,
                "type",
                "veth",
                "peer",
                "name",
                veth_router_host,
            ]
        )
        _run(["ip", "link", "set", veth_router_host, "netns", router_ns])

        _run(["ip", "addr", "add", host_v4, "dev", veth_host])
        _run(["ip", "addr", "add", host_v6, "dev", veth_host])
        _run(["ip", "link", "set", veth_host, "up"])

        _run(
            [
                "ip",
                "netns",
                "exec",
                router_ns,
                "ip",
                "addr",
                "add",
                router_host_v4,
                "dev",
                veth_router_host,
            ]
        )
        _run(
            [
                "ip",
                "netns",
                "exec",
                router_ns,
                "ip",
                "addr",
                "add",
                router_host_v6,
                "dev",
                veth_router_host,
            ]
        )
        _run(
            [
                "ip",
                "netns",
                "exec",
                router_ns,
                "ip",
                "link",
                "set",
                veth_router_host,
                "up",
            ]
        )

        # 2. Create Router <-> Server veth pair
        _run(
            [
                "ip",
                "netns",
                "exec",
                router_ns,
                "ip",
                "link",
                "add",
                veth_router_server,
                "type",
                "veth",
                "peer",
                "name",
                veth_server,
            ]
        )
        _run(
            [
                "ip",
                "netns",
                "exec",
                router_ns,
                "ip",
                "link",
                "set",
                veth_server,
                "netns",
                server_ns,
            ]
        )

        _run(
            [
                "ip",
                "netns",
                "exec",
                router_ns,
                "ip",
                "addr",
                "add",
                router_server_v4,
                "dev",
                veth_router_server,
            ]
        )
        _run(
            [
                "ip",
                "netns",
                "exec",
                router_ns,
                "ip",
                "addr",
                "add",
                router_server_v6,
                "dev",
                veth_router_server,
            ]
        )
        _run(
            [
                "ip",
                "netns",
                "exec",
                router_ns,
                "ip",
                "link",
                "set",
                veth_router_server,
                "up",
            ]
        )

        _run(
            [
                "ip",
                "netns",
                "exec",
                server_ns,
                "ip",
                "addr",
                "add",
                server_v4,
                "dev",
                veth_server,
            ]
        )
        _run(
            [
                "ip",
                "netns",
                "exec",
                server_ns,
                "ip",
                "addr",
                "add",
                server_v6,
                "dev",
                veth_server,
            ]
        )
        _run(["ip", "netns", "exec", server_ns, "ip", "link", "set", veth_server, "up"])

        # Bring up loopbacks
        _run(["ip", "netns", "exec", router_ns, "ip", "link", "set", "lo", "up"])
        _run(["ip", "netns", "exec", server_ns, "ip", "link", "set", "lo", "up"])

        # 3. Setup transit routing
        # Route on Host: Server subnet via Router host IP
        host_rt_via = router_host_v4.split("/")[0]
        host_rt_via6 = router_host_v6.split("/")[0]
        _run(["ip", "route", "add", "10.0.2.0/24", "via", host_rt_via, "dev", veth_host])
        _run(
            [
                "ip",
                "-6",
                "route",
                "add",
                "fd00:2::/64",
                "via",
                host_rt_via6,
                "dev",
                veth_host,
            ]
        )

        # Route on Server: Host subnet via Router server IP (default route is cleanest)
        srv_rt_via = router_server_v4.split("/")[0]
        srv_rt_via6 = router_server_v6.split("/")[0]
        _run(
            [
                "ip",
                "netns",
                "exec",
                server_ns,
                "ip",
                "route",
                "add",
                "default",
                "via",
                srv_rt_via,
                "dev",
                veth_server,
            ]
        )
        _run(
            [
                "ip",
                "netns",
                "exec",
                server_ns,
                "ip",
                "-6",
                "route",
                "add",
                "default",
                "via",
                srv_rt_via6,
                "dev",
                veth_server,
            ]
        )

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
        try:
            from nse.models.trace_event import TestStatusResponse
        except ImportError as exc:
            raise ImportError(
                "Pydantic is required to use get_status(). Install it with: pip install 'network-sandbox-engine[cli]'"
            ) from exc

        run = self._tests.get(test_id)
        if run is None:
            return None
        return TestStatusResponse(test_id=test_id, status=run.status)

    def get_event_queue(self, test_id: str) -> "asyncio.Queue[TraceEvent | None]":
        return self._tests[test_id].event_queue

    def release_test(self, test_id: str) -> None:
        """Called by the WebSocket handler after the connection closes."""
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
