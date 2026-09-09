# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""
NetnsController: manages ephemeral Linux network namespaces.

All subprocess calls use iproute2 (`ip`) and must be run as root.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import subprocess
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, cast

from nse.core.naming import NETNS_SWEEP_PREFIXES, VETH_SWEEP_PREFIXES
from nse.core.paths import resolve
from nse.core.utils import is_in_container

if TYPE_CHECKING:
    from nse.models.test_request import TestRequest
    from nse.models.trace_event import TraceEvent

logger = logging.getLogger("nse.core.netns")


@dataclass
class TestRun:
    __test__ = False

    test_id: str
    netns_name: str
    request: TestRequest
    status: str = "pending"  # pending | running | done | error
    event_queue: asyncio.Queue[TraceEvent | None] = field(
        default_factory=lambda: asyncio.Queue(maxsize=512)
    )


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
        cmd = self.controller.exec_prefix(self.name) + command.split()
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        returncode = proc.returncode if proc.returncode is not None else 1
        if returncode != 0:
            raise subprocess.CalledProcessError(
                returncode,
                cmd,
                output=stdout,
                stderr=stderr,
            )
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=returncode,
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
        from nse.models.test_request import PacketSpec

        injector = ScapyInjector()
        packet = PacketSpec(
            protocol=cast(Any, protocol),
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

    def __init__(self, use_nsenter: bool | None = None) -> None:
        self._active_ns: set[str] = set()  # namespace names
        if use_nsenter is None:
            self.use_nsenter = is_in_container()
        else:
            self.use_nsenter = use_nsenter
        self.startup_sweep()

    def startup_sweep(self) -> None:
        """Clean up orphan namespaces and veth pairs left behind by previous crashes."""
        try:
            res = subprocess.run(
                [resolve("ip"), "netns", "list"],
                capture_output=True,
                text=True,
                check=False,
                timeout=5.0,
            )
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    ns_name = line.split()[0] if line.split() else ""
                    if ns_name.startswith(NETNS_SWEEP_PREFIXES):
                        logger.info("Startup sweep: removing orphan netns %s", ns_name)
                        subprocess.run(
                            [resolve("ip"), "netns", "del", ns_name],
                            capture_output=True,
                            check=False,
                            timeout=5.0,
                        )
        except Exception as exc:
            logger.debug("Startup sweep netns list failed: %s", exc)

        try:
            res = subprocess.run(
                [resolve("ip"), "link", "show"],
                capture_output=True,
                text=True,
                check=False,
                timeout=5.0,
            )
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    parts = line.split(":")
                    if len(parts) >= 2:
                        iface = parts[1].strip().split("@")[0]
                        if iface.startswith(VETH_SWEEP_PREFIXES):
                            logger.info("Startup sweep: removing orphan veth link %s", iface)
                            subprocess.run(
                                [resolve("ip"), "link", "del", iface],
                                capture_output=True,
                                check=False,
                                timeout=5.0,
                            )
        except Exception as exc:
            logger.debug("Startup sweep veth list failed: %s", exc)

    def exec_prefix(self, name: str) -> list[str]:
        if self.use_nsenter:
            return [resolve("nsenter"), f"--net=/var/run/netns/{name}", "--"]
        else:
            return [resolve("ip"), "netns", "exec", name]

    def _run_in_netns(self, name: str, cmd: list[str]) -> subprocess.CompletedProcess[str]:
        return _run(self.exec_prefix(name) + cmd)

    # ------------------------------------------------------------------
    # Namespace lifecycle
    # ------------------------------------------------------------------

    def create_netns(self, name: str) -> None:
        """Create a new network namespace. Raises on failure."""
        logger.debug("Creating netns: %s", name)
        _run([resolve("ip"), "netns", "add", name])
        self._active_ns.add(name)
        # Disable DAD inside the netns to speed up IPv6 interface readiness
        try:
            self._run_in_netns(
                name,
                [
                    resolve("sysctl"),
                    "-w",
                    "net.ipv6.conf.all.accept_dad=0",
                ],
            )
            self._run_in_netns(
                name,
                [
                    resolve("sysctl"),
                    "-w",
                    "net.ipv6.conf.default.accept_dad=0",
                ],
            )
        except subprocess.CalledProcessError as e:
            logger.warning("Could not set accept_dad sysctls inside netns %s: %s", name, e)

    def destroy_netns(self, name: str) -> None:
        """Delete a network namespace with retry backoff. Idempotent."""
        logger.debug("Destroying netns: %s", name)
        delays = [0.1, 0.5, 1.0]
        for idx, delay in enumerate(delays):
            try:
                _run([resolve("ip"), "netns", "del", name])
                break
            except subprocess.CalledProcessError as err:
                stderr = err.stderr or ""
                if "No such file or directory" in stderr or "Invalid argument" in stderr:
                    logger.debug("netns %s already gone.", name)
                    break
                if idx < len(delays) - 1:
                    time.sleep(delay)
                else:
                    logger.warning("Failed to destroy netns %s after 3 attempts: %s", name, err)
            except subprocess.TimeoutExpired:
                logger.warning("Timeout destroying netns %s", name)
                break
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
        self._run_in_netns(name, [resolve("ip"), "link", "set", "lo", "up"])

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
            with contextlib.suppress(subprocess.CalledProcessError, OSError):
                _run([resolve("ip"), "link", "del", sandbox.ext_iface])

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
        _run([resolve("ip"), "link", "add", veth_host, "type", "veth", "peer", "name", veth_peer])
        # Move the peer end into the target namespace
        _run([resolve("ip"), "link", "set", veth_peer, "netns", netns_name])

        # --- Host side ---
        if v4_host:
            _run([resolve("ip"), "addr", "add", v4_host, "dev", veth_host])
        if v6_host:
            _run([resolve("ip"), "addr", "add", v6_host, "dev", veth_host])
        _run([resolve("ip"), "link", "set", veth_host, "up"])

        # --- Namespace side ---
        if v4_peer:
            self._run_in_netns(
                netns_name,
                [
                    resolve("ip"),
                    "addr",
                    "add",
                    v4_peer,
                    "dev",
                    veth_peer,
                ],
            )
        if v6_peer:
            self._run_in_netns(
                netns_name,
                [
                    resolve("ip"),
                    "addr",
                    "add",
                    v6_peer,
                    "dev",
                    veth_peer,
                ],
            )
        self._run_in_netns(netns_name, [resolve("ip"), "link", "set", veth_peer, "up"])
        self._run_in_netns(netns_name, [resolve("ip"), "link", "set", "lo", "up"])

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
        self._run_in_netns(router_ns, [resolve("sysctl"), "-w", "net.ipv4.ip_forward=1"])
        self._run_in_netns(
            router_ns,
            [
                resolve("sysctl"),
                "-w",
                "net.ipv6.conf.all.forwarding=1",
            ],
        )

        # 1. Create Host <-> Router veth pair
        _run(
            [
                resolve("ip"),
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
        _run([resolve("ip"), "link", "set", veth_router_host, "netns", router_ns])

        _run([resolve("ip"), "addr", "add", host_v4, "dev", veth_host])
        _run([resolve("ip"), "addr", "add", host_v6, "dev", veth_host])
        _run([resolve("ip"), "link", "set", veth_host, "up"])

        self._run_in_netns(
            router_ns,
            [
                resolve("ip"),
                "addr",
                "add",
                router_host_v4,
                "dev",
                veth_router_host,
            ],
        )
        self._run_in_netns(
            router_ns,
            [
                resolve("ip"),
                "addr",
                "add",
                router_host_v6,
                "dev",
                veth_router_host,
            ],
        )
        self._run_in_netns(
            router_ns,
            [
                resolve("ip"),
                "link",
                "set",
                veth_router_host,
                "up",
            ],
        )

        # 2. Create Router <-> Server veth pair
        self._run_in_netns(
            router_ns,
            [
                resolve("ip"),
                "link",
                "add",
                veth_router_server,
                "type",
                "veth",
                "peer",
                "name",
                veth_server,
            ],
        )
        self._run_in_netns(
            router_ns,
            [
                resolve("ip"),
                "link",
                "set",
                veth_server,
                "netns",
                server_ns,
            ],
        )

        self._run_in_netns(
            router_ns,
            [
                resolve("ip"),
                "addr",
                "add",
                router_server_v4,
                "dev",
                veth_router_server,
            ],
        )
        self._run_in_netns(
            router_ns,
            [
                resolve("ip"),
                "addr",
                "add",
                router_server_v6,
                "dev",
                veth_router_server,
            ],
        )
        self._run_in_netns(
            router_ns,
            [
                resolve("ip"),
                "link",
                "set",
                veth_router_server,
                "up",
            ],
        )

        self._run_in_netns(
            server_ns,
            [
                resolve("ip"),
                "addr",
                "add",
                server_v4,
                "dev",
                veth_server,
            ],
        )
        self._run_in_netns(
            server_ns,
            [
                resolve("ip"),
                "addr",
                "add",
                server_v6,
                "dev",
                veth_server,
            ],
        )
        self._run_in_netns(server_ns, [resolve("ip"), "link", "set", veth_server, "up"])

        # Bring up loopbacks
        self._run_in_netns(router_ns, [resolve("ip"), "link", "set", "lo", "up"])
        self._run_in_netns(server_ns, [resolve("ip"), "link", "set", "lo", "up"])

        # 3. Setup transit routing
        # Route on Host: Server subnet via Router host IP
        host_rt_via = router_host_v4.split("/")[0]
        host_rt_via6 = router_host_v6.split("/")[0]
        _run([resolve("ip"), "route", "add", "10.0.2.0/24", "via", host_rt_via, "dev", veth_host])
        _run(
            [
                resolve("ip"),
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
        self._run_in_netns(
            server_ns,
            [
                resolve("ip"),
                "route",
                "add",
                "default",
                "via",
                srv_rt_via,
                "dev",
                veth_server,
            ],
        )
        self._run_in_netns(
            server_ns,
            [
                resolve("ip"),
                "-6",
                "route",
                "add",
                "default",
                "via",
                srv_rt_via6,
                "dev",
                veth_server,
            ],
        )

    def cleanup_all(self) -> None:
        """
        Destroy all known namespaces.  Called on SIGINT/SIGTERM.
        Safe to call multiple times.
        """
        logger.info("Cleaning up %d namespace(s)…", len(self._active_ns))
        for name in list(self._active_ns):
            self.destroy_netns(name)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(cmd: list[str], timeout: float = 10.0) -> subprocess.CompletedProcess[str]:
    """Run a subprocess command, raising on non-zero exit or timeout."""
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=True,
        timeout=timeout,
    )
    return result
