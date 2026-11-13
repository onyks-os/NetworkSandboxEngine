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
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, cast

from nse.core.paths import resolve
from nse.core.resource_network import NetworkResources
from nse.core.resource_registry import Journal, OwnershipError, Resource, ResourceRegistry
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
        self._registry = ResourceRegistry()
        self._resources = NetworkResources(self.use_nsenter)
        self._runs: dict[str, str] = {}
        self.startup_sweep()

    def startup_sweep(self) -> None:
        """Recover verified abandoned ownership journals; preserve unmarked resources."""
        try:
            self._registry.recover(self._cleanup_resources)
            for name in self._resources.unmarked():
                logger.warning(
                    "Unmarked NSE resource %s left untouched; ownership is unknown", name
                )
        except (OSError, ValueError, OwnershipError, subprocess.SubprocessError) as exc:
            logger.warning("NSE startup recovery incomplete; resources preserved: %s", exc)

    def _cleanup_resources(self, journal: Journal, namespace: str | None = None) -> None:
        # Delete links before namespace names: a process may keep an unnamed
        # namespace alive. Routes attached to a deleted link disappear with it.
        links = [
            entry
            for entry in journal.data.resources
            if entry.kind == "link"
            and (namespace is None or namespace in (entry.netns, entry.peer_netns))
        ]
        for entry in links:
            self._remove_resource(journal, entry)
        namespaces = [
            entry
            for entry in journal.data.resources
            if entry.kind == "namespace" and (namespace is None or entry.name == namespace)
        ]
        for entry in namespaces:
            if any(
                link.kind == "link" and entry.name in (link.netns, link.peer_netns)
                for link in journal.data.resources
            ):
                logger.warning("Preserving namespace %s with unresolved links", entry.name)
                continue
            if (
                self._remove_resource(journal, entry)
                and journal.data.owner_id == self._registry.owner_id
            ):
                self._active_ns.discard(entry.name)
                self._runs.pop(entry.name, None)

    def _remove_resource(self, journal: Journal, entry: Resource) -> bool:
        try:
            observation = self._resources.inspect(entry, journal.marker(entry))
            if observation.status == "foreign":
                logger.warning(
                    "Preserving %s %s: ownership marker or identity differs", entry.kind, entry.name
                )
                return False
            if observation.status == "owned":
                if entry.kind == "namespace":
                    if not self._delete_namespace(entry.name):
                        return False
                else:
                    _run(
                        [
                            *self._resources.prefix(observation.netns),
                            resolve("ip"),
                            "link",
                            "del",
                            observation.name,
                        ]
                    )
            journal.discard(entry)
            return True
        except (OSError, ValueError, OwnershipError, subprocess.SubprocessError) as exc:
            logger.warning("Preserving unresolved %s %s: %s", entry.kind, entry.name, exc)
            return False

    def _cleanup_link(self, name: str) -> None:
        if self._registry.data is None:
            return
        with self._registry.edit() as journal:
            for entry in list(journal.data.resources):
                if entry.kind == "link" and name in (entry.name, entry.peer):
                    self._remove_resource(journal, entry)

    def _create_owned_pair(
        self, first: str, peer: str, peer_netns: str, first_netns: str | None = None
    ) -> None:
        with self._registry.edit() as journal:
            first_identity = self._resources.identity(first_netns)
            peer_identity = self._resources.identity(peer_netns)
            if first_identity is None or peer_identity is None:
                raise OwnershipError("cannot identify the namespaces owning the veth endpoints")
            entry = journal.add(
                Resource(
                    kind="link",
                    name=first,
                    peer=peer,
                    run_id=self._runs.setdefault(peer_netns, uuid.uuid4().hex),
                    netns=first_netns,
                    netns_identity=first_identity,
                    peer_netns=peer_netns,
                    peer_identity=peer_identity,
                )
            )
            marker = journal.marker(entry)
            # Some kernels ignore IFLA_IFALIAS during veth creation. The two MACs
            # are atomic creation attributes; a pending intent can be recovered
            # only if BOTH addresses and their peer relationship still match.
            first_mac, peer_mac = entry.mac_addresses()
            _run(
                [
                    *self._resources.prefix(first_netns),
                    resolve("ip"),
                    "link",
                    "add",
                    first,
                    "address",
                    first_mac,
                    "type",
                    "veth",
                    "peer",
                    "name",
                    peer,
                    "address",
                    peer_mac,
                ]
            )
            for interface in (first, peer):
                _run(
                    [
                        *self._resources.prefix(first_netns),
                        resolve("ip"),
                        "link",
                        "set",
                        "dev",
                        interface,
                        "alias",
                        marker,
                    ]
                )
            entry.state = "created"
            if self._resources.inspect(entry, marker).status != "owned":
                entry.state = "pending"
                raise OwnershipError("cannot confirm ownership markers on the new veth pair")
            journal.save()

    def _create_owned_route(self, command: list[str], interface: str) -> None:
        with self._registry.edit() as journal:
            parent = next(
                entry
                for entry in journal.data.resources
                if entry.kind == "link" and entry.name == interface
            )
            entry = journal.add(
                Resource(
                    kind="route",
                    name=f"route_{uuid.uuid4().hex}",
                    run_id=parent.run_id,
                    parent=parent.token,
                    route=tuple(command),
                )
            )
            _run(command)
            entry.state = "created"
            journal.save()

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
        with self._registry.edit() as journal:
            if any(
                entry.kind == "namespace" and entry.name == name for entry in journal.data.resources
            ):
                raise OwnershipError(f"namespace {name} is already registered by this controller")
            entry = journal.add(
                Resource(
                    kind="namespace",
                    name=name,
                    run_id=self._runs.setdefault(name, uuid.uuid4().hex),
                )
            )
            _run([resolve("ip"), "netns", "add", name])
            self._active_ns.add(name)
            self._run_in_netns(
                name, [resolve("ip"), "link", "set", "dev", "lo", "alias", journal.marker(entry)]
            )
            entry.identity = self._resources.identity(name)
            if entry.identity is None:
                raise OwnershipError(f"cannot confirm identity of newly created namespace {name}")
            if self._resources.inspect(entry, journal.marker(entry)).status != "owned":
                raise OwnershipError(f"cannot confirm ownership marker of namespace {name}")
            entry.state = "created"
            journal.save()
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
        """Remove only this controller's verified namespace and associated links."""
        if self._registry.data is None:
            logger.warning("Namespace %s is not owned by this controller; left untouched", name)
            return
        with self._registry.edit() as journal:
            if not any(
                entry.kind == "namespace" and entry.name == name for entry in journal.data.resources
            ):
                logger.warning("Namespace %s is not owned by this controller; left untouched", name)
                return
            self._cleanup_resources(journal, namespace=name)

    def _delete_namespace(self, name: str) -> bool:
        delays = [0.1, 0.5, 1.0]
        for idx, delay in enumerate(delays):
            try:
                _run([resolve("ip"), "netns", "del", name])
                return True
            except subprocess.CalledProcessError as err:
                if "No such file or directory" in (err.stderr or ""):
                    return True
                if idx < len(delays) - 1:
                    time.sleep(delay)
                else:
                    logger.warning("Failed to destroy netns %s after 3 attempts: %s", name, err)
            except subprocess.TimeoutExpired:
                logger.warning("Timeout destroying netns %s", name)
                break
        return False

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
            self._cleanup_link(sandbox.ext_iface)

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
        self._create_owned_pair(veth_host, veth_peer, netns_name)
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
        # Both namespaces belong to the same experiment within this controller.
        run_id = uuid.uuid4().hex
        self._runs.setdefault(router_ns, run_id)
        self._runs.setdefault(server_ns, run_id)
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
        self._create_owned_pair(veth_host, veth_router_host, router_ns)
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
        self._create_owned_pair(veth_router_server, veth_server, server_ns, router_ns)
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
        self._create_owned_route(
            [resolve("ip"), "route", "add", "10.0.2.0/24", "via", host_rt_via, "dev", veth_host],
            veth_host,
        )
        self._create_owned_route(
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
            ],
            veth_host,
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
        Destroy this controller's verified resources. Called on SIGINT/SIGTERM.
        Safe to call multiple times.
        """
        logger.info("Cleaning up %d namespace(s)…", len(self._active_ns))
        if self._registry.data is not None:
            with self._registry.edit() as journal:
                self._cleanup_resources(journal)


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
