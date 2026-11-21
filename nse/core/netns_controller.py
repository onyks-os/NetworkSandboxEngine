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
import os
import subprocess
import time
import uuid
from collections.abc import AsyncIterator, Iterator, Sequence
from dataclasses import dataclass, field
from ipaddress import ip_interface, ip_network
from typing import TYPE_CHECKING, Any, cast

from nse.core.async_work import run_blocking
from nse.core.host_firewall import warn_if_filtered
from nse.core.naming import NamespaceNames, interface_suffix
from nse.core.paths import resolve
from nse.core.process import (
    DEFAULT_GRACE,
    DEFAULT_OUTPUT_LIMIT,
    DEFAULT_START_TIMEOUT,
    ManagedProcess,
    NetnsIdentity,
    Output,
    ProtectedNamespaceError,
    spawn_process,
    terminate_namespace,
)
from nse.core.process import validate_argv as _validate_argv
from nse.core.resource_network import NetworkResources
from nse.core.resource_registry import Journal, OwnershipError, Resource, ResourceRegistry
from nse.core.utils import is_in_container
from nse.models.network_config import GatewayNetwork, SimpleNetwork

if TYPE_CHECKING:
    from collections.abc import Mapping

    from nse.models.process import ProcessIdentity, ProcessResult
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

    def __init__(
        self, controller: NetnsController, name: str, *, ext_netns: str | None = None
    ) -> None:
        self.controller = controller
        self.name = name
        # We derive interface names from the sandbox name
        self.ext_iface = f"vhr-{interface_suffix(name)}"
        self.peer_iface = f"vrh-{interface_suffix(name)}"
        #: Namespace holding :attr:`ext_iface`: None when it is the namespace NSE
        #: runs in, the host endpoint's own namespace with ``isolated_host=True``.
        self.ext_netns = ext_netns
        #: With ``isolated_host=True``, the host endpoint as a sandbox of its own:
        #: run a server on ``host_ip`` with ``sandbox.host.start_process()``.
        #: Its :attr:`ext_iface` is this sandbox's :attr:`peer_iface`, and back.
        self.host: NamespaceSandbox | None = None
        self._source_v4 = "10.0.1.1"
        self._source_v6 = "fd00:1::1"
        self._processes: list[ManagedProcess] = []

    async def start_process(
        self,
        argv: Sequence[str | os.PathLike[str]],
        *,
        identity: ProcessIdentity | None = None,
        env: Mapping[str, str] | None = None,
        cwd: str | os.PathLike[str] | None = None,
        stdout: Output = "capture",
        stderr: Output = "capture",
        max_output_bytes: int = DEFAULT_OUTPUT_LIMIT,
        start_timeout: float = DEFAULT_START_TIMEOUT,
    ) -> ManagedProcess:
        """
        Start a long-running program in the namespace and return its handle.

        *argv* is passed exactly, as for :meth:`exec_argv`. *identity* (UID, GID,
        groups, capabilities) is applied after entering the namespace and verified
        against what the kernel reports for the process itself before the
        program is allowed to start; a mismatch raises
        :class:`~nse.core.process.IdentityError` and nothing runs. Without
        *identity* the program runs as NSE does, and that identity is recorded.

        stdin is ``/dev/null``. *stdout*/*stderr* are ``"capture"`` (keeping at
        most *max_output_bytes*, counting the rest), ``"discard"`` or a path to
        a new file. Every process still running when the sandbox closes is
        stopped, together with anything else left in the namespace.
        """
        netns = self.controller.namespace_identity(self.name)
        if netns is None:
            raise OwnershipError(f"namespace {self.name} does not exist")
        process = await spawn_process(
            self.controller.exec_prefix(self.name),
            argv,
            netns=netns,
            identity=identity,
            env=env,
            cwd=cwd,
            stdout=stdout,
            stderr=stderr,
            max_output_bytes=max_output_bytes,
            start_timeout=start_timeout,
        )
        self._processes.append(process)
        return process

    async def run_process(
        self,
        argv: Sequence[str | os.PathLike[str]],
        *,
        timeout: float | None = None,
        grace: float = DEFAULT_GRACE,
        check: bool = False,
        **options: Any,
    ) -> ProcessResult:
        """
        Run a program to completion, as :meth:`start_process` then ``wait(timeout)``.

        When *timeout* expires the process and its group are stopped (SIGTERM,
        *grace* seconds, SIGKILL) and the result says ``termination="timeout"``.
        With *check*, a result that is not ``ok`` raises
        ``subprocess.CalledProcessError``.
        """
        process = await self.start_process(argv, **options)
        result = await process.wait(timeout, grace=grace)
        return result.check() if check else result

    async def _stop_processes(self) -> None:
        """Stop every managed process still running, in parallel."""
        processes, self._processes = self._processes, []
        results = await asyncio.gather(
            *(process.terminate() for process in processes), return_exceptions=True
        )
        for process, result in zip(processes, results, strict=True):
            if isinstance(result, BaseException):
                logger.warning("Stopping %s (pid %d) failed: %s", process.argv, process.pid, result)

    async def exec(self, command: str) -> subprocess.CompletedProcess[bytes]:
        """
        Run *command* inside the namespace, split on whitespace with ``str.split()``.

        No shell is involved: quotes, escapes, globs, pipes, redirections and
        variables are **not** interpreted, and an argument cannot contain a space.
        ``exec('python3 -c "print(1)"')`` passes ``'"print(1)"'`` with its quote
        characters. Use :meth:`exec_argv` to pass each argument exactly.

        Returns ``CompletedProcess[bytes]`` with ``args`` set to the full command
        (namespace prefix included); raises ``subprocess.CalledProcessError``
        carrying stdout/stderr on a non-zero exit.
        """
        return await self._run(command.split())

    async def exec_argv(
        self, argv: Sequence[str | os.PathLike[str]]
    ) -> subprocess.CompletedProcess[bytes]:
        """
        Run a program inside the namespace with exactly the given arguments.

        Each element of *argv* reaches the process as one argument, unchanged:
        spaces, quotes, empty strings, Unicode and shell metacharacters are
        literal, because no shell or splitting is involved. ``argv[0]`` is the
        program, looked up on the namespace process's ``PATH`` unless it is a path.

        Result and errors are those of :meth:`exec`. Raises ``TypeError`` for a
        bare string or a non-``str`` element and ``ValueError`` for an empty
        program name or an argument containing NUL, before anything is started.
        """
        return await self._run(_validate_argv(argv))

    async def _run(self, argv: list[str]) -> subprocess.CompletedProcess[bytes]:
        cmd = self.controller.exec_prefix(self.name) + argv
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await proc.communicate()
        except asyncio.CancelledError:
            # Do not leave the child running unobserved. Its own children stay
            # in the namespace until teardown stops everything in it; use
            # start_process() for a managed tree, identity and timeouts.
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            with contextlib.suppress(asyncio.CancelledError):
                await asyncio.shield(proc.wait())
            raise
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

        injector = ScapyInjector(use_nsenter=self.controller.use_nsenter)
        packet = PacketSpec(
            protocol=cast(Any, protocol),
            dst_port=dst_port,
            dst_ip=dst_ip,
            src_ip=src_ip or (self._source_v4 if "." in dst_ip else self._source_v6),
        )

        # Sniffing/injection scapy operations can be blocking, run in executor
        await run_blocking(
            injector.inject,
            packet,
            self.name,
            self.ext_iface,
            self.peer_iface,
            self.ext_netns,
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

    def _cleanup_resources(
        self, journal: Journal, namespace: str | None = None, run_id: str | None = None
    ) -> None:
        # Delete links before namespace names: a process may keep an unnamed
        # namespace alive. Routes attached to a deleted link disappear with it.
        links = [
            entry
            for entry in reversed(journal.data.resources)
            if entry.kind == "link"
            and (run_id is None or entry.run_id == run_id)
            and (namespace is None or namespace in (entry.netns, entry.peer_netns))
        ]
        for entry in links:
            self._remove_resource(journal, entry)
        namespaces = [
            entry
            for entry in reversed(journal.data.resources)
            if entry.kind == "namespace"
            and (namespace is None or entry.name == namespace)
            and (run_id is None or entry.run_id == run_id)
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

    @contextlib.contextmanager
    def _transaction(self, namespaces: Sequence[str], run_id: str) -> Iterator[None]:
        """Reserve all names and serialize preflight/setup against other NSE owners."""
        with self._registry.edit() as journal:
            if len(set(namespaces)) != len(namespaces):
                raise OwnershipError("a topology requires distinct namespace names")
            for name in namespaces:
                # Validate before either reserving or issuing a kernel command.
                Resource(kind="namespace", name=name, run_id=run_id)
                if name in self._runs or self._resources.namespace_exists(name):
                    raise OwnershipError(f"namespace {name} is already active or reserved")
            for name in namespaces:
                self._runs[name] = run_id
            try:
                yield
            except BaseException:
                self._cleanup_resources(journal, run_id=run_id)
                raise
            finally:
                for name in namespaces:
                    if not any(entry.run_id == run_id for entry in journal.data.resources):
                        self._runs.pop(name, None)

    def _cleanup_run(self, run_id: str) -> None:
        if self._registry.data is not None:
            with self._registry.edit() as journal:
                self._cleanup_resources(journal, run_id=run_id)

    def residual_resources(self, run_id: str) -> list[str]:
        """Resources of run *run_id* still recorded as owned, e.g. after a failed teardown.

        Cleanup keeps the record of anything it could not remove or verify, so a
        non-empty answer means the run did not clean up completely.
        """
        data = self._registry.data
        if data is None:
            return []
        return sorted(
            f"{entry.kind} {entry.name}" for entry in data.resources if entry.run_id == run_id
        )

    def _preflight(self, interfaces: Sequence[str], addresses: Sequence[str]) -> None:
        if len(set(interfaces)) != len(interfaces) or any(
            not name or len(name.encode()) > 15 or any(c in name for c in "/: \t\n")
            for name in interfaces
        ):
            raise ValueError("interface names must be distinct and fit Linux's 15 byte limit")
        existing = {link.ifname for link in self._resources.links(None)}
        if existing.intersection(interfaces):
            raise OwnershipError(
                f"host interface name conflict: {sorted(existing.intersection(interfaces))}"
            )
        networks = [ip_interface(address).network for address in addresses]
        for version in (4, 6):
            for route in self._resources.routes(version):
                if not route.dst or route.dst == "default":
                    continue
                destination = ip_network(route.dst, strict=False)
                if destination.prefixlen == 0:
                    continue
                for network in networks:
                    if network.version == destination.version and network.overlaps(destination):
                        raise OwnershipError(
                            f"subnet {network} conflicts with host route {destination} on {route.dev}"
                        )

    def _setup_topology(self, names: NamespaceNames, request: TestRequest, run_id: str) -> None:
        from nse.models.test_request import TopologyType

        if request.topology == TopologyType.GATEWAY:
            config = request.network or GatewayNetwork()
            assert isinstance(config, GatewayNetwork)
            with self._transaction((names.router_ns, names.server_ns), run_id):
                self._preflight(
                    (names.veth_host, names.veth_router_host),
                    (config.host_v4, config.host_v6, config.server_v4, config.server_v6),
                )
                self._configure_gateway(
                    names.router_ns,
                    names.server_ns,
                    names.veth_host,
                    names.veth_router_host,
                    names.veth_router_server,
                    names.veth_server,
                    config,
                )
        else:
            config_simple = request.network or SimpleNetwork()
            assert isinstance(config_simple, SimpleNetwork)
            with self._transaction((names.netns,), run_id):
                self._preflight(
                    (names.veth_host, names.veth_router_host),
                    (config_simple.host_v4, config_simple.host_v6),
                )
                self.create_netns(names.netns)
                self.create_veth_pair(
                    names.netns,
                    names.veth_host,
                    names.veth_router_host,
                    [config_simple.host_v4, config_simple.host_v6],
                    [config_simple.peer_v4, config_simple.peer_v6],
                )

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

    def namespace_identity(self, name: str) -> NetnsIdentity | None:
        """``(st_dev, st_ino)`` of namespace *name*, or None if it does not exist."""
        return self._resources.identity(name)

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
            entry.identity = self._resources.identity(name)
            if entry.identity is None:
                raise OwnershipError(f"cannot confirm identity of newly created namespace {name}")
            try:
                self._run_in_netns(
                    name,
                    [resolve("ip"), "link", "set", "dev", "lo", "alias", journal.marker(entry)],
                )
            except BaseException:
                # Live rollback has the successful exclusive creation and its
                # inode as evidence. Crash recovery still requires the marker.
                try:
                    unclaimed = all(not link.ifalias for link in self._resources.links(name))
                except Exception:
                    # Entering the namespace is what failed (e.g. `ip netns exec`
                    # in some containers). The exclusive creation under the
                    # registry lock and the unchanged inode remain the evidence;
                    # the original error, not this one, is re-raised below.
                    unclaimed = True
                if (
                    self._resources.identity(name) == entry.identity
                    and unclaimed
                    and self._delete_namespace(name)
                ):
                    journal.discard(entry)
                    self._active_ns.discard(name)
                raise
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
        # The namespace is the process boundary: nothing started in it, nor
        # anything those processes left behind (even detached from their
        # session), may outlive it unseen in an unnamed namespace.
        netns = self._resources.identity(name)
        if netns is not None:
            try:
                survivors = terminate_namespace(netns)
            except ProtectedNamespaceError as exc:
                logger.error("Not deleting namespace %s: %s", name, exc)
                return False
            if survivors:
                logger.warning(
                    "Processes %s survived SIGKILL in namespace %s; deleting it anyway",
                    survivors,
                    name,
                )
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
        *,
        isolated_host: bool = False,
    ) -> AsyncIterator[NamespaceSandbox]:
        """
        Context manager to safely construct and teardown an isolated namespace.

        By default the host end of the veth pair, with *host_ip*, is in the
        namespace NSE runs in, so traffic from the sandbox to *host_ip* crosses
        the host's own firewall; NSE logs a warning when that firewall may filter
        it. With *isolated_host*, the host end goes into a namespace of its own,
        ``nsh_<name>`` (:attr:`NamespaceSandbox.ext_netns`), created and removed
        with the sandbox: no host rule, route or firewall is on the path, and
        *host_ip* may overlap a host subnet. Run programs there through
        :attr:`NamespaceSandbox.host` and capture there with
        ``PCAPAsserter(iface=sandbox.ext_iface, netns=sandbox.ext_netns)``.
        """
        host_ns = f"nsh_{name}" if isolated_host else None
        sandbox = NamespaceSandbox(self, name, ext_netns=host_ns)

        run_id = uuid.uuid4().hex

        def setup() -> None:
            namespaces = (name,) if host_ns is None else (name, host_ns)
            with self._transaction(namespaces, run_id):
                self._preflight(
                    (sandbox.ext_iface, sandbox.peer_iface),
                    # An isolated endpoint shares no routing table with the host.
                    (config.host_v4, config.host_v6) if host_ns is None else (),
                )
                sandbox._source_v4 = str(ip_interface(config.host_v4).ip)
                sandbox._source_v6 = str(ip_interface(config.host_v6).ip)
                self.create_netns(name)
                if host_ns is None:
                    self.create_veth_pair(
                        name, sandbox.ext_iface, sandbox.peer_iface, host_ip, peer_ip
                    )
                    return
                self.create_netns(host_ns)
                self._configure_pair(
                    name, sandbox.ext_iface, sandbox.peer_iface, config, host_netns=host_ns
                )
                view = NamespaceSandbox(self, host_ns, ext_netns=name)
                view.ext_iface, view.peer_iface = sandbox.peer_iface, sandbox.ext_iface
                view._source_v4 = str(ip_interface(config.peer_v4).ip)
                view._source_v6 = str(ip_interface(config.peer_v6).ip)
                sandbox.host = view

        config = self._simple_network(host_ip, peer_ip)
        try:
            await run_blocking(setup)
            if host_ns is None:
                await run_blocking(warn_if_filtered, name, [config.host_v4, config.host_v6])
            yield sandbox
        finally:
            try:
                await asyncio.gather(
                    sandbox._stop_processes(),
                    *([sandbox.host._stop_processes()] if sandbox.host else []),
                )
            finally:
                await run_blocking(self._cleanup_run, run_id)

    @staticmethod
    def _simple_network(host_ip: str | list[str], peer_ip: str | list[str]) -> SimpleNetwork:
        addresses = {}
        for label, value in (("host", host_ip), ("peer", peer_ip)):
            for address in [value] if isinstance(value, str) else value:
                family = ip_interface(address).version
                key = f"{label}_v{family}"
                if key in addresses:
                    raise ValueError("at most one address per family is supported on each endpoint")
                addresses[key] = address
        return SimpleNetwork(**addresses)

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
        config = self._simple_network(host_ip, peer_ip)
        with self._registry.edit() as journal:
            self._preflight((veth_host, veth_peer), (config.host_v4, config.host_v6))
            before = {entry.token for entry in journal.data.resources}
            try:
                self._configure_pair(netns_name, veth_host, veth_peer, config)
            except BaseException:
                for entry in reversed(list(journal.data.resources)):
                    if entry.kind == "link" and entry.token not in before:
                        self._remove_resource(journal, entry)
                raise

    def _configure_pair(
        self,
        netns_name: str,
        veth_host: str,
        veth_peer: str,
        config: SimpleNetwork,
        host_netns: str | None = None,
    ) -> None:
        v4_host, v6_host = config.host_v4, config.host_v6
        v4_peer, v6_peer = config.peer_v4, config.peer_v6
        # Commands for the host end run where it lives: NSE's own namespace, or
        # the isolated host endpoint's.
        host = self._resources.prefix(host_netns)

        # Create the veth pair on the host side
        self._create_owned_pair(veth_host, veth_peer, netns_name, host_netns)
        # Move the peer end into the target namespace
        _run([*host, resolve("ip"), "link", "set", veth_peer, "netns", netns_name])

        # --- Host side ---
        if v4_host:
            _run([*host, resolve("ip"), "addr", "add", v4_host, "dev", veth_host])
        if v6_host:
            _run([*host, resolve("ip"), "addr", "add", v6_host, "dev", veth_host])
        _run([*host, resolve("ip"), "link", "set", veth_host, "up"])
        if host_netns is not None:
            _run([*host, resolve("ip"), "link", "set", "lo", "up"])

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
        config = GatewayNetwork(
            host_v4=host_v4,
            router_host_v4=router_host_v4,
            router_server_v4=router_server_v4,
            server_v4=server_v4,
            host_v6=host_v6,
            router_host_v6=router_host_v6,
            router_server_v6=router_server_v6,
            server_v6=server_v6,
        )
        with self._transaction((router_ns, server_ns), uuid.uuid4().hex):
            self._preflight((veth_host, veth_router_host), (host_v4, host_v6, server_v4, server_v6))
            self._configure_gateway(
                router_ns,
                server_ns,
                veth_host,
                veth_router_host,
                veth_router_server,
                veth_server,
                config,
            )

    def _configure_gateway(
        self,
        router_ns: str,
        server_ns: str,
        veth_host: str,
        veth_router_host: str,
        veth_router_server: str,
        veth_server: str,
        config: GatewayNetwork,
    ) -> None:
        host_v4, host_v6 = config.host_v4, config.host_v6
        router_host_v4, router_host_v6 = config.router_host_v4, config.router_host_v6
        router_server_v4, router_server_v6 = config.router_server_v4, config.router_server_v6
        server_v4, server_v6 = config.server_v4, config.server_v6
        if len({veth_router_host, veth_router_server, veth_server}) != 3:
            raise ValueError("gateway interfaces must have distinct names")
        # Validate the second pair too before creating either namespace.
        self._preflight((veth_router_server, veth_server), ())
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
            [
                resolve("ip"),
                "route",
                "add",
                str(ip_interface(server_v4).network),
                "via",
                host_rt_via,
                "dev",
                veth_host,
            ],
            veth_host,
        )
        self._create_owned_route(
            [
                resolve("ip"),
                "-6",
                "route",
                "add",
                str(ip_interface(server_v6).network),
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
