"""Real simple/gateway topologies coexisting: dual stack traffic across setup, teardown and crash."""

from __future__ import annotations

import multiprocessing
import os
import socket
import subprocess
import sys
import threading
import time
import uuid
from multiprocessing.connection import Connection
from pathlib import Path

import pytest

from nse.core import resource_registry
from nse.core.naming import NETNS_SWEEP_PREFIXES, VETH_SWEEP_PREFIXES, derive_names
from nse.core.netns_controller import NetnsController
from nse.core.resource_network import NetworkResources
from nse.models.network_config import GatewayNetwork, SimpleNetwork
from nse.models.test_request import PacketSpec, TestRequest, TopologyType

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(os.geteuid() != 0, reason="requires root and real network namespaces"),
]

_SEND = (
    "import socket,sys; a=sys.argv[1]; "
    "s=socket.socket(socket.AF_INET6 if ':' in a else socket.AF_INET, socket.SOCK_DGRAM); "
    "s.sendto(sys.argv[3].encode(), (a, int(sys.argv[2])))"
)


def _network(mode: str, n: int) -> SimpleNetwork | GatewayNetwork:
    if mode == "simple":
        return SimpleNetwork(
            host_v4=f"198.18.{n}.1/24",
            peer_v4=f"198.18.{n}.2/24",
            host_v6=f"fd42:{n}::1/64",
            peer_v6=f"fd42:{n}::2/64",
        )
    return GatewayNetwork(
        host_v4=f"198.18.{n}.1/24",
        router_host_v4=f"198.18.{n}.2/24",
        router_server_v4=f"198.19.{n}.1/24",
        server_v4=f"198.19.{n}.2/24",
        host_v6=f"fd42:{n}:1::1/64",
        router_host_v6=f"fd42:{n}:1::2/64",
        router_server_v6=f"fd42:{n}:2::1/64",
        server_v6=f"fd42:{n}:2::2/64",
    )


def _test_id(mode: str, n: int) -> str:
    return f"{mode[0]}{n}"


def _worker(runtime: str, mode: str, n: int, pipe: Connection) -> None:
    resource_registry.RUNTIME_DIR = Path(runtime)
    controller = NetnsController()
    request = TestRequest(
        rules="table ip filter {}",
        packets=[PacketSpec(protocol="udp")],
        topology=TopologyType(mode),
        network=_network(mode, n),
    )
    names = derive_names(_test_id(mode, n))
    try:
        controller._setup_topology(names, request, uuid.uuid4().hex)
        # The sender lives behind the topology: in the gateway case the packet is routed.
        sender = names.netns if request.topology == TopologyType.SIMPLE else names.server_ns
        pipe.send("ready")
        while (message := pipe.recv()) != "stop":
            address, port, payload = message
            subprocess.run(
                [
                    *controller.exec_prefix(sender),
                    sys.executable,
                    "-c",
                    _SEND,
                    address,
                    str(port),
                    payload,
                ],
                capture_output=True,
                check=True,
                timeout=5,
            )
            pipe.send("sent")
    finally:
        controller.cleanup_all()
        pipe.close()


#: IP_FREEBIND / IPV6_FREEBIND (Linux): bind an address that is still tentative
#: (IPv6 DAD), so the receiver can be bound to the exact host address at once.
_FREEBIND = {
    socket.AF_INET: (socket.IPPROTO_IP, getattr(socket, "IP_FREEBIND", 15)),
    socket.AF_INET6: (socket.IPPROTO_IPV6, getattr(socket, "IPV6_FREEBIND", 78)),
}


def _bind_exact(host: str) -> socket.socket:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    receiver = socket.socket(family, socket.SOCK_DGRAM)
    try:
        receiver.setsockopt(*_FREEBIND[family], 1)
        receiver.bind((host, 0))
    except BaseException:
        receiver.close()
        raise
    return receiver


class _Receivers:
    """Root-namespace UDP endpoints for both families."""

    def __init__(self) -> None:
        self.sockets: dict[str, socket.socket] = {}
        self.lock = threading.Lock()

    def bound(self, host: str) -> socket.socket:
        """A receiver bound to exactly *host*, never to every interface."""
        receiver = self.sockets.get(host)
        if receiver is None:
            receiver = _bind_exact(host)
            receiver.settimeout(0.25)
            self.sockets[host] = receiver
        return receiver

    def close(self) -> None:
        for receiver in self.sockets.values():
            receiver.close()

    def exchange(self, pipe: Connection, mode: str, n: int, label: str) -> None:
        """Deliver one datagram per family from the run behind *pipe* to its host address.

        Retries absorb IPv6 DAD on the root-namespace side; the exact payload is
        required, so a datagram from the other run can never satisfy the check.
        """
        network = _network(mode, n)
        for address in (network.host_v4, network.host_v6):
            host = address.split("/")[0]
            payload = f"{label} {uuid.uuid4().hex}"
            deadline = time.monotonic() + 10
            with self.lock:
                receiver = self.bound(host)
                while True:
                    assert time.monotonic() < deadline, f"{label}: no delivery to {host}"
                    pipe.send((host, receiver.getsockname()[1], payload))
                    assert pipe.poll(10), f"{label}: worker did not answer"
                    assert pipe.recv() == "sent"
                    try:
                        while receiver.recv(1024).decode() != payload:
                            pass
                        break
                    except TimeoutError:
                        continue


class _Background:
    """Keep exchanging traffic for one run while the other run changes the kernel state."""

    def __init__(self, receivers: _Receivers, pipe: Connection, mode: str, n: int, label: str):
        self.stop = threading.Event()
        self.rounds = 0
        self.error: BaseException | None = None

        def loop() -> None:
            try:
                while not self.stop.is_set():
                    receivers.exchange(pipe, mode, n, label)
                    self.rounds += 1
            except Exception as exc:  # reported by finish()
                self.error = exc

        self.thread = threading.Thread(target=loop, daemon=True)
        self.thread.start()

    def finish(self) -> int:
        self.stop.set()
        self.thread.join(30)
        assert not self.thread.is_alive()
        if self.error is not None:
            raise self.error
        return self.rounds


def _ready(pipe: Connection, process: multiprocessing.process.BaseProcess) -> None:
    deadline = time.monotonic() + 30
    while not pipe.poll(0.2):
        assert process.is_alive(), f"worker exited during setup (exit code {process.exitcode})"
        assert time.monotonic() < deadline, "worker did not finish the topology setup"
    assert pipe.recv() == "ready"


def _names_of(mode: str, n: int) -> tuple[set[str], set[str]]:
    names = derive_names(_test_id(mode, n))
    if mode == "simple":
        return {names.netns}, {names.veth_host}
    return {names.router_ns, names.server_ns}, {names.veth_host}


def _kernel_state() -> tuple[set[str], set[str], set[str]]:
    resources = NetworkResources(False)
    namespaces = (
        {p.name for p in Path("/var/run/netns").glob("*")}
        if Path("/var/run/netns").exists()
        else set()
    )
    links = {link.ifname for link in resources.links(None) if link.ifname}
    routes = {route.dst for version in (4, 6) for route in resources.routes(version) if route.dst}
    return namespaces, links, routes


def _server_routes(mode: str, n: int) -> set[str]:
    network = _network(mode, n)
    if not isinstance(network, GatewayNetwork):
        return set()
    return {f"198.19.{n}.0/24", f"fd42:{n}:2::/64"}


@pytest.mark.parametrize("crash", [False, True], ids=["normal-close", "SIGKILL"])
@pytest.mark.parametrize(
    ("first_mode", "second_mode"),
    [("simple", "simple"), ("gateway", "gateway"), ("simple", "gateway"), ("gateway", "simple")],
)
def test_topologies_coexist_with_dual_stack_traffic(
    runtime_registry: Path, first_mode: str, second_mode: str, crash: bool
) -> None:
    context = multiprocessing.get_context("spawn")
    first_pipe, first_child = context.Pipe()
    second_pipe, second_child = context.Pipe()
    a, b = 21, 22
    first = context.Process(
        target=_worker, args=(str(runtime_registry), first_mode, a, first_child)
    )
    second = context.Process(
        target=_worker, args=(str(runtime_registry), second_mode, b, second_child)
    )
    receivers = _Receivers()
    try:
        first.start()
        _ready(first_pipe, first)
        receivers.exchange(first_pipe, first_mode, a, "A alone")

        # A keeps transferring while B creates namespaces, links and routes.
        during_setup = _Background(receivers, first_pipe, first_mode, a, "A during B setup")
        second.start()
        _ready(second_pipe, second)
        assert during_setup.finish() >= 1
        receivers.exchange(first_pipe, first_mode, a, "A after B setup")
        receivers.exchange(second_pipe, second_mode, b, "B with A active")

        # B keeps transferring while A is torn down or killed.
        during_close = _Background(receivers, second_pipe, second_mode, b, "B during A close")
        if crash:
            first.kill()
        else:
            first_pipe.send("stop")
        first.join(15)
        assert not first.is_alive()
        assert first.exitcode == (-9 if crash else 0)
        NetnsController()  # recovers A after a crash; B's live owner lock protects B
        assert during_close.finish() >= 1

        namespaces, links, routes = _kernel_state()
        a_namespaces, a_links = _names_of(first_mode, a)
        b_namespaces, b_links = _names_of(second_mode, b)
        assert not namespaces & a_namespaces
        assert not links & a_links
        assert not routes & _server_routes(first_mode, a)
        assert b_namespaces <= namespaces
        assert b_links <= links
        assert _server_routes(second_mode, b) <= routes
        receivers.exchange(second_pipe, second_mode, b, "B after A teardown and recovery")

        second_pipe.send("stop")
        second.join(15)
        assert second.exitcode == 0
        namespaces, links, routes = _kernel_state()
        assert not {n for n in namespaces if n.startswith(NETNS_SWEEP_PREFIXES)}
        assert not {link for link in links if link.startswith(VETH_SWEEP_PREFIXES)}
        assert not routes & (_server_routes(first_mode, a) | _server_routes(second_mode, b))
    finally:
        for process in (first, second):
            if process.pid is not None:
                if process.is_alive():
                    process.kill()
                process.join(10)
        for pipe in (first_pipe, first_child, second_pipe, second_child):
            pipe.close()
        receivers.close()
        NetnsController()


def test_overlapping_subnet_fails_before_touching_the_active_run(runtime_registry: Path) -> None:
    context = multiprocessing.get_context("spawn")
    pipe, child = context.Pipe()
    first = context.Process(target=_worker, args=(str(runtime_registry), "gateway", 23, child))
    receivers = _Receivers()
    try:
        first.start()
        _ready(pipe, first)
        before = _kernel_state()
        controller = NetnsController()
        clash = TestRequest(
            rules="table ip filter {}",
            packets=[PacketSpec(protocol="udp")],
            topology=TopologyType.SIMPLE,
            network=SimpleNetwork(
                host_v4="198.19.23.10/24",  # A's server subnet, routed on the host
                peer_v4="198.19.23.11/24",
                host_v6="fd42:99::1/64",
                peer_v6="fd42:99::2/64",
            ),
        )
        with pytest.raises(resource_registry.OwnershipError, match="conflicts with host route"):
            controller._setup_topology(derive_names("clash"), clash, uuid.uuid4().hex)
        assert _kernel_state() == before
        controller.cleanup_all()
        receivers.exchange(pipe, "gateway", 23, "A survives the rejected overlap")
        pipe.send("stop")
        first.join(15)
        assert first.exitcode == 0
    finally:
        if first.is_alive():
            first.kill()
        first.join(10)
        pipe.close()
        child.close()
        receivers.close()
        NetnsController()
