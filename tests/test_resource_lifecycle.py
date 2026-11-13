"""Real traffic, independent processes, SIGKILL and kernel ownership recovery."""

from __future__ import annotations

import asyncio
import multiprocessing
import os
import socket
import subprocess
import sys
from multiprocessing.connection import Connection
from pathlib import Path

import pytest

from nse.core import netns_controller, resource_registry
from nse.core.naming import derive_names
from nse.core.netns_controller import NetnsController
from nse.core.netns_controller import TestRun as Run
from nse.core.paths import resolve
from nse.core.pipeline import run_test_pipeline
from nse.core.resource_network import NetworkResources
from nse.models.test_request import PacketSpec, TestRequest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(os.geteuid() != 0, reason="requires root and real network namespaces"),
]


def _send(controller: NetnsController, name: str, address: str, port: int, payload: str) -> None:
    script = "import socket,sys; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(sys.argv[3].encode(),(sys.argv[1],int(sys.argv[2])))"
    subprocess.run(
        [*controller.exec_prefix(name), sys.executable, "-c", script, address, str(port), payload],
        capture_output=True,
        check=True,
        timeout=5,
    )


def _worker(
    runtime: str, name: str, number: int, pipe: Connection, crash_on_link: bool = False
) -> None:
    resource_registry.RUNTIME_DIR = Path(runtime)
    controller = NetnsController()
    controller.create_netns(name)
    if crash_on_link:
        original = netns_controller._run

        def crash(command: list[str], timeout: float = 10.0) -> subprocess.CompletedProcess[str]:
            result = original(command, timeout)
            if command[1:3] == ["link", "add"]:
                pipe.send("created before alias")
                os._exit(73)
            return result

        netns_controller._run = crash
    controller.create_veth_pair(
        name,
        f"vhr-{name}",
        f"vrh-{name}",
        f"198.18.{number}.1/24",
        f"198.18.{number}.2/24",
    )
    pipe.send("ready")
    try:
        while True:
            message = pipe.recv()
            if message == "stop":
                break
            port, payload = message
            _send(controller, name, f"198.18.{number}.1", port, payload)
            pipe.send("sent")
    finally:
        controller.cleanup_all()
        pipe.close()


def _message(pipe: Connection) -> object:
    assert pipe.poll(15), "worker did not reach the expected barrier"
    return pipe.recv()


def _traffic(pipe: Connection, receiver: socket.socket, payload: str) -> None:
    pipe.send((receiver.getsockname()[1], payload))
    assert _message(pipe) == "sent"
    assert receiver.recv(1024) == payload.encode()


@pytest.mark.parametrize("crash", [False, True], ids=["normal-close", "SIGKILL"])
def test_other_process_keeps_transferring_during_teardown_and_recovery(
    runtime_registry: Path, crash: bool
) -> None:
    context = multiprocessing.get_context("spawn")
    first_pipe, first_child = context.Pipe()
    second_pipe, second_child = context.Pipe()
    first = context.Process(target=_worker, args=(str(runtime_registry), "nse_a", 11, first_child))
    second = context.Process(
        target=_worker, args=(str(runtime_registry), "nse_b", 12, second_child)
    )
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
        receiver.bind(("0.0.0.0", 0))
        receiver.settimeout(5)
        try:
            first.start()
            assert _message(first_pipe) == "ready"
            _traffic(first_pipe, receiver, "A before B starts")
            second.start()
            assert _message(second_pipe) == "ready"
            _traffic(first_pipe, receiver, "A survives B startup")
            _traffic(second_pipe, receiver, "B before A closes")
            if crash:
                first.kill()
            else:
                first_pipe.send("stop")
            first.join(10)
            assert not first.is_alive()
            assert first.exitcode == (-9 if crash else 0)
            NetnsController()  # recover A; the live B owner lock must prevent deletion
            assert not Path("/var/run/netns/nse_a").exists()
            assert Path("/var/run/netns/nse_b").exists()
            interfaces = {link.ifname for link in NetworkResources(False).links(None)}
            assert "vhr-nse_a" not in interfaces
            assert "vhr-nse_b" in interfaces
            _traffic(second_pipe, receiver, "B survives A teardown and startup recovery")
            second_pipe.send("stop")
            second.join(10)
            assert second.exitcode == 0
        finally:
            for process in (first, second):
                if process.pid is not None:
                    if process.is_alive():
                        process.kill()
                    process.join(10)
            for pipe in (first_pipe, first_child, second_pipe, second_child):
                pipe.close()
            NetnsController()


def test_real_crash_after_atomic_pair_creation_before_alias(runtime_registry: Path) -> None:
    context = multiprocessing.get_context("spawn")
    pipe, child = context.Pipe()
    process = context.Process(
        target=_worker, args=(str(runtime_registry), "nse_c", 13, child, True)
    )
    try:
        process.start()
        assert _message(pipe) == "created before alias"
        process.join(10)
        assert process.exitcode == 73
        assert any(
            link.ifname == "vhr-nse_c" and not link.ifalias
            for link in NetworkResources(False).links(None)
        )
        NetnsController()
        assert not Path("/var/run/netns/nse_c").exists()
        assert not any(link.ifname == "vhr-nse_c" for link in NetworkResources(False).links(None))
    finally:
        if process.is_alive():
            process.kill()
        process.join(10)
        pipe.close()
        child.close()
        NetnsController()


def test_real_unregistered_prefix_resources_survive_startup() -> None:
    ip = resolve("ip")
    subprocess.run([ip, "netns", "add", "nse_legacy"], check=True, timeout=5)
    try:
        subprocess.run(
            [ip, "link", "add", "vhr-legacy", "type", "veth", "peer", "name", "vrh-legacy"],
            check=True,
            timeout=5,
        )
        try:
            NetnsController()
            assert Path("/var/run/netns/nse_legacy").exists()
            assert any(link.ifname == "vhr-legacy" for link in NetworkResources(False).links(None))
        finally:
            subprocess.run([ip, "link", "del", "vhr-legacy"], check=True, timeout=5)
    finally:
        subprocess.run([ip, "netns", "del", "nse_legacy"], check=True, timeout=5)


def test_failed_pipeline_cannot_delete_another_runs_host_link() -> None:
    names = derive_names("duplicate")
    first = NetnsController()
    second = NetnsController()
    try:
        first.create_netns(names.netns)
        first.create_veth_pair(
            names.netns, names.veth_host, "veth-nse", "198.18.14.1/24", "198.18.14.2/24"
        )
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
            receiver.bind(("198.18.14.1", 0))
            receiver.settimeout(5)
            port = receiver.getsockname()[1]
            _send(first, names.netns, "198.18.14.1", port, "before failed setup")
            assert receiver.recv(1024) == b"before failed setup"
            request = TestRequest(
                rules="table ip filter {}",
                packets=[
                    PacketSpec(
                        protocol="udp", src_ip="198.18.14.1", dst_ip="198.18.14.2", dst_port=53
                    )
                ],
            )
            events = asyncio.run(
                run_test_pipeline(
                    request,
                    controller=second,
                    run=Run(test_id="duplicate", netns_name=names.netns, request=request),
                )
            )
            assert any(event.type == "error" for event in events)
            _send(first, names.netns, "198.18.14.1", port, "survives failed setup")
            assert receiver.recv(1024) == b"survives failed setup"
    finally:
        first.cleanup_all()
        second.cleanup_all()
