"""Managed processes in real network namespaces (root only)."""

from __future__ import annotations

import asyncio
import multiprocessing
import os
import shutil
import signal
import sys
import time
from multiprocessing.connection import Connection
from pathlib import Path

import pytest

from nse.core import resource_registry
from nse.core.mock_listener import ListenerStartError, start_listener
from nse.core.netns_controller import NetnsController
from nse.core.process import IdentityError, namespace_processes
from nse.core.utils import is_in_container
from nse.models.process import ProcessIdentity

pytestmark = [
    pytest.mark.integration,
    pytest.mark.asyncio,
    pytest.mark.skipif(os.geteuid() != 0, reason="requires root and real network namespaces"),
]

NOBODY = 65534
#: A system interpreter: the test virtualenv may not be readable by nobody.
SYSTEM_PYTHON = shutil.which("python3", path="/usr/bin:/bin")
BIND_80 = (
    "import socket; s = socket.socket(socket.AF_INET6); "
    "s.bind(('::', 80)); print('bound', flush=True)"
)


def _alive(pid: int) -> bool:
    try:
        state = Path(f"/proc/{pid}/stat").read_bytes().rsplit(b")", 1)[1].split()[0]
    except OSError:
        return False
    return state != b"Z"


def _start_time(pid: int) -> bytes | None:
    try:
        return Path(f"/proc/{pid}/stat").read_bytes().rsplit(b")", 1)[1].split()[19]
    except OSError:
        return None


@pytest.mark.parametrize("use_nsenter", [False, True], ids=["ip-netns-exec", "nsenter"])
async def test_root_process_identity_is_verified_in_the_namespace(
    runtime_registry: Path, use_nsenter: bool
) -> None:
    if not use_nsenter and is_in_container():
        pytest.skip("`ip netns exec` cannot remount /sys in this container; see nsenter")
    controller = NetnsController(use_nsenter=use_nsenter)
    async with controller.create_namespace("nse_proc_root") as ns:
        result = await ns.run_process(["ip", "-o", "link", "show"], timeout=10, check=True)
        assert result.identity.uids == (0, 0, 0, 0)
        assert "sys_admin" in result.identity.capabilities_effective
        assert ns.peer_iface.encode() in (result.stdout or b"")  # really inside
        assert ns.ext_iface.encode() not in (result.stdout or b"")


@pytest.mark.skipif(SYSTEM_PYTHON is None, reason="needs a system python3")
async def test_unprivileged_identity_with_one_capability(runtime_registry: Path) -> None:
    assert SYSTEM_PYTHON is not None
    controller = NetnsController()
    async with controller.create_namespace("nse_proc_nobody") as ns:
        allowed = await ns.run_process(
            [SYSTEM_PYTHON, "-c", BIND_80],
            identity=ProcessIdentity(uid=NOBODY, gid=NOBODY, capabilities={"net_bind_service"}),
            timeout=10,
        )
        assert allowed.ok, allowed.stderr
        assert allowed.stdout == b"bound\n"
        assert allowed.identity.uids == allowed.identity.gids == (NOBODY,) * 4
        assert allowed.identity.groups == ()
        assert allowed.identity.capabilities_effective == ("net_bind_service",)

        refused = await ns.run_process(
            [SYSTEM_PYTHON, "-c", BIND_80],
            identity=ProcessIdentity(uid=NOBODY, gid=NOBODY),
            timeout=10,
        )
        assert refused.returncode == 1
        assert b"PermissionError" in (refused.stderr or b"")
        assert refused.identity.capabilities_effective == ()
        assert refused.identity.capabilities_permitted == ()


async def test_root_with_reduced_capabilities_cannot_exceed_them(runtime_registry: Path) -> None:
    controller = NetnsController()
    async with controller.create_namespace("nse_proc_caps") as ns:
        result = await ns.run_process(
            ["ip", "link", "add", "nseproc0", "type", "dummy"],
            identity=ProcessIdentity(capabilities={"net_raw"}),
            timeout=10,
        )
        assert result.identity.uids == (0, 0, 0, 0)
        assert result.identity.capabilities_bounding == ("net_raw",)
        assert result.returncode != 0  # net_admin was not kept
        assert b"Operation not permitted" in (result.stderr or b"")


async def test_an_identity_that_cannot_be_verified_never_runs(
    runtime_registry: Path, tmp_path: Path
) -> None:
    witness = tmp_path / "ran"
    controller = NetnsController()
    async with controller.create_namespace("nse_proc_refuse") as ns:
        with pytest.MonkeyPatch.context() as patcher:
            from nse.core import process as process_module

            patcher.setattr(process_module, "_setpriv_args", lambda identity: [])
            with pytest.raises(IdentityError):
                await ns.start_process(
                    ["touch", str(witness)], identity=ProcessIdentity(uid=NOBODY, gid=NOBODY)
                )
    assert not witness.exists()


async def test_timeout_stops_a_process_with_children(runtime_registry: Path) -> None:
    controller = NetnsController()
    async with controller.create_namespace("nse_proc_timeout") as ns:
        netns = controller.namespace_identity(ns.name)
        assert netns is not None
        process = await ns.start_process(["/bin/sh", "-c", "sleep 60 & sleep 60 & wait"])
        deadline = time.monotonic() + 5
        while len(namespace_processes(netns)) < 3 and time.monotonic() < deadline:
            await asyncio.sleep(0.02)
        members = namespace_processes(netns)
        assert len(members) >= 3
        result = await process.wait(0.3, grace=1.0)
        assert result.termination == "timeout"
        assert not [pid for pid in members if _alive(pid)]
        assert namespace_processes(netns) == []


async def test_teardown_stops_detached_descendants_and_spares_other_runs(
    runtime_registry: Path,
) -> None:
    controller = NetnsController()
    async with controller.create_namespace("nse_proc_other") as other:
        other_netns = controller.namespace_identity(other.name)
        assert other_netns is not None
        bystander = await other.start_process(["sleep", "60"])
        async with controller.create_namespace(
            "nse_proc_detach",
            host_ip=["198.18.31.1/24", "fd42:31::1/64"],
            peer_ip=["198.18.31.2/24", "fd42:31::2/64"],
        ) as ns:
            netns = controller.namespace_identity(ns.name)
            assert netns is not None
            launcher = await ns.start_process(["/bin/sh", "-c", "setsid sleep 60 & echo ok"])
            assert (await launcher.wait(10)).termination == "exited"
            deadline = time.monotonic() + 5
            while not namespace_processes(netns) and time.monotonic() < deadline:
                await asyncio.sleep(0.02)
            detached = namespace_processes(netns)
            assert len(detached) == 1  # outside any managed group, inside the namespace
        assert not _alive(detached[0])
        assert bystander.returncode is None  # another run's process is untouched
        assert namespace_processes(other_netns) == [bystander.pid]


def _crashing_owner(runtime: str, pipe: Connection) -> None:
    resource_registry.RUNTIME_DIR = Path(runtime)

    async def main() -> None:
        controller = NetnsController()
        async with controller.create_namespace("nse_proc_crash") as ns:
            process = await ns.start_process(["/bin/sh", "-c", "setsid sleep 300 & wait"])
            netns = controller.namespace_identity(ns.name)
            assert netns is not None
            deadline = time.monotonic() + 5
            while len(namespace_processes(netns)) < 2 and time.monotonic() < deadline:
                await asyncio.sleep(0.02)
            pipe.send((process.pid, namespace_processes(netns)))
            await asyncio.sleep(300)

    asyncio.run(main())


async def test_recovery_after_a_crash_stops_what_the_dead_owner_left(
    runtime_registry: Path,
) -> None:
    context = multiprocessing.get_context("spawn")
    parent, child = context.Pipe()
    owner = context.Process(target=_crashing_owner, args=(str(runtime_registry), child))
    owner.start()
    try:
        assert parent.poll(30), "owner did not start its processes"
        leader, members = parent.recv()
        assert leader in members
        assert len(members) >= 2
        started = {pid: _start_time(pid) for pid in members}
        owner.kill()
        owner.join(10)
        assert all(_alive(pid) for pid in members)  # orphaned, still running
        NetnsController()  # startup recovery of the dead owner's journal
        assert not Path("/var/run/netns/nse_proc_crash").exists()
        # Gone, or the PID now belongs to a different process (different start time).
        assert all(not _alive(pid) or _start_time(pid) != started[pid] for pid in members)
    finally:
        if owner.is_alive():
            owner.kill()
            owner.join(10)
        parent.close()
        child.close()
        NetnsController()


async def test_listener_bind_failure_is_distinguished(runtime_registry: Path) -> None:
    controller = NetnsController()
    async with controller.create_namespace("nse_proc_listen") as ns:
        netns = controller.namespace_identity(ns.name)
        assert netns is not None
        prefix = controller.exec_prefix(ns.name)
        first = await start_listener(prefix, netns, "tcp", 8080)
        try:
            with pytest.raises(ListenerStartError) as caught:
                await start_listener(prefix, netns, "tcp", 8080)
            assert b"Address already in use" in caught.value.stderr
        finally:
            await first.terminate()
        # The same port is free again once the first listener is stopped.
        again = await start_listener(prefix, netns, "tcp", 8080)
        await again.terminate()


async def test_a_sigterm_ignoring_process_is_killed(runtime_registry: Path) -> None:
    controller = NetnsController()
    async with controller.create_namespace("nse_proc_stubborn") as ns:
        process = await ns.start_process(
            [
                sys.executable,
                "-c",
                "import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); print('ready', flush=True); time.sleep(60)",
            ]
        )
        await process.wait_for_output(b"ready", timeout=10)
        result = await process.terminate(grace=0.3)
        assert result.returncode == -signal.SIGKILL
