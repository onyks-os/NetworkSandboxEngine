"""Managed processes without privileges.

The namespace prefix is empty, so the launch chain (probe, identity check, exec)
runs for real. Namespace membership is simulated: a process belongs to the fake
namespace FAKE when its environment carries this test's token, which every
descendant inherits, including one that detaches with setsid. The privileged
tests check the real boundary.
"""

from __future__ import annotations

import asyncio
import contextlib
import errno
import json
import os
import signal
import socket
import subprocess
import sys
import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from nse.core import process as process_module
from nse.core.process import (
    IdentityError,
    ProcessExitedError,
    ProcessStartError,
    ProtectedNamespaceError,
    namespace_processes,
    signal_namespace,
    spawn_process,
    terminate_namespace,
)
from nse.models.process import (
    EffectiveIdentity,
    ProcessIdentity,
    ProcessResult,
    capability_names,
)

pytestmark = pytest.mark.asyncio

FAKE = (0, 424242)


@pytest.fixture
def sandbox_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, str]]:
    """Environment whose carriers count as members of the FAKE namespace."""
    token = f"NSE_TEST_NETNS={uuid.uuid4().hex}".encode()
    real = process_module._netns_of

    def netns_of(pid: int) -> tuple[int, int] | None:
        try:
            if token in Path(f"/proc/{pid}/environ").read_bytes().split(b"\0"):
                return FAKE
        except OSError:
            return None
        return real(pid)

    monkeypatch.setattr(process_module, "_netns_of", netns_of)
    key, value = token.decode().split("=")
    env = {**os.environ, key: value}
    yield env
    leftovers = namespace_processes(FAKE)
    described = [_describe(pid) for pid in leftovers]  # before they are killed
    for pid in leftovers:
        os.kill(pid, signal.SIGKILL)
    assert not leftovers, f"test left processes behind: {described}"


def _describe(pid: int) -> str:
    """What a leftover process is: enough to tell a leak from one still dying."""
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
        cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").strip()
    except OSError as exc:
        return f"{pid} (gone: {exc})"
    fields = stat[stat.rindex(")") + 2 :].split()  # after "pid (comm) "
    state, ppid, pgid = fields[0], fields[1], fields[2]
    return f"{pid} state={state} ppid={ppid} pgid={pgid} own_pid={os.getpid()} cmd={cmdline!r}"


def _alive(pid: int) -> bool:
    try:
        state = Path(f"/proc/{pid}/stat").read_bytes().rsplit(b")", 1)[1].split()[0]
    except OSError:
        return False
    return state != b"Z"


def _wait_for(condition: Any, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.02)
    return bool(condition())


async def _spawn(argv: list[str], env: dict[str, str], **options: Any) -> Any:
    return await spawn_process([], argv, netns=FAKE, env=env, **options)


# --------------------------------------------------------------------------- models


async def test_identity_defaults_mean_unchanged() -> None:
    identity = ProcessIdentity()
    assert not identity.requested
    assert identity.effective_groups is None
    assert process_module._setpriv_args(identity) == []


async def test_identity_validation() -> None:
    with pytest.raises(ValueError, match="explicit gid"):
        ProcessIdentity(uid=1000)
    with pytest.raises(ValueError, match="unknown capability"):
        ProcessIdentity(capabilities={"net_teleport"})
    with pytest.raises(ValueError, match="not one string"):
        ProcessIdentity(capabilities="net_raw")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="not a name"):
        ProcessIdentity(capabilities={3})  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="non-negative"):
        ProcessIdentity(groups=(-1,))
    with pytest.raises(ValueError):
        ProcessIdentity(uid=-1, gid=0)
    with pytest.raises(ValueError):
        ProcessIdentity(shell=True)  # type: ignore[call-arg]
    assert ProcessIdentity(uid=0).gid is None  # root keeps its group only by request
    assert ProcessIdentity(capabilities={"CAP_NET_RAW", "net_admin"}).capabilities == {
        "net_raw",
        "net_admin",
    }
    assert ProcessIdentity(groups=(5, 3, 5)).groups == (3, 5)


async def test_setpriv_arguments() -> None:
    args = process_module._setpriv_args(
        ProcessIdentity(
            uid=1000,
            gid=1000,
            capabilities={"net_raw", "net_bind_service"},
            no_new_privileges=True,
        )
    )
    caps = "-all,+net_bind_service,+net_raw"
    assert args == [
        "--reuid=1000",
        "--regid=1000",
        "--clear-groups",  # a uid change never keeps root's supplementary groups
        f"--inh-caps={caps}",
        f"--ambient-caps={caps}",
        f"--bounding-set={caps}",
        "--no-new-privs",
    ]
    assert process_module._setpriv_args(ProcessIdentity(gid=5, groups=(7, 8))) == [
        "--regid=5",
        "--groups=7,8",
    ]
    assert process_module._setpriv_args(ProcessIdentity(capabilities=set())) == [
        "--inh-caps=-all",
        "--ambient-caps=-all",
        "--bounding-set=-all",
    ]


STATUS = """Name:\tsh
Uid:\t65534\t65534\t65534\t65534
Gid:\t65534\t65534\t65534\t65534
Groups:\t
CapInh:\t0000000000000400
CapPrm:\t0000000000000400
CapEff:\t0000000000000400
CapBnd:\t0000000000000400
CapAmb:\t0000000000000400
NoNewPrivs:\t1
"""


async def test_effective_identity_is_parsed_from_proc_status() -> None:
    observed = EffectiveIdentity.from_status(STATUS)
    assert observed.uids == observed.gids == (65534,) * 4
    assert observed.groups == ()
    assert observed.capabilities_effective == ("net_bind_service",)
    assert observed.no_new_privileges
    wanted = ProcessIdentity(
        uid=65534, gid=65534, capabilities={"net_bind_service"}, no_new_privileges=True
    )
    assert observed.mismatches(wanted) == []
    with pytest.raises(ValueError, match="lacks 'CapAmb'"):
        EffectiveIdentity.from_status(STATUS.replace("CapAmb", "Other"))
    with pytest.raises(ValueError, match="expected 4 ids"):
        EffectiveIdentity.from_status(STATUS.replace("Uid:\t65534\t", "Uid:\t"))


async def test_every_kind_of_mismatch_is_reported() -> None:
    observed = EffectiveIdentity.from_status(STATUS.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0"))
    problems = observed.mismatches(
        ProcessIdentity(
            uid=1000, gid=1000, groups=(4,), capabilities={"net_raw"}, no_new_privileges=True
        )
    )
    assert len(problems) == 8  # uid, gid, groups, 4 capability sets, no_new_privs
    # A non-root process that asked for no capabilities must hold none.
    assert observed.mismatches(ProcessIdentity()) == [
        "non-root process holds capabilities ('net_bind_service',)"
    ]


async def test_capability_names_cover_unknown_bits() -> None:
    assert capability_names(0) == ()
    assert capability_names(1 << 12 | 1) == ("chown", "net_admin")
    assert capability_names(1 << 50) == ("cap_50",)


# --------------------------------------------------------------------------- running


async def test_a_process_runs_with_literal_arguments_and_a_recorded_identity(
    sandbox_env: dict[str, str],
) -> None:
    argv = [sys.executable, "-c", "import sys; print(sys.argv[1:])", "a b", "$HOME", ""]
    process = await _spawn(argv, sandbox_env)
    result = await process.wait(10)
    assert result.ok
    assert result.termination == "exited"
    assert result.stdout == b"['a b', '$HOME', '']\n"
    assert result.argv == argv
    assert result.command[-len(argv) :] == argv
    assert result.identity.uids == (os.getuid(),) * 4  # unchanged, but verified and recorded
    assert result.started_at <= result.ended_at
    assert await process.wait() is result  # one result, however often asked
    assert await process.terminate() is result
    assert process.returncode == 0


async def test_failure_and_check(sandbox_env: dict[str, str]) -> None:
    process = await _spawn(
        [sys.executable, "-c", "import sys; sys.stderr.write('bad'); sys.exit(3)"], sandbox_env
    )
    result = await process.wait(10)
    assert not result.ok
    assert result.returncode == 3
    assert result.stderr == b"bad"
    with pytest.raises(subprocess.CalledProcessError) as caught:
        result.check()
    assert caught.value.returncode == 3
    assert caught.value.stderr == b"bad"
    assert json.loads(result.model_dump_json())["stderr"] == "YmFk"  # base64, never lossy


async def test_a_missing_program_is_a_start_error(sandbox_env: dict[str, str]) -> None:
    with pytest.raises(ProcessStartError) as caught:
        await _spawn(["nse-no-such-program"], sandbox_env)
    assert caught.value.reason == "program_not_found"


async def test_a_failing_launch_chain_is_reported_with_its_stderr(
    sandbox_env: dict[str, str],
) -> None:
    prefix = ["/bin/sh", "-c", "echo 'setpriv: cannot apply' >&2; exit 1", "chain"]
    with pytest.raises(ProcessStartError) as caught:
        await spawn_process(prefix, ["true"], netns=FAKE, env=sandbox_env)
    assert caught.value.reason == "launch_failed"
    assert b"cannot apply" in caught.value.stderr
    assert "cannot apply" in str(caught.value)


async def test_a_launch_chain_that_never_reports_times_out_and_is_stopped(
    sandbox_env: dict[str, str],
) -> None:
    prefix = ["/bin/sh", "-c", "sleep 30", "chain"]
    began = time.monotonic()
    with pytest.raises(ProcessStartError) as caught:
        await spawn_process(prefix, ["true"], netns=FAKE, env=sandbox_env, start_timeout=0.3)
    assert caught.value.reason == "timeout"
    assert time.monotonic() - began < 5


async def test_cancelling_the_start_leaves_nothing_running(sandbox_env: dict[str, str]) -> None:
    prefix = ["/bin/sh", "-c", "sleep 30", "chain"]
    task = asyncio.ensure_future(spawn_process(prefix, ["true"], netns=FAKE, env=sandbox_env))
    assert await asyncio.to_thread(_wait_for, lambda: bool(namespace_processes(FAKE)))
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, timeout=10)


async def test_a_cancel_while_the_child_is_created_stops_what_it_started(
    sandbox_env: dict[str, str],
) -> None:
    """The child exists before creation returns. A cancel in that window must
    stop its whole group, not only the leader asyncio would kill."""
    real = asyncio.create_subprocess_exec
    created = asyncio.Event()
    release = asyncio.Event()

    async def slow_create(*args: Any, **kwargs: Any) -> asyncio.subprocess.Process:
        proc = await real(*args, **kwargs)
        try:
            created.set()
            await release.wait()
        except asyncio.CancelledError:
            proc.kill()  # what asyncio does to a transport whose creation is cancelled
            await proc.wait()
            raise
        return proc

    # `; :` makes the shell fork sleep instead of becoming it, as dash does.
    prefix = ["/bin/sh", "-c", "sleep 30; :", "chain"]
    with patch.object(asyncio, "create_subprocess_exec", slow_create):
        task = asyncio.ensure_future(spawn_process(prefix, ["true"], netns=FAKE, env=sandbox_env))
        await asyncio.wait_for(created.wait(), 10)
        assert await asyncio.to_thread(_wait_for, lambda: len(namespace_processes(FAKE)) == 2)
        task.cancel()
        asyncio.get_running_loop().call_later(0.2, release.set)
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=10)
    assert namespace_processes(FAKE) == []


async def test_a_cancelled_creation_that_failed_has_nothing_to_stop(
    sandbox_env: dict[str, str],
) -> None:
    release = asyncio.Event()

    async def failing_create(*args: Any, **kwargs: Any) -> asyncio.subprocess.Process:
        await release.wait()
        raise OSError("fork failed")

    with patch.object(asyncio, "create_subprocess_exec", failing_create):
        task = asyncio.ensure_future(spawn_process(["true"], ["true"], netns=FAKE, env=sandbox_env))
        await asyncio.sleep(0.05)
        task.cancel()
        asyncio.get_running_loop().call_later(0.05, release.set)
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=10)


async def test_an_identity_mismatch_never_runs_the_application(
    sandbox_env: dict[str, str], tmp_path: Path
) -> None:
    witness = tmp_path / "ran"
    # setpriv would set no_new_privs; dropping the option makes the kernel
    # report an identity other than the one requested.
    with (
        patch.object(process_module, "_setpriv_args", lambda identity: []),
        pytest.raises(IdentityError) as caught,
    ):
        await _spawn(
            ["touch", str(witness)], sandbox_env, identity=ProcessIdentity(no_new_privileges=True)
        )
    assert caught.value.reason == "identity_mismatch"
    assert caught.value.problems == ["no_new_privs is not set"]
    assert caught.value.observed is not None
    assert not witness.exists()


async def test_no_new_privileges_is_applied_and_verified(sandbox_env: dict[str, str]) -> None:
    process = await _spawn(
        ["cat", "/proc/self/status"], sandbox_env, identity=ProcessIdentity(no_new_privileges=True)
    )
    result = await process.wait(10)
    assert result.identity.no_new_privileges
    assert b"NoNewPrivs:\t1" in (result.stdout or b"")


async def test_an_unsupported_capability_is_refused_before_starting() -> None:
    with (
        patch.object(process_module, "_cap_last_cap", lambda: 39),
        pytest.raises(ProcessStartError) as caught,
    ):
        await spawn_process(
            [], ["true"], netns=FAKE, identity=ProcessIdentity(capabilities={"checkpoint_restore"})
        )
    assert caught.value.reason == "identity_unsupported"


async def test_invalid_arguments_are_rejected_before_anything_starts() -> None:
    with pytest.raises(TypeError):
        await spawn_process([], "echo hi", netns=FAKE)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="non-negative"):
        await spawn_process([], ["true"], netns=FAKE, max_output_bytes=-1)


# --------------------------------------------------------------------------- stopping


TREE = """
sleep 60 &
setsid sleep 60 &
trap '' TERM
while :; do sleep 0.05; done
"""


async def test_timeout_stops_the_process_and_its_group(sandbox_env: dict[str, str]) -> None:
    process = await _spawn(["/bin/sh", "-c", "sleep 60 & sleep 60 & wait"], sandbox_env)
    assert _wait_for(lambda: len(namespace_processes(FAKE, pgid=process.pid)) >= 3)
    children = namespace_processes(FAKE, pgid=process.pid)
    result = await process.wait(0.2, grace=1.0)
    assert result.termination == "timeout"
    assert result.returncode == -signal.SIGTERM
    assert not [pid for pid in children if _alive(pid)]


async def test_sigterm_is_escalated_to_sigkill(sandbox_env: dict[str, str]) -> None:
    process = await _spawn(["/bin/sh", "-c", TREE], sandbox_env)
    assert _wait_for(lambda: len(namespace_processes(FAKE)) >= 3)
    began = time.monotonic()
    result = await process.terminate(grace=0.3)
    assert result.termination == "terminated"
    assert result.returncode == -signal.SIGKILL
    assert time.monotonic() - began < 5
    # The process group is gone; the descendant that left it with setsid is
    # still in the namespace, and that is where the namespace sweep finds it.
    detached = namespace_processes(FAKE)
    assert len(detached) == 1
    assert terminate_namespace(FAKE, grace=0.3) == []
    assert not namespace_processes(FAKE)


async def test_cancellation_stops_the_process(sandbox_env: dict[str, str]) -> None:
    process = await _spawn(["/bin/sh", "-c", "sleep 60 & wait"], sandbox_env)
    task = asyncio.ensure_future(process.wait())
    await asyncio.sleep(0.1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, timeout=10)
    result = await process.wait()
    assert result.termination == "cancelled"
    assert not namespace_processes(FAKE)


async def test_async_with_terminates(sandbox_env: dict[str, str]) -> None:
    async with await _spawn(["sleep", "60"], sandbox_env) as process:
        assert process.returncode is None
    assert (await process.wait()).termination == "terminated"


async def test_a_natural_exit_leaves_the_group_to_the_namespace_teardown(
    sandbox_env: dict[str, str],
) -> None:
    process = await _spawn(["/bin/sh", "-c", "sleep 60 & echo started"], sandbox_env)
    result = await process.wait(10)
    assert result.termination == "exited"
    assert result.stdout == b"started\n"
    assert not result.output_complete  # the background sleep still holds stdout
    assert len(namespace_processes(FAKE)) == 1
    assert terminate_namespace(FAKE, grace=0.5) == []


# --------------------------------------------------------------------------- output


async def test_captured_output_is_bounded(sandbox_env: dict[str, str]) -> None:
    process = await _spawn(
        [sys.executable, "-c", "import sys; sys.stdout.write('x' * 3000)"],
        sandbox_env,
        max_output_bytes=1000,
    )
    result = await process.wait(10)
    assert result.stdout == b"x" * 1000
    assert result.stdout_dropped == 2000
    assert result.output_complete


async def test_output_to_files_and_discarded(sandbox_env: dict[str, str], tmp_path: Path) -> None:
    out = tmp_path / "out.log"
    process = await _spawn(
        ["/bin/sh", "-c", "echo to-file; echo dropped >&2"],
        sandbox_env,
        stdout=out,
        stderr="discard",
    )
    result = await process.wait(10)
    assert out.read_bytes() == b"to-file\n"
    assert out.stat().st_mode & 0o777 == 0o600  # output may hold secrets
    assert result.stdout is None
    assert result.stdout_path == str(out)
    assert result.stderr is None
    with pytest.raises(ValueError, match="not captured"):
        process.output("stdout")
    with pytest.raises(FileExistsError):  # an existing artifact is never overwritten
        await _spawn(["true"], sandbox_env, stdout=out)


async def test_readiness_by_explicit_output(sandbox_env: dict[str, str]) -> None:
    process = await _spawn(
        [
            sys.executable,
            "-u",
            "-c",
            "import time; time.sleep(0.2); print('READY'); time.sleep(60)",
        ],
        sandbox_env,
    )
    await process.wait_for_output(b"READY", timeout=10)
    assert process.output() == b"READY\n"
    await process.terminate()


async def test_a_process_that_exits_before_readiness_is_reported(
    sandbox_env: dict[str, str],
) -> None:
    process = await _spawn(
        [sys.executable, "-c", "import sys; sys.stderr.write('bind failed'); sys.exit(1)"],
        sandbox_env,
    )
    with pytest.raises(ProcessExitedError) as caught:
        await process.wait_for_output(b"READY", timeout=10)
    assert caught.value.result.returncode == 1
    assert caught.value.result.stderr == b"bind failed"


async def test_readiness_output_printed_just_before_exit_still_counts(
    sandbox_env: dict[str, str],
) -> None:
    process = await _spawn(["/bin/sh", "-c", "echo READY"], sandbox_env)
    await process.wait(10)
    await process.wait_for_output(b"READY", timeout=1)


async def test_readiness_timeout_leaves_the_process_running(sandbox_env: dict[str, str]) -> None:
    process = await _spawn(["sleep", "60"], sandbox_env, stderr="discard")
    with pytest.raises(TimeoutError):
        await process.wait_for_output(b"READY", timeout=0.2)
    assert process.returncode is None
    with pytest.raises(ValueError, match="not captured"):
        await process.wait_for_output(b"x", timeout=1, stream="stderr")
    await process.terminate()


# --------------------------------------------------------------------------- the namespace boundary


async def test_nse_own_namespace_is_never_swept() -> None:
    own = process_module._netns_of(os.getpid())
    assert own is not None
    with pytest.raises(ProtectedNamespaceError):
        namespace_processes(own)
    with pytest.raises(ProtectedNamespaceError):
        terminate_namespace(own)


async def test_an_empty_namespace_is_a_no_op() -> None:
    assert terminate_namespace(FAKE) == []
    assert signal_namespace(FAKE, signal.SIGTERM) == 0


async def test_a_recycled_pid_is_never_signalled(sandbox_env: dict[str, str]) -> None:
    """Membership is checked after the pidfd pins the process."""
    stranger = subprocess.Popen(["sleep", "60"])
    try:
        assert not process_module._send(stranger.pid, FAKE, signal.SIGKILL, None)
        assert stranger.poll() is None
    finally:
        stranger.kill()
        stranger.wait()
    assert not process_module._send(stranger.pid, FAKE, signal.SIGKILL, None)  # gone


async def test_signalling_without_pidfd_checks_the_start_time(
    sandbox_env: dict[str, str],
) -> None:
    member = subprocess.Popen(["sleep", "60"], env=sandbox_env)
    try:
        with patch.object(
            process_module, "pidfd_open", MagicMock(side_effect=OSError(errno.ENOSYS, "nosys"))
        ):
            stranger = subprocess.Popen(["sleep", "60"])
            try:
                assert not process_module._send(stranger.pid, FAKE, signal.SIGKILL, None)
            finally:
                stranger.kill()
                stranger.wait()
            reused: list[list[bytes] | None] = [[b"S"] * 20, [b"S"] * 19 + [b"other-start"]]
            with patch.object(process_module, "_stat_fields", lambda pid: reused.pop(0)):
                assert not process_module._send(member.pid, FAKE, signal.SIGKILL, None)
            assert member.poll() is None
            assert process_module._send(member.pid, FAKE, signal.SIGKILL, None)
        assert member.wait(5) == -signal.SIGKILL
    finally:
        if member.poll() is None:
            member.kill()
            member.wait()
    with patch.object(
        process_module, "pidfd_open", MagicMock(side_effect=OSError(errno.EPERM, "denied"))
    ):
        assert not process_module._send(os.getpid(), FAKE, signal.SIGKILL, None)


async def test_survivors_are_reported(sandbox_env: dict[str, str]) -> None:
    with (
        patch.object(process_module, "namespace_processes", lambda netns, pgid=None: [123]),
        patch.object(process_module, "signal_namespace", lambda *a, **k: 1),
    ):
        assert terminate_namespace(FAKE, grace=0.05, timeout=0.05) == [123]


async def test_process_group_filter(sandbox_env: dict[str, str]) -> None:
    process = await _spawn(["/bin/sh", "-c", "setsid sleep 60 & sleep 60"], sandbox_env)
    assert _wait_for(lambda: len(namespace_processes(FAKE)) >= 3)
    in_group = namespace_processes(FAKE, pgid=process.pid)
    assert process.pid in in_group
    assert len(namespace_processes(FAKE)) == len(in_group) + 1
    await process.terminate(grace=0.5)
    assert terminate_namespace(FAKE, grace=0.5) == []


async def test_result_model_is_frozen() -> None:
    identity = EffectiveIdentity.from_status(STATUS)
    result = ProcessResult(
        argv=["x"],
        command=["x"],
        pid=1,
        identity=identity,
        termination="exited",
        returncode=0,
        started_at=0,
        ended_at=1,
    )
    assert result.ok
    with pytest.raises(ValueError):
        result.returncode = 1  # type: ignore[misc]


async def test_pidfd_works_with_and_without_the_python_wrappers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    child = subprocess.Popen(["sleep", "60"])
    try:
        # The raw syscalls, as on Python builds without os.pidfd_open.
        monkeypatch.delattr(os, "pidfd_open", raising=False)
        monkeypatch.delattr(signal, "pidfd_send_signal", raising=False)
        fd = process_module.pidfd_open(child.pid)
        try:
            process_module.pidfd_send_signal(fd, 0)
        finally:
            os.close(fd)
        with pytest.raises(ProcessLookupError):
            process_module.pidfd_open(2**22 + 1)  # above pid_max: no such process
        # The wrappers, when the build has them.
        calls: list[Any] = []
        monkeypatch.setattr(os, "pidfd_open", lambda pid: calls.append(pid) or 99, raising=False)
        monkeypatch.setattr(
            signal, "pidfd_send_signal", lambda fd, sig: calls.append((fd, sig)), raising=False
        )
        assert process_module.pidfd_open(child.pid) == 99
        process_module.pidfd_send_signal(99, 0)
        assert calls == [child.pid, (99, 0)]
    finally:
        child.kill()
        child.wait()


# --------------------------------------------------------------------------- mock listeners


async def test_a_listener_is_ready_only_once_it_has_bound() -> None:
    from nse.core.mock_listener import start_listener

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    listener = await start_listener([], FAKE, "TCP", port, host="127.0.0.1")
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
            client.sendall(b"echo")
            assert client.recv(4) == b"echo"
    finally:
        assert (await listener.terminate()).termination == "terminated"


async def test_a_listener_that_cannot_bind_is_a_listener_start_error() -> None:
    from nse.core.mock_listener import ListenerStartError, start_listener

    with socket.socket() as taken:
        taken.bind(("127.0.0.1", 0))
        taken.listen()
        port = taken.getsockname()[1]
        with pytest.raises(ListenerStartError) as caught:
            await start_listener([], FAKE, "tcp", port, host="127.0.0.1")
    assert caught.value.proto == "tcp"
    assert caught.value.port == port
    assert "before it was bound" in str(caught.value)
    assert b"Address already in use" in caught.value.stderr


async def test_a_listener_that_never_confirms_is_stopped() -> None:
    from nse.core import mock_listener

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    with (
        patch.object(mock_listener, "READY_MARKER", b"never printed"),
        pytest.raises(mock_listener.ListenerStartError, match="did not confirm"),
    ):
        await mock_listener.start_listener([], FAKE, "udp", port, host="127.0.0.1", timeout=0.5)
    # The udp port is free again: the listener was stopped, not abandoned.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as again:
        again.bind(("127.0.0.1", port))


async def test_cancelling_a_listener_start_stops_it() -> None:
    from nse.core import mock_listener

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    with patch.object(mock_listener, "READY_MARKER", b"never printed"):
        task = asyncio.ensure_future(
            mock_listener.start_listener([], FAKE, "tcp", port, host="127.0.0.1", timeout=30)
        )
        await asyncio.sleep(1.0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=10)
    with socket.socket() as again:
        again.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        again.bind(("127.0.0.1", port))


# --------------------------------------------------------------------------- sandbox and controller


def _sandbox(env: dict[str, str] | None = None, identity: Any = FAKE) -> Any:
    from nse.core.netns_controller import NamespaceSandbox

    controller = MagicMock()
    controller.namespace_identity.return_value = identity
    controller.exec_prefix.return_value = (
        [] if env is None else ["/usr/bin/env", *(f"{k}={v}" for k, v in env.items())]
    )
    return NamespaceSandbox(controller, "nse_x")


async def test_sandbox_runs_and_registers_processes(sandbox_env: dict[str, str]) -> None:
    sandbox = _sandbox(sandbox_env)
    result = await sandbox.run_process(["/bin/sh", "-c", "echo hi"], timeout=10)
    assert result.ok
    assert result.stdout == b"hi\n"
    with pytest.raises(subprocess.CalledProcessError):
        await sandbox.run_process(["/bin/sh", "-c", "exit 4"], timeout=10, check=True)
    timed_out = await sandbox.run_process(["sleep", "60"], timeout=0.2, grace=0.5)
    assert timed_out.termination == "timeout"

    running = await sandbox.start_process(["sleep", "60"])
    assert running in sandbox._processes
    await sandbox._stop_processes()
    assert (await running.wait()).termination == "terminated"
    assert sandbox._processes == []


async def test_a_failed_stop_is_logged_not_raised(
    sandbox_env: dict[str, str], caplog: pytest.LogCaptureFixture
) -> None:
    sandbox = _sandbox(sandbox_env)
    process = await sandbox.start_process(["sleep", "60"])
    with patch.object(process, "terminate", side_effect=OSError("gone")):
        await sandbox._stop_processes()
    assert "failed: gone" in caplog.text
    await process.terminate()


async def test_a_missing_namespace_cannot_start_processes() -> None:
    from nse.core.resource_registry import OwnershipError

    with pytest.raises(OwnershipError, match="does not exist"):
        await _sandbox(identity=None).start_process(["true"])


async def test_deleting_a_namespace_stops_what_runs_inside(
    resource_kernel: None, caplog: pytest.LogCaptureFixture
) -> None:
    from nse.core import netns_controller
    from nse.core.netns_controller import NetnsController

    with patch.object(NetnsController, "startup_sweep", lambda self: None):
        controller = NetnsController(use_nsenter=False)
    swept: list[Any] = []
    with (
        patch.object(netns_controller, "_run"),
        patch.object(
            netns_controller, "terminate_namespace", lambda netns: swept.append(netns) or [4242]
        ),
    ):
        assert controller._delete_namespace("nse_x")
    assert swept == [(1, 1)]  # the identity resource_kernel reports
    assert "survived SIGKILL" in caplog.text

    def refuse(netns: Any) -> list[int]:
        raise ProtectedNamespaceError("host namespace")

    with (
        patch.object(netns_controller, "_run") as run,
        patch.object(netns_controller, "terminate_namespace", refuse),
    ):
        assert not controller._delete_namespace("nse_x")  # never deleted, never swept
    run.assert_not_called()


async def test_an_unreadable_identity_report_is_a_launch_failure(
    sandbox_env: dict[str, str],
) -> None:
    # The handshake is the chain's stdin: write something that is not a report.
    prefix = ["/bin/sh", "-c", 'printf "not a status\\n" >&0; exit 1', "chain"]
    with pytest.raises(ProcessStartError) as caught:
        await spawn_process(prefix, ["true"], netns=FAKE, env=sandbox_env)
    assert caught.value.reason == "launch_failed"


async def test_stderr_to_a_file(sandbox_env: dict[str, str], tmp_path: Path) -> None:
    err = tmp_path / "err.log"
    process = await _spawn(["/bin/sh", "-c", "echo oops >&2"], sandbox_env, stderr=err)
    result = await process.wait(10)
    assert result.stderr is None
    assert result.stderr_path == str(err)
    assert err.read_bytes() == b"oops\n"


async def test_readiness_asked_after_the_end_reuses_the_result(
    sandbox_env: dict[str, str],
) -> None:
    process = await _spawn(["true"], sandbox_env)
    result = await process.wait(10)
    with pytest.raises(ProcessExitedError) as caught:
        await process.wait_for_output(b"READY", timeout=1)
    assert caught.value.result is result
    assert result.check() is result


async def test_kernel_facts() -> None:
    assert process_module._cap_last_cap() >= 37  # every supported kernel knows audit_read
    assert process_module._netns_of(2**22 + 1) is None  # above pid_max: never a process
    assert ProcessIdentity(capabilities=None).capabilities is None


async def test_the_application_inherits_only_stdio(sandbox_env: dict[str, str]) -> None:
    """stdin is /dev/null; no NSE descriptor (handshake, pipes) leaks into the app."""
    process = await _spawn(
        [
            sys.executable,
            "-c",
            "import json, os; print(json.dumps(sorted(os.listdir('/proc/self/fd'))))",
        ],
        sandbox_env,
    )
    result = await process.wait(10)
    assert result.stdout is not None
    # 0-2 plus the descriptor listdir itself opened to read the directory.
    assert json.loads(result.stdout) == ["0", "1", "2", "3"]
    readlink = await _spawn(["readlink", "/proc/self/fd/0"], sandbox_env)
    assert (await readlink.wait(10)).stdout == b"/dev/null\n"


POSIX_SHELLS = [
    shell for shell in ("/bin/sh", "/usr/bin/dash", "/bin/dash") if os.access(shell, os.X_OK)
]


@pytest.mark.parametrize("shell", POSIX_SHELLS)
async def test_the_probe_works_in_every_posix_shell(
    sandbox_env: dict[str, str], shell: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """dash only redirects descriptors 0-9; the handshake must never need more."""
    real = process_module.resolve
    monkeypatch.setattr(
        process_module, "resolve", lambda name: shell if name == "sh" else real(name)
    )
    # Push the descriptor numbers well above 9 in NSE, as a busy process would.
    with contextlib.ExitStack() as held:
        for _ in range(20):
            held.enter_context(open(os.devnull, "rb"))
        process = await _spawn(["/bin/echo", "probe ok"], sandbox_env)
        assert (await process.wait(10)).stdout == b"probe ok\n"


async def test_concurrent_waiters_share_one_result(sandbox_env: dict[str, str]) -> None:
    process = await _spawn(["/bin/sh", "-c", "sleep 0.2"], sandbox_env)

    async def readiness() -> ProcessResult:
        try:
            await process.wait_for_output(b"never", timeout=10)
        except ProcessExitedError as exc:
            return exc.result
        raise AssertionError("marker cannot appear")

    waited, ready, stopped = await asyncio.gather(
        process.wait(10), readiness(), process.terminate(grace=5)
    )
    assert waited is ready is stopped


async def test_capabilities_are_always_stored_frozen() -> None:
    identity = ProcessIdentity(capabilities={"net_raw"})
    assert isinstance(identity.capabilities, frozenset)
    assert hash(identity)  # a frozen model stays hashable


async def test_a_leftover_is_described_with_its_state_parent_and_group() -> None:
    child = subprocess.Popen(["sleep", "30"])
    try:
        text = _describe(child.pid)
    finally:
        child.kill()
        child.wait()
    assert f"ppid={os.getpid()}" in text
    assert "cmd=b'sleep 30'" in text
    assert "state=" in text
    assert "gone" in _describe(2**22 + 1)  # above pid_max: never a live process
