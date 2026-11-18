"""NamespaceSandbox.exec_argv(): literal arguments, validation, shared result contract.

With an empty namespace prefix the real process is started, so these tests see
the bytes that actually reach ``sys.argv`` without needing root. The privileged
tests repeat the decisive case through ``ip netns exec`` / ``nsenter``.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from nse import NetnsController
from nse.core.netns_controller import NamespaceSandbox
from nse.core.utils import is_in_container

pytestmark = pytest.mark.asyncio

ECHO_ARGV = "import json, sys; sys.stdout.write(json.dumps(sys.argv[1:]))"
#: The same program without spaces, so that exec()'s whitespace split keeps it whole.
ECHO_ARGV_NO_SPACES = (
    "__import__('sys').stdout.write(__import__('json').dumps(__import__('sys').argv[1:]))"
)

#: Arguments a whitespace split or a shell would alter.
LITERALS = [
    "two words",
    "  leading and trailing  ",
    "'single quoted'",
    '"double quoted"',
    "",
    "ünïcødé ✓ 漢字",
    "$HOME",
    "${PATH}",
    "*",
    "?",
    "a|b",
    "a;b",
    "a&&b",
    "`id`",
    "$(id)",
    "> out.txt",
    "back\\slash",
    "line\nbreak",
    "\ttab",
    "-n",
    "--",
]


def _sandbox(prefix: list[str] | None = None) -> NamespaceSandbox:
    return NamespaceSandbox(MagicMock(exec_prefix=lambda name: list(prefix or [])), "nse_x")


async def test_every_argument_reaches_the_process_literally() -> None:
    result = await _sandbox().exec_argv([sys.executable, "-c", ECHO_ARGV, *LITERALS])
    assert json.loads(result.stdout) == LITERALS
    assert result.returncode == 0
    assert result.args == [sys.executable, "-c", ECHO_ARGV, *LITERALS]


async def test_exec_keeps_the_historic_whitespace_split() -> None:
    """The documented trap, unchanged: quotes are characters, not grouping."""
    result = await _sandbox().exec(f'{sys.executable} -c {ECHO_ARGV_NO_SPACES} "a  b"')
    assert json.loads(result.stdout) == ['"a', 'b"']


async def test_path_like_arguments_are_accepted(tmp_path: Path) -> None:
    script = tmp_path / "argv.py"
    script.write_text(ECHO_ARGV)
    result = await _sandbox().exec_argv([Path(sys.executable), script, tmp_path])
    assert json.loads(result.stdout) == [str(tmp_path)]


async def test_failure_raises_called_process_error_with_output() -> None:
    argv = [sys.executable, "-c", "import sys; print('out'); sys.stderr.write('err'); sys.exit(3)"]
    with pytest.raises(subprocess.CalledProcessError) as caught:
        await _sandbox().exec_argv(argv)
    assert caught.value.returncode == 3
    assert caught.value.cmd == argv
    assert caught.value.output.strip() == b"out"
    assert caught.value.stderr == b"err"


async def test_the_namespace_prefix_is_prepended_unchanged() -> None:
    calls: list[tuple[Any, ...]] = []

    async def spawn(*args: Any, **kwargs: Any) -> Any:
        calls.append(args)
        proc = MagicMock(returncode=0)

        async def communicate() -> tuple[bytes, bytes]:
            return b"", b""

        proc.communicate = communicate
        return proc

    sandbox = _sandbox(["/usr/sbin/ip", "netns", "exec", "nse_x"])
    with patch("asyncio.create_subprocess_exec", spawn):
        result = await sandbox.exec_argv(["printf", "%s", "a b"])
    assert calls == [("/usr/sbin/ip", "netns", "exec", "nse_x", "printf", "%s", "a b")]
    assert result.args == list(calls[0])


@pytest.mark.parametrize(
    ("argv", "error"),
    [
        ("echo hello", TypeError),
        (b"echo", TypeError),
        (42, TypeError),
        (["echo", b"bytes"], TypeError),
        (["echo", 3], TypeError),
        ([], ValueError),
        ([""], ValueError),
        (["echo", "nul\0byte"], ValueError),
    ],
)
async def test_invalid_argv_is_rejected_before_anything_starts(argv: Any, error: type) -> None:
    with patch("asyncio.create_subprocess_exec") as spawn, pytest.raises(error):
        await _sandbox().exec_argv(argv)
    spawn.assert_not_called()


async def test_cancellation_does_not_leave_the_child_running() -> None:
    started: list[asyncio.subprocess.Process] = []
    real_spawn = asyncio.create_subprocess_exec

    async def spawn(*args: Any, **kwargs: Any) -> asyncio.subprocess.Process:
        proc = await real_spawn(*args, **kwargs)
        started.append(proc)
        return proc

    with patch("asyncio.create_subprocess_exec", spawn):
        task = asyncio.ensure_future(
            _sandbox().exec_argv([sys.executable, "-c", "import time; time.sleep(60)"])
        )
        while not started:
            await asyncio.sleep(0.01)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=10)
    assert started[0].returncode is not None  # reaped, not orphaned
    with pytest.raises(ProcessLookupError):
        os.kill(started[0].pid, 0)


# --------------------------------------------------------------------------- real namespace


@pytest.mark.integration
@pytest.mark.skipif(os.geteuid() != 0, reason="requires root and real network namespaces")
@pytest.mark.parametrize("use_nsenter", [False, True], ids=["ip-netns-exec", "nsenter"])
async def test_literal_arguments_inside_a_real_namespace(
    runtime_registry: Path, use_nsenter: bool
) -> None:
    if not use_nsenter and is_in_container():
        pytest.skip("`ip netns exec` cannot remount /sys in this container; see nsenter")
    controller = NetnsController(use_nsenter=use_nsenter)
    async with controller.create_namespace("nse_execargv") as ns:
        assert ns.controller.exec_prefix(ns.name)[0].endswith("nsenter" if use_nsenter else "ip")
        result = await ns.exec_argv([sys.executable, "-c", ECHO_ARGV, *LITERALS])
        assert json.loads(result.stdout) == LITERALS
        # It really runs in the namespace: only lo and the peer veth are visible.
        visible = await ns.exec_argv(["ip", "-o", "link", "show"])
        assert ns.peer_iface.encode() in visible.stdout
        assert ns.ext_iface.encode() not in visible.stdout
        with pytest.raises(subprocess.CalledProcessError) as caught:
            await ns.exec_argv([sys.executable, "-c", "import sys; sys.exit(7)"])
        assert caught.value.returncode == 7
