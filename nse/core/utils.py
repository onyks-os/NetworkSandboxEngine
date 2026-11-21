# Copyright (c) 2026 onyks
# Licensed under the MIT License.

import contextlib
import ctypes
import errno
import os

_CLONE_NEWNET = 0x40000000


def enter_netns(name: str) -> None:
    """Move the calling thread, and only it, into network namespace *name*.

    Linux keeps the network namespace per thread, so a dedicated thread can open
    sockets inside a namespace while the rest of the process stays where it is.
    The move cannot be undone: call this only from a thread that exists for the
    namespace and ends with it. Raises ``OSError(ENODEV)`` when *name* does not
    exist and ``OSError`` for any other failure, before anything is opened.
    """
    if not name or "/" in name or name in (".", ".."):
        raise ValueError(f"invalid network namespace name: {name!r}")
    path = os.path.join("/var/run/netns", name)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    except FileNotFoundError as exc:
        raise OSError(errno.ENODEV, f"network namespace {name!r} does not exist") from exc
    try:
        setns = getattr(os, "setns", None)  # Python 3.12+
        if setns is not None:
            setns(fd, _CLONE_NEWNET)
        else:
            libc = ctypes.CDLL(None, use_errno=True)
            if libc.setns(fd, _CLONE_NEWNET) != 0:
                code = ctypes.get_errno()
                raise OSError(code, os.strerror(code), path)
    finally:
        os.close(fd)


def is_in_container() -> bool:
    """
    Robustly check if the current process is running inside a container.
    """
    # 1. Check standard environment variable 'container'
    if os.environ.get("CONTAINER") or os.environ.get("container"):  # noqa: SIM112
        return True

    # 2. Check traditional /.dockerenv file
    if os.path.exists("/.dockerenv"):
        return True

    # 3. Check /proc/1/environ for container environment hints
    with contextlib.suppress(OSError):
        if os.path.exists("/proc/1/environ"):
            with open("/proc/1/environ", "rb") as f:
                env_data = f.read()
                if b"container=" in env_data or b"docker" in env_data:
                    return True

    # 4. Check cgroup entries (works for cgroups v1 and v2)
    with contextlib.suppress(OSError):
        if os.path.exists("/proc/1/cgroup"):
            with open("/proc/1/cgroup") as f:
                cgroups = f.read()
                for runtime in ("docker", "kubepods", "containerd", "lxc"):
                    if runtime in cgroups:
                        return True

    return False
