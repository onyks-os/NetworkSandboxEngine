# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""Private, crash-persistent ownership journals for Linux network resources.

The owner lock proves activity; a PID is diagnostic only. Every journal edit and
recovery runs under the same directory lock, including the kernel operation.
Lock files must never be replaced while an owner can still be using them.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import logging
import os
import re
import stat
import threading
import uuid
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

logger = logging.getLogger("nse.core.resources")
RUNTIME_DIR = Path("/run/nse")
Name = Annotated[str, Field(pattern=r"^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,254}$")]
Token = Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
Identity = tuple[int, int]


class OwnershipError(RuntimeError):
    """Ownership cannot be established; leave the resource untouched."""


class Resource(BaseModel):
    """An intent is durable before creation; markers survive a lost confirmation."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    kind: Literal["namespace", "link", "route"]
    name: Name
    run_id: Token
    token: Token = Field(default_factory=lambda: uuid.uuid4().hex)
    state: Literal["pending", "created"] = "pending"
    identity: Identity | None = None
    netns: Name | None = None
    netns_identity: Identity | None = None
    peer: Name | None = None
    peer_netns: Name | None = None
    peer_identity: Identity | None = None
    parent: Token | None = None
    route: tuple[str, ...] = ()  # diagnostic only; never executed from a journal

    def mac_addresses(self) -> tuple[str, str]:
        """A fresh pair of locally administered unicast addresses per intent."""
        raw = bytearray(hashlib.sha256(self.token.encode()).digest()[:12])
        raw[0] = (raw[0] & 0xFC) | 2
        raw[6] = (raw[6] & 0xFC) | 2
        return raw[:6].hex(":"), raw[6:].hex(":")


class Ownership(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Literal[1] = 1
    owner_id: Token
    scope: Identity
    boot_id: str
    pid: int
    process_start: str
    resources: list[Resource] = Field(default_factory=list)

    @model_validator(mode="after")
    def check_resources(self) -> Ownership:
        tokens = {resource.token for resource in self.resources}
        if len(tokens) != len(self.resources):
            raise ValueError("duplicate resource identity")
        links = {resource.token: resource for resource in self.resources if resource.kind == "link"}
        for resource in self.resources:
            if resource.kind == "route":
                parent = links.get(resource.parent or "")
                if parent is None or parent.run_id != resource.run_id:
                    raise ValueError("route does not belong to a recorded link")
        return self


# Serialize descriptor creation with fork, so a child cannot inherit a lease
# between os.open() and registration. Closing the duplicate must NOT LOCK_UN:
# flock locks refer to the shared open file description, including after fork.
_fd_mutex = threading.RLock()
_fds: set[int] = set()


def _after_fork() -> None:
    for fd in _fds:
        os.close(fd)
    _fds.clear()
    _fd_mutex.release()


os.register_at_fork(
    before=_fd_mutex.acquire, after_in_parent=_fd_mutex.release, after_in_child=_after_fork
)


def _open(path: str | Path, flags: int, *, directory: int | None = None) -> int:
    with _fd_mutex:
        fd = os.open(
            path, flags | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, 0o600, dir_fd=directory
        )
        _fds.add(fd)
        return fd


def _close(fd: int) -> None:
    with _fd_mutex:
        _fds.remove(fd)
        os.close(fd)


@contextlib.contextmanager
def _file(path: str | Path, flags: int, *, directory: int | None = None) -> Iterator[int]:
    fd = _open(path, flags, directory=directory)
    try:
        yield fd
    finally:
        _close(fd)


def _trusted(fd: int, *, is_directory: bool = False) -> None:
    info = os.fstat(fd)
    expected = stat.S_ISDIR if is_directory else stat.S_ISREG
    if (
        not expected(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o077
        or (not is_directory and info.st_nlink != 1)
    ):
        raise OwnershipError(
            "NSE runtime metadata must be private, singly linked and owned by the caller"
        )


def namespace_identity(name: str | None = None) -> Identity | None:
    path = Path("/proc/thread-self/ns/net") if name is None else Path("/var/run/netns") / name
    try:
        info = path.stat()
    except FileNotFoundError:
        return None
    return info.st_dev, info.st_ino


class Journal:
    """A journal view valid only while the registry's coordination lock is held."""

    def __init__(self, directory: int, data: Ownership) -> None:
        self.directory = directory
        self.data = data

    def marker(self, resource: Resource) -> str:
        return f"nse:{self.data.owner_id}:{resource.run_id}:{resource.token}"

    def save(self) -> None:
        raw = self.data.model_dump_json().encode()
        if len(raw) > 4 * 1024 * 1024:
            raise OwnershipError("ownership journal exceeds 4 MiB")
        temporary = f".{uuid.uuid4().hex}.tmp"
        try:
            with (
                _file(
                    temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, directory=self.directory
                ) as fd,
                open(fd, "wb", closefd=False) as stream,
            ):
                stream.write(raw)
                stream.flush()
                os.fsync(fd)
            os.replace(
                temporary,
                f"{self.data.owner_id}.json",
                src_dir_fd=self.directory,
                dst_dir_fd=self.directory,
            )
            os.fsync(self.directory)
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temporary, dir_fd=self.directory)

    def add(self, resource: Resource) -> Resource:
        self.data.resources.append(resource)
        self.save()
        return resource

    def discard(self, resource: Resource) -> None:
        # Routes bound to a deleted veth disappear in the kernel with that link.
        self.data.resources[:] = [
            entry
            for entry in self.data.resources
            if entry.token != resource.token and entry.parent != resource.token
        ]
        self.save()


class ResourceRegistry:
    """One live lease per controller, with separate run IDs in its journal."""

    def __init__(self) -> None:
        self.pid = os.getpid()
        self._owner_fd: int | None = None
        self._closed = False
        self.owner_id = uuid.uuid4().hex
        scope = namespace_identity()
        assert scope is not None  # /proc/self/ns/net exists on supported Linux
        self.scope = scope
        self.directory = RUNTIME_DIR / f"netns-{scope[0]}-{scope[1]}"
        self.boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        self._mutex = threading.RLock()
        self.data: Ownership | None = None

    def _check_process(self) -> None:
        if os.getpid() != self.pid or self._closed:
            raise OwnershipError("create a new NetnsController after fork or lease closure")
        if namespace_identity() != self.scope:
            raise OwnershipError("controller used from a different network namespace")

    @contextlib.contextmanager
    def _locked_directory(self, *, create: bool) -> Iterator[int | None]:
        self._check_process()
        with self._mutex:
            if create:
                self.directory.parent.mkdir(mode=0o700, exist_ok=True)
            with contextlib.ExitStack() as stack:
                try:
                    root = stack.enter_context(
                        _file(self.directory.parent, os.O_RDONLY | os.O_DIRECTORY)
                    )
                    _trusted(root, is_directory=True)
                    if create:
                        with contextlib.suppress(FileExistsError):
                            os.mkdir(self.directory.name, 0o700, dir_fd=root)
                    directory = stack.enter_context(
                        _file(self.directory.name, os.O_RDONLY | os.O_DIRECTORY, directory=root)
                    )
                    _trusted(directory, is_directory=True)
                except FileNotFoundError:
                    if create:
                        raise
                    yield None
                    return
                with _file(
                    "coordination.lock", os.O_RDWR | os.O_CREAT, directory=directory
                ) as lock:
                    _trusted(lock)
                    fcntl.flock(lock, fcntl.LOCK_EX)
                    yield directory

    @contextlib.contextmanager
    def edit(self) -> Iterator[Journal]:
        with self._locked_directory(create=True) as directory:
            assert directory is not None
            if self.data is None:
                fd = _open(
                    f"{self.owner_id}.lock", os.O_RDWR | os.O_CREAT | os.O_EXCL, directory=directory
                )
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    start = (
                        Path(f"/proc/{self.pid}/stat").read_text().rpartition(")")[2].split()[19]
                    )
                    data = Ownership(
                        owner_id=self.owner_id,
                        scope=self.scope,
                        boot_id=self.boot_id,
                        pid=self.pid,
                        process_start=start,
                    )
                    Journal(directory, data).save()
                except BaseException:
                    _close(fd)
                    raise
                self.data = data
                self._owner_fd = fd
            yield Journal(directory, self.data)

    def recover(self, cleanup: Callable[[Journal], None]) -> None:
        with self._locked_directory(create=False) as directory:
            if directory is None:
                return
            for filename in sorted(os.listdir(directory)):
                if not re.fullmatch(r"[0-9a-f]{32}\.json", filename):
                    continue
                owner = filename[:-5]
                try:
                    with _file(f"{owner}.lock", os.O_RDWR, directory=directory) as lock:
                        _trusted(lock)
                        try:
                            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        except BlockingIOError:
                            continue  # also works for two controllers in one process
                        with _file(filename, os.O_RDONLY, directory=directory) as source:
                            _trusted(source)
                            with open(source, "rb", closefd=False) as stream:
                                raw = stream.read(4 * 1024 * 1024 + 1)
                        if len(raw) > 4 * 1024 * 1024:
                            raise OwnershipError("ownership journal exceeds 4 MiB")
                        data = Ownership.model_validate_json(raw)
                        if (
                            data.owner_id != owner
                            or data.scope != self.scope
                            or data.boot_id != self.boot_id
                        ):
                            raise OwnershipError(
                                "ownership journal identity does not match its runtime scope"
                            )
                        journal = Journal(directory, data)
                        cleanup(journal)
                        if not data.resources:
                            os.unlink(filename, dir_fd=directory)
                            os.unlink(f"{owner}.lock", dir_fd=directory)
                            os.fsync(directory)
                except (OSError, ValueError, OwnershipError) as exc:
                    logger.warning("Preserving unresolved NSE journal %s: %s", filename, exc)

    def close(self) -> None:
        """Release the lease without deleting network resources; recovery may retry."""
        if os.getpid() == self.pid and self._owner_fd is not None:
            _close(self._owner_fd)
            self._owner_fd = None
        self._closed = True

    def __del__(self) -> None:
        self.close()
