"""Real filesystem, lock, corruption and process-boundary tests."""

from __future__ import annotations

import fcntl
import json
import multiprocessing
import os
import stat
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from nse.core import resource_registry as registry_module
from nse.core.resource_registry import (
    Journal,
    Ownership,
    OwnershipError,
    Resource,
    ResourceRegistry,
    namespace_identity,
)


def record() -> Resource:
    return Resource(kind="namespace", name="nse_a", run_id="a" * 32)


def abandon() -> ResourceRegistry:
    registry = ResourceRegistry()
    with registry.edit() as journal:
        journal.add(record())
    registry.close()
    return registry


def _recover_worker(
    directory: str, barrier: multiprocessing.synchronize.Barrier, output: str
) -> None:
    registry_module.RUNTIME_DIR = Path(directory)
    registry = ResourceRegistry()
    barrier.wait(timeout=10)

    def remove(journal: Journal) -> None:
        with open(output, "a") as stream:
            stream.write(journal.data.owner_id + "\n")
        for resource in list(journal.data.resources):
            journal.discard(resource)

    registry.recover(remove)


def test_private_atomic_journal_and_active_owner_lock(runtime_registry: Path) -> None:
    registry = ResourceRegistry()
    with registry.edit() as journal:
        resource = journal.add(record())
        assert journal.marker(resource).startswith(f"nse:{registry.owner_id}:")
        assert not list(registry.directory.glob(".*.tmp"))
        data = Ownership.model_validate_json(
            (registry.directory / f"{registry.owner_id}.json").read_bytes()
        )
        assert data.pid == os.getpid()
        assert data.process_start.isdigit()
        assert data.resources[0] == resource
    assert stat.S_IMODE(runtime_registry.stat().st_mode) == 0o700
    for path in registry.directory.iterdir():
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    called: list[str] = []
    ResourceRegistry().recover(lambda journal: called.append(journal.data.owner_id))
    assert not called
    registry.close()
    registry.close()
    ResourceRegistry().recover(lambda journal: called.append(journal.data.owner_id))
    assert called == [registry.owner_id]
    assert (registry.directory / f"{registry.owner_id}.json").exists()


def test_empty_owner_is_removed_only_after_lock_release() -> None:
    registry = ResourceRegistry()
    with registry.edit():
        pass
    registry.close()
    ResourceRegistry().recover(lambda journal: None)
    assert not list(registry.directory.glob("*.json"))
    assert not (registry.directory / f"{registry.owner_id}.lock").exists()
    assert (registry.directory / "coordination.lock").exists()


def test_two_processes_cannot_recover_the_same_journal_twice(
    runtime_registry: Path, tmp_path: Path
) -> None:
    dead = abandon()
    context = multiprocessing.get_context("spawn")
    barrier = context.Barrier(2)
    output = tmp_path / "recovered.txt"
    workers = [
        context.Process(target=_recover_worker, args=(str(runtime_registry), barrier, str(output)))
        for _ in range(2)
    ]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(15)
        assert not worker.is_alive()
        assert worker.exitcode == 0
    assert output.read_text().splitlines() == [dead.owner_id]
    assert not list(dead.directory.glob("*.json"))


@pytest.mark.parametrize(
    "corruption",
    ["json", "version", "owner", "scope", "boot", "path", "duplicates", "route", "large"],
)
def test_invalid_journal_is_preserved_without_cleanup(corruption: str) -> None:
    dead = abandon()
    path = dead.directory / f"{dead.owner_id}.json"
    data = json.loads(path.read_text())
    if corruption == "json":
        path.write_text("{")
    elif corruption == "large":
        path.write_text(" " * (4 * 1024 * 1024 + 1))
    else:
        if corruption == "version":
            data["version"] = 99
        elif corruption == "owner":
            data["owner_id"] = "b" * 32
        elif corruption == "scope":
            data["scope"] = [99, 99]
        elif corruption == "boot":
            data["boot_id"] = "previous boot"
        elif corruption == "path":
            data["resources"][0]["name"] = "../../outside"
        elif corruption == "duplicates":
            data["resources"].append(data["resources"][0])
        elif corruption == "route":
            data["resources"][0]["kind"] = "route"
        path.write_text(json.dumps(data))
    with patch("nse.core.resource_registry.logger.warning") as warning:
        ResourceRegistry().recover(lambda journal: pytest.fail("unsafe cleanup"))
    warning.assert_called()
    assert path.exists()


@pytest.mark.parametrize(
    "target", ["journal", "owner-lock", "coordination-lock", "directory", "root"]
)
@pytest.mark.parametrize("damage", ["permissions", "symlink"])
def test_untrusted_metadata_is_never_used(target: str, damage: str, tmp_path: Path) -> None:
    dead = abandon()
    paths = {
        "journal": dead.directory / f"{dead.owner_id}.json",
        "owner-lock": dead.directory / f"{dead.owner_id}.lock",
        "coordination-lock": dead.directory / "coordination.lock",
        "directory": dead.directory,
        "root": dead.directory.parent,
    }
    path = paths[target]
    if damage == "permissions":
        path.chmod(0o777)
    else:
        moved = path.with_name(path.name + "-original")
        path.rename(moved)
        path.symlink_to(moved)
    registry = ResourceRegistry()
    if target in ("directory", "root", "coordination-lock"):
        with pytest.raises((OSError, OwnershipError)):
            registry.recover(lambda journal: pytest.fail("unsafe cleanup"))
    else:
        registry.recover(lambda journal: pytest.fail("unsafe cleanup"))
    assert path.exists()


@pytest.mark.parametrize("target", ["json", "lock"])
def test_hard_links_and_missing_lock_are_not_treated_as_abandonment(
    target: str, tmp_path: Path
) -> None:
    dead = abandon()
    source = dead.directory / f"{dead.owner_id}.{target}"
    os.link(source, tmp_path / "other-link")
    ResourceRegistry().recover(lambda journal: pytest.fail("hard-linked metadata"))
    (dead.directory / f"{dead.owner_id}.lock").unlink()
    ResourceRegistry().recover(lambda journal: pytest.fail("missing lock is not proof"))
    assert (dead.directory / f"{dead.owner_id}.json").exists()


def _fork_check(runtime: Path, result: Path) -> None:
    registry_module.RUNTIME_DIR = runtime
    registry = ResourceRegistry()
    with registry.edit() as journal:
        journal.add(record())
    assert registry._owner_fd is not None
    fd = registry._owner_fd
    pid = os.fork()
    if pid == 0:
        try:
            try:
                os.fstat(fd)
            except OSError:
                pass
            else:
                os._exit(2)
            try:
                with registry.edit():
                    pass
            except OwnershipError:
                pass
            else:
                os._exit(3)
            ResourceRegistry().recover(lambda journal: os._exit(4))
            result.write_text("child cannot inherit ownership")
            os._exit(0)
        except BaseException:
            os._exit(5)
    _, status = os.waitpid(pid, 0)
    assert os.waitstatus_to_exitcode(status) == 0
    assert result.exists()
    assert os.fstat(fd)
    assert fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC
    registry.close()


def test_fork_closes_inherited_descriptors_without_unlocking_parent(
    runtime_registry: Path, tmp_path: Path
) -> None:
    # pytest may have executor threads from other tests. Exercise fork in a
    # fresh interpreter, and bound the entire check so a lock regression fails.
    code = "import runpy,sys; from pathlib import Path; runpy.run_path(sys.argv[1])['_fork_check'](Path(sys.argv[2]),Path(sys.argv[3]))"
    subprocess.run(
        [sys.executable, "-c", code, __file__, str(runtime_registry), str(tmp_path / "child.txt")],
        check=True,
        capture_output=True,
        timeout=15,
    )


@pytest.mark.parametrize("target", ["json", "lock"])
def test_fifo_metadata_is_rejected_without_blocking(target: str) -> None:
    dead = abandon()
    path = dead.directory / f"{dead.owner_id}.{target}"
    path.unlink()
    os.mkfifo(path, 0o600)
    ResourceRegistry().recover(lambda journal: pytest.fail("FIFO metadata is untrusted"))
    assert path.is_fifo()


def test_scope_changes_closed_registry_and_missing_runtime_are_safe() -> None:
    registry = ResourceRegistry()
    registry.recover(lambda journal: pytest.fail("no runtime directory"))
    with (
        patch("nse.core.resource_registry.namespace_identity", return_value=(99, 99)),
        pytest.raises(OwnershipError, match="network namespace"),
        registry.edit(),
    ):
        pass
    registry.close()
    with pytest.raises(OwnershipError, match="closure"), registry.edit():
        pass
    assert namespace_identity("nse_nonexistent") is None


def test_atomic_write_failure_leaves_previous_journal_and_no_temporary_files() -> None:
    registry = ResourceRegistry()
    with registry.edit() as journal:
        journal.add(record())
        path = registry.directory / f"{registry.owner_id}.json"
        old = path.read_bytes()
        with patch("os.replace", side_effect=OSError("disk full")), pytest.raises(OSError):
            journal.save()
        assert path.read_bytes() == old
        assert not list(registry.directory.glob(".*.tmp"))
        with (
            patch.object(Ownership, "model_dump_json", return_value=" " * (4 * 1024 * 1024 + 1)),
            pytest.raises(OwnershipError, match="4 MiB"),
        ):
            journal.save()


def test_missing_runtime_parent_does_not_allow_partial_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(registry_module, "RUNTIME_DIR", tmp_path / "absent" / "runtime")
    registry = ResourceRegistry()
    with pytest.raises(FileNotFoundError), registry.edit():
        pass
