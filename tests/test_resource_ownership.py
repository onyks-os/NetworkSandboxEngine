"""Ownership regressions with a stateful kernel, not successful command mocks."""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from unittest.mock import patch

import pytest

from nse.core.netns_controller import NetnsController
from nse.core.paths import resolve
from nse.core.resource_network import Inspection, LinkInfo, NetworkResources
from nse.core.resource_registry import Journal, OwnershipError, Resource


class Kernel:
    def __init__(self) -> None:
        self.namespaces: dict[str | None, tuple[int, int]] = {None: (1, 1)}
        self.devices: dict[tuple[str | None, str], LinkInfo] = {}
        self.pairs: dict[int, int] = {}
        self.routes: set[tuple[str, ...]] = set()
        self.commands: list[list[str]] = []
        self.serial = 1
        self.after: Callable[[list[str]], None] = lambda command: None

    def identity(self, name: str | None) -> tuple[int, int] | None:
        return self.namespaces.get(name)

    def links(self, name: str | None) -> list[LinkInfo]:
        return [device for (namespace, _), device in self.devices.items() if namespace == name]

    def unmarked(self) -> list[str]:
        return []

    def remove(self, index: int) -> None:
        indices = {index, self.pairs.get(index)}
        for key, device in list(self.devices.items()):
            if device.ifindex in indices:
                self.devices.pop(key)
                self.routes = {route for route in self.routes if device.ifname not in route}

    def run(self, command: list[str], timeout: float = 10.0) -> subprocess.CompletedProcess[str]:
        self.commands.append(command)
        namespace: str | None = None
        args = command[1:]
        if args[:2] == ["netns", "exec"]:
            namespace, args = args[2], args[4:]
        if args[:2] == ["netns", "add"]:
            name = args[2]
            if name in self.namespaces:
                raise subprocess.CalledProcessError(1, command, stderr="File exists")
            self.serial += 1
            self.namespaces[name] = (1, self.serial)
            self.devices[name, "lo"] = LinkInfo(ifname="lo", ifindex=1)
        elif args[:2] == ["netns", "del"]:
            name = args[2]
            self.namespaces.pop(name, None)
            for (location, _), device in list(self.devices.items()):
                if location == name:
                    if device.ifname == "lo":
                        self.devices.pop((location, device.ifname))
                    else:
                        assert device.ifindex is not None
                        self.remove(device.ifindex)
        elif args[:2] == ["link", "add"]:
            first, peer = args[2], args[9]
            if (namespace, first) in self.devices or (namespace, peer) in self.devices:
                raise subprocess.CalledProcessError(1, command, stderr="File exists")
            self.serial += 2
            self.devices[namespace, first] = LinkInfo(
                ifname=first, ifindex=self.serial, link=peer, address=args[4]
            )
            self.devices[namespace, peer] = LinkInfo(
                ifname=peer, ifindex=self.serial + 1, link=first, address=args[11]
            )
            self.pairs[self.serial] = self.serial + 1
            self.pairs[self.serial + 1] = self.serial
        elif args[:3] == ["link", "set", "dev"] and args[4] == "alias":
            self.devices[namespace, args[3]].ifalias = args[5]
        elif args[:2] == ["link", "set"] and len(args) > 3 and args[3] == "netns":
            device = self.devices.pop((namespace, args[2]))
            self.devices[args[4], device.ifname] = device
        elif args[:2] == ["link", "del"]:
            device = self.devices[namespace, args[2]]
            assert device.ifindex is not None
            self.remove(device.ifindex)
        elif "route" in args and "add" in args:
            self.routes.add(tuple(command))
        self.after(command)
        return subprocess.CompletedProcess(command, 0, "", "")


@pytest.fixture
def kernel(monkeypatch: pytest.MonkeyPatch) -> Kernel:
    kernel = Kernel()
    monkeypatch.setattr("nse.core.netns_controller._run", kernel.run)
    monkeypatch.setattr(NetworkResources, "identity", lambda self, name: kernel.identity(name))
    monkeypatch.setattr(NetworkResources, "links", lambda self, name: kernel.links(name))
    monkeypatch.setattr(NetworkResources, "unmarked", lambda self: kernel.unmarked())
    return kernel


def topology(controller: NetnsController, name: str) -> None:
    controller.create_netns(name)
    controller.create_veth_pair(name, f"vhr-{name}", f"vrh-{name}")


def test_live_controllers_and_separate_runs_do_not_remove_each_other(kernel: Kernel) -> None:
    first = NetnsController(use_nsenter=False)
    topology(first, "a")
    second = NetnsController(use_nsenter=False)
    topology(second, "b")
    topology(first, "c")
    assert first._runs["a"] != first._runs["c"]
    second.destroy_netns("a")
    assert "a" in kernel.namespaces
    first.cleanup_all()
    first.cleanup_all()
    assert "a" not in kernel.namespaces
    assert "c" not in kernel.namespaces
    assert "b" in kernel.namespaces
    assert (None, "vhr-b") in kernel.devices
    second.cleanup_all()
    assert not kernel.devices


def test_recovery_removes_only_dead_owner_and_associated_routes(kernel: Kernel) -> None:
    dead = NetnsController(use_nsenter=False)
    dead.create_gateway_topology("router", "server", "vhr-a", "vrh-a", "vrs-a", "vsr-a")
    assert dead._runs["router"] == dead._runs["server"]
    assert len(kernel.routes) == 4  # two host and two server routes
    live = NetnsController(use_nsenter=False)
    topology(live, "live")
    dead._registry.close()  # simulate owner death; process-level tests use SIGKILL
    NetnsController(use_nsenter=False)
    assert set(kernel.namespaces) == {None, "live"}
    assert not kernel.routes
    assert (None, "vhr-live") in kernel.devices


def test_recovery_preserves_reused_namespace_name_even_with_old_marker(kernel: Kernel) -> None:
    dead = NetnsController(use_nsenter=False)
    dead.create_netns("reused")
    kernel.namespaces["reused"] = (1, 999)
    dead._registry.close()
    NetnsController(use_nsenter=False)
    assert "reused" in kernel.namespaces


@pytest.mark.parametrize("change", ["alias", "address", "peer", "namespace", "missing-endpoint"])
def test_uncertain_link_ownership_preserves_resource_and_journal(
    kernel: Kernel, change: str
) -> None:
    dead = NetnsController(use_nsenter=False)
    topology(dead, "a")
    assert dead._registry.data is not None
    link = next(item for item in dead._registry.data.resources if item.kind == "link")
    # Return the pair to its creation namespace to exercise pending identity.
    peer = kernel.devices.pop(("a", "vrh-a"))
    kernel.devices[None, peer.ifname] = peer
    with dead._registry.edit() as journal:
        link.state = "pending" if change != "alias" else "created"
        for device in kernel.devices.values():
            if device.ifname in ("vhr-a", "vrh-a"):
                device.ifalias = None
        if change == "address":
            peer.address = "02:00:00:00:00:00"
        elif change == "peer":
            peer.link = "some-other-veth"
        elif change == "namespace":
            link.netns_identity = (9, 9)
        elif change == "missing-endpoint":
            kernel.devices.pop((None, "vrh-a"))
        journal.save()
    dead._registry.close()
    NetnsController(use_nsenter=False)
    assert (None, "vhr-a") in kernel.devices
    assert list(dead._registry.directory.glob("*.json"))


def test_crash_between_link_creation_and_alias_is_recovered_from_both_macs(kernel: Kernel) -> None:
    dead = NetnsController(use_nsenter=False)
    dead.create_netns("a")

    def crash(command: list[str]) -> None:
        if command[1:3] == ["link", "add"]:
            raise KeyboardInterrupt

    kernel.after = crash
    with pytest.raises(KeyboardInterrupt):
        dead.create_veth_pair("a", "vhr-a", "vrh-a")
    kernel.after = lambda command: None
    dead._registry.close()
    NetnsController(use_nsenter=False)
    assert not kernel.devices
    assert set(kernel.namespaces) == {None}


def test_crash_before_namespace_marker_is_preserved_for_manual_recovery(kernel: Kernel) -> None:
    dead = NetnsController(use_nsenter=False)

    def crash(command: list[str]) -> None:
        if command[1:3] == ["netns", "add"]:
            raise KeyboardInterrupt

    kernel.after = crash
    with pytest.raises(KeyboardInterrupt):
        dead.create_netns("a")
    dead._registry.close()
    kernel.after = lambda command: None
    NetnsController(use_nsenter=False)
    assert "a" in kernel.namespaces
    assert list(dead._registry.directory.glob("*.json"))


def test_failed_teardown_retains_ownership_and_recovery_retries(kernel: Kernel) -> None:
    dead = NetnsController(use_nsenter=False)
    topology(dead, "a")

    def fail(command: list[str], timeout: float = 10.0) -> subprocess.CompletedProcess[str]:
        if "del" in command:
            raise subprocess.TimeoutExpired(command, timeout)
        return kernel.run(command, timeout)

    with patch("nse.core.netns_controller._run", fail):
        dead.cleanup_all()
    assert "a" in dead._active_ns
    assert dead._registry.data is not None
    assert len(dead._registry.data.resources) == 2
    dead._registry.close()
    NetnsController(use_nsenter=False)
    assert not kernel.devices


def test_existing_resource_is_not_adopted_after_failed_creation(kernel: Kernel) -> None:
    first = NetnsController(use_nsenter=False)
    topology(first, "a")
    second = NetnsController(use_nsenter=False)
    with pytest.raises(subprocess.CalledProcessError):
        second.create_netns("a")
    second.destroy_netns("a")
    second.cleanup_all()
    second._registry.close()
    NetnsController(use_nsenter=False)
    assert "a" in kernel.namespaces
    assert (None, "vhr-a") in kernel.devices


def test_duplicate_registration_and_foreign_destroy_are_safe(kernel: Kernel) -> None:
    owner = NetnsController(use_nsenter=False)
    owner.destroy_netns("external")
    owner._cleanup_link("external")
    owner.create_netns("a")
    with pytest.raises(OwnershipError, match="already registered"):
        owner.create_netns("a")
    before = len(kernel.commands)
    owner.destroy_netns("external")
    assert len(kernel.commands) == before


def test_missing_resource_is_removed_from_journal_and_cleanup_link_is_scoped(
    kernel: Kernel,
) -> None:
    owner = NetnsController(use_nsenter=False)
    topology(owner, "a")
    owner._cleanup_link("external")
    owner._cleanup_link("vrh-a")
    owner._cleanup_link("vhr-a")
    assert (None, "vhr-a") not in kernel.devices
    kernel.namespaces.pop("a")
    owner.cleanup_all()
    assert owner._registry.data is not None
    assert not owner._registry.data.resources


@pytest.mark.parametrize("existing_lease", [False, True])
def test_intent_write_failure_prevents_any_kernel_mutation(
    kernel: Kernel, existing_lease: bool
) -> None:
    owner = NetnsController(use_nsenter=False)
    if existing_lease:
        with owner._registry.edit():
            pass
    with patch.object(Journal, "save", side_effect=OSError("disk full")), pytest.raises(OSError):
        owner.create_netns("a")
    assert not kernel.commands


def test_namespace_or_marker_confirmation_failure_is_explicit(kernel: Kernel) -> None:
    owner = NetnsController(use_nsenter=False)
    with (
        patch.object(owner._resources, "identity", return_value=None),
        pytest.raises(OwnershipError),
    ):
        owner.create_netns("a")
    with (
        patch.object(owner._resources, "inspect", return_value=Inspection("foreign", "b")),
        pytest.raises(OwnershipError),
    ):
        owner.create_netns("b")


def test_link_creation_refuses_unidentifiable_namespace_and_unconfirmed_marker(
    kernel: Kernel,
) -> None:
    owner = NetnsController(use_nsenter=False)
    with pytest.raises(OwnershipError, match="identify"):
        owner.create_veth_pair("absent", "vhr-a", "vrh-a")
    owner.create_netns("a")
    with (
        patch.object(owner._resources, "inspect", return_value=Inspection("foreign", "vhr-a")),
        pytest.raises(OwnershipError),
    ):
        owner.create_veth_pair("a", "vhr-a", "vrh-a")


def test_invalid_namespace_name_cannot_escape_netns_directory(kernel: Kernel) -> None:
    with pytest.raises(ValueError):
        NetnsController(use_nsenter=False).create_netns("../../somewhere")
    assert not kernel.commands


def test_pending_numeric_peer_identity_and_renamed_marker(kernel: Kernel) -> None:
    owner = NetnsController(use_nsenter=False)
    entry = Resource(kind="link", name="first", peer="peer", run_id="a" * 32)
    first_mac, peer_mac = entry.mac_addresses()
    links = [
        LinkInfo(ifname="first", ifindex=2, link_index=3, address=first_mac),
        LinkInfo(ifname="peer", ifindex=3, link_index=2, address=peer_mac),
    ]
    assert NetworkResources._pending_pair_matches(entry, "marker", links)
    assert not NetworkResources._pending_pair_matches(entry, "marker", links[:1])
    topology(owner, "a")
    first = kernel.devices.pop((None, "vhr-a"))
    first.ifname = "renamed"
    kernel.devices[None, first.ifname] = first
    owner.cleanup_all()
    assert not kernel.devices


def test_network_prefix_and_json_queries() -> None:
    backend = NetworkResources(use_nsenter=True)
    assert backend.prefix("a") == [resolve("nsenter"), "--net=/var/run/netns/a", "--"]
    with patch(
        "subprocess.run", return_value=subprocess.CompletedProcess([], 0, '[{"ifname":"lo"}]')
    ):
        assert backend.links("a")[0].ifname == "lo"


def test_inaccessible_namespace_cannot_prove_link_absence(kernel: Kernel) -> None:
    entry = Resource(
        kind="link",
        name="first",
        peer="peer",
        run_id="a" * 32,
        netns="unreachable",
        netns_identity=(1, 8),
        peer_netns="also_unreachable",
        peer_identity=(1, 9),
    )
    assert NetworkResources(False).inspect(entry, "marker").status == "foreign"


def test_cleanup_all_on_fresh_controller_and_recovery_in_missing_scope(kernel: Kernel) -> None:
    NetnsController(False).cleanup_all()
    assert not kernel.commands


def test_legacy_inventory_is_diagnostic_only() -> None:
    backend = NetworkResources(use_nsenter=False)
    listing = subprocess.CompletedProcess([], 0, "nse_old\nnse_new\nordinary\n\n")

    def links(name: str | None) -> list[LinkInfo]:
        if name is None:
            return [
                LinkInfo(ifname="vhr-old"),
                LinkInfo(ifname="vhr-live", ifalias="nse:owner"),
                LinkInfo(ifname="eth0"),
            ]
        return [LinkInfo(ifname="lo", ifalias="nse:owner" if name == "nse_new" else None)]

    with patch("subprocess.run", return_value=listing), patch.object(backend, "links", links):
        assert backend.unmarked() == ["nse_old", "vhr-old"]
