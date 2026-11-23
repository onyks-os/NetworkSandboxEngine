"""Keep test ownership journals isolated from the machine's real NSE state."""

from pathlib import Path
from typing import Any

import pytest

from nse.core import host_firewall, resource_registry
from nse.core.resource_network import Inspection, NetworkResources
from nse.core.resource_registry import Resource


@pytest.fixture(autouse=True)
def runtime_registry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    directory = tmp_path / "runtime"
    monkeypatch.setattr(resource_registry, "RUNTIME_DIR", directory)
    return directory


@pytest.fixture(autouse=True)
def quiet_host_firewall(monkeypatch: pytest.MonkeyPatch) -> None:
    """Never read the machine's own ruleset: the diagnostic is tested on its own."""
    monkeypatch.setattr(host_firewall, "_findings", [])
    monkeypatch.setattr(host_firewall, "_warned", False)


@pytest.fixture
def resource_kernel(monkeypatch: pytest.MonkeyPatch) -> None:
    """Kernel observations for existing tests that already mock every mutation.

    Ownership/recovery tests use their own stateful kernel or the real kernel;
    they must not use this fixture.
    """
    monkeypatch.setattr(NetworkResources, "identity", lambda self, name: (1, 1))
    monkeypatch.setattr(NetworkResources, "namespace_exists", lambda self, name: False)
    monkeypatch.setattr(NetworkResources, "links", lambda self, name: [])
    monkeypatch.setattr(NetworkResources, "routes", lambda self, version: [])
    monkeypatch.setattr(NetworkResources, "unmarked", lambda self: [])

    def inspect(self: NetworkResources, resource: Resource, marker: str) -> Inspection:
        return Inspection("owned", resource.name, resource.netns)

    monkeypatch.setattr(NetworkResources, "inspect", inspect)


class LocalSandbox:
    """A stand-in sandbox that runs programs in the test's own namespace.

    It goes through the real launch chain (identity handshake, output capture,
    process-group stop), so stimuli and receivers run exactly as they do in a
    namespace, on loopback, without privileges. The namespace identity is a
    placeholder: NSE refuses to signal its own namespace, and no other process
    is in this one, so only the managed process group is ever signalled.
    """

    ext_iface = "lo"
    ext_netns = None

    async def start_process(self, argv: Any, **options: Any) -> Any:
        from nse.core.process import spawn_process

        return await spawn_process([], argv, netns=(1, 1), **options)

    async def run_process(self, argv: Any, *, timeout: float | None = None, **options: Any) -> Any:
        process = await self.start_process(argv, **options)
        return await process.wait(timeout)


@pytest.fixture
def local_sandbox() -> LocalSandbox:
    return LocalSandbox()
