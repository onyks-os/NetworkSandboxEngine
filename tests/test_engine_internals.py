# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""
Unit tests for the supporting engine modules: rule loading, namespace
lifecycle, packet forging, mock listeners and container detection.

None of these need root. They cover the paths that only ever ran under `sudo`
before, which is how a namespace-name bug survived: `ScapyInjector` derived a
router namespace called `nse_router_<suffix>`, a name `naming.derive_names` has
never produced, so gateway-topology MAC lookups could only fail.
"""

from __future__ import annotations

import socket
import subprocess
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from nse.core.mock_listener import run_tcp_server, run_udp_server, start_mock_listener
from nse.core.naming import (
    NETNS_SWEEP_PREFIXES,
    VETH_SWEEP_PREFIXES,
    derive_names,
)
from nse.core.netns_controller import NetnsController, _run
from nse.core.rule_engine import (
    RuleEngine,
    RuleValidationError,
    _parse_nft_errors,
    _temp_rules_file,
)
from nse.core.scapy_injector import _build_scapy_script, _get_mac_address
from nse.core.utils import is_in_container
from nse.models.test_request import PacketSpec


@pytest.fixture
def controller() -> NetnsController:
    """A controller whose startup sweep has been neutralised."""
    with patch.object(NetnsController, "startup_sweep", lambda self: None):
        return NetnsController(use_nsenter=False)


# ---------------------------------------------------------------------------
# naming
# ---------------------------------------------------------------------------


def test_derive_names_is_deterministic() -> None:
    assert derive_names("abc123def456") == derive_names("abc123def456")


def test_derive_names_layout() -> None:
    names = derive_names("abc123def456")
    assert names.netns == "nse_abc123def456"
    assert names.router_ns == "nsr_abc123def456"
    assert names.server_ns == "nss_abc123def456"
    assert names.veth_host == "vhr-abc123de"
    assert names.veth_router_host == "vrh-abc123de"


def test_veth_names_fit_the_kernel_limit() -> None:
    """Linux caps interface names at 15 characters; longer names fail at runtime."""
    names = derive_names("0123456789abcdef")
    for iface in (
        names.veth_host,
        names.veth_router_host,
        names.veth_router_server,
        names.veth_server,
    ):
        assert len(iface) <= 15, iface


def test_sweep_prefixes_cover_every_derived_name() -> None:
    """A prefix the sweep does not know about becomes an orphan nobody cleans."""
    names = derive_names("abc123def456")
    assert names.netns.startswith(NETNS_SWEEP_PREFIXES)
    assert names.router_ns.startswith(NETNS_SWEEP_PREFIXES)
    assert names.server_ns.startswith(NETNS_SWEEP_PREFIXES)
    for iface in (
        names.veth_host,
        names.veth_router_host,
        names.veth_router_server,
        names.veth_server,
    ):
        assert iface.startswith(VETH_SWEEP_PREFIXES)


# ---------------------------------------------------------------------------
# utils.is_in_container
# ---------------------------------------------------------------------------


def test_is_in_container_via_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("container", "podman")
    assert is_in_container() is True


def test_is_in_container_via_dockerenv(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("container", raising=False)
    monkeypatch.delenv("CONTAINER", raising=False)
    with patch("os.path.exists", lambda p: p == "/.dockerenv"):
        assert is_in_container() is True


def test_is_in_container_via_cgroup(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("container", raising=False)
    monkeypatch.delenv("CONTAINER", raising=False)
    cgroup = tmp_path / "cgroup"
    cgroup.write_text("0::/kubepods/besteffort/podabc\n")

    real_open = open

    def fake_open(path, *args, **kwargs):  # type: ignore[no-untyped-def]
        if path == "/proc/1/cgroup":
            return real_open(cgroup, *args, **kwargs)
        raise OSError("nope")

    with (
        patch("os.path.exists", lambda p: p == "/proc/1/cgroup"),
        patch("builtins.open", fake_open),
    ):
        assert is_in_container() is True


def test_is_in_container_false_on_a_bare_host(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("container", raising=False)
    monkeypatch.delenv("CONTAINER", raising=False)
    with patch("os.path.exists", lambda p: False):
        assert is_in_container() is False


def test_is_in_container_tolerates_unreadable_proc(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("container", raising=False)
    monkeypatch.delenv("CONTAINER", raising=False)
    with (
        patch("os.path.exists", lambda p: p.startswith("/proc/1")),
        patch("builtins.open", side_effect=OSError("permission denied")),
    ):
        assert is_in_container() is False


# ---------------------------------------------------------------------------
# rule_engine
# ---------------------------------------------------------------------------


def test_temp_rules_file_writes_and_removes() -> None:
    with _temp_rules_file("table ip t {}") as path:
        assert Path(path).read_text() == "table ip t {}"
    assert not Path(path).exists()


def test_temp_rules_file_survives_an_already_deleted_file() -> None:
    with _temp_rules_file("x") as path:
        Path(path).unlink()
    assert not Path(path).exists()


def test_parse_nft_errors_structures_positions() -> None:
    stderr = "/tmp/r.nft:3:10-14: Error: syntax error, unexpected string"
    errors = _parse_nft_errors(stderr, "/tmp/r.nft")
    assert errors == [
        {
            "line": 3,
            "column_range": "10-14",
            "level": "Error",
            "message": "syntax error, unexpected string",
        }
    ]


def test_parse_nft_errors_attaches_context_to_the_previous_error() -> None:
    stderr = "/tmp/r.nft:3:10-14: Error: syntax error\n  tcp dport bogus accept\n"
    errors = _parse_nft_errors(stderr, "/tmp/r.nft")
    assert errors[0]["context"] == ["tcp dport bogus accept"]


def test_parse_nft_errors_keeps_unstructured_output() -> None:
    errors = _parse_nft_errors("something went wrong", "/tmp/r.nft")
    assert errors == [{"raw": "something went wrong"}]


def test_rule_engine_load_refuses_the_root_namespace() -> None:
    """Loading into init_net would mutate the host firewall — the one thing NSE promises not to do."""
    with pytest.raises(ValueError, match="refusing to inject into init_net"):
        RuleEngine().load("table ip t {}", "")


def test_rule_engine_load_targets_the_requested_namespace() -> None:
    with patch("subprocess.run", return_value=MagicMock(returncode=0)) as run:
        RuleEngine().load("table ip filter {}", "nse_x")
    assert run.call_count == 1
    assert run.call_args[0][0][:4] == ["ip", "netns", "exec", "nse_x"]


def test_rule_engine_load_writes_the_scaffolding_into_the_file() -> None:
    written: list[str] = []
    original = _temp_rules_file.__init__

    def capture(self, rules):  # type: ignore[no-untyped-def]
        written.append(rules)
        original(self, rules)

    with (
        patch.object(_temp_rules_file, "__init__", capture),
        patch("subprocess.run", return_value=MagicMock(returncode=0)),
    ):
        RuleEngine().load("table ip filter {}", "nse_x")

    assert "nse_trace" in written[0]
    assert "meta nftrace set 1" in written[0]
    assert "table ip filter {}" in written[0]


def test_rule_engine_load_raises_on_nft_rejection() -> None:
    failure = MagicMock(returncode=1, stderr="/tmp/r.nft:1:1-5: Error: nope")
    with patch("subprocess.run", return_value=failure), pytest.raises(RuleValidationError):
        RuleEngine().load("garbage", "nse_x")


def test_rule_engine_uses_nsenter_when_configured() -> None:
    engine = RuleEngine(use_nsenter=True)
    assert engine.exec_prefix("nse_x") == ["nsenter", "--net=/var/run/netns/nse_x", "--"]


def test_rule_engine_flush_is_best_effort() -> None:
    with patch("subprocess.run", return_value=MagicMock(returncode=1)) as run:
        RuleEngine().flush("nse_x")
    assert run.call_args[0][0][-2:] == ["flush", "ruleset"]
    assert run.call_args.kwargs["check"] is False


def test_rule_engine_validate_accepts_valid_rules() -> None:
    with patch("subprocess.run", return_value=MagicMock(returncode=0)):
        RuleEngine().validate("table ip filter {}")


# ---------------------------------------------------------------------------
# netns_controller
# ---------------------------------------------------------------------------


def test_run_raises_on_failure() -> None:
    with pytest.raises(subprocess.CalledProcessError):
        _run(["false"])


def test_destroy_netns_is_idempotent(controller: NetnsController) -> None:
    err = subprocess.CalledProcessError(1, "ip", stderr="Cannot remove: No such file or directory")
    with patch("nse.core.netns_controller._run", side_effect=err) as run:
        controller.destroy_netns("nse_gone")
    assert run.call_count == 1  # recognised as already-gone, not retried


def test_destroy_netns_retries_then_gives_up(controller: NetnsController) -> None:
    err = subprocess.CalledProcessError(1, "ip", stderr="Device or resource busy")
    with (
        patch("nse.core.netns_controller._run", side_effect=err) as run,
        patch("time.sleep"),
    ):
        controller.destroy_netns("nse_busy")
    assert run.call_count == 3


def test_destroy_netns_survives_a_timeout(controller: NetnsController) -> None:
    with patch(
        "nse.core.netns_controller._run",
        side_effect=subprocess.TimeoutExpired("ip", 10.0),
    ):
        controller.destroy_netns("nse_stuck")


def test_create_netns_tolerates_missing_sysctl(controller: NetnsController) -> None:
    """A namespace without IPv6 sysctls must still be usable."""
    calls: list[list[str]] = []

    def fake_run(cmd, timeout=10.0):  # type: ignore[no-untyped-def]
        calls.append(cmd)
        if "sysctl" in cmd:
            raise subprocess.CalledProcessError(1, cmd)
        return MagicMock(returncode=0)

    with patch("nse.core.netns_controller._run", side_effect=fake_run):
        controller.create_netns("nse_x")
    assert ["ip", "netns", "add", "nse_x"] in calls
    assert "nse_x" in controller._active_ns


def test_cleanup_all_destroys_every_tracked_namespace(controller: NetnsController) -> None:
    controller._active_ns = {"nse_a", "nse_b"}
    with patch.object(controller, "destroy_netns") as destroy:
        controller.cleanup_all()
    assert destroy.call_count == 2


def test_startup_sweep_removes_orphans() -> None:
    netns_list = MagicMock(returncode=0, stdout="nse_dead (id: 1)\nunrelated\n")
    link_list = MagicMock(returncode=0, stdout="3: vhr-dead@if4: <BROADCAST>\n4: eth0: <UP>\n")
    deletions: list[list[str]] = []

    def fake_run(cmd, **kwargs):  # type: ignore[no-untyped-def]
        if cmd[:3] == ["ip", "netns", "list"]:
            return netns_list
        if cmd[:3] == ["ip", "link", "show"]:
            return link_list
        deletions.append(cmd)
        return MagicMock(returncode=0)

    with patch("subprocess.run", side_effect=fake_run):
        NetnsController(use_nsenter=False)

    assert ["ip", "netns", "del", "nse_dead"] in deletions
    assert ["ip", "link", "del", "vhr-dead"] in deletions
    assert not any("eth0" in c for c in deletions)


def test_startup_sweep_survives_a_missing_ip_binary() -> None:
    with patch("subprocess.run", side_effect=FileNotFoundError("no ip")):
        NetnsController(use_nsenter=False)  # must not raise


def test_controller_autodetects_container_mode() -> None:
    with (
        patch.object(NetnsController, "startup_sweep", lambda self: None),
        patch("nse.core.netns_controller.is_in_container", return_value=True),
    ):
        assert NetnsController().use_nsenter is True


# ---------------------------------------------------------------------------
# scapy_injector helpers
# ---------------------------------------------------------------------------


def test_get_mac_address_parses_ip_output() -> None:
    out = MagicMock(
        stdout="3: veth0: <UP> mtu 1500 link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff"
    )
    with patch("subprocess.run", return_value=out):
        assert _get_mac_address("veth0") == "aa:bb:cc:dd:ee:ff"


def test_get_mac_address_raises_when_absent() -> None:
    with (
        patch("subprocess.run", return_value=MagicMock(stdout="3: veth0: <UP>")),
        pytest.raises(RuntimeError, match="Could not parse MAC"),
    ):
        _get_mac_address("veth0")


def test_get_mac_address_enters_the_namespace_when_asked() -> None:
    out = MagicMock(stdout="link/ether aa:bb:cc:dd:ee:ff")
    with patch("subprocess.run", return_value=out) as run:
        _get_mac_address("veth0", netns_name="nse_x")
    assert run.call_args[0][0][:4] == ["ip", "netns", "exec", "nse_x"]


def test_get_mac_address_uses_nsenter_in_containers() -> None:
    out = MagicMock(stdout="link/ether aa:bb:cc:dd:ee:ff")
    with patch("subprocess.run", return_value=out) as run:
        _get_mac_address("veth0", netns_name="nse_x", use_nsenter=True)
    assert run.call_args[0][0][0] == "nsenter"


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        (PacketSpec(protocol="tcp", dst_port=80), "TCP(sport=12345, dport=80"),
        (PacketSpec(protocol="udp", dst_port=53), "UDP(sport=12345, dport=53)"),
        (PacketSpec(protocol="icmp"), "ICMP()"),
        (PacketSpec(protocol="icmp", src_ip="fd00::1", dst_ip="fd00::2"), "ICMPv6EchoRequest()"),
    ],
)
def test_build_scapy_script_layer4(spec: PacketSpec, expected: str) -> None:
    script = _build_scapy_script(spec, "veth0", "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02")
    assert expected in script


def test_build_scapy_script_selects_ipv6() -> None:
    spec = PacketSpec(protocol="tcp", src_ip="fd00::1", dst_ip="fd00::2", dst_port=80)
    script = _build_scapy_script(spec, "veth0", "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02")
    assert "IPv6(src='fd00::1'" in script
    assert "IP(src=" not in script


def test_build_scapy_script_carries_tcp_flags() -> None:
    spec = PacketSpec(protocol="tcp", dst_port=80, tcp_flags=["S", "a"])
    script = _build_scapy_script(spec, "veth0", "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02")
    assert "flags='SA'" in script


def test_build_scapy_script_quotes_interface_names() -> None:
    """The script is interpolated into `python3 -c`; unquoted names would be code."""
    spec = PacketSpec(protocol="tcp", dst_port=80)
    script = _build_scapy_script(spec, "veth-a.0", "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02")
    assert "iface='veth-a.0'" in script


# ---------------------------------------------------------------------------
# mock_listener
# ---------------------------------------------------------------------------


def test_start_mock_listener_builds_the_namespace_command() -> None:
    with patch("subprocess.Popen") as popen, patch("time.sleep"):
        start_mock_listener("nse_x", "TCP", 8080)
    cmd = popen.call_args[0][0]
    assert cmd[:4] == ["ip", "netns", "exec", "nse_x"]
    assert "--proto" in cmd
    assert "tcp" in cmd
    assert "8080" in cmd


def test_start_mock_listener_uses_nsenter_in_containers() -> None:
    with patch("subprocess.Popen") as popen, patch("time.sleep"):
        start_mock_listener("nse_x", "udp", 53, use_nsenter=True)
    assert popen.call_args[0][0][0] == "nsenter"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def test_tcp_mock_listener_echoes() -> None:
    port = _free_port()
    threading.Thread(target=run_tcp_server, args=("127.0.0.1", port), daemon=True).start()
    deadline = time.time() + 5.0
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1.0) as client:
                client.sendall(b"ping")
                assert client.recv(16) == b"ping"
                return
        except OSError:
            time.sleep(0.05)
    pytest.fail("TCP mock listener never accepted a connection")


def test_udp_mock_listener_echoes() -> None:
    port = _free_port()
    threading.Thread(target=run_udp_server, args=("127.0.0.1", port), daemon=True).start()
    deadline = time.time() + 5.0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(0.5)
        while time.time() < deadline:
            try:
                client.sendto(b"ping", ("127.0.0.1", port))
                assert client.recv(16) == b"ping"
                return
            except OSError:
                time.sleep(0.05)
    pytest.fail("UDP mock listener never answered")


def test_tcp_mock_listener_exits_when_the_port_is_taken() -> None:
    with socket.socket() as taken:
        taken.bind(("127.0.0.1", 0))
        taken.listen(1)
        port = int(taken.getsockname()[1])
        with pytest.raises(SystemExit) as exc:
            run_tcp_server("127.0.0.1", port)
    assert exc.value.code == 1


def test_udp_mock_listener_exits_when_the_port_is_taken() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as taken:
        taken.bind(("127.0.0.1", 0))
        port = int(taken.getsockname()[1])
        with pytest.raises(SystemExit) as exc:
            run_udp_server("127.0.0.1", port)
    assert exc.value.code == 1


# ---------------------------------------------------------------------------
# NamespaceSandbox
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sandbox_exec_returns_output() -> None:
    from nse.core.netns_controller import NamespaceSandbox

    proc = MagicMock()
    proc.communicate = _async_return((b"hello", b""))
    proc.returncode = 0

    with patch("asyncio.create_subprocess_exec", _async_return(proc)):
        sandbox = NamespaceSandbox(
            MagicMock(exec_prefix=lambda n: ["ip", "netns", "exec", n]), "nse_x"
        )
        result = await sandbox.exec("echo hello")
    assert result.stdout == b"hello"


@pytest.mark.asyncio
async def test_sandbox_exec_raises_on_failure() -> None:
    from nse.core.netns_controller import NamespaceSandbox

    proc = MagicMock()
    proc.communicate = _async_return((b"", b"boom"))
    proc.returncode = 2

    sandbox = NamespaceSandbox(MagicMock(exec_prefix=lambda n: ["ip", "netns", "exec", n]), "nse_x")
    with (
        patch("asyncio.create_subprocess_exec", _async_return(proc)),
        pytest.raises(subprocess.CalledProcessError),
    ):
        await sandbox.exec("false")


@pytest.mark.asyncio
async def test_sandbox_exec_treats_a_missing_returncode_as_failure() -> None:
    from nse.core.netns_controller import NamespaceSandbox

    proc = MagicMock()
    proc.communicate = _async_return((b"", b""))
    proc.returncode = None

    sandbox = NamespaceSandbox(MagicMock(exec_prefix=lambda n: ["ip", "netns", "exec", n]), "nse_x")
    with (
        patch("asyncio.create_subprocess_exec", _async_return(proc)),
        pytest.raises(subprocess.CalledProcessError),
    ):
        await sandbox.exec("hang")


@pytest.mark.asyncio
async def test_sandbox_inject_packet_defaults_the_source_family() -> None:
    from nse.core.netns_controller import NamespaceSandbox

    injector = MagicMock()
    with patch("nse.core.scapy_injector.ScapyInjector", lambda *a, **k: injector):
        sandbox = NamespaceSandbox(MagicMock(), "nse_x")
        await sandbox.inject_packet("udp", 53, "fd00:1::2")
    spec = injector.inject.call_args[0][0]
    assert spec.src_ip == "fd00:1::1"


@pytest.mark.asyncio
async def test_sandbox_inject_packet_defaults_ipv4_source() -> None:
    from nse.core.netns_controller import NamespaceSandbox

    injector = MagicMock()
    with patch("nse.core.scapy_injector.ScapyInjector", lambda *a, **k: injector):
        sandbox = NamespaceSandbox(MagicMock(), "nse_x")
        await sandbox.inject_packet("tcp", 80, "10.0.1.2")
    assert injector.inject.call_args[0][0].src_ip == "10.0.1.1"


def _async_return(value: object):  # type: ignore[no-untyped-def]
    """Build an AsyncMock-like callable returning *value*."""

    async def _inner(*args: object, **kwargs: object) -> object:
        return value

    return _inner


# ---------------------------------------------------------------------------
# ScapyInjector.inject
# ---------------------------------------------------------------------------


def test_injector_detects_the_outgoing_direction() -> None:
    """A packet sourced from the sandbox address must be sent from inside the netns."""
    from nse.core.scapy_injector import ScapyInjector

    spec = PacketSpec(protocol="tcp", src_ip="10.0.0.2", dst_ip="10.0.0.1", dst_port=80)
    with (
        patch("nse.core.scapy_injector._get_mac_address", return_value="aa:bb:cc:dd:ee:ff"),
        patch("subprocess.run", return_value=MagicMock(returncode=0, stdout="", stderr="")) as run,
    ):
        ScapyInjector().inject(spec, "nse_x", "vhr-x", "veth-nse")
    assert run.call_args[0][0][:4] == ["ip", "netns", "exec", "nse_x"]


def test_injector_raises_when_the_outgoing_script_fails() -> None:
    from nse.core.scapy_injector import ScapyInjector

    spec = PacketSpec(protocol="tcp", src_ip="10.0.0.2", dst_ip="10.0.0.1", dst_port=80)
    failed = MagicMock(returncode=1, stdout="", stderr="no such device")
    with (
        patch("nse.core.scapy_injector._get_mac_address", return_value="aa:bb:cc:dd:ee:ff"),
        patch("subprocess.run", return_value=failed),
        pytest.raises(RuntimeError, match="no such device"),
    ):
        ScapyInjector().inject(spec, "nse_x", "vhr-x", "veth-nse")


def test_injector_reports_a_missing_interface_clearly() -> None:
    from nse.core.scapy_injector import ScapyInjector

    spec = PacketSpec(protocol="tcp", dst_port=80)
    with (
        patch(
            "nse.core.scapy_injector._get_mac_address",
            side_effect=subprocess.CalledProcessError(1, "ip"),
        ),
        pytest.raises(RuntimeError, match="Failed to retrieve MAC addresses"),
    ):
        ScapyInjector().inject(spec, "nse_x", "vhr-x", "veth-nse")


def test_injector_looks_up_the_host_mac_in_the_given_namespace() -> None:
    """
    The gateway regression: the router namespace used to be *derived* from the
    interface name as "nse_router_<suffix>", which no code ever creates.
    """
    from nse.core.scapy_injector import ScapyInjector

    spec = PacketSpec(protocol="udp", dst_port=53)
    seen: list[tuple[str, str | None]] = []

    def fake_mac(iface, netns_name=None, use_nsenter=False):  # type: ignore[no-untyped-def]
        seen.append((iface, netns_name))
        return "aa:bb:cc:dd:ee:ff"

    with (
        patch("nse.core.scapy_injector._get_mac_address", side_effect=fake_mac),
        patch("scapy.all.sendp"),
    ):
        ScapyInjector().inject(spec, "nsr_abc", "vrh-abc", "veth-nse", host_netns="nsr_abc")

    assert ("vrh-abc", "nsr_abc") in seen


def test_injector_sends_ipv6_in_process() -> None:
    from nse.core.scapy_injector import ScapyInjector

    spec = PacketSpec(protocol="icmp", src_ip="fd00::1", dst_ip="fd00::2")
    with (
        patch("nse.core.scapy_injector._get_mac_address", return_value="aa:bb:cc:dd:ee:ff"),
        patch("scapy.all.sendp") as sendp,
    ):
        ScapyInjector().inject(spec, "nse_x", "vhr-x", "veth-nse")
    assert sendp.call_count == 1


def test_injector_wraps_scapy_failures() -> None:
    from nse.core.scapy_injector import ScapyInjector

    spec = PacketSpec(protocol="tcp", dst_port=80)
    with (
        patch("nse.core.scapy_injector._get_mac_address", return_value="aa:bb:cc:dd:ee:ff"),
        patch("scapy.all.sendp", side_effect=OSError("interface down")),
        pytest.raises(RuntimeError, match="Packet injection failed"),
    ):
        ScapyInjector().inject(spec, "nse_x", "vhr-x", "veth-nse")


# ---------------------------------------------------------------------------
# PCAPAsserter filter composition
# ---------------------------------------------------------------------------


def test_pcap_asserter_combines_filters() -> None:
    from nse.core.sniffer import PCAPAsserter

    with patch("scapy.all.AsyncSniffer"):
        asserter = PCAPAsserter(iface="veth0", filter="port 53")
    assert asserter.filter == "(not arp and not icmp6) and (port 53)"


def test_pcap_asserter_default_filter() -> None:
    from nse.core.sniffer import PCAPAsserter

    with patch("scapy.all.AsyncSniffer"):
        asserter = PCAPAsserter(iface="veth0")
    assert asserter.filter == "not arp and not icmp6"


# ---------------------------------------------------------------------------
# Model validation
# ---------------------------------------------------------------------------


def test_packet_spec_rejects_unknown_tcp_flags() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="Invalid TCP flag"):
        PacketSpec(protocol="tcp", tcp_flags=["Z"])


def test_packet_spec_upper_cases_tcp_flags() -> None:
    assert PacketSpec(protocol="tcp", tcp_flags=["s", "a"]).tcp_flags == ["S", "A"]


def test_packet_spec_rejects_invalid_ip() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="Invalid IP address"):
        PacketSpec(protocol="tcp", src_ip="10.0.0.256")


def test_is_in_container_via_proc_environ(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("container", raising=False)
    monkeypatch.delenv("CONTAINER", raising=False)
    environ = tmp_path / "environ"
    environ.write_bytes(b"PATH=/usr/bin\x00container=podman\x00")

    real_open = open

    def fake_open(path, *args, **kwargs):  # type: ignore[no-untyped-def]
        if path == "/proc/1/environ":
            return real_open(environ, *args, **kwargs)
        raise OSError("nope")

    with (
        patch("os.path.exists", lambda p: p == "/proc/1/environ"),
        patch("builtins.open", fake_open),
    ):
        assert is_in_container() is True


# ---------------------------------------------------------------------------
# mock_listener entry point and loop resilience
# ---------------------------------------------------------------------------


def test_mock_listener_main_dispatches_tcp() -> None:
    from nse.core import mock_listener

    with patch.object(mock_listener, "run_tcp_server") as tcp:
        mock_listener.main(["--proto", "tcp", "--port", "8080", "--host", "127.0.0.1"])
    tcp.assert_called_once_with("127.0.0.1", 8080)


def test_mock_listener_main_dispatches_udp() -> None:
    from nse.core import mock_listener

    with patch.object(mock_listener, "run_udp_server") as udp:
        mock_listener.main(["--proto", "udp", "--port", "53"])
    udp.assert_called_once_with("::", 53)


def test_mock_listener_main_exits_cleanly_on_interrupt() -> None:
    from nse.core import mock_listener

    with (
        patch.object(mock_listener, "run_tcp_server", side_effect=KeyboardInterrupt),
        pytest.raises(SystemExit) as exc,
    ):
        mock_listener.main(["--proto", "tcp", "--port", "8080"])
    assert exc.value.code == 0


def _looping_socket(accept_effects: list[object]) -> MagicMock:
    sock = MagicMock()
    sock.accept.side_effect = accept_effects
    sock.recvfrom.side_effect = accept_effects
    return sock


def test_tcp_server_recovers_from_a_transient_accept_error() -> None:
    sock = _looping_socket([OSError("EINTR"), KeyboardInterrupt()])
    with patch("socket.socket", return_value=sock), patch("time.sleep") as sleep:
        run_tcp_server("127.0.0.1", 9999)
    assert sleep.called  # backed off instead of spinning


def test_udp_server_recovers_from_a_transient_recv_error() -> None:
    sock = _looping_socket([OSError("EINTR"), KeyboardInterrupt()])
    with patch("socket.socket", return_value=sock), patch("time.sleep") as sleep:
        run_udp_server("127.0.0.1", 9999)
    assert sleep.called


def test_tcp_server_handles_a_client_that_disconnects() -> None:
    """The echo handler must close the connection rather than leak the socket."""
    conn = MagicMock()
    conn.recv.side_effect = [b"hi", b""]
    sock = MagicMock()
    sock.accept.side_effect = [(conn, ("127.0.0.1", 1234)), KeyboardInterrupt()]

    started: list[threading.Thread] = []
    real_thread = threading.Thread

    def capture(*args: object, **kwargs: object) -> threading.Thread:
        thread = real_thread(*args, **kwargs)  # type: ignore[arg-type]
        started.append(thread)
        return thread

    with patch("socket.socket", return_value=sock), patch("threading.Thread", capture):
        run_tcp_server("127.0.0.1", 9999)

    for thread in started:
        thread.join(timeout=2.0)
    conn.sendall.assert_called_once_with(b"hi")
    conn.close.assert_called_once()


def test_tcp_server_client_handler_swallows_socket_errors() -> None:
    conn = MagicMock()
    conn.recv.side_effect = OSError("connection reset")
    sock = MagicMock()
    sock.accept.side_effect = [(conn, ("127.0.0.1", 1234)), KeyboardInterrupt()]

    started: list[threading.Thread] = []
    real_thread = threading.Thread

    def capture(*args: object, **kwargs: object) -> threading.Thread:
        thread = real_thread(*args, **kwargs)  # type: ignore[arg-type]
        started.append(thread)
        return thread

    with patch("socket.socket", return_value=sock), patch("threading.Thread", capture):
        run_tcp_server("127.0.0.1", 9999)

    for thread in started:
        thread.join(timeout=2.0)
    conn.close.assert_called_once()


def test_servers_select_the_ipv6_family_for_ipv6_hosts() -> None:
    sock = MagicMock()
    sock.recvfrom.side_effect = [KeyboardInterrupt()]
    with patch("socket.socket", return_value=sock) as factory:
        run_udp_server("fd00::1", 9999)
    assert factory.call_args[0][0] == socket.AF_INET6


# ---------------------------------------------------------------------------
# HarvestState
# ---------------------------------------------------------------------------


def test_harvest_state_healthiness() -> None:
    """Only these two states mean the oracle did its job; the rest are failures."""
    from nse.core.trace_harvester import HarvestState

    assert HarvestState.STOPPED.is_healthy
    assert HarvestState.RUNNING.is_healthy
    assert not HarvestState.TIMEOUT.is_healthy
    assert not HarvestState.CLEAN_EOF.is_healthy
    assert not HarvestState.ERROR.is_healthy
    assert not HarvestState.NOT_STARTED.is_healthy


# ---------------------------------------------------------------------------
# Packaging
# ---------------------------------------------------------------------------


def test_package_version_matches_pyproject() -> None:
    """
    `nse.__version__` used to be a literal, and it drifted: it still read 2.0.0
    while pyproject declared 2.1.0. Reading it from installed metadata cannot
    drift, and this asserts the metadata matches the source of truth.
    """
    import re

    import nse

    text = (Path(__file__).resolve().parent.parent / "pyproject.toml").read_text()
    # Read it the way .github/workflows/release.yml does, rather than with
    # tomllib: that is stdlib only from 3.11, and this suite runs on 3.10.
    # Matching the workflow's own parse is also the point - it is the string the
    # tag is checked against.
    match = re.search(r'^version = "([^"]+)"', text, re.M)
    assert match is not None, "pyproject.toml has no top-level version"
    assert nse.__version__ == match.group(1)


def test_public_api_is_importable() -> None:
    import nse

    for name in nse.__all__:
        assert hasattr(nse, name), name
