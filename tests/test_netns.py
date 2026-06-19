"""
Tests for the NSE core headless library.

Mirrors the previous backend/tests/ suite, updated to import from the new
root-level nse/ package layout.

Integration tests (requiring root/netns/scapy) are gated behind pytest.mark.skipif.
"""

import asyncio
import os
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from nse.core.netns_controller import NetnsController
from nse.core.rule_engine import RuleEngine, RuleValidationError
from nse.core.scapy_injector import ScapyInjector
from nse.core.pipeline import parse_conntrack_line
from nse.core.sniffer import PCAPAsserter
from nse.models.test_request import PacketSpec, TopologyType, TestRequest
from nse.models.trace_event import TraceEvent

# Import the trace_harvester parse helper from the gui daemon
from gui.daemon.trace_harvester import _parse_line as _parse_trace_line
from gui.daemon.mock_listener import start_mock_listener

# Determine if running as root
IS_ROOT = os.geteuid() == 0


# ===========================================================================
# 1. NetnsController Tests
# ===========================================================================


@patch("nse.core.netns_controller._run")
def test_netns_lifecycle(mock_run: MagicMock) -> None:
    controller = NetnsController()

    controller.create_netns("nse_test")
    mock_run.assert_any_call(["ip", "netns", "add", "nse_test"])
    assert "nse_test" in controller._active_ns

    controller.destroy_netns("nse_test")
    mock_run.assert_any_call(["ip", "netns", "del", "nse_test"])
    assert "nse_test" not in controller._active_ns


@patch("nse.core.netns_controller._run")
def test_create_veth_pair(mock_run: MagicMock) -> None:
    controller = NetnsController()
    controller.create_veth_pair("nse_test", "veth-host", "veth-nse", "10.0.0.1/24", "10.0.0.2/24")

    calls = [c[0][0] for c in mock_run.call_args_list]
    assert [
        "ip",
        "link",
        "add",
        "veth-host",
        "type",
        "veth",
        "peer",
        "name",
        "veth-nse",
    ] in calls
    assert ["ip", "link", "set", "veth-nse", "netns", "nse_test"] in calls
    assert ["ip", "addr", "add", "10.0.0.1/24", "dev", "veth-host"] in calls
    assert ["ip", "link", "set", "veth-host", "up"] in calls
    assert [
        "ip",
        "netns",
        "exec",
        "nse_test",
        "ip",
        "addr",
        "add",
        "10.0.0.2/24",
        "dev",
        "veth-nse",
    ] in calls


# ===========================================================================
# 2. RuleEngine Tests
# ===========================================================================


@patch("subprocess.run")
def test_rule_engine_validation_success(mock_run: MagicMock) -> None:
    engine = RuleEngine()
    mock_run.return_value = subprocess.CompletedProcess(
        args=["nft", "--check", "-f", "dummy.nft"], returncode=0, stdout="", stderr=""
    )

    engine.validate("table ip filter {}")
    assert mock_run.called


@patch("subprocess.run")
def test_rule_engine_validation_failure(mock_run: MagicMock) -> None:
    engine = RuleEngine()
    mock_run.return_value = subprocess.CompletedProcess(
        args=["nft", "--check", "-f", "dummy.nft"],
        returncode=1,
        stdout="",
        stderr="/tmp/rules_abc.nft:3:12-15: Error: syntax error, unexpected policy",
    )

    with pytest.raises(RuleValidationError) as exc_info:
        engine.validate("table ip filter {}")

    errors = exc_info.value.errors
    assert len(errors) == 1
    assert errors[0]["line"] == 3
    assert "syntax error" in errors[0]["message"]


# ===========================================================================
# 3. ScapyInjector Tests
# ===========================================================================


@patch("scapy.all.sendp")
@patch("nse.core.scapy_injector._get_mac_address")
def test_scapy_injector_incoming(mock_get_mac: MagicMock, mock_sendp: MagicMock) -> None:
    injector = ScapyInjector()

    mock_get_mac.side_effect = lambda dev, *args, **kwargs: {
        "veth-host": "00:11:22:33:44:55",
        "veth-nse": "66:77:88:99:aa:bb",
    }[dev]

    spec = PacketSpec(protocol="tcp", src_ip="10.0.0.1", dst_ip="10.0.0.2")
    injector.inject(spec, "nse_test", "veth-host", "veth-nse")

    mock_sendp.assert_called_once()
    pkt = mock_sendp.call_args[0][0]
    assert pkt.src == "00:11:22:33:44:55"
    assert pkt.dst == "66:77:88:99:aa:bb"
    assert mock_sendp.call_args[1]["iface"] == "veth-host"


@patch("nse.core.scapy_injector._get_mac_address")
@patch("subprocess.run")
def test_scapy_injector_outgoing(mock_run: MagicMock, mock_get_mac: MagicMock) -> None:
    injector = ScapyInjector()

    mock_get_mac.side_effect = lambda dev, *args, **kwargs: {
        "veth-host": "00:11:22:33:44:55",
        "veth-nse": "66:77:88:99:aa:bb",
    }[dev]

    spec = PacketSpec(protocol="tcp", src_ip="10.0.0.2", dst_ip="10.0.0.1")
    mock_run.return_value = subprocess.CompletedProcess(
        args=[], returncode=0, stdout="Packet sent:"
    )

    injector.inject(spec, "nse_test", "veth-host", "veth-nse")

    called_cmd = mock_run.call_args[0][0]
    assert called_cmd[:4] == ["ip", "netns", "exec", "nse_test"]


# ===========================================================================
# 4. TraceHarvester Parser Tests
# ===========================================================================


def test_parse_hook_line() -> None:
    line = 'trace id 1be8aad4 ip filter input packet: iif "veth-nse" ether saddr 00:11:22:33:44:55'
    event = _parse_trace_line(line)

    assert event is not None
    assert event.type == "hook"
    assert event.trace_id == "1be8aad4"
    assert event.family == "ip"
    assert event.table == "filter"
    assert event.chain == "input"
    assert event.hook == "veth-nse"


def test_parse_match_line() -> None:
    line = "trace id 1be8aad4 ip filter input rule 0x4 (handle 3) tcp dport 80 drop (verdict drop)"
    event = _parse_trace_line(line)

    assert event is not None
    assert event.type == "match"
    assert event.trace_id == "1be8aad4"
    assert event.rule_handle == 3
    assert event.rule_text == "tcp dport 80 drop"
    assert event.verdict == "drop"


def test_parse_verdict_line() -> None:
    line = "trace id 1be8aad4 ip filter input verdict accept"
    event = _parse_trace_line(line)

    assert event is not None
    assert event.type == "verdict"
    assert event.trace_id == "1be8aad4"
    assert event.verdict == "ACCEPT"


# ===========================================================================
# 5. Conntrack Parsing Tests
# ===========================================================================


def test_parse_conntrack_line_tcp_established() -> None:
    line = "ipv4     2 tcp      6 115 ESTABLISHED src=10.0.1.1 dst=10.0.2.2 sport=54321 dport=80 src=10.0.2.2 dst=10.0.1.1 sport=80 dport=54321 [ASSURED] mark=0 use=1"
    parsed = parse_conntrack_line(line)
    assert parsed is not None
    assert parsed["proto"] == "TCP"
    assert parsed["state"] == "ESTABLISHED"
    assert parsed["src"] == "10.0.1.1"
    assert parsed["dst"] == "10.0.2.2"
    assert parsed["sport"] == 54321
    assert parsed["dport"] == 80


def test_parse_conntrack_line_tcp_syn_sent() -> None:
    line = "ipv4     2 tcp      6 120 SYN_SENT src=10.0.1.1 dst=10.0.2.2 sport=54321 dport=80 [UNREPLIED] src=10.0.2.2 dst=10.0.1.1 sport=80 dport=54321 mark=0 use=1"
    parsed = parse_conntrack_line(line)
    assert parsed is not None
    assert parsed["proto"] == "TCP"
    assert parsed["state"] == "SYN_SENT"


def test_parse_conntrack_line_udp() -> None:
    line = "ipv4     2 udp      17 29 src=10.0.1.1 dst=10.0.2.2 sport=54321 dport=53 src=10.0.2.2 dst=10.0.1.1 sport=53 dport=54321 mark=0 use=1"
    parsed = parse_conntrack_line(line)
    assert parsed is not None
    assert parsed["proto"] == "UDP"
    assert parsed["state"] == "ESTABLISHED"


def test_parse_conntrack_line_ipv6() -> None:
    line = "ipv6     10 tcp      6 115 ESTABLISHED src=fd00:1::1 dst=fd00:2::2 sport=54321 dport=80 src=fd00:2::2 dst=fd00:1::1 sport=80 dport=54321 [ASSURED] mark=0 use=1"
    parsed = parse_conntrack_line(line)
    assert parsed is not None
    assert parsed["proto"] == "TCP"
    assert parsed["src"] == "fd00:1::1"


# ===========================================================================
# 6. Model Validation Tests
# ===========================================================================


def test_ipv6_packet_spec_validation() -> None:
    spec = PacketSpec(
        protocol="tcp",
        src_ip="fd00:1::1",
        dst_ip="fd00:2::2",
        src_port=123,
        dst_port=456,
    )
    assert spec.src_ip == "fd00:1::1"
    assert spec.dst_ip == "fd00:2::2"

    with pytest.raises(ValueError):
        PacketSpec(protocol="tcp", src_ip="invalid-ip-string", dst_ip="10.0.0.2")


def test_topology_types() -> None:
    assert TopologyType.SIMPLE == "simple"
    assert TopologyType.GATEWAY == "gateway"

    req = TestRequest(
        rules="table ip filter {}",
        packets=[
            PacketSpec(protocol="tcp", src_ip="10.0.0.1", dst_ip="10.0.0.2"),
            PacketSpec(protocol="udp", src_ip="10.0.0.1", dst_ip="10.0.0.2"),
        ],
        topology=TopologyType.GATEWAY,
    )
    assert len(req.packets) == 2
    assert req.topology == TopologyType.GATEWAY


def test_trace_event_serialisation() -> None:
    import json

    event = TraceEvent(
        type="verdict",
        trace_id="abcd1234",
        family="ip",
        table="filter",
        chain="input",
        verdict="DROP",
        timestamp=1700000000.0,
    )
    data = json.loads(event.model_dump_json())
    assert data["type"] == "verdict"
    assert data["verdict"] == "DROP"


# ===========================================================================
# 7. Gateway Topology Setup
# ===========================================================================


@patch("nse.core.netns_controller._run")
def test_create_gateway_topology(mock_run: MagicMock) -> None:
    controller = NetnsController()
    controller.create_gateway_topology(
        router_ns="nse_router_t1",
        server_ns="nse_server_t1",
        veth_host="vhr-t1",
        veth_router_host="vrh-t1",
        veth_router_server="vrs-t1",
        veth_server="veth-nse",
        host_v4="10.0.1.1/24",
        router_host_v4="10.0.1.2/24",
        router_server_v4="10.0.2.1/24",
        server_v4="10.0.2.2/24",
        host_v6="fd00:1::1/64",
        router_host_v6="fd00:1::2/64",
        router_server_v6="fd00:2::1/64",
        server_v6="fd00:2::2/64",
    )

    calls = [c[0][0] for c in mock_run.call_args_list]
    assert ["ip", "netns", "add", "nse_router_t1"] in calls
    assert ["ip", "netns", "add", "nse_server_t1"] in calls
    assert [
        "ip",
        "netns",
        "exec",
        "nse_router_t1",
        "sysctl",
        "-w",
        "net.ipv4.ip_forward=1",
    ] in calls


# ===========================================================================
# 8. Mock Listener Spawning
# ===========================================================================


@patch("subprocess.Popen")
def test_start_mock_listener(mock_popen: MagicMock) -> None:
    mock_popen.return_value = MagicMock()

    start_mock_listener("nse_server_t1", "tcp", 80, "::")

    assert mock_popen.called
    cmd_args = mock_popen.call_args[0][0]
    assert cmd_args[:4] == ["ip", "netns", "exec", "nse_server_t1"]
    assert "--proto" in cmd_args
    assert "tcp" in cmd_args
    assert "--port" in cmd_args
    assert "80" in cmd_args


# ===========================================================================
# 9. PCAPAsserter Mocked Tests (Non-Root)
# ===========================================================================


@patch("nse.core.netns_controller._run")
@pytest.mark.asyncio
async def test_create_namespace_lifecycle_mocked(mock_run: MagicMock) -> None:
    controller = NetnsController()

    controller.create_veth_pair = MagicMock()
    controller.create_netns = MagicMock()
    controller.destroy_netns = MagicMock()

    async with controller.create_namespace("mock_ttp") as ns:
        assert ns.name == "mock_ttp"
        assert ns.ext_iface == "vhr-mock_ttp"
        assert ns.peer_iface == "vrh-mock_ttp"

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = MagicMock()
            fut = asyncio.Future()
            fut.set_result((b"output", b""))
            mock_proc.communicate = MagicMock(return_value=fut)
            mock_proc.returncode = 0
            mock_exec.return_value = mock_proc

            res = await ns.exec("echo hello")
            assert res.returncode == 0
            assert res.stdout == b"output"

    assert controller.destroy_netns.called


@patch("scapy.all.AsyncSniffer")
@pytest.mark.asyncio
async def test_pcap_asserter_mocked(mock_sniffer_cls: MagicMock) -> None:
    mock_sniffer = MagicMock()
    mock_sniffer_cls.return_value = mock_sniffer

    asserter = PCAPAsserter(iface="vhr-mock", filter="port 80")
    assert "port 80" in asserter.filter

    await asserter.start()
    assert mock_sniffer.start.called

    mock_sniffer.stop.return_value = ["packet1", "packet2"]
    captured = await asserter.stop()
    assert captured == ["packet1", "packet2"]


# ===========================================================================
# 10. Real Integration Tests (Requires Root)
# ===========================================================================


@pytest.mark.skipif(not IS_ROOT, reason="Requires root/sudo privileges")
@pytest.mark.asyncio
async def test_real_namespace_context_manager() -> None:
    controller = NetnsController()

    async with controller.create_namespace("ttp_real") as ns:
        res = await ns.exec("ip link show lo")
        assert res.returncode == 0
        assert b"UP" in res.stdout
        assert os.path.exists(f"/sys/class/net/{ns.ext_iface}")

    assert not os.path.exists(f"/sys/class/net/{ns.ext_iface}")

    with pytest.raises(subprocess.CalledProcessError):
        subprocess.run(
            ["ip", "netns", "exec", "ttp_real", "ip", "addr"],
            check=True,
            capture_output=True,
        )


@pytest.mark.skipif(not IS_ROOT, reason="Requires root/sudo privileges")
@pytest.mark.asyncio
async def test_real_pcap_assertion() -> None:
    controller = NetnsController()

    async with controller.create_namespace(
        "ttp_pcap", host_ip="10.0.0.1/24", peer_ip="10.0.0.2/24"
    ) as ns:
        # Give Linux kernel a moment to transition veth link state to UP
        await asyncio.sleep(0.5)

        # Arm the sniffer on the host interface
        sniffer = PCAPAsserter(iface=ns.ext_iface, filter="udp port 53")
        await sniffer.start()

        # Inject a DNS UDP packet originating from inside the namespace (Netns -> Host)
        await ns.inject_packet(protocol="udp", dst_port=53, dst_ip="8.8.8.8", src_ip="10.0.0.2")

        # Let the packet propagate
        await asyncio.sleep(0.15)

        captured = await sniffer.stop()
        assert len(captured) >= 1


@pytest.mark.asyncio
async def test_rootd_rpc_communication(tmp_path) -> None:
    from gui.rootd import RootDaemon
    from gui.api.rootd_client import RootdClient
    from nse.models.test_request import TestRequest

    socket_path = str(tmp_path / "test-nse-core.sock")
    daemon = RootDaemon(socket_path=socket_path)
    await daemon.start()

    client = RootdClient(socket_path=socket_path)

    try:
        from unittest.mock import patch

        with (
            patch("gui.rootd.RuleEngine") as mock_engine_cls,
            patch.object(daemon.controller, "enqueue_test") as mock_enqueue,
            patch.object(daemon.controller, "get_status") as mock_get_status,
            patch.object(daemon.controller, "has_test") as mock_has_test,
            patch.object(daemon.controller, "get_event_queue") as mock_get_event_queue,
        ):
            mock_engine = mock_engine_cls.return_value
            mock_engine.validate.return_value = None

            # Test validate_rules
            await client.validate_rules("table ip filter { chain input {} }")
            mock_engine.validate.assert_called_with("table ip filter { chain input {} }")

            # Test submit_test
            from nse.models.test_request import PacketSpec

            mock_enqueue.return_value = None
            req = TestRequest(rules="rules", packets=[PacketSpec(protocol="tcp")])
            await client.submit_test(test_id="test1", request=req)
            mock_enqueue.assert_called_once()

            # Test get_status
            from nse.models.trace_event import TestStatusResponse

            mock_get_status.return_value = TestStatusResponse(test_id="test1", status="running")
            status_res = await client.get_status("test1")
            assert status_res.status == "running"
            mock_get_status.assert_called_with("test1")

            # Test stream_events
            mock_has_test.return_value = True
            queue = asyncio.Queue()
            mock_get_event_queue.return_value = queue

            from nse.models.trace_event import TraceEvent

            event = TraceEvent(
                type="hook", trace_id="123", family="ip", table="filter", chain="input"
            )
            await queue.put(event)
            await queue.put(None)  # Sentinel

            events = []
            async for ev in client.stream_events("test1"):
                events.append(ev)

            assert len(events) == 2
            assert events[0].trace_id == "123"
            assert events[1] is None

    finally:
        await daemon.shutdown()
