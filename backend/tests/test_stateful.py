import pytest
from unittest.mock import MagicMock, patch
import subprocess

from nse.models.test_request import PacketSpec, TopologyType, TestRequest
from nse.core.netns_controller import NetnsController
from nse.core.pipeline import parse_conntrack_line, read_conntrack_table
from nse.core.mock_listener import start_mock_listener


# ===========================================================================
# 1. Conntrack Parsing Tests
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
    assert parsed["src"] == "10.0.1.1"
    assert parsed["dst"] == "10.0.2.2"
    assert parsed["sport"] == 54321
    assert parsed["dport"] == 80


def test_parse_conntrack_line_udp() -> None:
    line = "ipv4     2 udp      17 29 src=10.0.1.1 dst=10.0.2.2 sport=54321 dport=53 src=10.0.2.2 dst=10.0.1.1 sport=53 dport=54321 mark=0 use=1"
    parsed = parse_conntrack_line(line)
    assert parsed is not None
    assert parsed["proto"] == "UDP"
    assert parsed["state"] == "ESTABLISHED"  # Default fallback state for non-TCP
    assert parsed["src"] == "10.0.1.1"
    assert parsed["dst"] == "10.0.2.2"
    assert parsed["sport"] == 54321
    assert parsed["dport"] == 53


def test_parse_conntrack_line_ipv6() -> None:
    line = "ipv6     10 tcp      6 115 ESTABLISHED src=fd00:1::1 dst=fd00:2::2 sport=54321 dport=80 src=fd00:2::2 dst=fd00:1::1 sport=80 dport=54321 [ASSURED] mark=0 use=1"
    parsed = parse_conntrack_line(line)
    assert parsed is not None
    assert parsed["proto"] == "TCP"
    assert parsed["state"] == "ESTABLISHED"
    assert parsed["src"] == "fd00:1::1"
    assert parsed["dst"] == "fd00:2::2"
    assert parsed["sport"] == 54321
    assert parsed["dport"] == 80


# ===========================================================================
# 2. IPv6 Address Validation
# ===========================================================================

def test_ipv6_packet_spec_validation() -> None:
    # Valid IPv6 addresses should work
    spec = PacketSpec(protocol="tcp", src_ip="fd00:1::1", dst_ip="fd00:2::2", src_port=123, dst_port=456)
    assert spec.src_ip == "fd00:1::1"
    assert spec.dst_ip == "fd00:2::2"

    # Invalid addresses should raise error
    with pytest.raises(ValueError):
        PacketSpec(protocol="tcp", src_ip="invalid-ip-string", dst_ip="10.0.0.2")


# ===========================================================================
# 3. Topology Options
# ===========================================================================

def test_topology_types() -> None:
    assert TopologyType.SIMPLE == "simple"
    assert TopologyType.GATEWAY == "gateway"

    # Verify TestRequest initialization works with multiple packets and topology
    req = TestRequest(
        rules="table ip filter {}",
        packets=[
            PacketSpec(protocol="tcp", src_ip="10.0.0.1", dst_ip="10.0.0.2"),
            PacketSpec(protocol="udp", src_ip="10.0.0.1", dst_ip="10.0.0.2")
        ],
        topology=TopologyType.GATEWAY
    )
    assert len(req.packets) == 2
    assert req.topology == TopologyType.GATEWAY


# ===========================================================================
# 4. Gateway Topology Setup
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
        server_v6="fd00:2::2/64"
    )

    calls = [c[0][0] for c in mock_run.call_args_list]
    
    # Verify namespaces are created
    assert ["ip", "netns", "add", "nse_router_t1"] in calls
    assert ["ip", "netns", "add", "nse_server_t1"] in calls

    # Verify routing and forwarding is enabled
    assert ["ip", "netns", "exec", "nse_router_t1", "sysctl", "-w", "net.ipv4.ip_forward=1"] in calls
    assert ["ip", "netns", "exec", "nse_router_t1", "sysctl", "-w", "net.ipv6.conf.all.forwarding=1"] in calls

    # Verify double links configuration
    assert ["ip", "link", "add", "vhr-t1", "type", "veth", "peer", "name", "vrh-t1"] in calls
    assert ["ip", "addr", "add", "10.0.1.1/24", "dev", "vhr-t1"] in calls
    assert ["ip", "addr", "add", "fd00:1::1/64", "dev", "vhr-t1"] in calls
    assert ["ip", "route", "add", "10.0.2.0/24", "via", "10.0.1.2", "dev", "vhr-t1"] in calls


# ===========================================================================
# 5. Mock Listener Spawning
# ===========================================================================

@patch("subprocess.Popen")
def test_start_mock_listener(mock_popen: MagicMock) -> None:
    mock_popen.return_value = MagicMock()
    
    # We spawn a background TCP listener on port 80 inside the server namespace
    proc = start_mock_listener("nse_server_t1", "tcp", 80, "::")
    
    assert mock_popen.called
    cmd_args = mock_popen.call_args[0][0]
    
    # Check that ip netns exec is used along with command args
    assert cmd_args[:4] == ["ip", "netns", "exec", "nse_server_t1"]
    assert "--proto" in cmd_args
    assert "tcp" in cmd_args
    assert "--port" in cmd_args
    assert "80" in cmd_args
