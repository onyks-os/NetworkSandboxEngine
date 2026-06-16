import pytest
from unittest.mock import MagicMock, patch
import subprocess

from nse.core.netns_controller import NetnsController
from nse.core.rule_engine import RuleEngine, RuleValidationError
from nse.core.scapy_injector import ScapyInjector
from nse.core.trace_harvester import _parse_line
from nse.models.test_request import PacketSpec


# ===========================================================================
# 1. NetnsController Tests
# ===========================================================================

@patch("nse.core.netns_controller._run")
def test_netns_lifecycle(mock_run: MagicMock) -> None:
    controller = NetnsController()
    
    # Test creation
    controller.create_netns("nse_test")
    mock_run.assert_any_call(["ip", "netns", "add", "nse_test"])
    assert "nse_test" in controller._active_ns
    
    # Test destruction
    controller.destroy_netns("nse_test")
    mock_run.assert_any_call(["ip", "netns", "del", "nse_test"])
    assert "nse_test" not in controller._active_ns


@patch("nse.core.netns_controller._run")
def test_create_veth_pair(mock_run: MagicMock) -> None:
    controller = NetnsController()
    controller.create_veth_pair("nse_test", "veth-host", "veth-nse", "10.0.0.1/24", "10.0.0.2/24")
    
    # Check that it called the commands to create, move, and configure the interfaces
    calls = [c[0][0] for c in mock_run.call_args_list]
    assert ["ip", "link", "add", "veth-host", "type", "veth", "peer", "name", "veth-nse"] in calls
    assert ["ip", "link", "set", "veth-nse", "netns", "nse_test"] in calls
    assert ["ip", "addr", "add", "10.0.0.1/24", "dev", "veth-host"] in calls
    assert ["ip", "link", "set", "veth-host", "up"] in calls
    assert ["ip", "netns", "exec", "nse_test", "ip", "addr", "add", "10.0.0.2/24", "dev", "veth-nse"] in calls


# ===========================================================================
# 2. RuleEngine Tests
# ===========================================================================

@patch("subprocess.run")
def test_rule_engine_validation_success(mock_run: MagicMock) -> None:
    engine = RuleEngine()
    mock_run.return_value = subprocess.CompletedProcess(
        args=["nft", "--check", "-f", "dummy.nft"],
        returncode=0,
        stdout="",
        stderr=""
    )
    
    # Should not raise any error
    engine.validate("table ip filter {}")
    assert mock_run.called


@patch("subprocess.run")
def test_rule_engine_validation_failure(mock_run: MagicMock) -> None:
    engine = RuleEngine()
    mock_run.return_value = subprocess.CompletedProcess(
        args=["nft", "--check", "-f", "dummy.nft"],
        returncode=1,
        stdout="",
        stderr="/tmp/rules_abc.nft:3:12-15: Error: syntax error, unexpected policy"
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
    
    # Mock MAC address lookups
    mock_get_mac.side_effect = lambda dev, *args, **kwargs: {
        "veth-host": "00:11:22:33:44:55",
        "veth-nse": "66:77:88:99:aa:bb"
    }[dev]
    
    # Incoming packet: src 10.0.0.1 -> dst 10.0.0.2 (local netns IP)
    spec = PacketSpec(protocol="tcp", src_ip="10.0.0.1", dst_ip="10.0.0.2")
    
    injector.inject(spec, "nse_test", "veth-host", "veth-nse")
    
    # Incoming should run in-process using sendp directly
    mock_sendp.assert_called_once()
    pkt = mock_sendp.call_args[0][0]
    
    assert pkt.src == "00:11:22:33:44:55"
    assert pkt.dst == "66:77:88:99:aa:bb"
    assert mock_sendp.call_args[1]["iface"] == "veth-host"


@patch("nse.core.scapy_injector._get_mac_address")
@patch("subprocess.run")
def test_scapy_injector_outgoing(mock_run: MagicMock, mock_get_mac: MagicMock) -> None:
    injector = ScapyInjector()
    
    # Mock MAC address lookups
    mock_get_mac.side_effect = lambda dev, *args, **kwargs: {
        "veth-host": "00:11:22:33:44:55",
        "veth-nse": "66:77:88:99:aa:bb"
    }[dev]
    
    # Outgoing packet: src 10.0.0.2 (netns IP) -> dst 10.0.0.1
    spec = PacketSpec(protocol="tcp", src_ip="10.0.0.2", dst_ip="10.0.0.1")
    
    mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="Packet sent:")
    
    injector.inject(spec, "nse_test", "veth-host", "veth-nse")
    
    # Outgoing should run INSIDE the netns
    called_cmd = mock_run.call_args[0][0]
    assert called_cmd[:4] == ["ip", "netns", "exec", "nse_test"]


# ===========================================================================
# 4. TraceHarvester Parser Tests
# ===========================================================================

def test_parse_hook_line() -> None:
    line = 'trace id 1be8aad4 ip filter input packet: iif "veth-nse" ether saddr 00:11:22:33:44:55'
    event = _parse_line(line)
    
    assert event is not None
    assert event.type == "hook"
    assert event.trace_id == "1be8aad4"
    assert event.family == "ip"
    assert event.table == "filter"
    assert event.chain == "input"
    assert event.hook == "veth-nse"


def test_parse_match_line() -> None:
    line = 'trace id 1be8aad4 ip filter input rule 0x4 (handle 3) tcp dport 80 drop (verdict drop)'
    event = _parse_line(line)
    
    assert event is not None
    assert event.type == "match"
    assert event.trace_id == "1be8aad4"
    assert event.family == "ip"
    assert event.table == "filter"
    assert event.chain == "input"
    assert event.rule_handle == 3
    assert event.rule_text == "tcp dport 80 drop"
    assert event.verdict == "drop"


def test_parse_verdict_line() -> None:
    line = 'trace id 1be8aad4 ip filter input verdict accept'
    event = _parse_line(line)
    
    assert event is not None
    assert event.type == "verdict"
    assert event.trace_id == "1be8aad4"
    assert event.family == "ip"
    assert event.table == "filter"
    assert event.chain == "input"
    assert event.verdict == "ACCEPT"
