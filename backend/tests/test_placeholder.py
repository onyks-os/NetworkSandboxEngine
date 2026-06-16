"""
Placeholder tests — ensure the test suite bootstraps cleanly.

Real integration tests (requiring root + nft + Scapy) will live in
tests/integration/ and be gated behind `make integration-test`.
"""

import pytest


def test_imports() -> None:
    """Verify all NSE modules can be imported without errors."""
    import nse
    import nse.cli
    import nse.main
    import nse.api.routes
    import nse.api.websocket
    import nse.core.netns_controller
    import nse.core.rule_engine
    import nse.core.scapy_injector
    import nse.core.trace_harvester
    import nse.core.pipeline
    import nse.models.test_request
    import nse.models.trace_event


def test_packet_spec_validation() -> None:
    """PacketSpec rejects invalid IPs and unknown TCP flags."""
    from nse.models.test_request import PacketSpec
    import pydantic

    # Valid
    spec = PacketSpec(protocol="tcp", src_ip="10.0.0.1", dst_ip="10.0.0.2", dst_port=80)
    assert spec.protocol == "tcp"

    # Invalid IP
    with pytest.raises(pydantic.ValidationError):
        PacketSpec(protocol="tcp", src_ip="999.999.999.999", dst_ip="10.0.0.2")

    # Invalid flag
    with pytest.raises(pydantic.ValidationError):
        PacketSpec(protocol="tcp", src_ip="10.0.0.1", dst_ip="10.0.0.2", tcp_flags=["X"])


def test_trace_event_serialisation() -> None:
    """TraceEvent serialises to JSON without errors."""
    import json
    from nse.models.trace_event import TraceEvent

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
