"""Responses stay available but cannot be counted as additional stimuli."""

from __future__ import annotations

import pytest

from nse.cli.runner import evaluate_case, reduce_verdicts
from nse.core.trace_attribution import TraceAttribution, packet_matches
from nse.core.trace_harvester import _parse_line
from nse.models.test_request import PacketSpec
from nse.models.trace_event import TraceEvent


def hook(trace: str, body: str) -> TraceEvent:
    event = _parse_line(f'trace id {trace} inet nse_trace pre packet: iif "veth0" {body}')
    assert event is not None
    return event


def test_gateway_echo_response_is_retained_without_inflating_the_stimulus_count() -> None:
    packets = [
        PacketSpec(protocol="udp", src_ip="10.0.1.1", dst_ip="10.0.2.2", dst_port=port)
        for port in (53, 80)
    ]
    attribution = TraceAttribution(packets)
    events = []
    for trace, body, verdict in (
        ("a1", "ip saddr 10.0.1.1 ip daddr 10.0.2.2 udp sport 12345 udp dport 53", "ACCEPT"),
        ("a2", "ip saddr 10.0.2.2 ip daddr 10.0.1.1 udp sport 53 udp dport 12345", "DROP"),
        ("a3", "ip saddr 10.0.1.1 ip daddr 10.0.2.2 udp sport 12345 udp dport 80", "DROP"),
    ):
        for event in (
            hook(trace, body),
            TraceEvent(type="verdict", trace_id=trace, table="filter", verdict=verdict),
        ):
            attribution.observe(event)
            events.append(event)
    assert [e.packet_role for e in events] == [
        "stimulus",
        "stimulus",
        "response",
        "response",
        "stimulus",
        "stimulus",
    ]
    assert reduce_verdicts(events) == ["ACCEPT", "DROP"]
    assert evaluate_case("gateway", ["ACCEPT", "DROP"], events).passed
    # A missing or duplicated injected trace still fails the exact count gate.
    assert evaluate_case("missing", ["ACCEPT", "DROP", "DROP"], events).oracle_error
    extra = TraceEvent(
        type="verdict", trace_id="a4", table="filter", verdict="DROP", packet_role="stimulus"
    )
    assert evaluate_case("extra", ["ACCEPT", "DROP"], [*events, extra]).oracle_error


@pytest.mark.parametrize("protocol", ["udp", "tcp", "icmp"])
@pytest.mark.parametrize("ipv6", [False, True])
def test_tuple_matching_normalizes_ipv6_and_checks_ports_and_direction(
    protocol: str, ipv6: bool
) -> None:
    src, dst, layer = ("fd00::1", "fd00::2", "ip6") if ipv6 else ("192.0.2.1", "192.0.2.2", "ip")
    spec = PacketSpec(protocol=protocol, src_ip=src, dst_ip=dst)
    transport = (
        f"{protocol} sport 12345 {protocol} dport 80"
        if protocol != "icmp"
        else f"{'icmpv6' if ipv6 else 'icmp'} type echo-request"
    )
    event = hook("a1", f"{layer} saddr {src} {layer} daddr {dst} {transport}")
    assert packet_matches(event, spec)
    assert not packet_matches(event, spec, reverse=True)
    assert not packet_matches(TraceEvent(type="verdict"), spec)
    if protocol != "icmp":
        event.packet_dst_port = 81
        assert not packet_matches(event, spec)


def test_first_hook_attribution_survives_nat_and_missing_packet_fields() -> None:
    attribution = TraceAttribution([PacketSpec(protocol="udp")])
    first = hook("a1", "ip saddr 10.0.0.1 ip daddr 10.0.0.2 udp sport 12345 udp dport 80")
    attribution.observe(first)
    translated = hook("a1", "ip saddr 203.0.113.1 ip daddr 192.0.2.9 udp sport 12345 udp dport 80")
    attribution.observe(translated)
    assert translated.packet_role == "stimulus"
    background = hook("a2", "ip6 saddr fe80::1 ip6 daddr ff02::16 ip6 nexthdr 0")
    attribution.observe(background)
    assert background.packet_role == "background"
    unidentified = TraceEvent(type="verdict", trace_id="a3", verdict="DROP", table="filter")
    attribution.observe(unidentified)
    assert unidentified.packet_role is None
    attribution.observe(TraceEvent(type="error"))
    # An unclassified verdict is preserved in legacy reduction; never rounded
    # to a clean result simply because packet metadata was missing.
    assert reduce_verdicts([unidentified]) == ["DROP"]
