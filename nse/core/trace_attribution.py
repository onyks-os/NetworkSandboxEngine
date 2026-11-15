"""Attribute traces before NAT while retaining responses and background events."""

from __future__ import annotations

from ipaddress import ip_address
from typing import Literal

from nse.models.test_request import PacketSpec
from nse.models.trace_event import TraceEvent


def packet_matches(event: TraceEvent, spec: PacketSpec, *, reverse: bool = False) -> bool:
    source, destination = (spec.dst_ip, spec.src_ip) if reverse else (spec.src_ip, spec.dst_ip)
    if (
        not event.packet_src_ip
        or not event.packet_dst_ip
        or ip_address(event.packet_src_ip) != ip_address(source)
        or ip_address(event.packet_dst_ip) != ip_address(destination)
        or event.packet_protocol != spec.protocol
    ):
        return False
    if spec.protocol == "icmp":
        return True
    sport, dport = spec.src_port or 12345, spec.dst_port or 80
    if reverse:
        sport, dport = dport, sport
    return (event.packet_src_port, event.packet_dst_port) == (sport, dport)


class TraceAttribution:
    def __init__(self, packets: list[PacketSpec]) -> None:
        self.packets = packets
        self.roles: dict[str, Literal["stimulus", "response", "background"]] = {}

    def observe(self, event: TraceEvent) -> None:
        if not event.trace_id:
            return
        if event.trace_id not in self.roles and event.packet_src_ip and event.packet_dst_ip:
            # The first hook precedes user NAT chains. Later hooks may expose
            # translated addresses; they must inherit, not replace, attribution.
            role: Literal["stimulus", "response", "background"] = "background"
            if any(packet_matches(event, packet) for packet in self.packets):
                role = "stimulus"
            elif any(packet_matches(event, packet, reverse=True) for packet in self.packets):
                role = "response"
            self.roles[event.trace_id] = role
        event.packet_role = self.roles.get(event.trace_id)
