# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""Kernel observations used to verify journal ownership before deletion."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, TypeAdapter

from nse.core.naming import NETNS_SWEEP_PREFIXES, VETH_SWEEP_PREFIXES
from nse.core.paths import resolve
from nse.core.resource_registry import Resource, namespace_identity


class LinkInfo(BaseModel):
    ifname: str
    ifalias: str | None = None
    address: str | None = None
    ifindex: int | None = None
    link: str | None = None
    link_index: int | None = None


@dataclass(frozen=True)
class Inspection:
    status: Literal["owned", "missing", "foreign"]
    name: str
    netns: str | None = None


class NetworkResources:
    def __init__(self, use_nsenter: bool) -> None:
        self.use_nsenter = use_nsenter

    def prefix(self, netns: str | None) -> list[str]:
        if netns is None:
            return []
        if self.use_nsenter:
            return [resolve("nsenter"), f"--net=/var/run/netns/{netns}", "--"]
        return [resolve("ip"), "netns", "exec", netns]

    def identity(self, netns: str | None) -> tuple[int, int] | None:
        return namespace_identity(netns)

    def links(self, netns: str | None) -> list[LinkInfo]:
        result = subprocess.run(
            [*self.prefix(netns), resolve("ip"), "-j", "link", "show"],
            capture_output=True,
            text=True,
            check=True,
            timeout=5.0,
        )
        return TypeAdapter(list[LinkInfo]).validate_json(result.stdout)

    def inspect(self, resource: Resource, marker: str) -> Inspection:
        if resource.kind == "namespace":
            identity = self.identity(resource.name)
            if identity is None:
                return Inspection("missing", resource.name)
            if resource.identity is not None and identity != resource.identity:
                return Inspection("foreign", resource.name)
            owned = any(
                link.ifname == "lo" and link.ifalias == marker for link in self.links(resource.name)
            )
            return Inspection("owned" if owned else "foreign", resource.name)

        reachable = False
        foreign = False
        creation_links: list[LinkInfo] = []
        for netns, expected, name in (
            (resource.netns, resource.netns_identity, resource.name),
            (resource.peer_netns, resource.peer_identity, resource.peer),
        ):
            identity = self.identity(netns)
            if identity is None or expected is None:
                continue
            if identity != expected:
                foreign = True
                continue
            reachable = True
            links = self.links(netns)
            if netns == resource.netns:
                creation_links = links
            for link in links:
                if link.ifalias == marker:
                    return Inspection("owned", link.ifname, netns)
                if link.ifname == name:
                    foreign = True
        if resource.state == "pending" and self._pending_pair_matches(
            resource, marker, creation_links
        ):
            return Inspection("owned", resource.name, resource.netns)
        return Inspection("foreign" if foreign or not reachable else "missing", resource.name)

    @staticmethod
    def _pending_pair_matches(resource: Resource, marker: str, links: list[LinkInfo]) -> bool:
        first = next((link for link in links if link.ifname == resource.name), None)
        peer = next((link for link in links if link.ifname == resource.peer), None)
        if first is None or peer is None:
            return False
        return (
            (first.address, peer.address) == resource.mac_addresses()
            and first.ifalias in (None, "", marker)
            and peer.ifalias in (None, "", marker)
            and (
                (first.link == peer.ifname and peer.link == first.ifname)
                or (
                    first.ifindex is not None
                    and peer.ifindex is not None
                    and first.link_index == peer.ifindex
                    and peer.link_index == first.ifindex
                )
            )
        )

    def unmarked(self) -> list[str]:
        """Prefix matches are diagnostics, never deletion candidates."""
        result = subprocess.run(
            [resolve("ip"), "netns", "list"],
            capture_output=True,
            text=True,
            check=True,
            timeout=5.0,
        )
        names = [line.split()[0] for line in result.stdout.splitlines() if line.split()]
        resources = []
        for name in names:
            if name.startswith(NETNS_SWEEP_PREFIXES) and not any(
                link.ifname == "lo" and (link.ifalias or "").startswith("nse:")
                for link in self.links(name)
            ):
                resources.append(name)
        resources.extend(
            link.ifname
            for link in self.links(None)
            if link.ifname.startswith(VETH_SWEEP_PREFIXES)
            and not (link.ifalias or "").startswith("nse:")
        )
        return resources
