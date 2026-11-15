"""Explicit dual stack addresses for independent topology experiments."""

from __future__ import annotations

from ipaddress import ip_interface

from pydantic import BaseModel, ConfigDict, model_validator
from typing_extensions import Self


class SimpleNetwork(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    host_v4: str = "10.0.0.1/24"
    peer_v4: str = "10.0.0.2/24"
    host_v6: str = "fd00::1/64"
    peer_v6: str = "fd00::2/64"

    @model_validator(mode="after")
    def check_addresses(self) -> Self:
        _check_pair(self.host_v4, self.peer_v4, 4)
        _check_pair(self.host_v6, self.peer_v6, 6)
        return self


class GatewayNetwork(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    host_v4: str = "10.0.1.1/24"
    router_host_v4: str = "10.0.1.2/24"
    router_server_v4: str = "10.0.2.1/24"
    server_v4: str = "10.0.2.2/24"
    host_v6: str = "fd00:1::1/64"
    router_host_v6: str = "fd00:1::2/64"
    router_server_v6: str = "fd00:2::1/64"
    server_v6: str = "fd00:2::2/64"

    @model_validator(mode="after")
    def check_addresses(self) -> Self:
        _check_pair(self.host_v4, self.router_host_v4, 4)
        _check_pair(self.router_server_v4, self.server_v4, 4)
        _check_pair(self.host_v6, self.router_host_v6, 6)
        _check_pair(self.router_server_v6, self.server_v6, 6)
        for host, server in ((self.host_v4, self.server_v4), (self.host_v6, self.server_v6)):
            if ip_interface(host).network.overlaps(ip_interface(server).network):
                raise ValueError("gateway host and server subnets must not overlap")
        return self


def _check_pair(first: str, second: str, version: int) -> None:
    if "/" not in first or "/" not in second:
        raise ValueError("topology addresses require an explicit prefix length")
    a, b = ip_interface(first), ip_interface(second)
    if a.version != version or b.version != version:
        raise ValueError(f"expected IPv{version} interface addresses")
    if a.network != b.network or a.ip == b.ip:
        raise ValueError("link endpoints require distinct addresses in the same subnet")
