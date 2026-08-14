# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""
Centralised naming conventions for network namespaces and veth pairs.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class NamespaceNames:
    test_id: str
    netns: str
    router_ns: str
    server_ns: str
    veth_host: str
    veth_router_host: str
    veth_router_server: str
    veth_server: str


def derive_names(test_id: str) -> NamespaceNames:
    """Derive deterministic namespace and veth interface names from test_id."""
    suffix = test_id[:8]
    return NamespaceNames(
        test_id=test_id,
        netns=f"nse_{test_id}",
        router_ns=f"nsr_{test_id}",
        server_ns=f"nss_{test_id}",
        veth_host=f"vhr-{suffix}",
        veth_router_host=f"vrh-{suffix}",
        veth_router_server=f"vrs-{suffix}",
        veth_server=f"vsr-{suffix}",
    )


# Prefixes used by the startup cleanup sweep
NETNS_SWEEP_PREFIXES = ("nse_", "nsr_", "nss_")
VETH_SWEEP_PREFIXES = ("vhr-", "vrh-", "vrs-", "vsr-")
