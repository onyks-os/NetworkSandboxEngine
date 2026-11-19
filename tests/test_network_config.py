"""Topology addresses and CLI network settings are explicit and validated."""

import pytest
from pydantic import ValidationError

from nse.cli.runner import SuiteConfigError, build_case
from nse.core.naming import derive_names
from nse.core.netns_controller import NamespaceSandbox, NetnsController
from nse.models.network_config import GatewayNetwork, SimpleNetwork
from nse.models.test_request import TestRequest


def test_whole_identity_changes_interface_names_and_stays_within_kernel_limit() -> None:
    a, b = derive_names("sameprefix-first"), derive_names("sameprefix-second")
    assert a.veth_host != b.veth_host
    assert len(a.veth_host) == len(b.veth_host) == 15
    assert (
        NamespaceSandbox(None, a.test_id).ext_iface != NamespaceSandbox(None, b.test_id).ext_iface
    )


@pytest.mark.parametrize(
    "values",
    [
        {"host_v4": "10.0.0.1"},
        {"host_v4": "invalid"},
        {"host_v4": "fd00::1/64"},
        {"peer_v4": "10.0.0.1/24"},
        {"peer_v4": "10.0.1.2/24"},
        {"unknown": "10.0.0.1/24"},
    ],
)
def test_simple_network_rejects_invalid_or_ambiguous_settings(values: dict[str, str]) -> None:
    with pytest.raises(ValidationError):
        SimpleNetwork(**values)


def test_gateway_network_rejects_overlapping_host_and_server_links() -> None:
    with pytest.raises(ValidationError, match="must not overlap"):
        GatewayNetwork(router_server_v4="10.0.1.3/24", server_v4="10.0.1.4/24")


@pytest.mark.parametrize(
    ("mode", "model"), [("simple", SimpleNetwork), ("gateway", GatewayNetwork)]
)
def test_network_model_is_selected_from_the_topology(mode, model) -> None:
    request = TestRequest.model_validate(
        {
            "rules": "table ip f {}",
            "topology": mode,
            "packets": [{"protocol": "udp"}],
            "network": {},
        }
    )
    assert isinstance(request.network, model)
    assert TestRequest.model_validate(request.model_dump()).network == request.network


def test_simple_network_lists_do_not_silently_discard_extra_addresses() -> None:
    with pytest.raises(ValueError, match="at most one address"):
        NetnsController._simple_network(["10.0.0.1/24", "10.0.0.3/24"], "10.0.0.2/24")


def test_cli_uses_explicit_network_for_default_packet_addresses() -> None:
    _, request, _ = build_case(
        {
            "rules": "table ip f {}",
            "topology": "gateway",
            "network": {
                "host_v4": "198.18.10.1/24",
                "router_host_v4": "198.18.10.2/24",
                "router_server_v4": "198.18.11.1/24",
                "server_v4": "198.18.11.2/24",
            },
            "packets": [{"protocol": "udp"}],
        },
        0,
    )
    assert request.packets[0].src_ip == "198.18.10.1"
    assert request.packets[0].dst_ip == "198.18.11.2"
    with pytest.raises(SuiteConfigError, match="invalid network"):
        build_case({"rules": "table ip f {}", "network": {"host_v4": "invalid"}}, 0)
