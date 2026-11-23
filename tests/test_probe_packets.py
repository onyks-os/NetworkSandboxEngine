"""The bytes of each stimulus, and finding a stimulus and its reply in a capture."""

from __future__ import annotations

from typing import Any

import pytest
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import ICMPv6EchoReply, ICMPv6EchoRequest, IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from nse.core import probe_packets
from nse.models.stimulus import Endpoint, StimulusResult

PROBE = "0123456789abcdef01234567"


def _result(**fields: Any) -> StimulusResult:
    base: dict[str, Any] = {
        "kind": "udp",
        "transport": "udp",
        "family": 4,
        "probe_id": PROBE,
        "destination": Endpoint(address="192.0.2.1", port=53),
        "source": Endpoint(address="10.0.1.2", port=40000),
        "payload": b"",
        "outcome": "sent",
    }
    base.update(fields)
    return StimulusResult(**base)


def test_the_probe_id_is_found_wherever_it_is_carried() -> None:
    assert probe_packets.extract_probe_id(b"xx" + probe_packets.marker(PROBE)) == PROBE
    assert probe_packets.extract_probe_id(probe_packets.stun_binding_request(PROBE)) == PROBE
    query = probe_packets.dns_query(PROBE, probe_packets.dns_qname(PROBE, "nse.test"), "A")
    assert probe_packets.extract_probe_id(query) == PROBE
    assert probe_packets.extract_probe_id(probe_packets.quic_initial(PROBE)) == PROBE
    assert probe_packets.extract_probe_id(probe_packets.icmp_echo(PROBE, 4)) == PROBE
    assert probe_packets.extract_probe_id(b"nse-probe:short") is None
    assert probe_packets.extract_probe_id(b"\x00" * 40) is None


@pytest.mark.parametrize("family", [4, 6])
def test_icmp_echo_is_a_valid_echo_request(family: int) -> None:
    raw = probe_packets.icmp_echo(PROBE, family)
    if family == 4:
        echo = ICMP(raw)
        assert echo.type == 8
        assert echo.id == int(PROBE[:4], 16)
        assert probe_packets.checksum(raw) == 0  # a correct checksum sums to zero
        assert bytes(echo.payload) == probe_packets.marker(PROBE)
    else:
        assert raw[0] == 128
        assert raw[2:4] == b"\x00\x00"


def test_checksum_of_odd_length_data() -> None:
    assert probe_packets.checksum(b"\x01") == 0xFEFF
    assert probe_packets.checksum(b"\xff\xff\xff\xff") == 0


def test_dns_query_and_response_parsing() -> None:
    query = probe_packets.dns_query(PROBE, "nse-x.example", "AAAA")
    assert query[:2] == bytes.fromhex(PROBE[:4])
    assert query[2:4] == b"\x01\x00"
    parsed = probe_packets.parse_dns(query)
    assert parsed.qname == "nse-x.example"
    assert parsed.rcode_name == "NOERROR"
    # A response with a compressed answer of each family and an unknown rcode.
    answer = (
        query[:2]
        + b"\x81\x8b\x00\x01\x00\x03\x00\x00\x00\x00"
        + query[12:]
        + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\xc0\x00\x02\x01"
        + b"\xc0\x0c\x00\x1c\x00\x01\x00\x00\x00\x3c\x00\x10"
        + bytes(15)
        + b"\x01"
        + b"\xc0\x0c\x00\x10\x00\x01\x00\x00\x00\x3c\x00\x02hi"
    )
    parsed = probe_packets.parse_dns(answer)
    assert parsed.addresses == ("192.0.2.1", "::1")
    assert parsed.rcode == 11
    assert parsed.rcode_name == "RCODE11"


@pytest.mark.parametrize(
    "message",
    [
        b"\x00" * 5,
        b"\x00\x00\x80\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03abc",  # name runs off the end
        b"\x00\x00\x80\x00\x00\x01\x00\x00\x00\x00\x00\x00\xc0\x0c",  # pointer to itself
        b"\x00\x00\x80\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\x01",
    ],
)
def test_malformed_dns_is_a_value_error(message: bytes) -> None:
    with pytest.raises(ValueError):
        probe_packets.parse_dns(message)


def test_invalid_dns_names_are_refused() -> None:
    for name in ("a..b", "x" * 64 + ".test"):
        with pytest.raises(ValueError):
            probe_packets.dns_query(PROBE, name, "A")


@pytest.mark.parametrize(("address", "port"), [("10.0.1.2", 40000), ("fd00:1::2", 3478)])
def test_stun_mapped_address_round_trip(address: str, port: int) -> None:
    from nse._agents.receiver import stun_response

    request = probe_packets.stun_binding_request(PROBE)
    assert len(request) == 20
    assert request[8:20] == bytes.fromhex(PROBE)
    response, label = stun_response(request, (address, port))
    assert label == "binding"
    assert response is not None
    assert probe_packets.parse_stun_mapped_address(response) == Endpoint(address=address, port=port)


def test_stun_parsing_ignores_what_is_not_a_success_response() -> None:
    assert probe_packets.parse_stun_mapped_address(b"\x00" * 10) is None
    request = probe_packets.stun_binding_request(PROBE)
    assert probe_packets.parse_stun_mapped_address(request) is None
    # A success response with only an unknown, padded attribute.
    other = b"\x01\x01\x00\x08" + request[4:20] + b"\x80\x22\x00\x03abc\x00"
    assert probe_packets.parse_stun_mapped_address(other) is None


def test_quic_initial_shape() -> None:
    datagram = probe_packets.quic_initial(PROBE)
    assert len(datagram) == probe_packets.QUIC_INITIAL_SIZE
    assert datagram[0] == 0xC3
    assert datagram[1:5] == b"\x00\x00\x00\x01"
    assert datagram[5] == 8
    assert datagram[6:14] == bytes.fromhex(PROBE[:16])
    length = int.from_bytes(datagram[16:18], "big") & 0x3FFF
    assert 18 + length == len(datagram)  # the Length field covers the rest


def test_family_of_refuses_names() -> None:
    assert probe_packets.family_of("::1") == 6
    with pytest.raises(ValueError):
        probe_packets.family_of("localhost")


# --------------------------------------------------------------------------- captures


def _frame(packet: Any) -> Any:
    return Ether(bytes(Ether() / packet))


def test_udp_requests_and_replies_are_found_by_probe_or_port() -> None:
    result = _result()
    out = _frame(
        IP(src="10.0.1.2", dst="192.0.2.1")
        / UDP(sport=40000, dport=53)
        / Raw(probe_packets.marker(PROBE))
    )
    natted = _frame(  # source rewritten on the way: still the probe
        IP(src="10.9.9.9", dst="192.0.2.1")
        / UDP(sport=1, dport=53)
        / Raw(probe_packets.marker(PROBE))
    )
    other_probe = _frame(
        IP(src="10.0.1.2", dst="192.0.2.1")
        / UDP(sport=1, dport=53)
        / Raw(probe_packets.marker("f" * 24))
    )
    wrong_port = _frame(IP(dst="192.0.2.1") / UDP(sport=40000, dport=54))
    back = _frame(IP(src="192.0.2.1", dst="10.0.1.2") / UDP(sport=53, dport=40000) / Raw(b"x"))
    unrelated = _frame(IP(src="192.0.2.1", dst="10.0.1.2") / UDP(sport=53, dport=1))
    tcp = _frame(IP(dst="192.0.2.1") / TCP(sport=40000, dport=53))
    arp_like = Ether() / Raw(b"\x00" * 30)
    packets = [out, natted, other_probe, wrong_port, back, unrelated, tcp, arp_like]
    assert probe_packets.request_packets(result, packets) == [out, natted]
    assert probe_packets.reply_packets(result, packets) == [back]


def test_a_bare_syn_is_found_by_its_source_port() -> None:
    result = _result(
        kind="tcp_connect", transport="tcp", destination=Endpoint(address="192.0.2.1", port=80)
    )
    syn = _frame(IP(src="10.0.1.2", dst="192.0.2.1") / TCP(sport=40000, dport=80, flags="S"))
    other = _frame(IP(src="10.0.1.2", dst="192.0.2.1") / TCP(sport=40001, dport=80, flags="S"))
    rst = _frame(IP(src="192.0.2.1", dst="10.0.1.2") / TCP(sport=80, dport=40000, flags="RA"))
    assert probe_packets.request_packets(result, [syn, other, rst]) == [syn]
    assert probe_packets.reply_packets(result, [syn, other, rst]) == [rst]


def test_a_result_without_source_is_matched_by_probe_only() -> None:
    result = _result(source=None)
    plain = _frame(IP(dst="192.0.2.1") / UDP(sport=40000, dport=53))
    assert probe_packets.request_packets(result, [plain]) == []


@pytest.mark.parametrize("family", [4, 6])
def test_icmp_echo_and_reply_are_found_by_probe(family: int) -> None:
    dst, src = ("192.0.2.1", "10.0.1.2") if family == 4 else ("2001:db8::1", "fd00:1::2")
    result = _result(
        kind="icmp_echo",
        transport="icmp",
        family=family,
        destination=Endpoint(address=dst, port=0),
        source=None,
    )
    data = probe_packets.marker(PROBE)
    if family == 4:
        request = _frame(IP(src=src, dst=dst) / ICMP(type=8) / Raw(data))
        reply = _frame(IP(src=dst, dst=src) / ICMP(type=0) / Raw(data))
        foreign = _frame(IP(src=src, dst=dst) / ICMP(type=8) / Raw(b"ping"))
        # An ICMP error quoting the request is not its reply.
        error = _frame(IP(src=dst, dst=src) / ICMP(type=3, code=3) / Raw(data))
    else:
        request = _frame(IPv6(src=src, dst=dst) / ICMPv6EchoRequest(data=data))
        reply = _frame(IPv6(src=dst, dst=src) / ICMPv6EchoReply(data=data))
        foreign = _frame(IPv6(src=src, dst=dst) / ICMPv6EchoRequest(data=b"ping"))
        error = _frame(IPv6(src=dst, dst=src) / UDP(sport=1, dport=2) / Raw(data))
    packets = [request, reply, foreign, error]
    assert probe_packets.request_packets(result, packets) == [request]
    assert probe_packets.reply_packets(result, packets) == [reply]
