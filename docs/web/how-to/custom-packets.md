# How-To: Custom Packet Specifications

NSE allows forging custom TCP, UDP, and ICMP packets across IPv4 and IPv6 protocols using `PacketSpec`.

---

## PacketSpec Schema

```python
from pydantic import BaseModel, Field
from typing import Literal

class PacketSpec(BaseModel):
    protocol: Literal["tcp", "udp", "icmp"] = Field(description="Layer 4 protocol")
    src_ip: str = Field(default="10.0.0.1", description="Source IPv4 or IPv6 address")
    dst_ip: str = Field(default="10.0.0.2", description="Destination IPv4 or IPv6 address")
    src_port: int | None = Field(default=12345, description="Source port for TCP/UDP")
    dst_port: int | None = Field(default=80, description="Destination port for TCP/UDP")
    tcp_flags: list[str] | None = Field(default=None, description="TCP flags, e.g. ['SYN', 'ACK']")
```

---

## TCP Flags & State Testing

Forge TCP packets with specific flags:

```python
# SYN Packet
syn_packet = PacketSpec(
    protocol="tcp",
    src_ip="10.0.0.1",
    dst_ip="10.0.0.2",
    dst_port=443,
    tcp_flags=["SYN"]
)

# ACK Packet
ack_packet = PacketSpec(
    protocol="tcp",
    src_ip="10.0.0.1",
    dst_ip="10.0.0.2",
    dst_port=443,
    tcp_flags=["ACK"]
)
```

---

## IPv6 Packets

Specify IPv6 addresses for automatic IPv6 / ICMPv6 injection:

```python
ipv6_packet = PacketSpec(
    protocol="icmp",
    src_ip="fd00:1::1",
    dst_ip="fd00:2::2",
)
```
