"""
ScapyInjector — forge and inject raw packets into a network namespace.

The injector uses Scapy's ``sendp()`` (Layer 2) to craft packets from a
``PacketSpec`` and fire them into the veth interface inside the target netns.

How it enters the namespace
---------------------------
Linux does not allow ``sendp()`` to directly target an interface in another
netns from the current process.  We use ``nsenter(1)`` to re-exec a tiny
Python one-liner that builds and sends the packet from *inside* the namespace.
This keeps the NSE daemon process itself in the root namespace while still
operating on the right network context.

Alternatively, for future optimisation, the injector could fork and call
``setns(2)`` via ctypes — but nsenter is simpler and auditable.
"""

from __future__ import annotations

import json
import logging
import subprocess
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from nse.models.test_request import PacketSpec

logger = logging.getLogger("nse.core.scapy_injector")


class ScapyInjector:
    """Build and inject a packet described by a PacketSpec into a netns."""

    def inject(
        self,
        spec: "PacketSpec",
        netns_name: str,
        veth_host: str,
        veth_peer: str,
    ) -> None:
        """
        Construct and send a packet matching *spec* inside or into *netns_name*.

        Args:
            spec:       Packet specification (protocol, IPs, ports, flags).
            netns_name: Name of the target network namespace.
            veth_host:  Host-side interface name.
            veth_peer:  Namespace-side interface name.
        """
        logger.info(
            "Injecting %s packet: %s -> %s (netns=%s)",
            spec.protocol.upper(),
            spec.src_ip,
            spec.dst_ip,
            netns_name,
        )

        try:
            host_mac = _get_mac_address(veth_host)
            peer_mac = _get_mac_address(veth_peer, netns_name)
        except Exception as exc:
            logger.error("Failed to retrieve MAC addresses: %s", exc)
            raise RuntimeError(f"Failed to retrieve MAC addresses: {exc}") from exc

        # Determine injection direction:
        # If the source IP matches the sandbox IP (default 10.0.0.2), it is outgoing (Netns -> Host).
        # Otherwise, it is incoming (Host -> Netns).
        is_incoming = True
        if spec.src_ip == "10.0.0.2":
            is_incoming = False

        if is_incoming:
            # Incoming: Host -> Netns.
            # Src MAC = host, Dst MAC = peer. Send on host interface.
            src_mac = host_mac
            dst_mac = peer_mac
            inject_interface = veth_host
            
            # --- IN-PROCESS OPTIMISATION ---
            # Running this in-process avoids the 200-500ms lag caused by starting a new python
            # interpreter and re-importing scapy in a subprocess.
            try:
                logger.debug("Performing in-process L2 injection on host interface %s", inject_interface)
                from scapy.all import Ether, IP, TCP, UDP, ICMP, sendp, conf
                conf.verb = 0

                proto = spec.protocol.lower()
                src_port = spec.src_port or 12345
                dst_port = spec.dst_port or 80

                # Formulate Layer 4 packet payload
                if proto == "tcp":
                    tcp_flags_str = "".join(spec.tcp_flags) if spec.tcp_flags else ""
                    l4 = TCP(sport=src_port, dport=dst_port, flags=tcp_flags_str)
                elif proto == "udp":
                    l4 = UDP(sport=src_port, dport=dst_port)
                elif proto == "icmp":
                    l4 = ICMP()
                else:
                    l4 = TCP(sport=src_port, dport=dst_port)

                pkt = Ether(src=src_mac, dst=dst_mac) / IP(src=spec.src_ip, dst=spec.dst_ip) / l4
                sendp(pkt, iface=inject_interface, verbose=False)
                logger.debug("In-process packet sent successfully: %s", pkt.summary())
            except Exception as exc:
                logger.error("In-process Scapy injection failed: %s", exc)
                raise RuntimeError(f"Packet injection failed: {exc}") from exc

        else:
            # Outgoing: Netns -> Host.
            # Src MAC = peer, Dst MAC = host. Send on peer interface from inside netns context.
            # Fallback to ip netns exec since we need to change namespace context.
            src_mac = peer_mac
            dst_mac = host_mac
            inject_interface = veth_peer

            script = _build_scapy_script(
                spec=spec,
                interface=inject_interface,
                src_mac=src_mac,
                dst_mac=dst_mac,
            )

            logger.debug("Running injection inside netns %s on interface %s", netns_name, inject_interface)
            cmd = [
                "ip", "netns", "exec", netns_name,
                sys.executable, "-c", script,
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
            )

            if result.returncode != 0:
                logger.error("Scapy injection failed:\n%s", result.stderr)
                raise RuntimeError(f"Packet injection failed: {result.stderr.strip()}")

            logger.debug("Injection stdout: %s", result.stdout.strip())


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_mac_address(interface: str, netns_name: str | None = None) -> str:
    """Retrieve the MAC address of a network interface (optionally in a netns)."""
    import re
    cmd = []
    if netns_name:
        cmd += ["ip", "netns", "exec", netns_name]
    cmd += ["ip", "-o", "link", "show", "dev", interface]

    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    m = re.search(r"link/ether\s+([0-9a-fA-F:]{17})", result.stdout)
    if not m:
        raise RuntimeError(f"Could not parse MAC address for interface {interface} from: {result.stdout}")
    return m.group(1)


def _build_scapy_script(spec: "PacketSpec", interface: str, src_mac: str, dst_mac: str) -> str:
    """
    Build a self-contained Python/Scapy one-liner script.

    Used when switching namespaces via `ip netns exec`.
    """
    proto = spec.protocol.lower()
    src_ip = spec.src_ip or "10.0.0.1"
    dst_ip = spec.dst_ip or "10.0.0.2"
    src_port = spec.src_port or 12345
    dst_port = spec.dst_port or 80

    tcp_flags_str = ""
    if spec.tcp_flags:
        tcp_flags_str = "".join(spec.tcp_flags)

    if proto == "tcp":
        l4 = f"TCP(sport={src_port}, dport={dst_port}, flags={tcp_flags_str!r})"
    elif proto == "udp":
        l4 = f"UDP(sport={src_port}, dport={dst_port})"
    elif proto == "icmp":
        l4 = "ICMP()"
    else:
        l4 = f"TCP(sport={src_port}, dport={dst_port})"

    script = f"""
from scapy.all import Ether, IP, TCP, UDP, ICMP, sendp, conf
conf.verb = 0
pkt = Ether(src={src_mac!r}, dst={dst_mac!r}) / IP(src={src_ip!r}, dst={dst_ip!r}) / {l4}
sendp(pkt, iface={interface!r})
print("Packet sent:", pkt.summary())
"""
    return script
