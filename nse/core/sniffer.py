"""
PCAPAsserter — packet sniffing assertion tool based on Scapy's AsyncSniffer.

Designed for automated headless pipeline testing to verify zero-leak policies.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scapy.packet import Packet

logger = logging.getLogger("nse.core.sniffer")


class PCAPAsserter:
    """
    Asynchronous packet sniffer wrapper based on Scapy's AsyncSniffer.
    Used for asserting that no traffic leaks outside sandbox boundaries.
    """

    def __init__(self, iface: str, filter: str | None = None) -> None:
        from scapy.all import AsyncSniffer

        self.iface = iface
        # Ignore noisy background packets by default:
        # - arp: Address Resolution Protocol
        # - icmp6: IPv6 ICMP Router Solicitation/Advertisement and Neighbor discovery noise
        default_filter = "not arp and not icmp6"
        if filter:
            self.filter = f"({default_filter}) and ({filter})"
        else:
            self.filter = default_filter

        self._sniffer = AsyncSniffer(iface=self.iface, filter=self.filter)

    async def start(self) -> None:
        """Start the async sniffer."""
        logger.info(
            "Starting PCAP sniffer on %s with BPF filter: %s",
            self.iface,
            self.filter,
        )
        self._sniffer.start()

    async def stop(self) -> list[Packet]:
        """Stop the async sniffer and return captured packets."""
        logger.info("Stopping PCAP sniffer on %s", self.iface)
        loop = asyncio.get_running_loop()
        # Sniffer.stop() blocks until the sniffing thread joins, execute in executor
        packets = await loop.run_in_executor(None, self._sniffer.stop)
        return list(packets)
