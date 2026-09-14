# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""
PCAPAsserter: packet sniffing assertion tool based on Scapy's AsyncSniffer.

Designed for automated headless pipeline testing to verify zero-leak policies.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scapy.packet import Packet

logger = logging.getLogger("nse.core.sniffer")

#: ICMPv6 message types 133-137: Router Solicitation, Router Advertisement,
#: Neighbour Solicitation, Neighbour Advertisement and Redirect. All of them are
#: link-local by definition - they carry a hop limit of 255 and are discarded by
#: the first router - so none can reach a remote observer and none belongs in a
#: leak assertion.
ND_TYPE_MIN = 133
ND_TYPE_MAX = 137

#: Background chatter suppressed on every capture unless a caller opts out.
#:
#: This used to read ``not arp and not icmp6``, which was broader than the noise
#: it meant to describe. ICMPv6 is not only Neighbour Discovery: the expression
#: also discarded echo request/reply to a **globally routable** address, which is
#: cleartext traffic leaving the host - precisely what a class named for
#: "asserting that no traffic leaks outside sandbox boundaries" exists to catch.
#: Because the filter is compiled into BPF, those packets never reached
#: userspace, so no consumer could see or recover them.
#:
#: Narrowed to the ND types the comment always claimed. See
#: https://github.com/onyks-os/NetworkSandboxEngine/issues/14.
DEFAULT_FILTER = (
    f"not arp and not (icmp6 and icmp6[icmp6type] >= {ND_TYPE_MIN} "
    f"and icmp6[icmp6type] <= {ND_TYPE_MAX})"
)


class PCAPAsserter:
    """
    Asynchronous packet sniffer wrapper based on Scapy's AsyncSniffer.
    Used for asserting that no traffic leaks outside sandbox boundaries.
    """

    def __init__(
        self,
        iface: str,
        filter: str | None = None,
        *,
        replace_default_filter: bool = False,
    ) -> None:
        """
        Arm a sniffer on *iface*.

        *filter* is combined with :data:`DEFAULT_FILTER` unless
        *replace_default_filter* is set, in which case it is used alone. The
        override exists because the default is compiled into BPF and evaluated
        in the kernel: a packet it excludes never reaches userspace, so a caller
        that needs to assert on suppressed traffic cannot compensate downstream.
        Combining is the safe default; replacing is the escape hatch.
        """
        from scapy.all import AsyncSniffer

        self.iface = iface
        if filter and replace_default_filter:
            self.filter = filter
        elif filter:
            self.filter = f"({DEFAULT_FILTER}) and ({filter})"
        else:
            self.filter = DEFAULT_FILTER

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
        packets = await loop.run_in_executor(None, self._sniffer.stop)
        return list(packets) if packets is not None else []
