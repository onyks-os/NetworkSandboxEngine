"""
TraceHarvester — parse `nft monitor trace` output into TraceEvent objects.

nft monitor trace emits lines like:

    trace id 1be8aad4 ip filter input packet: iif "veth0" ...
    trace id 1be8aad4 ip filter input rule 0x4 (handle 3) tcp dport 80 accept (verdict accept)
    trace id 1be8aad4 ip filter input verdict accept
    trace id 1be8aad4 ip filter input policy accept

Each line is parsed into a TraceEvent and pushed onto an asyncio.Queue
that the WebSocket handler reads from.

The sentinel value ``None`` is pushed when monitoring ends (process exits or
times out) to signal the WebSocket to send a "done" event and close.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from nse.models.trace_event import TraceEvent

logger = logging.getLogger("nse.core.trace_harvester")

# --- Regex patterns for nft monitor trace output --------------------------

_PACKET_RE = re.compile(
    r"trace id (?P<trace_id>\w+) (?P<family>\w+) (?P<table>\w+) (?P<chain>\w+) "
    r"packet: iif \"(?P<iif>[^\"]+)\""
)
_RULE_RE = re.compile(
    r"trace id (?P<trace_id>\w+) (?P<family>\w+) (?P<table>\w+) (?P<chain>\w+) "
    r"rule (?:(?P<rule_id>0x[\da-f]+) \(handle (?P<handle>\d+)\) )?(?P<rule_text>.+?)"
    r"(?: \(verdict (?P<verdict>\w+)\))?$"
)
_VERDICT_RE = re.compile(
    r"trace id (?P<trace_id>\w+) (?P<family>\w+) (?P<table>\w+) (?P<chain>\w+) "
    r"(?:verdict|policy) (?P<verdict>\w+)"
)


class TraceHarvester:
    """
    Async subprocess wrapper for `nft monitor trace`.

    Usage::

        harvester = TraceHarvester()
        await harvester.start(netns_name="nse_abc", queue=event_queue)
        # later…
        harvester.stop()
    """

    def __init__(self) -> None:
        self._proc: asyncio.subprocess.Process | None = None
        self._task: asyncio.Task | None = None

    async def start(
        self,
        netns_name: str,
        queue: "asyncio.Queue[TraceEvent | None]",
        timeout: float = 10.0,
    ) -> None:
        """
        Launch `nft monitor trace` inside *netns_name* and begin streaming.

        Args:
            netns_name: The target network namespace.
            queue:      Output queue (TraceEvent or None sentinel on completion).
            timeout:    Max seconds to wait for trace events before giving up.
        """
        cmd = ["ip", "netns", "exec", netns_name, "nft", "monitor", "trace"]
        logger.debug("Starting trace monitor: %s", " ".join(cmd))

        self._proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=None,
        )
        self._task = asyncio.ensure_future(self._read_loop(queue=queue, timeout=timeout))

    async def _read_loop(
        self,
        queue: "asyncio.Queue[TraceEvent | None]",
        timeout: float,
    ) -> None:
        """Read stdout line by line, parse, and push to queue."""

        assert self._proc is not None
        assert self._proc.stdout is not None

        deadline = asyncio.get_event_loop().time() + timeout

        try:
            while True:
                remaining = deadline - asyncio.get_event_loop().time()
                if remaining <= 0:
                    logger.debug("Trace monitor timeout reached.")
                    break

                try:
                    line_bytes = await asyncio.wait_for(
                        self._proc.stdout.readline(), timeout=remaining
                    )
                except asyncio.TimeoutError:
                    break

                if not line_bytes:
                    break  # EOF

                line = line_bytes.decode(errors="replace").strip()
                if not line:
                    continue

                event = _parse_line(line)
                if event is not None:
                    logger.debug("TraceEvent: %s", event)
                    await queue.put(event)

        except Exception as exc:
            logger.exception("Error in trace read loop: %s", exc)
        finally:
            await queue.put(None)  # Sentinel → WebSocket sends "done"
            self.stop()

    def stop(self) -> None:
        """Terminate the monitor process."""
        if self._proc and self._proc.returncode is None:
            try:
                self._proc.terminate()
            except ProcessLookupError:
                pass
        if self._task and not self._task.done():
            try:
                current = asyncio.current_task()
            except RuntimeError:
                current = None
            if self._task is not current:
                self._task.cancel()


# ---------------------------------------------------------------------------
# Line parser
# ---------------------------------------------------------------------------


def _parse_line(line: str) -> "TraceEvent | None":
    """Attempt to parse a single `nft monitor trace` line into a TraceEvent."""
    from nse.models.trace_event import TraceEvent

    now = time.time()

    m = _PACKET_RE.match(line)
    if m:
        return TraceEvent(
            type="hook",
            trace_id=m.group("trace_id"),
            family=m.group("family"),
            table=m.group("table"),
            chain=m.group("chain"),
            hook=m.group("iif"),
            timestamp=now,
        )

    m = _RULE_RE.match(line)
    if m:
        return TraceEvent(
            type="match",
            trace_id=m.group("trace_id"),
            family=m.group("family"),
            table=m.group("table"),
            chain=m.group("chain"),
            rule_handle=int(m.group("handle")) if m.group("handle") else None,
            rule_text=m.group("rule_text").strip(),
            verdict=m.group("verdict"),
            timestamp=now,
        )

    m = _VERDICT_RE.match(line)
    if m:
        return TraceEvent(
            type="verdict",
            trace_id=m.group("trace_id"),
            family=m.group("family"),
            table=m.group("table"),
            chain=m.group("chain"),
            verdict=m.group("verdict").upper(),
            timestamp=now,
        )

    logger.debug("Unparsed trace line: %r", line)
    return None
