"""
Test pipeline — orchestrates a single NSE test run.

IMPORTANT — asyncio + blocking subprocess:
All subprocess calls (ip, nft, scapy) are blocking.  Running them directly
in the event loop would freeze it and prevent the TraceHarvester's _read_loop
from ever getting scheduled.  Every blocking call is therefore wrapped with
``loop.run_in_executor(None, ...)`` to offload to the default ThreadPoolExecutor.

Lifecycle:
    1. Create netns + veth pair        (executor)
    2. Load nftables rules             (executor)
    3. Start nft monitor trace         (async subprocess, in event loop)
    4. Small sleep → let nft start up
    5. Inject packet via Scapy         (executor)
    6. Await harvester task            ← THIS is what drains trace events
    7. Teardown netns                  (executor, finally)
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from nse.core.rule_engine import RuleEngine, RuleValidationError
from nse.core.scapy_injector import ScapyInjector
from nse.core.trace_harvester import TraceHarvester
from nse.models.trace_event import TraceEvent

if TYPE_CHECKING:
    from nse.core.netns_controller import NetnsController, TestRun

logger = logging.getLogger("nse.core.pipeline")

_VETH_PEER = "veth-nse"   # lives inside the netns

# How long to wait for trace events after packet injection (seconds).
# nft monitor trace can take a moment to emit output.
_TRACE_TIMEOUT = 5.0

# How long to let `nft monitor trace` initialise before injecting the packet.
_WARMUP_DELAY = 0.4


async def run_test_pipeline(controller: "NetnsController", run: "TestRun") -> None:
    """Full test lifecycle coroutine. Runs async inside the FastAPI event loop."""
    netns = run.netns_name
    queue = run.event_queue
    loop = asyncio.get_event_loop()

    # Generate a unique host-side interface name to support parallel runs safely (max 15 chars in Linux)
    veth_host = f"vh-{run.test_id[:10]}"

    run.status = "running"
    harvester = TraceHarvester()

    try:
        # ------------------------------------------------------------------
        # 1. Network namespace + veth  (blocking → executor)
        # ------------------------------------------------------------------
        logger.info("[%s] Creating netns %s", run.test_id, netns)
        await loop.run_in_executor(None, controller.create_netns, netns)

        # Determine packet direction to assign IPs correctly:
        # Host interface gets host_ip, and netns interface gets peer_ip.
        src_ip = run.request.packet.src_ip or "10.0.0.1"
        dst_ip = run.request.packet.dst_ip or "10.0.0.2"

        is_incoming = True
        if src_ip == "10.0.0.2":
            is_incoming = False

        if is_incoming:
            host_ip_val = src_ip
            peer_ip_val = dst_ip
        else:
            host_ip_val = dst_ip
            peer_ip_val = src_ip

        host_ip = f"{host_ip_val}/24"
        peer_ip = f"{peer_ip_val}/24"

        await loop.run_in_executor(
            None,
            controller.create_veth_pair,
            netns,
            veth_host,
            _VETH_PEER,
            host_ip,
            peer_ip,
        )

        # ------------------------------------------------------------------
        # 2. Load nftables rules  (blocking → executor)
        # ------------------------------------------------------------------
        engine = RuleEngine()
        logger.info("[%s] Loading rules into netns", run.test_id)
        # Auto-inject `meta nftrace set 1` so tracing is always armed,
        # even if the user forgot to include it in their ruleset.
        traced_rules = _inject_trace_flag(run.request.rules)
        await loop.run_in_executor(
            None, engine.load, traced_rules, netns
        )

        # ------------------------------------------------------------------
        # 3. Start trace harvester (async subprocess — stays on event loop)
        # ------------------------------------------------------------------
        logger.info("[%s] Starting trace harvester", run.test_id)
        await harvester.start(
            netns_name=netns, queue=queue, timeout=_TRACE_TIMEOUT
        )

        # Let nft monitor trace initialise before we fire the packet.
        # Without this delay the packet may arrive before the monitor is ready.
        await asyncio.sleep(_WARMUP_DELAY)

        # ------------------------------------------------------------------
        # 4. Inject packet  (blocking → executor)
        # ------------------------------------------------------------------
        logger.info("[%s] Injecting packet", run.test_id)
        injector = ScapyInjector()
        await loop.run_in_executor(
            None,
            injector.inject,
            run.request.packet,
            netns,
            veth_host,
            _VETH_PEER,
        )

        # ------------------------------------------------------------------
        # 5. Wait for the harvester to drain all trace events.
        #    The harvester's _read_loop pushes None (sentinel) when it
        #    hits EOF or the _TRACE_TIMEOUT, then the WS handler closes.
        # ------------------------------------------------------------------
        logger.info("[%s] Waiting for trace events…", run.test_id)
        if harvester._task is not None:
            await harvester._task

        run.status = "done"
        logger.info("[%s] Pipeline complete", run.test_id)

    except RuleValidationError as exc:
        logger.error("[%s] Rule load failed: %s", run.test_id, exc.errors)
        run.status = "error"
        await queue.put(
            TraceEvent(
                type="error",
                trace_id=run.test_id,
                verdict="ERROR",
                raw_message=str(exc.errors),
            )
        )
        await queue.put(None)
        harvester.stop()

    except Exception as exc:
        logger.exception("[%s] Pipeline error: %s", run.test_id, exc)
        run.status = "error"
        await queue.put(
            TraceEvent(
                type="error",
                trace_id=run.test_id,
                verdict="ERROR",
                raw_message=str(exc),
            )
        )
        await queue.put(None)
        harvester.stop()

    finally:
        # ------------------------------------------------------------------
        # Teardown — runs AFTER harvester has drained all events.
        # The kernel GC cleans up rules and interfaces inside the netns.
        # ------------------------------------------------------------------
        logger.info("[%s] Tearing down netns %s", run.test_id, netns)
        import subprocess

        await loop.run_in_executor(None, controller.destroy_netns, netns)
        # Clean up the host-side veth (disappears with its peer, but be explicit)
        await loop.run_in_executor(
            None,
            lambda: subprocess.run(
                ["ip", "link", "del", veth_host], capture_output=True, check=False
            ),
        )


def _inject_trace_flag(rules: str) -> str:
    """
    Auto-prepend ``meta nftrace set 1`` after the chain declaration line.

    nftables chain declarations look like:
        type filter hook input priority 0; policy drop;
    OR (split across tokens on a single line):
        type filter hook input priority 0;

    The regex captures the ENTIRE declaration — including the optional
    ``policy <POL>;`` suffix — so the inserted statement ends up on its
    own line and not concatenated with ``policy drop;``.

    Skips injection if ``meta nftrace set 1`` is already present.
    """
    import re

    # Already has tracing — don't inject again
    if "meta nftrace set" in rules:
        return rules

    # Match the full chain type declaration:
    #   type <TYPE> hook <HOOK> priority <PRIO>;[ policy <POL>;]
    # The optional policy clause is part of the captured group so the
    # substitution places the trace statement AFTER it, not in the middle.
    pattern = re.compile(
        r'(type\s+\w+\s+hook\s+\w+\s+priority\s+[^;]+;'   # type … priority N;
        r'(?:[ \t]*policy\s+\w+\s*;)?)',                    # optional: policy drop;
        re.MULTILINE,
    )
    return pattern.sub(r'\1\n        meta nftrace set 1', rules)
