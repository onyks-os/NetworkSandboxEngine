# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""
Test pipeline: orchestrates a single NSE test run.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import subprocess
import uuid
from typing import Any, cast

from nse.core.mock_listener import start_mock_listener
from nse.core.naming import derive_names
from nse.core.netns_controller import NetnsController, TestRun
from nse.core.rule_engine import RuleEngine, RuleValidationError
from nse.core.scapy_injector import ScapyInjector
from nse.core.trace_harvester import TraceHarvester
from nse.models.test_request import TestRequest, TopologyType
from nse.models.trace_event import TraceEvent

logger = logging.getLogger("nse.core.pipeline")

_VETH_PEER = "veth-nse"  # lives inside the netns

# How long to wait for trace events after packet injection (seconds).
_TRACE_TIMEOUT = 5.0
_VERDICT_TIMEOUT = float(os.getenv("NSE_VERDICT_TIMEOUT", "2.0"))


def parse_conntrack_line(line: str) -> dict[str, Any] | None:
    parts = line.strip().split()
    if len(parts) < 6:
        return None
    proto = parts[2]

    state = None
    if proto == "tcp":
        tcp_states = {
            "ESTABLISHED",
            "SYN_SENT",
            "SYN_RECV",
            "FIN_WAIT",
            "TIME_WAIT",
            "CLOSE",
            "CLOSE_WAIT",
            "LAST_ACK",
        }
        for p in parts[4:7]:
            if p in tcp_states:
                state = p
                break
        if not state:
            state = "UNKNOWN"
    else:
        state = "ESTABLISHED"

    src, dst = None, None
    sport, dport = None, None

    for p in parts:
        if p.startswith("src=") and not src:
            src = p.split("=")[1]
        elif p.startswith("dst=") and not dst:
            dst = p.split("=")[1]
        elif p.startswith("sport=") and not sport:
            sport = int(p.split("=")[1])
        elif p.startswith("dport=") and not dport:
            dport = int(p.split("=")[1])

    if src and dst:
        return {
            "proto": proto.upper(),
            "state": state,
            "src": src,
            "dst": dst,
            "sport": sport,
            "dport": dport,
        }
    return None


def read_conntrack_table(netns: str, use_nsenter: bool = False) -> list[dict[str, Any]]:
    exec_cmd = (
        ["nsenter", f"--net=/var/run/netns/{netns}", "--"]
        if use_nsenter
        else ["ip", "netns", "exec", netns]
    )
    try:
        res = subprocess.run(
            [*exec_cmd, "cat", "/proc/net/nf_conntrack"],
            capture_output=True,
            text=True,
            check=True,
        )
        lines = res.stdout.strip().split("\n")
    except (subprocess.CalledProcessError, OSError):
        try:
            res = subprocess.run(
                [*exec_cmd, "cat", "/proc/net/ip_conntrack"],
                capture_output=True,
                text=True,
                check=True,
            )
            lines = res.stdout.strip().split("\n")
        except (subprocess.CalledProcessError, OSError):
            return []

    entries = []
    for line in lines:
        if not line.strip():
            continue
        entry = parse_conntrack_line(line)
        if entry:
            entries.append(entry)
    return entries


async def run_test_pipeline(
    request: TestRequest,
    controller: NetnsController | None = None,
    queue: asyncio.Queue[TraceEvent | None] | None = None,
    run: TestRun | None = None,
) -> list[TraceEvent]:
    """
    Full test lifecycle coroutine.

    Executes a test request in isolated Linux network namespaces, injecting packets
    and collecting kernel nftables trace events.
    """
    if controller is None:
        controller = NetnsController()

    if run is None:
        test_id = uuid.uuid4().hex[:12]
        netns_name = f"nse_{test_id}"
        run = TestRun(test_id=test_id, netns_name=netns_name, request=request)
        if queue is not None:
            run.event_queue = queue

    event_queue = run.event_queue
    collected_events: list[TraceEvent] = []

    async def emit_event(evt: TraceEvent | None) -> None:
        if evt is not None:
            collected_events.append(evt)
        await event_queue.put(evt)

    run.status = "running"
    req = request
    names = derive_names(run.test_id)
    netns = names.netns
    router_ns = names.router_ns
    server_ns = names.server_ns
    veth_host = names.veth_host
    veth_router_host = names.veth_router_host
    veth_router_server = names.veth_router_server
    veth_server = names.veth_server

    is_gateway = req.topology == TopologyType.GATEWAY
    listeners = []
    harvester = TraceHarvester()
    engine = RuleEngine(use_nsenter=controller.use_nsenter)
    injector = ScapyInjector(use_nsenter=controller.use_nsenter)

    loop = asyncio.get_running_loop()
    target_netns = router_ns if is_gateway else netns

    try:
        # ------------------------------------------------------------------
        # 1. Setup Network Topology
        # ------------------------------------------------------------------
        if is_gateway:
            logger.info("[%s] Setting up Gateway topology: netns=%s", run.test_id, router_ns)
            await loop.run_in_executor(
                None,
                controller.create_gateway_topology,
                router_ns,
                server_ns,
                veth_host,
                veth_router_host,
                veth_router_server,
                veth_server,
            )
        else:
            logger.info("[%s] Setting up Simple topology: netns=%s", run.test_id, netns)
            await loop.run_in_executor(None, controller.create_netns, netns)
            await loop.run_in_executor(
                None,
                controller.create_veth_pair,
                netns,
                veth_host,
                _VETH_PEER,
            )

        # ------------------------------------------------------------------
        # 2. Spawning background mock listeners inside server/sandbox namespace
        # ------------------------------------------------------------------
        listener_netns = server_ns if is_gateway else netns
        logger.info(
            "[%s] Spawning background mock listeners inside %s", run.test_id, listener_netns
        )

        for pkt in req.packets:
            if pkt.dst_port:
                proc = start_mock_listener(
                    netns_name=listener_netns,
                    proto=pkt.protocol,
                    port=pkt.dst_port,
                    use_nsenter=controller.use_nsenter,
                )
                listeners.append({"proto": pkt.protocol, "port": pkt.dst_port, "proc": proc})

        # ------------------------------------------------------------------
        # 3. Load nftables Rules
        # ------------------------------------------------------------------
        logger.info("[%s] Loading nftables rules into netns %s", run.test_id, target_netns)
        await loop.run_in_executor(None, engine.load, req.rules, target_netns)

        # ------------------------------------------------------------------
        # 4. Start nft monitor trace & wait for readiness probe
        # ------------------------------------------------------------------
        logger.info("[%s] Starting nft monitor trace", run.test_id)

        def on_trace_event(evt: TraceEvent) -> None:
            collected_events.append(evt)

        await harvester.start(
            netns_name=target_netns,
            queue=event_queue,
            timeout=_TRACE_TIMEOUT,
            use_nsenter=controller.use_nsenter,
            on_event=on_trace_event,
        )

        # Readiness probe replacement for hardcoded delay
        await harvester.wait_ready(timeout=2.0)

        # ------------------------------------------------------------------
        # 5. Inject Packet Sequence (Per-packet ordering-based injection)
        # ------------------------------------------------------------------
        for idx, pkt in enumerate(req.packets, start=1):
            logger.info(
                "[%s] Injecting packet %d/%d (%s -> %s:%s)",
                run.test_id,
                idx,
                len(req.packets),
                pkt.src_ip,
                pkt.dst_ip,
                pkt.dst_port,
            )
            veth_peer_target = veth_router_host if is_gateway else _VETH_PEER
            await loop.run_in_executor(
                None,
                injector.inject,
                pkt,
                target_netns,
                veth_host,
                veth_peer_target,
            )
            # Short per-packet delay to let kernel trace process the verdict deterministically
            await asyncio.sleep(0.15)

        # ------------------------------------------------------------------
        # 6. Collect conntrack entries & finish
        # ------------------------------------------------------------------
        await asyncio.sleep(0.3)

        ct_entries = await loop.run_in_executor(
            None, read_conntrack_table, target_netns, controller.use_nsenter
        )
        for ct in ct_entries:
            await emit_event(
                TraceEvent(
                    type="conntrack",
                    trace_id=run.test_id,
                    rule_text=f"state={ct['state']} proto={ct['proto']} {ct['src']}:{ct['sport']} -> {ct['dst']}:{ct['dport']}",
                )
            )

        harvester.stop()
        run.status = "done"
        logger.info("[%s] Test pipeline finished successfully", run.test_id)

    except RuleValidationError as exc:
        logger.warning("[%s] Rule validation error: %s", run.test_id, exc)
        run.status = "error"
        await emit_event(
            TraceEvent(
                type="error",
                trace_id=run.test_id,
                verdict="ERROR",
                raw_message=str(exc.errors),
            )
        )
        await emit_event(None)
        harvester.stop()

    except Exception as exc:
        logger.exception("[%s] Pipeline error", run.test_id)
        run.status = "error"
        await emit_event(
            TraceEvent(
                type="error",
                trace_id=run.test_id,
                verdict="ERROR",
                raw_message=str(exc),
            )
        )
        await emit_event(None)
        harvester.stop()

    finally:
        # ------------------------------------------------------------------
        # Teardown mock listeners
        # ------------------------------------------------------------------
        logger.info("[%s] Tearing down mock listeners", run.test_id)
        for listener in listeners:
            listener_proc: subprocess.Popen[str] = cast(subprocess.Popen[str], listener["proc"])
            try:
                listener_proc.terminate()
                listener_proc.wait(timeout=0.5)
            except (OSError, subprocess.SubprocessError):
                with contextlib.suppress(OSError, subprocess.SubprocessError):
                    listener_proc.kill()

        # ------------------------------------------------------------------
        # Teardown namespaces & host interfaces (blocking → executor)
        # ------------------------------------------------------------------
        logger.info("[%s] Tearing down network topology", run.test_id)

        if is_gateway:
            await loop.run_in_executor(None, controller.destroy_netns, router_ns)
            await loop.run_in_executor(None, controller.destroy_netns, server_ns)
        else:
            await loop.run_in_executor(None, controller.destroy_netns, netns)

        # Explicitly clean up host veth
        await loop.run_in_executor(
            None,
            lambda: subprocess.run(
                ["ip", "link", "del", veth_host],
                capture_output=True,
                check=False,
            ),
        )

    return collected_events
