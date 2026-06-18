"""
Test pipeline — orchestrates a single NSE test run.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from nse.core.rule_engine import RuleEngine, RuleValidationError
from nse.core.scapy_injector import ScapyInjector

try:
    from nse.models.trace_event import TraceEvent
    from nse.models.test_request import TopologyType
except ImportError:
    TraceEvent = None

    class TopologyType:
        SIMPLE = "simple"
        GATEWAY = "gateway"


try:
    from gui.daemon.trace_harvester import TraceHarvester
    from gui.daemon.mock_listener import start_mock_listener
except ImportError:
    TraceHarvester = None
    start_mock_listener = None

if TYPE_CHECKING:
    from nse.core.netns_controller import NetnsController, TestRun

logger = logging.getLogger("nse.core.pipeline")

_VETH_PEER = "veth-nse"  # lives inside the netns

# How long to wait for trace events after packet injection (seconds).
_TRACE_TIMEOUT = 5.0

# How long to let `nft monitor trace` initialise before injecting the packet.
_WARMUP_DELAY = 0.4


def parse_conntrack_line(line: str) -> dict | None:
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


def read_conntrack_table(netns: str) -> list[dict]:
    import subprocess

    try:
        res = subprocess.run(
            ["ip", "netns", "exec", netns, "cat", "/proc/net/nf_conntrack"],
            capture_output=True,
            text=True,
            check=True,
        )
        lines = res.stdout.strip().split("\n")
    except Exception:
        try:
            res = subprocess.run(
                ["ip", "netns", "exec", netns, "cat", "/proc/net/ip_conntrack"],
                capture_output=True,
                text=True,
                check=True,
            )
            lines = res.stdout.strip().split("\n")
        except Exception:
            return []

    entries = []
    for line in lines:
        if not line.strip():
            continue
        entry = parse_conntrack_line(line)
        if entry:
            entries.append(entry)
    return entries


async def run_test_pipeline(controller: "NetnsController", run: "TestRun") -> None:
    """Full test lifecycle coroutine. Runs async inside the event loop."""
    if TraceHarvester is None or start_mock_listener is None:
        raise RuntimeError(
            "GUI/daemon dependencies (trace_harvester, mock_listener) are missing. "
            "Please install the GUI components or run with full dependencies."
        )

    if TraceEvent is None:
        raise RuntimeError(
            "Pydantic models are missing. Please install the optional CLI/GUI dependencies."
        )

    netns = run.netns_name
    queue = run.event_queue
    loop = asyncio.get_event_loop()

    # Determine topology settings
    is_gateway = run.request.topology == TopologyType.GATEWAY
    router_ns = f"nse_router_{run.test_id[:10]}"
    server_ns = f"nse_server_{run.test_id[:10]}"

    rules_netns = router_ns if is_gateway else run.netns_name
    target_netns = server_ns if is_gateway else run.netns_name

    veth_host = f"vhr-{run.test_id[:10]}" if is_gateway else f"vh-{run.test_id[:10]}"
    veth_router_host = f"vrh-{run.test_id[:10]}"
    veth_router_server = f"vrs-{run.test_id[:10]}"
    veth_server = _VETH_PEER

    run.status = "running"
    harvester = TraceHarvester()
    listeners = []

    try:
        # ------------------------------------------------------------------
        # 1. Create Network Topology (blocking → executor)
        # ------------------------------------------------------------------
        if is_gateway:
            logger.info(
                "[%s] Setting up Gateway topology: router=%s, server=%s",
                run.test_id,
                router_ns,
                server_ns,
            )
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
        # 2. Spawn Mock Listeners on target/server namespace
        # ------------------------------------------------------------------
        logger.info(
            "[%s] Spawning background mock listeners inside %s",
            run.test_id,
            target_netns,
        )
        for packet in run.request.packets:
            if packet.dst_port:
                # Check direction: run listener if packet is incoming
                packet_incoming = True
                if packet.src_ip in ("10.0.0.2", "fd00::2", "10.0.2.2", "fd00:2::2"):
                    packet_incoming = False

                if packet_incoming:
                    bind_ip = "::" if ":" in packet.dst_ip else "0.0.0.0"
                    # Prevent duplicates
                    if not any(
                        lst["port"] == packet.dst_port and lst["proto"] == packet.protocol
                        for lst in listeners
                    ):
                        proc = await loop.run_in_executor(
                            None,
                            start_mock_listener,
                            target_netns,
                            packet.protocol,
                            packet.dst_port,
                            bind_ip,
                        )
                        listeners.append(
                            {
                                "proc": proc,
                                "port": packet.dst_port,
                                "proto": packet.protocol,
                            }
                        )

        # ------------------------------------------------------------------
        # 3. Load nftables rules (blocking → executor)
        # ------------------------------------------------------------------
        engine = RuleEngine()
        logger.info("[%s] Loading rules into netns %s", run.test_id, rules_netns)
        traced_rules = _inject_trace_flag(run.request.rules)
        await loop.run_in_executor(None, engine.load, traced_rules, rules_netns)

        # ------------------------------------------------------------------
        # 4. Start trace harvester (async subprocess — stays on event loop)
        # ------------------------------------------------------------------
        logger.info("[%s] Starting trace harvester on netns %s", run.test_id, rules_netns)
        await harvester.start(netns_name=rules_netns, queue=queue, timeout=_TRACE_TIMEOUT)

        # Let nft monitor trace initialise
        await asyncio.sleep(_WARMUP_DELAY)

        # ------------------------------------------------------------------
        # 5. Inject packet sequence
        # ------------------------------------------------------------------
        injector = ScapyInjector()
        for idx, packet in enumerate(run.request.packets):
            logger.info(
                "[%s] Injecting packet %d/%d",
                run.test_id,
                idx + 1,
                len(run.request.packets),
            )

            # Setup injection netns & interface arguments
            if is_gateway:
                packet_incoming = True
                if packet.src_ip in ("10.0.0.2", "fd00::2", "10.0.2.2", "fd00:2::2"):
                    packet_incoming = False

                if packet_incoming:
                    inject_netns = router_ns
                    inj_veth_host = veth_host
                    inj_veth_peer = veth_router_host
                else:
                    inject_netns = server_ns
                    inj_veth_host = veth_router_server
                    inj_veth_peer = veth_server
            else:
                inject_netns = run.netns_name
                inj_veth_host = veth_host
                inj_veth_peer = _VETH_PEER

            await loop.run_in_executor(
                None,
                injector.inject,
                packet,
                inject_netns,
                inj_veth_host,
                inj_veth_peer,
            )

            # Give a small slice for processing/trace events to trigger
            await asyncio.sleep(0.3)

            # Push live conntrack table updates
            entries = await loop.run_in_executor(None, read_conntrack_table, rules_netns)
            for entry in entries:
                await queue.put(
                    TraceEvent(
                        type="conntrack",
                        ct_proto=entry["proto"],
                        ct_state=entry["state"],
                        ct_src=entry["src"],
                        ct_dst=entry["dst"],
                        ct_sport=entry["sport"],
                        ct_dport=entry["dport"],
                    )
                )

        # Wait for the trace harvester to finish draining events.
        logger.info("[%s] Waiting for trace events to complete…", run.test_id)
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
        # Teardown mock listeners
        # ------------------------------------------------------------------
        logger.info("[%s] Tearing down mock listeners", run.test_id)
        for listener in listeners:
            try:
                listener["proc"].terminate()
                listener["proc"].wait(timeout=0.5)
            except Exception:
                try:
                    listener["proc"].kill()
                except Exception:
                    pass

        # ------------------------------------------------------------------
        # Teardown namespaces & host interfaces (blocking → executor)
        # ------------------------------------------------------------------
        logger.info("[%s] Tearing down network topology", run.test_id)
        import subprocess

        if is_gateway:
            await loop.run_in_executor(None, controller.destroy_netns, router_ns)
            await loop.run_in_executor(None, controller.destroy_netns, server_ns)
        else:
            await loop.run_in_executor(None, controller.destroy_netns, netns)

        # Explicitly clean up host veth
        await loop.run_in_executor(
            None,
            lambda: subprocess.run(
                ["ip", "link", "del", veth_host], capture_output=True, check=False
            ),
        )


def _inject_trace_flag(rules: str) -> str:
    """
    Auto-prepend ``meta nftrace set 1`` after the chain declaration line.
    """
    import re

    # Already has tracing — don't inject again
    if "meta nftrace set" in rules:
        return rules

    pattern = re.compile(
        r"(type\s+\w+\s+hook\s+\w+\s+priority\s+[^;]+;"  # type … priority N;
        r"(?:[ \t]*policy\s+\w+\s*;)?)",  # optional: policy drop;
        re.MULTILINE,
    )
    return pattern.sub(r"\1\n        meta nftrace set 1", rules)
