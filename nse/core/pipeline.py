# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""
Test pipeline: orchestrates a single NSE test run.

The oracle contract
-------------------

A firewall test is a negative assertion ("this packet did not get through"), and
a negative assertion is worthless unless the instrument is known to be working.
So every run carries its own positive control: a *canary* packet is injected
before the test packets and again after them, and the run is only reported as a
result if the kernel trace for **both** canaries was observed.

* The pre-canary replaces the old readiness probe, which signalled that this
  process had scheduled its read loop — not that ``nft monitor trace`` had
  actually subscribed to the kernel. Packets injected in that window were lost.
* The post-canary proves the monitor was still watching when the last test
  packet went in. It is what catches a trace deadline expiring mid-run, which
  used to silently truncate the verdict stream.

If either canary is not observed the pipeline emits an ``error`` event and the
caller fails the test. It is never possible for this pipeline to report a clean
verdict list that it did not actually measure.
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
from nse.core.paths import resolve
from nse.core.rule_engine import RuleEngine, RuleValidationError
from nse.core.scapy_injector import ScapyInjector
from nse.core.trace_harvester import TraceHarvester
from nse.models.test_request import PacketSpec, TestRequest, TopologyType
from nse.models.trace_event import TraceEvent

logger = logging.getLogger("nse.core.pipeline")

_VETH_PEER = "veth-nse"  # lives inside the netns

#: Seconds of inactivity the trace monitor tolerates before declaring a timeout.
#: The deadline is *extended* by this much after every injection, so a long
#: packet sequence can never outlive a deadline fixed when the loop started.
_TRACE_IDLE_TIMEOUT = float(os.getenv("NSE_TRACE_IDLE_TIMEOUT", "5.0"))

#: Settling time between injections, so trace events keep packet order.
_INJECT_SETTLE = float(os.getenv("NSE_INJECT_SETTLE", "0.15"))

#: Time given to the kernel to flush the last verdicts before conntrack is read.
_DRAIN_DELAY = float(os.getenv("NSE_DRAIN_DELAY", "0.3"))

# --- Canary (oracle positive control) -------------------------------------

#: Ports the canary uses. Chosen high and fixed so a user suite that happens to
#: test the same port still works: canaries are excluded by trace id, not port.
_CANARY_DST_PORT = 64999
_CANARY_SRC_PORT = 64998
#: How many times a canary is re-injected before the oracle is declared blind.
_CANARY_ATTEMPTS = int(os.getenv("NSE_CANARY_ATTEMPTS", "25"))
#: How long to wait for each canary attempt to show up in the trace stream.
_CANARY_INTERVAL = float(os.getenv("NSE_CANARY_INTERVAL", "0.2"))


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
        [resolve("nsenter"), f"--net=/var/run/netns/{netns}", "--"]
        if use_nsenter
        else [resolve("ip"), "netns", "exec", netns]
    )
    try:
        res = subprocess.run(
            [*exec_cmd, resolve("cat"), "/proc/net/nf_conntrack"],
            capture_output=True,
            text=True,
            check=True,
        )
        lines = res.stdout.strip().split("\n")
    except (subprocess.CalledProcessError, OSError):
        try:
            res = subprocess.run(
                [*exec_cmd, resolve("cat"), "/proc/net/ip_conntrack"],
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


def _canary_spec(dst_ip: str, src_ip: str) -> PacketSpec:
    """Build the probe packet used as the oracle's positive control."""
    return PacketSpec(
        protocol="udp",
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=_CANARY_SRC_PORT,
        dst_port=_CANARY_DST_PORT,
    )


async def _probe_oracle(
    *,
    label: str,
    harvester: TraceHarvester,
    injector: ScapyInjector,
    spec: PacketSpec,
    target_netns: str,
    veth_host: str,
    veth_peer: str,
    host_netns: str | None,
    attempts: int = _CANARY_ATTEMPTS,
    interval: float = _CANARY_INTERVAL,
) -> bool:
    """
    Inject a canary packet until its kernel trace is observed.

    Returns True as soon as the harvester reports a *new* event, which is the
    only evidence that the monitor is really attached to the kernel. Returns
    False if no canary was ever seen, meaning the oracle is blind and nothing it
    says about the test packets can be trusted.
    """
    loop = asyncio.get_running_loop()
    for attempt in range(1, attempts + 1):
        harvester.arm_event_signal()
        harvester.extend_deadline(_TRACE_IDLE_TIMEOUT)
        try:
            await loop.run_in_executor(
                None,
                lambda: injector.inject(
                    spec,
                    target_netns,
                    veth_host,
                    veth_peer,
                    host_netns,
                ),
            )
        except Exception as exc:
            logger.debug("%s canary injection attempt %d failed: %s", label, attempt, exc)
            await asyncio.sleep(interval)
            continue

        if await harvester.wait_for_event(timeout=interval):
            logger.info("%s canary observed after %d attempt(s)", label, attempt)
            return True

    logger.error("%s canary was never observed after %d attempts", label, attempts)
    return False


async def run_test_pipeline(
    request: TestRequest,
    controller: NetnsController | None = None,
    queue: asyncio.Queue[TraceEvent | None] | None = None,
    run: TestRun | None = None,
) -> list[TraceEvent]:
    """
    Full test lifecycle coroutine.

    Executes a test request in isolated Linux network namespaces, injecting
    packets and collecting kernel nftables trace events.

    The returned list never contains canary events: they are the pipeline's own
    instrument check, not part of the user's test. If a canary is missed, the
    list contains an ``error`` event instead of a verdict stream, so a caller
    cannot mistake "the oracle saw nothing" for "nothing happened".
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
    canary_trace_ids: set[str] = set()

    async def emit_event(evt: TraceEvent | None) -> None:
        if evt is not None:
            collected_events.append(evt)
        await event_queue.put(evt)

    async def emit_oracle_error(message: str) -> None:
        """Report a failure of the *instrument*, not of the ruleset under test."""
        logger.error("[%s] Oracle error: %s", run.test_id, message)
        run.status = "error"
        await emit_event(
            TraceEvent(
                type="error",
                trace_id=run.test_id,
                verdict="ERROR",
                raw_message=f"oracle: {message}",
            )
        )

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
    veth_peer_target = veth_router_host if is_gateway else _VETH_PEER
    # The "host" end of the injection link is in the root namespace for both
    # topologies; the router namespace only owns the peer end.
    host_netns: str | None = None

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
        # 4. Start nft monitor trace
        # ------------------------------------------------------------------
        logger.info("[%s] Starting nft monitor trace", run.test_id)

        def on_trace_event(evt: TraceEvent) -> None:
            collected_events.append(evt)

        initial_timeout = max(
            _TRACE_IDLE_TIMEOUT,
            2.0 + _INJECT_SETTLE * len(req.packets) + _CANARY_ATTEMPTS * _CANARY_INTERVAL,
        )
        await harvester.start(
            netns_name=target_netns,
            queue=event_queue,
            timeout=initial_timeout,
            use_nsenter=controller.use_nsenter,
            on_event=on_trace_event,
        )
        await harvester.wait_ready(timeout=2.0)

        # ------------------------------------------------------------------
        # 5. Readiness canary — prove the oracle can see before trusting it
        # ------------------------------------------------------------------
        first_packet = req.packets[0]
        canary = _canary_spec(dst_ip=first_packet.dst_ip, src_ip=first_packet.src_ip)
        probe_kwargs = {
            "harvester": harvester,
            "injector": injector,
            "spec": canary,
            "target_netns": target_netns,
            "veth_host": veth_host,
            "veth_peer": veth_peer_target,
            "host_netns": host_netns,
        }

        logger.info("[%s] Probing the oracle with a readiness canary", run.test_id)
        if not await _probe_oracle(label="readiness", **probe_kwargs):  # type: ignore[arg-type]
            await emit_oracle_error(
                "readiness canary was never observed - `nft monitor trace` is not "
                "reporting kernel events, so no verdict from this run would be "
                "evidence of anything"
            )
            await emit_event(None)
            return _without_canaries(collected_events, canary_trace_ids)
        canary_trace_ids.update(harvester.seen_trace_ids)

        # ------------------------------------------------------------------
        # 6. Inject Packet Sequence (Per-packet ordering-based injection)
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
            harvester.extend_deadline(_TRACE_IDLE_TIMEOUT)
            await loop.run_in_executor(
                None,
                injector.inject,
                pkt,
                target_netns,
                veth_host,
                veth_peer_target,
                host_netns,
            )
            # Short per-packet delay to let kernel trace process the verdict deterministically
            await asyncio.sleep(_INJECT_SETTLE)

        await asyncio.sleep(_DRAIN_DELAY)

        # ------------------------------------------------------------------
        # 7. Liveness canary — prove the oracle was STILL seeing at the end
        # ------------------------------------------------------------------
        logger.info("[%s] Probing the oracle with a liveness canary", run.test_id)
        before_liveness = set(harvester.seen_trace_ids)
        if not await _probe_oracle(label="liveness", **probe_kwargs):  # type: ignore[arg-type]
            await emit_oracle_error(
                "liveness canary was never observed - the trace monitor stopped "
                "reporting before the run finished, so the verdict stream is "
                "truncated by an unknown amount"
            )
        canary_trace_ids.update(set(harvester.seen_trace_ids) - before_liveness)

        # ------------------------------------------------------------------
        # 8. Collect conntrack entries & finish
        # ------------------------------------------------------------------
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

        # ------------------------------------------------------------------
        # 9. Close the monitor and report anything that made it untrustworthy
        # ------------------------------------------------------------------
        await harvester.aclose()
        for problem in harvester.health_errors():
            await emit_oracle_error(problem)

        if run.status != "error":
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
        await harvester.aclose()

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
        await harvester.aclose()

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
                [resolve("ip"), "link", "del", veth_host],
                capture_output=True,
                check=False,
            ),
        )

    return _without_canaries(collected_events, canary_trace_ids)


def _without_canaries(events: list[TraceEvent], canary_trace_ids: set[str]) -> list[TraceEvent]:
    """
    Drop the pipeline's own probe packets from the reported event stream.

    The canaries are the instrument check. Leaving them in would make every
    caller re-derive which events were theirs, and the first caller to forget
    would silently count a probe as a verdict.
    """
    if not canary_trace_ids:
        return events
    return [e for e in events if not (e.trace_id and e.trace_id in canary_trace_ids)]
