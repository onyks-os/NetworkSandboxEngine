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
import time
import uuid
from typing import Any

from nse.core.async_work import finish_work, run_blocking
from nse.core.environment import collect_environment
from nse.core.mock_listener import start_listener
from nse.core.naming import NamespaceNames, derive_names
from nse.core.netns_controller import NetnsController, TestRun
from nse.core.paths import resolve
from nse.core.process import ManagedProcess
from nse.core.rule_engine import RuleEngine, RuleValidationError
from nse.core.scapy_injector import ScapyInjector
from nse.core.trace_attribution import TraceAttribution, packet_matches
from nse.core.trace_harvester import TraceHarvester
from nse.core.verdicts import reduce_verdicts, trace_verdicts
from nse.models.experiment_report import (
    CanaryObservation,
    CanaryStatus,
    ExperimentInput,
    ExperimentReport,
    ExperimentResult,
    Observations,
    OracleStatus,
    Outcome,
    RunInfo,
    Stage,
    StageError,
    StimulusObservation,
    StimulusResult,
)
from nse.models.process import ProcessResult
from nse.models.test_request import PacketSpec, TestRequest, TopologyType
from nse.models.trace_event import TraceEvent

logger = logging.getLogger("nse.core.pipeline")

#: Stages whose failure means the experiment was never set up.
_SETUP_STAGES = frozenset({"setup", "listeners", "rules", "monitor"})

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
    tally: list[int] | None = None,
) -> bool:
    """
    Inject a canary packet until its kernel trace is observed.

    Returns True as soon as the harvester reports a *new* event, which is the
    only evidence that the monitor is really attached to the kernel. Returns
    False if no canary was ever seen, meaning the oracle is blind and nothing it
    says about the test packets can be trusted. Each attempt is appended to
    *tally*, for the experiment report.
    """
    for attempt in range(1, attempts + 1):
        if tally is not None:
            tally.append(attempt)
        harvester.arm_event_signal(lambda event: packet_matches(event, spec))
        harvester.extend_deadline(_TRACE_IDLE_TIMEOUT)
        try:
            await run_blocking(
                injector.inject, spec, target_netns, veth_host, veth_peer, host_netns
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


class _Experiment:
    """What one run records. Both entry points read it; neither re-runs anything."""

    def __init__(
        self, request: TestRequest, run: TestRun, names: NamespaceNames, ownership_id: str
    ) -> None:
        self.request = request
        self.run = run
        self.names = names
        self.ownership_id = ownership_id
        self.is_gateway = request.topology == TopologyType.GATEWAY
        self.events: list[TraceEvent] = []
        self.canary_trace_ids: set[str] = set()
        self.attribution = TraceAttribution(request.packets)
        self.stage: Stage = "setup"
        self.outcome: Outcome | None = None
        self.errors: list[StageError] = []
        self.oracle_errors: list[str] = []
        self.canaries: dict[str, tuple[CanaryStatus, list[int], set[str]]] = {
            "readiness": ("not_reached", [], set()),
            "liveness": ("not_reached", [], set()),
        }
        self.injected_at: dict[int, float] = {}
        self.processes: list[ProcessResult] = []
        self.teardown_error: Exception | None = None
        self.residual: list[str] = []
        self.started_at = time.time()
        self.ended_at = self.started_at
        self.phases: dict[str, float] = {}
        self._phase_started = time.monotonic()

    def enter(self, stage: Stage) -> None:
        """Close the timing of the current stage and start *stage*."""
        now = time.monotonic()
        self.phases[self.stage] = self.phases.get(self.stage, 0.0) + now - self._phase_started
        self.stage, self._phase_started = stage, now

    def fail(self, outcome: Outcome, kind: str, message: str, stage: Stage | None = None) -> None:
        """Record an error; the first failure decides the outcome."""
        if self.outcome is None:
            self.outcome = outcome
        self.errors.append(StageError(stage=stage or self.stage, kind=kind, message=message))

    def user_events(self) -> list[TraceEvent]:
        return _without_canaries(self.events, self.canary_trace_ids)


async def _execute(
    request: TestRequest,
    controller: NetnsController,
    run: TestRun,
    timeout: float | None,
) -> _Experiment:
    """The experiment itself: setup, oracle checks, stimuli, collection, teardown."""
    event_queue = run.event_queue
    names = derive_names(run.test_id)
    experiment = _Experiment(request, run, names, uuid.uuid4().hex)
    collected_events = experiment.events

    async def emit_event(evt: TraceEvent | None) -> None:
        if evt is not None:
            collected_events.append(evt)
        await event_queue.put(evt)

    async def emit_error(message: str) -> None:
        run.status = "error"
        await emit_event(
            TraceEvent(type="error", trace_id=run.test_id, verdict="ERROR", raw_message=message)
        )

    async def emit_oracle_error(message: str) -> None:
        """Report a failure of the *instrument*, not of the ruleset under test."""
        logger.error("[%s] Oracle error: %s", run.test_id, message)
        experiment.oracle_errors.append(message)
        experiment.fail("instrument_failure", "oracle", message)
        await emit_error(f"oracle: {message}")

    run.status = "running"
    req = request
    target_netns = names.router_ns if experiment.is_gateway else names.netns
    listener_netns = names.server_ns if experiment.is_gateway else names.netns
    veth_host = names.veth_host
    veth_peer_target = names.veth_router_host
    # The "host" end of the injection link is in the root namespace for both
    # topologies; the router namespace only owns the peer end.
    host_netns: str | None = None

    listeners: list[ManagedProcess] = []
    harvester = TraceHarvester()
    engine = RuleEngine(use_nsenter=controller.use_nsenter)
    injector = ScapyInjector(use_nsenter=controller.use_nsenter)
    attribution = experiment.attribution

    async def probe(label: str, **probe_kwargs: Any) -> bool:
        tally: list[int] = []
        observed = await _probe_oracle(label=label, tally=tally, **probe_kwargs)
        trace_ids = set(harvester.matched_trace_ids)
        experiment.canary_trace_ids.update(trace_ids)
        experiment.canaries[label] = ("observed" if observed else "missed", tally, trace_ids)
        return observed

    async def body() -> None:
        # 1. Network topology
        await run_blocking(controller._setup_topology, names, req, experiment.ownership_id)

        # 2. Mock listeners inside the server/sandbox namespace, confirmed bound
        experiment.enter("listeners")
        logger.info(
            "[%s] Spawning background mock listeners inside %s", run.test_id, listener_netns
        )
        listener_identity = controller.namespace_identity(listener_netns)
        if listener_identity is None:
            raise RuntimeError(f"listener namespace {listener_netns} does not exist")
        # One listener per (protocol, port): a second one would fail to bind.
        wanted = dict.fromkeys(
            (pkt.protocol.lower(), pkt.dst_port) for pkt in req.packets if pkt.dst_port
        )
        for proto, port in wanted:
            listeners.append(
                await start_listener(
                    controller.exec_prefix(listener_netns), listener_identity, proto, port
                )
            )

        # 3. The ruleset under test
        experiment.enter("rules")
        logger.info("[%s] Loading nftables rules into netns %s", run.test_id, target_netns)
        await run_blocking(engine.load, req.rules, target_netns)

        # 4. nft monitor trace
        experiment.enter("monitor")
        logger.info("[%s] Starting nft monitor trace", run.test_id)

        def on_trace_event(evt: TraceEvent) -> None:
            attribution.observe(evt)
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

        # 5. Readiness canary: prove the oracle can see before trusting it
        experiment.enter("readiness")
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
        if not await probe("readiness", **probe_kwargs):
            await emit_oracle_error(
                "readiness canary was never observed - `nft monitor trace` is not "
                "reporting kernel events, so no verdict from this run would be "
                "evidence of anything"
            )
            await emit_event(None)
            return

        # 6. The stimuli, one at a time so trace events keep packet order
        experiment.enter("injection")
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
            experiment.injected_at[idx - 1] = time.time()
            await run_blocking(
                injector.inject, pkt, target_netns, veth_host, veth_peer_target, host_netns
            )
            # Short per-packet delay to let kernel trace process the verdict deterministically
            await asyncio.sleep(_INJECT_SETTLE)
        await asyncio.sleep(_DRAIN_DELAY)

        # 7. Liveness canary: prove the oracle was STILL seeing at the end
        experiment.enter("liveness")
        logger.info("[%s] Probing the oracle with a liveness canary", run.test_id)
        if not await probe("liveness", **probe_kwargs):
            await emit_oracle_error(
                "liveness canary was never observed - the trace monitor stopped "
                "reporting before the run finished, so the verdict stream is "
                "truncated by an unknown amount"
            )

        # 8. Conntrack entries, then close the monitor and report its health
        experiment.enter("collection")
        ct_entries = await run_blocking(read_conntrack_table, target_netns, controller.use_nsenter)
        for ct in ct_entries:
            await emit_event(
                TraceEvent(
                    type="conntrack",
                    trace_id=run.test_id,
                    rule_text=f"state={ct['state']} proto={ct['proto']} {ct['src']}:{ct['sport']} -> {ct['dst']}:{ct['dport']}",
                )
            )
        await harvester.aclose()
        for problem in harvester.health_errors():
            await emit_oracle_error(problem)

        if run.status != "error":
            run.status = "done"
            logger.info("[%s] Test pipeline finished successfully", run.test_id)

    try:
        task = asyncio.ensure_future(body())
        try:
            done, _ = await asyncio.wait({task}, timeout=timeout)
        except asyncio.CancelledError:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
            raise
        if not done:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
            message = f"timeout: the run exceeded {timeout}s and was stopped"
            logger.error("[%s] %s (stage %s)", run.test_id, message, experiment.stage)
            experiment.fail("timeout", "timeout", message)
            await emit_error(message)
            await emit_event(None)
            await harvester.aclose()
        else:
            task.result()

    except asyncio.CancelledError:
        run.status = "error"
        raise

    except RuleValidationError as exc:
        logger.warning("[%s] Rule validation error: %s", run.test_id, exc)
        experiment.fail("rules_invalid", type(exc).__name__, str(exc.errors))
        await emit_error(str(exc.errors))
        await emit_event(None)
        await harvester.aclose()

    except Exception as exc:
        logger.exception("[%s] Pipeline error", run.test_id)
        failure: Outcome = (
            "setup_failure" if experiment.stage in _SETUP_STAGES else "execution_failure"
        )
        experiment.fail(failure, type(exc).__name__, str(exc))
        await emit_error(str(exc))
        await emit_event(None)
        await harvester.aclose()

    finally:
        experiment.enter("teardown")

        async def teardown() -> None:
            try:
                await harvester.aclose()
            finally:
                try:
                    results = await asyncio.gather(
                        *(listener.terminate(grace=0.5) for listener in listeners),
                        return_exceptions=True,
                    )
                    for result in results:
                        if isinstance(result, BaseException):
                            logger.warning(
                                "[%s] Stopping a listener failed: %s", run.test_id, result
                            )
                        else:
                            experiment.processes.append(result)
                finally:
                    # Only this invocation's random ownership ID can be discharged;
                    # deleting each namespace also stops anything left inside it.
                    await run_blocking(controller._cleanup_run, experiment.ownership_id)

        try:
            await finish_work(teardown())
        except Exception as exc:
            logger.error("[%s] Teardown failed: %s", run.test_id, exc)
            experiment.teardown_error = exc
            experiment.errors.append(
                StageError(stage="teardown", kind=type(exc).__name__, message=str(exc))
            )
        experiment.residual = [
            str(item) for item in controller.residual_resources(experiment.ownership_id)
        ]
        experiment.enter("teardown")  # close the teardown timing
        experiment.ended_at = time.time()

    return experiment


def _new_run(request: TestRequest, queue: asyncio.Queue[TraceEvent | None] | None) -> TestRun:
    test_id = uuid.uuid4().hex[:12]
    run = TestRun(test_id=test_id, netns_name=f"nse_{test_id}", request=request)
    if queue is not None:
        run.event_queue = queue
    return run


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

    :func:`run_test_pipeline_report` runs the same experiment and returns the
    full :class:`~nse.models.experiment_report.ExperimentReport` instead.
    """
    experiment = await _execute(
        request, controller or NetnsController(), run or _new_run(request, queue), None
    )
    if experiment.teardown_error is not None:
        raise experiment.teardown_error  # as before: a failed teardown is never silent
    return experiment.user_events()


async def run_test_pipeline_report(
    request: TestRequest,
    controller: NetnsController | None = None,
    queue: asyncio.Queue[TraceEvent | None] | None = None,
    run: TestRun | None = None,
    *,
    timeout: float | None = None,
) -> ExperimentReport:
    """
    Run the experiment of :func:`run_test_pipeline` and return its full report.

    The same implementation runs; only the result differs. Errors do not
    raise: setup, rule, oracle, execution and teardown failures are recorded
    with their stage, and ``result.outcome`` tells them apart. With *timeout*,
    a run still going after that many seconds is stopped (``outcome="timeout"``)
    and torn down. Cancellation still propagates.
    """
    controller = controller or NetnsController()
    experiment = await _execute(request, controller, run or _new_run(request, queue), timeout)
    return _build_report(experiment, controller)


def _build_report(experiment: _Experiment, controller: NetnsController) -> ExperimentReport:
    names = experiment.names
    events = experiment.user_events()
    by_trace = dict(trace_verdicts(events))
    traces_of: dict[int, list[str]] = {
        index: [] for index in range(len(experiment.request.packets))
    }
    for trace_id, indices in experiment.attribution.stimuli.items():
        if trace_id in experiment.canary_trace_ids:
            continue
        for index in indices:
            traces_of[index].append(trace_id)

    readiness, liveness = experiment.canaries["readiness"], experiment.canaries["liveness"]
    result = ExperimentResult(
        outcome=experiment.outcome or "completed",
        oracle=OracleStatus(
            readiness=readiness[0], liveness=liveness[0], errors=list(experiment.oracle_errors)
        ),
        verdicts=reduce_verdicts(events),
        stimuli=[
            StimulusResult(index=index, verdicts=[by_trace[t] for t in traces if t in by_trace])
            for index, traces in traces_of.items()
        ],
        errors=list(experiment.errors),
        teardown_complete=experiment.teardown_error is None and not experiment.residual,
        residual_resources=list(experiment.residual),
    )
    if experiment.is_gateway:
        namespaces = {"router": names.router_ns, "server": names.server_ns}
        interfaces = {
            "host": names.veth_host,
            "router_host": names.veth_router_host,
            "router_server": names.veth_router_server,
            "server": names.veth_server,
        }
    else:
        namespaces = {"sandbox": names.netns}
        interfaces = {"host": names.veth_host, "sandbox": names.veth_router_host}
    return ExperimentReport(
        input=ExperimentInput.of(experiment.request),
        environment=collect_environment(bool(controller.use_nsenter)),
        result=result,
        observations=Observations(
            events=events,
            canary_events=[
                e for e in experiment.events if e.trace_id in experiment.canary_trace_ids
            ],
            canaries={
                label: CanaryObservation(
                    status=status, attempts=len(tally), trace_ids=sorted(trace_ids)
                )
                for label, (status, tally, trace_ids) in experiment.canaries.items()
            },
            stimuli=[
                StimulusObservation(
                    index=index,
                    injected_at=experiment.injected_at.get(index),
                    trace_ids=traces_of[index],
                )
                for index in traces_of
            ],
            processes=list(experiment.processes),
        ),
        run=RunInfo(
            test_id=experiment.run.test_id,
            ownership_id=experiment.ownership_id,
            namespaces=namespaces,
            interfaces=interfaces,
            started_at=experiment.started_at,
            ended_at=experiment.ended_at,
            phases=dict(experiment.phases),
        ),
    )


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
