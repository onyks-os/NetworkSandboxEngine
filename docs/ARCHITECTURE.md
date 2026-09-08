# Network Sandbox Engine (NSE) - Technical Architecture (v2.1.0)

## 1. System Goal

The Network Sandbox Engine (NSE) provides an isolated, deterministic testing environment for `nftables` firewall rulesets.

Unlike userspace packet filtering simulators, NSE leverages the actual Linux kernel network stack via Network Namespaces (`netns`) and Virtual Ethernet pairs (`veth`) to validate and trace real packets through real kernel code paths. This guarantees full fidelity to production Linux routing and firewall behavior.

NSE ships as one thing: `network-sandbox-engine` on PyPI, a Python library plus a
CLI runner, depending only on `scapy` and `pydantic` (`pyyaml` for the `[cli]`
extra). The FastAPI + Svelte web interface that earlier versions carried was
archived in 2.1.0; it remains in git history at tag `v2.0.0`.

---

## 2. Repository Layout

```
NetworkSandboxEngine/
|
|-- nse/                        # PyPI wheel (only this directory is packaged)
|   |-- __init__.py             # Public API: NetnsController, PCAPAsserter, __version__
|   |-- core/
|   |   |-- naming.py           # Uniform netns/veth derive_names() and sweep rules
|   |   |-- netns_controller.py # Namespace lifecycle, veth wiring, and startup sweep
|   |   |-- scapy_injector.py   # L2/L3 packet forging and injection
|   |   |-- sniffer.py          # PCAPAsserter (AsyncSniffer wrapper)
|   |   |-- pipeline.py         # run_test_pipeline() orchestrator
|   |   |-- rule_engine.py      # nft load / validate / trace-arm
|   |   |-- trace_harvester.py  # nft monitor trace parser and readiness probe
|   |   `-- mock_listener.py    # TCP/UDP echo daemon spawner
|   |-- models/
|   |   |-- test_request.py     # PacketSpec, TestRequest, TopologyType
|   |   `-- trace_event.py      # TraceEvent model
|   `-- cli/
|       `-- runner.py           # nse-runner CLI entrypoint (YAML/JSON)
|
|-- tests/
|   |-- test_netns.py             # Legacy unit suite (namespaces, injection, models)
|   |-- test_engine_internals.py  # Rule engine, controller, injector, listeners
|   |-- test_trace_harvester.py   # Read-loop terminal states and blindness detection
|   |-- test_trace_parser.py      # Golden-file corpus for the trace parser
|   |-- test_runner_logic.py      # Pure decision logic of the CLI runner
|   |-- test_runner_cli.py        # Runner exit codes with the pipeline stubbed
|   |-- test_pipeline_unit.py     # Canary contract with every boundary stubbed
|   |-- test_docs_examples.py     # The YAML in the docs must parse
|   |-- test_oracle_e2e.py        # Privileged e2e oracle integration tests
|   `-- fixtures/nft_trace/       # Golden `nft monitor trace` corpus
|
|-- pyproject.toml              # Build config (packages only nse/)
|-- Makefile                    # Development & local CI automation
`-- conftest.py                 # sys.path root injection for pytest
```

### Architectural Boundaries

Enforced by `import-linter` contracts in `make lint`:

- `nse.core` and `nse.models` must not import `nse.cli` - the engine cannot
  depend on the CLI that drives it.
- `nse.models` must not import the engine - models stay a leaf.

`pydantic` is a mandatory core dependency of `nse/`.

---

## 3. Component Reference

### 3.1 `NetnsController` (`nse/core/netns_controller.py`)

Manages the full lifecycle of network namespaces.

- `create_netns(name)` / `destroy_netns(name)`: raw `ip netns add` / `del`. `destroy_netns` features a 3-attempt exponential backoff retry.
- `startup_sweep()`: automatically cleans orphan `nse_*`, `nsr_*`, `nss_*` netns and `vhr-*`, `vrh-*`, `vrs-*`, `vsr-*` veth links on initialization.
- `create_veth_pair(ns, host_iface, peer_iface, host_ip, peer_ip)`: veth creation, peer assignment into the namespace, IP configuration, and link-up.
- `create_gateway_topology(...)`: three-namespace setup (Host, Router, Server) with dual-stack IPv4/IPv6, sysctl forwarding, and static routes.

### 3.2 `RuleEngine` (`nse/core/rule_engine.py`)

Handles compilation and injection of `nftables` rulesets with enforced subprocess timeouts.

- `validate(rules_text)`: dry-run using `nft --check -f <file>`. Raises `RuleValidationError` on failure with line-level details.
- `load(rules_text, netns)`: loads rules into a specific namespace and prepends `meta nftrace set 1` to arm kernel tracing.

### 3.3 `TraceHarvester` (`nse/core/trace_harvester.py`)

Parses `nft monitor trace` output into structured `TraceEvent` objects, and makes
every way it can stop seeing observable.

- `state` (`HarvestState`): why the read loop ended - `STOPPED` (we asked),
  `CLEAN_EOF` (the monitor died on its own), `TIMEOUT`, or `ERROR`. Only
  `STOPPED` is acceptable. These were previously indistinguishable: all four
  pushed the same `None` sentinel.
- `unparsed_trace_lines`: lines that look like trace output but that no pattern
  matched. Any value above zero means the parser does not understand this
  kernel's format, and is reported as an oracle error rather than a debug log.
- `health_errors()`: the reasons this harvester cannot be trusted, which the
  pipeline turns into `error` events.
- `wait_for_event(timeout)`: resolves only once the kernel has actually delivered
  a parsed event. This is the readiness proof the canary probe uses.
- `wait_ready(timeout=2.0)`: signals that *this process* is reading. Retained for
  diagnostics and explicitly **not** sufficient to conclude that a later packet
  will be observed - it fires before `nft monitor trace` has subscribed to the
  kernel.
- `extend_deadline(seconds)`: pushes the inactivity deadline out. The read loop
  polls its deadline so an extension takes effect mid-read; a fixed deadline
  previously truncated long runs silently.
- `aclose(timeout)`: stops the monitor and drains the read loop without
  cancelling it mid-line, so the state it returns is trustworthy.
- Supports an optional `on_event` callback for synchronous event collection alongside queue streaming.

### 3.4 `run_test_pipeline` (`nse/core/pipeline.py`)

Main orchestrator function:

```python
async def run_test_pipeline(
    request: TestRequest,
    controller: NetnsController | None = None,
    queue: asyncio.Queue[TraceEvent | None] | None = None,
    run: TestRun | None = None,
) -> list[TraceEvent]
```

Executing:
1. Network topology setup
2. Mock listener spawning (one per injected `dst_port`)
3. Ruleset loading & kernel trace arming
4. Trace harvester startup
5. **Readiness canary** - a probe packet is injected and re-injected until its
   own kernel trace event is observed. If it never is, the run emits an oracle
   error and the test packets are never injected: no verdict from a blind
   monitor would be evidence of anything.
6. Sequential packet injection, extending the trace deadline after each packet
7. **Liveness canary** - a second probe after the last test packet, proving the
   monitor was still watching. A miss means the verdict stream is truncated.
8. Conntrack polling, harvester close, and health check
9. Full resource teardown in a `finally` block

Canary trace ids are stripped from the returned event list, so probes never
appear in a caller's verdict stream. See
[The Verdict Oracle](web/explanation/deterministic-oracle.md).

---

## 4. Network Topologies

### 4.1 Simple (Host - Sandbox)

```
  Root (Host) Namespace              Sandbox Namespace ("nse_XYZ")
+------------------------+          +------------------------+
|  iface: vhr-XYZ        |          |  iface: veth-nse       |
|  IPv4: 10.0.0.1/24     |<- veth ->|  IPv4: 10.0.0.2/24     |
|  IPv6: fd00::1/64      |          |  IPv6: fd00::2/64      |
+------------------------+          +------------------------+
```

### 4.2 Gateway (Host - Router - Server)

```
   Host (Root)             Router Netns ("nsr_XYZ")             Server Netns ("nss_XYZ")
+--------------+          +--------------------------------+     +--------------+
| vhr-XYZ      |<- veth ->| vrh-XYZ  (10.0.1.2/fd00:1::2) |     | veth-nse     |
| 10.0.1.1     |          |                                |<- veth ->| 10.0.2.2     |
| fd00:1::1    |          | vrs-XYZ  (10.0.2.1/fd00:2::1)  |     | fd00:2::2    |
+--------------+          +--------------------------------+     +--------------+
```

---

## 5. Security and Isolation

- **Namespace Isolation**: Rulesets are confined to isolated network namespaces identified by per-test UUIDs. `RuleEngine.load()` refuses an empty namespace name, so a missing argument cannot fall through to the host firewall.
- **No listening surface**: NSE runs as root because `ip netns` and kernel tracing require it, but it opens no socket, port or RPC endpoint. It is invoked, it measures, it exits. The web server that ran in-process as root in 2.0.0 was removed in 2.1.0.
- **Deterministic teardown**: namespaces and host-side veth interfaces are removed in a `finally` block with retry backoff, and a startup sweep removes anything a previously crashed run left behind.
- **Pre-Validation**: `nft --check` runs before any `load()` call, preventing malformed rulesets from reaching the kernel.