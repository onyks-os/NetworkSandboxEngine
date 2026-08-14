# Network Sandbox Engine (NSE) - Technical Architecture (v2.0.0)

## 1. System Goal

The Network Sandbox Engine (NSE) provides an isolated, deterministic testing environment for `nftables` firewall rulesets.

Unlike userspace packet filtering simulators, NSE leverages the actual Linux kernel network stack via Network Namespaces (`netns`) and Virtual Ethernet pairs (`veth`) to validate and trace real packets through real kernel code paths. This guarantees full fidelity to production Linux routing and firewall behavior.

NSE ships in two layers:

| Layer          | Package                  | Description                                                             |
|----------------|--------------------------|-------------------------------------------------------------------------|
| Headless Core  | `network-sandbox-engine` on PyPI | Pure Python library and CLI runner. Core dependencies: `scapy`, `pydantic`. |
| GUI Layer      | In-repository (`gui/`)   | In-process FastAPI, Uvicorn, and Svelte web interface. Not on PyPI.   |

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
|-- gui/                        # Not on PyPI
|   |-- server.py               # FastAPI app and Uvicorn CLI (In-process execution)
|   |-- api/
|   |   |-- routes.py           # POST /api/test, GET /test/{test_id}
|   |   `-- websocket.py        # WS /ws/{test_id} trace event streaming
|   `-- gui_svelte/             # Svelte + Vite frontend
|
|-- tests/
|   |-- test_netns.py           # Unit test suite
|   |-- test_trace_parser.py    # Golden file parser test suite
|   `-- test_oracle_e2e.py      # Privileged e2e oracle integration tests
|
|-- pyproject.toml              # Build config (packages only nse/)
|-- Makefile                    # Development & local CI automation
`-- conftest.py                 # sys.path root injection for pytest
```

### Architectural Boundary

`nse/` must not import from `gui/`. `gui/` may freely import from `nse/`. The dependency is strictly one-directional, enforced by `import-linter` contracts (`make lint`).

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

Parses `nft monitor trace` output into structured `TraceEvent` objects.

- `wait_ready(timeout=2.0)`: readiness probe using `asyncio.Event` that signals when the trace monitor subprocess is up and reading.
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
1. Rule syntax validation
2. Network topology setup
3. Mock listener spawning
4. Ruleset loading & kernel trace arming
5. Trace harvester startup with readiness probe
6. Sequential packet injection & conntrack polling
7. Full resource teardown in a `finally` block

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
   Host (Root)             Router Netns ("nse_router_XYZ")      Server Netns ("nse_server_XYZ")
+--------------+          +--------------------------------+     +--------------+
| vhr-XYZ      |<- veth ->| vrh-XYZ  (10.0.1.2/fd00:1::2) |     | veth-nse     |
| 10.0.1.1     |          |                                |<- veth ->| 10.0.2.2     |
| fd00:1::1    |          | vrs-XYZ  (10.0.2.1/fd00:2::1)  |     | fd00:2::2    |
+--------------+          +--------------------------------+     +--------------+
```

---

## 5. Security and Isolation

- **Namespace Isolation**: Rulesets are confined to isolated network namespaces identified by per-test UUIDs.
- **In-Process Root Security**: The web server runs as a single root process with direct state management in FastAPI `app.state`.
- **Pre-Validation**: `nft --check` runs before any `load()` call, preventing malformed rulesets from reaching the kernel.