# Network Sandbox Engine (NSE) - Technical Architecture

## 1. System Goal

The Network Sandbox Engine (NSE) provides an isolated, deterministic testing environment for `nftables` firewall rulesets.

Unlike userspace packet filtering simulators, NSE leverages the actual Linux kernel network stack via Network Namespaces (`netns`) and Virtual Ethernet pairs (`veth`) to validate and trace real packets through real kernel code paths. This guarantees full fidelity to production Linux routing and firewall behavior.

NSE ships in two layers:

| Layer          | Package                  | Description                                                             |
|----------------|--------------------------|-------------------------------------------------------------------------|
| Headless Core  | `network-sandbox-engine` on PyPI | Pure Python library and CLI runner. Hard dependency: `scapy`. |
| GUI Daemon     | In-repository (`gui/`)   | FastAPI, Uvicorn, and Svelte web interface. Not distributed via PyPI.   |

---

## 2. Repository Layout

```
NetworkSandboxEngine/
|
|-- nse/                        # PyPI wheel (only this directory is packaged)
|   |-- __init__.py             # Public API: NetnsController, PCAPAsserter
|   |-- core/
|   |   |-- netns_controller.py # Namespace lifecycle and veth wiring
|   |   |-- scapy_injector.py   # L2/L3 packet forging and injection
|   |   |-- sniffer.py          # PCAPAsserter (AsyncSniffer wrapper)
|   |   |-- pipeline.py         # run_test_pipeline() orchestrator
|   |   `-- rule_engine.py      # nft load / validate / trace-arm
|   |-- models/
|   |   |-- base.py             # Pure stdlib dataclasses (no Pydantic)
|   |   |-- test_request.py     # PacketSpec, TestRequest, TopologyType
|   |   `-- trace_event.py      # TraceEvent (Pydantic, lazy import)
|   `-- cli/
|       `-- runner.py           # nse-runner CLI entrypoint (YAML/JSON)
|
|-- gui/                        # Not on PyPI
|   |-- server.py               # FastAPI app and Uvicorn CLI
|   |-- api/
|   |   |-- routes.py           # POST /api/test, GET /api/status
|   |   |-- websocket.py        # WS /ws/{test_id}
|   |   `-- deps.py             # FastAPI dependency injection helpers
|   |-- daemon/
|   |   |-- trace_harvester.py  # nft monitor trace subprocess and parser
|   |   `-- mock_listener.py    # TCP/UDP echo daemon spawner
|   `-- gui_svelte/             # Svelte + Vite frontend
|
|-- tests/
|   `-- test_netns.py           # 20 unit tests + 2 root-only integration tests
|
|-- pyproject.toml              # Build config (packages only nse/)
|-- Makefile
`-- conftest.py                 # sys.path root injection for pytest
```

### Architectural Boundary

`nse/` must not import from `gui/`. `gui/` may freely import from `nse/`. The dependency is strictly one-directional.

All Pydantic and PyYAML imports inside `nse/` are wrapped in `try/except ImportError` to keep the core installable with only `scapy` as a hard dependency.

---

## 3. Component Reference

### 3.1 `NetnsController` (`nse/core/netns_controller.py`)

Manages the full lifecycle of network namespaces.

- `create_netns(name)` / `destroy_netns(name)`: raw `ip netns add` / `del`.
- `create_veth_pair(ns, host_iface, peer_iface, host_ip, peer_ip)`: veth creation, peer assignment into the namespace, IP configuration, and link-up.
- `create_gateway_topology(...)`: three-namespace setup (Host, Router, Server) with dual-stack IPv4/IPv6, sysctl forwarding, and static routes on all three legs.
- `async create_namespace(name, ...)`: async context manager combining creation, veth wiring, and teardown in a `finally` block.
- `async ns.inject_packet(...)`: convenience wrapper around `ScapyInjector` from within a namespace context.
- `async ns.exec(cmd)`: runs an arbitrary command via `ip netns exec` and returns a `CompletedProcess`.

DAD (IPv6 Duplicate Address Detection) is disabled globally in all namespaces via `accept_dad=0` sysctl to prevent interface initialization delays.

### 3.2 `RuleEngine` (`nse/core/rule_engine.py`)

Handles compilation and injection of `nftables` rulesets.

- `validate(rules_text)`: writes rules to a temporary file and invokes `nft --check -f <file>`. Raises `RuleValidationError` on failure, parsing stderr line numbers and error messages into a structured list.
- `load(rules_text, netns)`: loads rules into a specific namespace and automatically prepends `meta nftrace set 1` to arm kernel tracing.

### 3.3 `ScapyInjector` (`nse/core/scapy_injector.py`)

Forges and injects Layer 2/3 packets.

- Supported protocols: `tcp`, `udp`, `icmp`, `icmpv6`.
- Incoming direction (host to namespace): uses `sendp()` in the current process on the host-side interface. Latency is under 1 ms.
- Outgoing direction (namespace to host): spawns `ip netns exec <ns> python3 -c "..."` as a subprocess inside the peer namespace.
- MAC addresses are resolved via `SIOCGIFHWADDR` ioctl.

### 3.4 `PCAPAsserter` (`nse/core/sniffer.py`)

Wraps Scapy's `AsyncSniffer` for interface-level packet capture assertions.

- `await start()`: arms a BPF filter on a given interface.
- `await stop()`: stops capture and returns the list of captured Scapy packet objects.

### 3.5 `run_test_pipeline` (`nse/core/pipeline.py`)

The main orchestrator function that chains all components:

```
TestRequest
    |
    v
1. Validate rules (RuleEngine.validate)
2. Create topology (NetnsController)
3. Spawn mock listeners (gui.daemon.mock_listener - lazy import)
4. Load and arm nft rules (RuleEngine.load)
5. Start trace harvester (gui.daemon.trace_harvester - lazy import)
6. Inject packets (ScapyInjector) -> poll conntrack after each packet
7. Teardown (finally block - always runs)
    |
    v
List[TraceEvent]
```

Steps 3 and 5 use lazy imports. If `gui.daemon` is not installed, the pipeline skips those steps: mock listeners and WebSocket streaming are disabled, but the verdict loop continues to function.

### 3.6 `TraceHarvester` (`gui/daemon/trace_harvester.py`)

Part of the GUI layer. Not included in the wheel.

- Spawns `nft monitor trace` as an async subprocess inside the evaluation namespace.
- Parses each output line into a `TraceEvent` using regex patterns for `hook`, `match`, and `verdict` line types.
- Streams events through an `asyncio.Queue` consumed by the WebSocket handler.

### 3.7 `MockListener` (`gui/daemon/mock_listener.py`)

Part of the GUI layer. Not included in the wheel.

- `start_mock_listener(netns, proto, port, bind_ip)`: spawns a background `subprocess.Popen` running a TCP/UDP echo server via `ip netns exec`.
- Enables complete TCP handshakes (`SYN`, `SYN-ACK`, `ACK`) and valid conntrack state generation without manual configuration.

### 3.8 CLI Runner (`nse/cli/runner.py`)

- Invoked as `nse-runner --file <yaml>`.
- Reads YAML test definitions, invokes `run_test_pipeline` for each, and validates actual verdicts against `expect.verdict`.
- Silent drops (no matching trace event) are treated as `DROP`.
- Exits with `0` if all tests pass, `1` on any failure.
- PyYAML and Pydantic are imported with `try/except ImportError`; an error message with install instructions is shown if the `[cli]` extra is absent.

---

## 4. Network Topologies

### 4.1 Simple (Host - Sandbox)

```
  Root (Host) Namespace              Sandbox Namespace ("nse_XYZ")
+------------------------+          +------------------------+
|  iface: vhr-XYZ        |          |  iface: vrh-XYZ        |
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
  route: 10.0.2.0/24       ip_forward=1                          route: default
  via 10.0.1.2              ipv6.conf.all.forwarding=1           via 10.0.2.1
```

Rules are loaded into the Router namespace to test `forward` chain hooks and NAT.

---

## 5. Test Lifecycle

1. **Submission**: `TestRequest` (rules, packet sequence, topology) is passed to `run_test_pipeline()` or `POST /api/test`.
2. **Rule Validation**: `RuleEngine.validate()` dry-runs the ruleset. Returns `RuleValidationError` with line-level details on failure.
3. **Topology Setup**: `NetnsController` allocates namespaces, creates veth pairs, configures dual-stack IP addresses, and enables forwarding sysctls for the gateway topology.
4. **Mock Listener Spawning**: Destination ports in all packets are auto-detected and echo daemons are spawned inside the target namespace.
5. **Rule Loading**: `RuleEngine.load()` injects the ruleset with `meta nftrace set 1` prepended automatically.
6. **Harvester Start**: `TraceHarvester` begins reading `nft monitor trace` output.
7. **Sequential Packet Injection**: For each `PacketSpec`: forge, inject, sleep 300 ms, poll conntrack, stream `TraceEvent` to the consumer.
8. **Teardown**: A `finally` block closes the harvester, terminates mock listener processes, and calls `destroy_netns()` for every allocated namespace.

---

## 6. Data Models

### PacketSpec

```python
PacketSpec(
    protocol: Literal["tcp", "udp", "icmp", "icmpv6"],
    src_ip: str,   # IPv4 or IPv6
    dst_ip: str,   # IPv4 or IPv6
    src_port: int = 0,
    dst_port: int = 0,
    tcp_flags: list[Literal["S", "A", "F", "R", "P"]] = ["S"],
    size: int = 64,
)
```

### TraceEvent

```python
TraceEvent(
    type: Literal["hook", "match", "verdict"],
    trace_id: str,
    family: str,          # "ip" or "ip6"
    table: str,
    chain: str,
    hook: str | None,         # present on "hook" events
    rule_handle: int | None,  # present on "match" events
    rule_text: str | None,
    verdict: str | None,      # "ACCEPT", "DROP", "CONTINUE", etc.
    timestamp: float,
)
```

---

## 7. Optional GUI Layer

The GUI daemon adds a web interface on top of the headless core. It is not distributed via PyPI and must be run from a repository clone.

### API Endpoints

| Method | Path                    | Description                                      |
|--------|-------------------------|--------------------------------------------------|
| POST   | `/api/test`             | Submit a `TestRequest`; returns `{"test_id": "..."}` |
| GET    | `/api/status/{test_id}` | Poll test status                                 |
| WS     | `/ws/{test_id}`         | Stream `TraceEvent` JSON messages                |

### WebSocket Protocol

Each message is a JSON-serialized `TraceEvent`. The connection is closed by the server after teardown completes or after a configurable timeout.

### Frontend Components

- **Rule Editor**: textarea for `nftables` ruleset authoring.
- **Packet Crafter**: form for building ordered `PacketSpec` lists with topology selection.
- **Pipeline Visualizer**: animated vertical node map showing the hook, rule match, and verdict flow in real-time.
- **Conntrack Table**: live tabular view of active connection states streamed from the daemon.

---

## 8. Security and Isolation

- **Namespace isolation**: rules are never loaded into the host network tables. All rulesets are confined to namespaces identified by a per-test UUID.
- **Unix socket in production**: the daemon binds to `/run/nse.sock` in production mode, accessible only to local root or a configured reverse proxy. No TCP exposure.
- **Namespace GC**: on `SIGINT` or `SIGTERM`, the FastAPI lifespan handler iterates the in-memory namespace registry and performs a synchronous cleanup loop before exit.
- **Rule pre-validation**: `nft --check` runs before any `load()` call, preventing injection of malformed rulesets.

---

## 9. Dependency Matrix

| Dependency       | Required by    | Install extra   |
|------------------|----------------|-----------------|
| `scapy>=2.5.0`   | Core (always)  | (base)          |
| `pydantic>=2.0.0`| Models, CLI    | `[cli]`         |
| `pyyaml>=6.0`    | CLI runner     | `[cli]`         |
| `fastapi`        | GUI daemon     | (in-repo only)  |
| `uvicorn`        | GUI daemon     | (in-repo only)  |
| `websockets`     | GUI daemon     | (in-repo only)  |