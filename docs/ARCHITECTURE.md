# Network Sandbox Engine (NSE) - Technical Design Document

## 1. System Goal

The Network Sandbox Engine (NSE) provides an isolated, deterministic, and visual testing environment for `nftables` firewall rulesets. 

Unlike traditional userspace packet filtering simulators, NSE leverages the actual Linux kernel network stack via **Network Namespaces** (`netns`) and **Virtual Ethernet pairs** (`veth`) to validate and trace real packets. This architecture guarantees 100% fidelity to production Linux routing and firewall behavior, providing immediate visual feedback to rule authors.

---

## 2. System Architecture

The project employs a split **Client-Daemon architecture** to cleanly separate high-privilege system operations (requiring root access) from the low-privilege user interface.

```
┌─────────────────────────────────┐           ┌─────────────────────────────────┐
│     Frontend UI (Svelte/Vite)   │           │     Backend Daemon (FastAPI)    │
│     (Runs in userspace)         │           │     (Runs as root / sudo -E)    │
└────────────────┬────────────────┘           └────────────────▲────────────────┘
                 │                                             │
                 │ 1. POST /api/test (JSON request)            │
                 ├─────────────────────────────────────────────┘
                 │
                 │ 2. WS /ws/{test_id} (Live trace events)
                 ◄─────────────────────────────────────────────┐
                                                               │
                                                       [ Trace Harvester ]
                                                       Runs "nft monitor trace"
```

### 2.1 Backend Daemon (Core Engine)
* **Privilege Level:** Runs as `root` (requires `CAP_NET_ADMIN` to manage namespaces, routing, and raw socket injection).
* **Stack:** Python 3.10+ using `FastAPI` and `uvicorn`.
* **Binding Interfaces:**
  * **Development Mode (`--dev`):** Binds to `127.0.0.1:8000` over TCP. Vite proxies requests to enable smooth local DX.
  * **Production Mode (default):** Binds to a local Unix Domain Socket (default `/run/nse.sock`). The static compiled frontend is served directly from the FastAPI daemon to eliminate CORS and simplify deployment.

### 2.2 Core Python Components
* **`NetnsController` ([netns_controller.py](file:///home/onyks/Documents/GitHub/NetworkSandboxEngine/backend/nse/core/netns_controller.py)):** Orchestrates the lifecycle of network namespaces. It supports creating both standard single sandbox namespaces (`simple` topology) and multi-namespace transit environments (`gateway` topology with router + server namespaces). It configures loopback devices, creates `veth` pairs, manages routing paths, and disables IPv6 Duplicate Address Detection (DAD) globally for instant address availability.
* **`RuleEngine` ([rule_engine.py](file:///home/onyks/Documents/GitHub/NetworkSandboxEngine/backend/nse/core/rule_engine.py)):** Handles compilation and injection of `nftables` rulesets using `nft -f`. It parses compilation errors (syntax errors) using regex and maps them to the exact line number of the user ruleset.
* **`ScapyInjector` ([scapy_injector.py](file:///home/onyks/Documents/GitHub/NetworkSandboxEngine/backend/nse/core/scapy_injector.py)):** Forges Layer 3/4 TCP, UDP, or ICMP packets. Supports both IPv4 and IPv6 (`IPv6`, `ICMPv6EchoRequest`). Leverages high-performance in-process injection (`sendp`) for host-originating packets to run in under 1ms, falling back to namespaced execution (`ip netns exec`) for egress packets.
* **`TraceHarvester` ([trace_harvester.py](file:///home/onyks/Documents/GitHub/NetworkSandboxEngine/backend/nse/core/trace_harvester.py)):** Spawns an async subprocess running `nft monitor trace` inside the target ruleset evaluation namespace, parsing kernel outputs into structured `TraceEvent` objects.
* **`MockListener` ([mock_listener.py](file:///home/onyks/Documents/GitHub/NetworkSandboxEngine/backend/nse/core/mock_listener.py)):** Spawns background TCP/UDP socket servers inside target namespaces. This allows completing TCP handshakes (SYN -> SYN-ACK -> ACK) and returning UDP echo traffic to establish valid conntrack connection states.
* **`TestPipeline` ([pipeline.py](file:///home/onyks/Documents/GitHub/NetworkSandboxEngine/backend/nse/core/pipeline.py)):** Chains topology setup, mock listener auto-spawning, ruleset loading, trace harvester starting, sequential packet injection, conntrack table scanning via `/proc/net/nf_conntrack`, event streaming, and clean cascading namespace teardown.

### 2.3 Frontend Interface
* **Stack:** Svelte + Vite.
* **Visual Components:**
  * **Rule Editor:** A Monaco/Text editor for writing `nftables` rulesets.
  * **Packet Crafter:** A form defining protocol, ports, IP headers (IPv4/IPv6), and TCP flags, supporting a list of packets (sequence) and network topology configuration.
  * **Pipeline Visualizer:** A real-time, animated vertical node map depicting packet hooks, rule matches, and final verdicts (ACCEPT/DROP), combined with a tabbed live **Conntrack Table** showing connection protocols, addresses, and states.

---

## 3. Network Design & Packet Pathing

NSE supports two visual topologies:

### 3.1 Simple Topology (Host ◄─► Sandbox)
The default isolated setup connecting the root host namespace to a single sandbox namespace. Both IPv4 and IPv6 subnets are configured on the link to support dual-stack testing.

```
       Root (Host) Namespace                      Sandbox Namespace ("nse_XYZ")
 ┌────────────────────────────────┐            ┌────────────────────────────────┐
 │  Interface: "vh-XYZ"           │            │  Interface: "veth-nse"         │
 │  IPv4: 10.0.0.1/24             │◄── veth ──►│  IPv4: 10.0.0.2/24             │
 │  IPv6: fd00::1/64              │            │  IPv6: fd00::2/64              │
 └────────────────────────────────┘            └────────────────────────────────┘
```

### 3.2 Gateway Topology (Host ◄─► Router ◄─► Server)
Simulates a routed transit topology. Firewall rulesets can be loaded into the intermediate **Router** namespace to test routing, forwarding hook rules (`forward` chain), and NAT translation.

```
   Host (Root)                  Router Netns ("nse_router_XYZ")               Server Netns ("nse_server_XYZ")
┌─────────────────┐             ┌───────────────────────────────┐             ┌─────────────────┐
│ Interface:      │             │ Interfaces:                   │             │ Interface:      │
│  "vhr-XYZ"      │◄── veth ───►│  "vrh-XYZ" (10.0.1.2, fd00:1::2)            │  "veth-nse"     │
│  (10.0.1.1,     │             │                               │◄── veth ───►│  (10.0.2.2,     │
│   fd00:1::1)    │             │  "vrs-XYZ" (10.0.2.1, fd00:2::1)            │   fd00:2::2)    │
└────────┬────────┘             └───────────────┬───────────────┘             └────────┬────────┘
         │                                      │                                      │
  Route: 10.0.2.0/24                     Forwarding: IPv4 & IPv6                       Route: default via
         via 10.0.1.2                    enabled via sysctl                            10.0.2.1
```

---

## 4. Test Lifecycle & Data Flow

A single test run consists of the following steps:

1. **Submission (HTTP POST):** The frontend submits `rules` (string), `packets` (list of JSON objects), and `topology` to `/api/test`. The daemon generates a `test_id`.
2. **Setup:** The `NetnsController` allocates target namespaces (`simple` or `gateway`), configures virtual Ethernet links, enables forwarding sysctls (for gateway), and configures IPv4/IPv6 subnets.
3. **Mock Listeners:** The pipeline automatically identifies destination ports in incoming packets and spawns socket echo listeners inside the target namespace using `mock_listener.py`.
4. **Rule Loading:** The `RuleEngine` loads the ruleset into the target evaluation namespace (Router for gateway, Sandbox for simple). It automatically injects `meta nftrace set 1` to arm tracing.
5. **Harvester Initialization:** The `TraceHarvester` starts `nft monitor trace` inside the evaluation namespace.
6. **Sequential Packet Injection:** The `ScapyInjector` loops through the packets:
   - Forges the packet (using `IP` or `IPv6`, and `TCP`/`UDP`/`ICMP`/`ICMPv6`).
   - Injects the packet on the correct interface.
   - Pauses ($0.3\text{s}$) to allow kernel processing.
   - Polls `/proc/net/nf_conntrack` from the namespace and pushes active connection entries over the WebSocket.
7. **Teardown (Finally Block):** The pipeline closes the trace harvester, terminates mock listener background processes, and deletes the namespaces, which prompts the kernel to clean up all virtual interfaces, routes, and rules.

---

## 5. Headless CLI Test Runner

NSE includes an automated headless test runner for CI/CD environments.
- **Command:** `nse test --file <path_to_yaml_suite>`
- **Execution:** Reads test definitions, invokes the test pipeline programmatically, evaluates actual verdict events against expectations, handles silent packet drops by treating them as `DROP`, and prints clean, color-coded summaries.
- **Exit Code:** Exits with `0` if all tests pass, and `1` if any fail, allowing direct integration into GitHub Actions and GitLab CI.

---

## 6. Security & Isolation Guidelines

* **Namespaced Loading:** The daemon strictly forbids rule loading unless a valid namespace parameter is specified. Rules are never injected into the host's main tables.
* **Unix Sockets:** In production, the Unix socket (`/run/nse.sock`) restricts access to authenticated local users or processes (e.g., an Nginx reverse proxy).
* **Namespace GC:** In the event of a daemon crash or forced shutdown (`SIGINT` or `SIGTERM`), the startup lifespan callback intercepts the signals and iterates through the in-memory active namespace registry, running a synchronous clean-up loop.