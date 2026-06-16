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
* **`NetnsController` ([netns_controller.py](file:///home/onyks/Documents/GitHub/NetworkSandboxEngine/backend/nse/core/netns_controller.py)):** Orchestrates the lifecycle of network namespaces. It dynamically allocates namespaces, configures `lo` loopback devices, creates `veth` interface pairs, moves interfaces inside the sandbox, and cleans up resource traces upon completion.
* **`RuleEngine` ([rule_engine.py](file:///home/onyks/Documents/GitHub/NetworkSandboxEngine/backend/nse/core/rule_engine.py)):** Handles compilation and injection of `nftables` rulesets. It passes rules directly to the kernel command `nft -f`. By analyzing `stderr` with line-matching regex patterns, it pinpoints compilation errors (e.g., syntax mistakes) to the exact line number of the user's ruleset.
* **`ScapyInjector` ([scapy_injector.py](file:///home/onyks/Documents/GitHub/NetworkSandboxEngine/backend/nse/core/scapy_injector.py)):** Forges Layer 3/4 TCP, UDP, or ICMP packets matching the test specification and injects them. 
* **`TraceHarvester` ([trace_harvester.py](file:///home/onyks/Documents/GitHub/NetworkSandboxEngine/backend/nse/core/trace_harvester.py)):** Spawns an async subprocess running `nft monitor trace` inside the target namespace. It parses raw stdout lines into structured, JSON-serializable `TraceEvent` models and streams them to the WebSocket queue.
* **`TestPipeline` ([pipeline.py](file:///home/onyks/Documents/GitHub/NetworkSandboxEngine/backend/nse/core/pipeline.py)):** An async workflow coordinator that chains setup, tracing initialization, packet injection, event collection, and teardown.

### 2.3 Frontend Interface
* **Stack:** Svelte + Vite. Svelte is selected for its lack of a virtual DOM, micro-animations support, and small bundle size.
* **Visual Components:**
  * **Rule Editor:** A Monaco/Text editor for writing `nftables` configuration.
  * **Packet Crafter:** A form defining protocols, ports, IP headers, and TCP flags.
  * **Pipeline Visualizer:** A real-time, animated vertical node map depicting packet hooks, rule matches, and final verdicts (ACCEPT/DROP).

---

## 3. Network Design & Packet Pathing

To test firewall rules deterministically, the sandbox configures a virtual point-to-point network between the host namespace and the sandbox namespace.

```
       Root (Host) Namespace                      Sandbox Namespace ("nse_XYZ")
 ┌────────────────────────────────┐            ┌────────────────────────────────┐
 │  Interface: "veth-host"        │            │  Interface: "veth-nse"         │
 │  IP: [packet.src_ip]           │◄── veth ──►│  IP: [packet.dst_ip]           │
 └────────────────────────────────┘            └────────────────────────────────┘
                 ▲                                             ▲
                 │                                             │
      INCOMING INJECTION PATH                       OUTGOING INJECTION PATH
      (Injected from root namespace)                (Injected from inside netns)
```

### 3.1 Interface IP Configuration
When a test runs, the `NetnsController` dynamically configures the `veth` pair using the source and destination IP addresses specified in the user's packet configuration:
* `veth-host` (on the root namespace) is configured with `packet.src_ip`.
* `veth-nse` (inside the sandbox namespace) is configured with `packet.dst_ip`.

This ensures that the routing table and local IP stack matches the packet's target subnets, enabling standard kernel packet processing.

### 3.2 Injection Paths (Ingress vs. Egress)
To test firewall hooks properly, packets must travel in the correct direction:
1. **Incoming Packets (Ingress):** If the destination IP is the sandbox IP (`dst_ip`), the packet must enter the namespace from the outside to hit `prerouting` and `input` hooks. The `ScapyInjector` retrieves the MAC addresses of both interfaces, builds the Ethernet frame as `Ether(src=host_mac, dst=peer_mac)`, and transmits the frame from the **root namespace** on the `veth-host` interface.
2. **Outgoing Packets (Egress):** If the packet is originating from the sandbox (`src_ip` matches the sandbox IP), the `ScapyInjector` enters the namespace using `ip netns exec` and transmits the frame on `veth-nse` targeting `veth-host`. This triggers `output` and `postrouting` hooks.

---

## 4. Test Lifecycle & Data Flow

A single test run consists of the following steps:

1. **Submission (HTTP POST):** The frontend submits `rules` (string) and `packet` (JSON object) to `/api/test`. The daemon generates a `test_id` and schedules the async pipeline task.
2. **Setup:** The `NetnsController` creates the namespace (`nse_{test_id}`), initializes the `veth` interfaces, and sets their link states to UP.
3. **Rule Loading:** The `RuleEngine` loads the user ruleset into the namespace.
   * *Automatic Tracing Instrument:* The daemon automatically parses the ruleset and inserts `meta nftrace set 1` as the first rule in every chain. This guarantees tracing is active even if the user forgets to include the directive.
4. **Harvester Initialization:** The `TraceHarvester` starts `nft monitor trace` inside the namespace. The pipeline sleeps for a short warmup period ($0.4\text{s}$) to allow the kernel monitor socket to open.
5. **Packet Injection:** The `ScapyInjector` fires the raw packet on the appropriate interface.
6. **Trace Collection:** As the kernel processes the packet, trace events are generated. The `TraceHarvester` reads stdout, parses events, and feeds them into the WebSocket queue.
7. **Teardown (Finally Block):** After a timeout of $5.0\text{s}$ or when a terminating verdict (e.g., `ACCEPT` or `DROP`) is processed, the pipeline task exits. The `finally` block executes `ip netns del`, which prompts the Linux kernel to automatically garbage collect all rulesets, routes, and virtual interfaces associated with the namespace.

---

## 5. Security & Isolation Guidelines

* **Tabular Safety:** The daemon strictly forbids rule loading unless a valid namespace parameter is specified. Rules are never injected into the host's `init_net` table.
* **Unix Sockets:** In production, the Unix socket (`/run/nse.sock`) restricts access to authenticated local users or processes (e.g., an Nginx reverse proxy).
* **Namespace GC:** In the event of a daemon crash or forced shutdown (`SIGINT` or `SIGTERM`), the startup lifespan callback intercepts the signals and iterates through the in-memory active namespace registry, running a synchronous clean-up loop.