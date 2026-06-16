# Network Sandbox Engine (NSE)

> A visual, deterministic firewall testing environment for `nftables` rules.

NSE uses ephemeral **Linux network namespaces** (`netns`) and **Scapy** to validate firewall logic safely, providing real-time visual feedback via a **Svelte / FastAPI** interface. Rules are executed by the actual Linux kernel, with zero userspace simulation.

---

## 🚀 How It Works

```text
 Svelte (Frontend)            FastAPI (Daemon)            Sandbox (Netns)
        │                            │                            │
        │─── 1. POST /api/test ─────►│                            │
        │    (rules + packet spec)   │─── 2. nft --check (dry) ───│
        │                            │                            │
        │◄── 3. 202 Accepted ────────│                            │
        │    (test_id)               │                            │
        │                            │─── 4. Setup Sandbox ──────►│
        │─── 5. Connect WebSocket ──►│    (netns, veth, rules)    │
        │    /ws/{test_id}           │                            │
        │                            │─── 6. nft monitor trace ──►│
        │                            │                            │
        │                            │─── 7. Inject Packet ──────►│
        │                            │                            │
        │                            │◄── 8. Emit Traces ─────────│
        │◄── 9. Stream TraceEvents ──│    (kernel evaluation)     │
        │    (WebSocket JSON)        │                            │
        │                            │─── 10. Teardown (GC) ─────►│
        ▼                            ▼                            ▼
```

The host firewall is **never touched** - rules live and die inside the isolated sandbox namespace.

---

## 🛠️ Architecture Overview

| Component            | Technology          | Description                                                                       |
| -------------------- | ------------------- | --------------------------------------------------------------------------------- |
| **Frontend**         | Svelte + Vite       | Rule Editor, Packet Crafter, and the animated Pipeline Trace                      |
| **Backend Daemon**   | FastAPI + Uvicorn   | Runs as `root`. Manages namespaces, configures veths, and monitors traces         |
| **Packet Injection** | Scapy (Layer 2/3)   | Dynamically routes packets through the veth wire (host-to-netns or netns-to-host) |
| **Tracing Engine**   | `nft monitor trace` | Captures kernel tracing logs and streams them over a WebSocket                    |
| **Isolation**        | `ip netns` + `veth` | Full kernel stack network namespace isolation                                     |

---

## 📋 Prerequisites

NSE requires a Linux machine running a kernel with namespace and `nftables` trace support (Kernel 5.4+).

| Tool / Dependency      | Purpose                                   |
| ---------------------- | ----------------------------------------- |
| **Python 3.10+**       | Runs the backend API daemon               |
| **Node.js 18+**        | Builds and runs the Svelte web interface  |
| **`nftables` (`nft`)** | Compiles rules and generates trace events |
| **`iproute2` (`ip`)**  | Manages network namespaces and veth pairs |

Install system utilities (Debian/Ubuntu):
```bash
sudo apt update
sudo apt install nftables iproute2 python3-venv python3-pip
```

---

## ⚡ Quickstart

Follow these steps to bootstrap and run NSE in development mode:

### 1. Bootstrap the Environment
Clone the repository and run the setup script to create the Python virtual environment and install Node modules:
```bash
git clone https://github.com/onyks-os/NetworkSandboxEngine.git
cd NetworkSandboxEngine
make setup
```

### 2. Start the Backend Daemon (Terminal 1)
The daemon requires root privileges to manage namespaces and inject raw packets. Run it with `sudo -E` to preserve the environment path to your virtual environment:
```bash
make backend
# Or run manually:
# sudo -E .venv/bin/python -m nse serve --dev
```
*The daemon will start and bind to `http://127.0.0.1:8000` over TCP.*

### 3. Start the Frontend Dev Server (Terminal 2)
Run the Vite development server as a normal (non-root) user:
```bash
make frontend
# Or run manually:
# cd frontend && npm run dev
```
Open **[http://localhost:5173](http://localhost:5173)** in your browser.

---

## 🎯 Key Features & Mechanics

### 1. Dynamic Packet Injection & MAC Routing
NSE automatically configures interface IP addresses matching the packet specification:
* `veth-host` on the host side gets `packet.src_ip`.
* `veth-nse` inside the namespace gets `packet.dst_ip`.

For **incoming packets** (the default firewall test), the engine retrieves the MAC address of `veth-nse` and fires the packet from the host namespace on `veth-host` targeting `veth-nse` at Layer 2 (`Ether(src=host_mac, dst=peer_mac)`). This guarantees the packet is processed as unicast ingress and enters the sandbox's `input` chain.

### 2. Automatic Trace Flag Instrumentation
You don't need to manually type `meta nftrace set 1` inside every chain in your ruleset. The backend engine automatically parses your rules and injects the trace directive as the first rule in every chain.

### 3. Graceful Shutdown & Cleanup
Pressing `Ctrl+C` inside the daemon terminal triggers a clean shutdown. The daemon catches the event, stops the server, and automatically runs `controller.cleanup_all()` to delete any active namespaces, ensuring zero residual network interfaces or configuration leaks on the host.

---

## 🧪 Testing

The Python backend includes a unit test suite that mocks system calls and checks packet routing, validation parsing, and CLI commands.

To run tests (no root required):
```bash
make test
```
*(Runs 12 unit tests, warning-free, in under 0.3s)*

---

## 📦 Production Deployment

To run NSE in production, serve the Svelte static frontend directly from the FastAPI daemon over a secure Unix socket:

1. **Compile Svelte assets:**
   ```bash
   make build-frontend
   ```
2. **Start the production daemon:**
   ```bash
   sudo -E .venv/bin/python -m nse serve
   ```
   *This binds the daemon to `/run/nse.sock` and serves the frontend static files from `frontend/dist` on the same port.*

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
