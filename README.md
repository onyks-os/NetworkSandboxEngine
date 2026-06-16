# Network Sandbox Engine (NSE)

> A visual, deterministic firewall testing environment for `nftables` rules.

NSE uses ephemeral **Linux network namespaces** (`netns`) and **Scapy** to validate firewall logic safely, providing real-time visual feedback via a **Svelte / FastAPI** interface. Rules are executed by the actual Linux kernel, with zero userspace simulation.

---

### 🚀 How It Works

```text
 Svelte (Frontend)            FastAPI (Daemon)            Sandbox (Netns)
        │                            │                            │
        │─── 1. POST /api/test ─────►│                            │
        │    (rules + packets seq)   │─── 2. Setup Topology ─────►│
        │                            │    (Simple or Gateway)     │
        │◄── 3. 202 Accepted ────────│                            │
        │    (test_id)               │─── 4. Spawn Listeners ────►│
        │                            │    (TCP/UDP port daemons)  │
        │─── 5. Connect WebSocket ──►│                            │
        │    /ws/{test_id}           │─── 6. load rules & trace ─►│
        │                            │                            │
        │                            │─── 7. Inject Packets ─────►│
        │                            │    (Sequential scapy)      │
        │                            │                            │
        │                            │◄── 8. Poll Conntrack ──────│
        │◄── 9. Stream Trace/CT ─────│    (cat /proc/net/ct)      │
        │    (WebSocket JSON)        │                            │
        │                            │─── 10. Teardown (GC) ─────►│
        ▼                            ▼                            ▼
```

The host firewall is **never touched** - rules live and die inside the isolated sandbox namespace.

---

## 🛠️ Architecture Overview

| Component            | Technology          | Description                                                                       |
| -------------------- | ------------------- | --------------------------------------------------------------------------------- |
| **Frontend**         | Svelte + Vite       | Rule Editor, Multi-Packet Crafter, and the animated Trace + Conntrack visualizer  |
| **Backend Daemon**   | FastAPI + Uvicorn   | Runs as `root`. Manages namespaces, configures routing tables, and runs tests     |
| **Packet Injection** | Scapy (Layer 2/3)   | Supports both IPv4 and IPv6 packet sequences (TCP flags, ICMP, ICMPv6, UDP)       |
| **Mock Listeners**   | TCP/UDP echo sockets| Auto-spawns background port listeners inside namespaces to simulate responders    |
| **Conntrack Engine** | `/proc/net/conntrack` | Captures active connection states (e.g., ESTABLISHED) and streams them dynamically|
| **CLI Test Runner**  | `nse test` (YAML)   | Headless test suite runner for CI/CD pipelines                                    |

---

## 📋 Prerequisites

NSE requires a Linux machine running a kernel with namespace and `nftables` trace support (Kernel 5.4+).

| Tool / Dependency      | Purpose                                   |
| ---------------------- | ----------------------------------------- |
| **Python 3.10+**       | Runs the backend API daemon & CLI runner  |
| **Node.js 18+**        | Builds and runs the Svelte web interface  |
| **`nftables` (`nft`)** | Compiles rules and generates trace events |
| **`iproute2` (`ip`)**  | Manages network namespaces and veth pairs |

Install system utilities (Debian/Ubuntu):
```bash
sudo apt update
sudo apt install nftables iproute2 python3-venv python3-pip conntrack
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

### 1. Stateful Packet Sequences & Conntrack Table
NSE lets you craft sequence lists of packets to simulate active flows (such as a TCP 3-way handshake). The engine polls `/proc/net/nf_conntrack` and updates the visual **Conntrack Table** in real-time, matching states like `SYN_SENT`, `ESTABLISHED`, or `TIME_WAIT`.

### 2. Automatic Mock Listeners
When you define a packet targeting a port (e.g. TCP port 80), the engine automatically spins up a background echo listener daemon inside the namespace. This daemon accepts connections and echoes payloads, generating valid TCP handshakes and conntrack table updates.

### 3. Gateway Routing TOPOLOGY
In addition to the simple point-to-point topology, you can select the **Gateway Topology** to spawn a **Host ◄─► Router ◄─► Server** setup. Firewall rules are loaded into the intermediate Router namespace to test forwarding hook rules (`forward` chain) and transit routing.

### 4. Dual-Stack IPv4/IPv6 Support
Fully supports IPv6 packet construction (including ICMPv6 echo requests). Link interfaces are configured with both IPv4 and IPv6 subnets by default, and DAD (Duplicate Address Detection) is disabled globally inside namespaces to prevent interface initialization delays.

---

## 🧪 Testing

### Running Unit Tests (Non-Root)
NSE has a robust test suite that validates the controller, scapy injector, and conntrack state machine:
```bash
make test
# Or run manually:
# .venv/bin/pytest
```
*(Runs 20 unit tests, warning-free)*

### Running Headless CLI Test Suite (Root Required)
You can run automated YAML-based test suites using the `nse test` subcommand:
```bash
sudo PYTHONPATH=backend .venv/bin/python -m nse.cli test --file backend/tests/test_suite.yaml
```
This is ideal for running automated assertions inside CI/CD pipelines (GitHub Actions, GitLab CI, etc.).

---

## 📦 Production Deployment & Releases

We support two deployment models: **Native Python Installation** (via packages) and **Docker Containerization**.

### 1. Automated Release Packaging (`make release`)

To build all release artifacts at once, run:
```bash
make release
```

This automated target:
1. Compiles the Svelte frontend into static assets (`frontend/dist/`).
2. Copies these assets into the Python package (`backend/nse/dist/`) so the frontend is fully self-contained.
3. Builds the Python package wheel (`.whl`) and source distribution (`.tar.gz`) inside the `release/` directory.
4. Copies the deployment templates (`Dockerfile` and `scripts/nse.service`) into the `release/` directory.
5. Computes `SHA256SUMS` and automatically prompts your local GPG agent to generate a signed signature file `SHA256SUMS.asc`.

The final release files can be found in the root **`release/`** directory:
* **`nse-1.0.0-py3-none-any.whl`**: The python wheel package containing the backend + embedded offline UI.
* **`nse-1.0.0.tar.gz`**: The source distribution.
* **`Dockerfile`**: For Docker container deployment.
* **`nse.service`**: The systemd service unit template for native service management.
* **`SHA256SUMS`**: Verification hashes.
* **`SHA256SUMS.asc`**: Authenticity signature signed with your GPG key.

---

### 2. Option A: Native Python Installation

To install and run natively on your host Linux system:

#### A.1 Install the Wheel Package
Install the packaged wheel using pip:
```bash
sudo pip install release/nse-1.0.0-py3-none-any.whl
```

#### A.2 Run the Service via Systemd
1. Copy the systemd unit file to the system directory:
   ```bash
   sudo cp release/nse.service /etc/systemd/system/
   ```
2. Reload systemd, enable and start the service:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable nse
   sudo systemctl start nse
   ```
   *The native service will start and bind to `/run/nse.sock`.*

---

### 3. Option B: Docker Container Deployment

To build and run the daemon in an isolated Docker container:

#### B.1 Build the Docker Image
Build the container image using the packaged `Dockerfile`:
```bash
docker build -t nse -f release/Dockerfile .
```

#### B.2 Run the Container
Running the sandbox engine requires netns and networking privileges. You must run the container with `--privileged` (or `--cap-add=NET_ADMIN`):
```bash
docker run --privileged -p 8000:8000 -d --name nse-container nse
```
*Access the interface in your browser at `http://localhost:8000`.*

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
