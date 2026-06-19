# Network Sandbox Engine (NSE)

A headless Python engine for deterministic, kernel-level `nftables` firewall testing, with an optional Svelte/FastAPI web GUI.

[![PyPI](https://img.shields.io/badge/PyPI-network--sandbox--engine-blue)](https://pypi.org/project/network-sandbox-engine/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Linux only](https://img.shields.io/badge/OS-Linux%20only-lightgrey.svg)](https://kernel.org/)

NSE uses ephemeral Linux network namespaces and Scapy to validate firewall logic. Rules are executed by the actual kernel: no userspace simulation, no host pollution.

---

## How It Works

```text
 [Library / CLI]            [FastAPI Daemon (optional)]     [Sandbox - Linux netns]
        |                              |                              |
        |-- run_test_pipeline() ------>|                              |
        |   (rules + packet sequence)  |-- 1. Create topology ------->| (veth pair / gateway)
        |                              |-- 2. Spawn mock listeners -->| (TCP/UDP echo daemons)
        |                              |-- 3. Load nft rules -------->|
        |                              |-- 4. Start nft monitor ----->| (trace harvester)
        |                              |-- 5. Inject packets -------->| (Scapy L2/L3)
        |                              |<- 6. Poll conntrack ---------| (/proc/net/nf_conntrack)
        |<-- TraceEvent stream --------|-- 7. Stream verdicts ------->| (WebSocket or iterator)
        |                              |-- 8. Teardown (GC) --------->| (namespace deleted)
```

The host firewall is never modified. Rules are confined to the isolated sandbox namespace and are destroyed with it at teardown.

---

## Architecture Overview

| Component              | Technology               | Description                                                                   |
| ---------------------- | ------------------------ | ----------------------------------------------------------------------------- |
| Headless Core          | Python 3.10+ / Scapy     | `NetnsController`, `PCAPAsserter`, `RuleEngine`, `ScapyInjector`, `Pipeline`  |
| CLI Test Runner        | `nse-runner` / YAML      | Headless YAML test suite runner for CI/CD pipelines                           |
| GUI Daemon (optional)  | FastAPI + Uvicorn        | REST and WebSocket API streaming `TraceEvent` objects from the kernel         |
| Frontend (optional)    | Svelte + Vite            | Rule editor, multi-packet crafter, animated trace visualizer, conntrack table |
| Packet Injection       | Scapy (Layer 2/3)        | IPv4 and IPv6, TCP with custom flags, UDP, ICMP, ICMPv6                       |
| Mock Listeners         | TCP/UDP echo sockets     | Background listeners inside namespaces to complete handshakes                 |
| Conntrack Engine       | `/proc/net/nf_conntrack` | Captures `ESTABLISHED`, `SYN_SENT`, `TIME_WAIT` states in real-time          |

---

## Prerequisites

NSE requires Linux with kernel 5.4 or later (namespace and nftables trace support).

| Dependency        | Purpose                                    |
| ----------------- | ------------------------------------------ |
| Python 3.10+      | Core library, CLI, and optional GUI daemon |
| nftables (`nft`)  | Compiles rules and generates trace events  |
| iproute2 (`ip`)   | Manages network namespaces and veth pairs  |
| conntrack         | Reads connection state from kernel tables  |
| Node.js 18+       | Required only to build the Svelte frontend |

```bash
# Debian / Ubuntu
sudo apt install nftables iproute2 python3-venv python3-pip conntrack
```

---

## Quickstart

### A. Headless library

```bash
pip install network-sandbox-engine
```

```python
import asyncio
from nse.core.pipeline import run_test_pipeline
from nse.models.test_request import PacketSpec, TestRequest

async def main():
    req = TestRequest(
        rules="table ip filter { chain input { type filter hook input priority 0; tcp dport 22 accept; drop; } }",
        packets=[PacketSpec(protocol="tcp", src_ip="10.0.0.1", dst_ip="10.0.0.2", dst_port=22)],
    )
    events = await run_test_pipeline(req)
    for ev in events:
        print(ev)

asyncio.run(main())
```

### B. CLI YAML runner

```bash
pip install "network-sandbox-engine[cli]"
nse-runner --file my_tests.yaml
```

```yaml
# my_tests.yaml
- name: SSH accepted
  rules: |
    table ip filter {
      chain input { type filter hook input priority 0; tcp dport 22 accept; drop; }
    }
  packets:
    - protocol: tcp
      src_ip: 10.0.0.1
      dst_ip: 10.0.0.2
      dst_port: 22
  expect:
    verdict: ACCEPT
```

### C. Full GUI (development mode)

```bash
git clone https://github.com/onyks-os/NetworkSandboxEngine.git
cd NetworkSandboxEngine
make setup     # bootstrap venv + npm install
make backend   # starts FastAPI daemon (requires sudo -E)
make frontend  # starts Vite dev server on port 5173
```

Open `http://localhost:5173` in a browser.

---

## Repository Layout

```
NetworkSandboxEngine/
|-- nse/                        # PyPI package (pip install network-sandbox-engine)
|   |-- __init__.py             # Public API: NetnsController, PCAPAsserter
|   |-- core/                   # Kernel-level primitives
|   |   |-- netns_controller.py
|   |   |-- scapy_injector.py
|   |   |-- sniffer.py          # PCAPAsserter
|   |   |-- pipeline.py         # run_test_pipeline()
|   |   `-- rule_engine.py      # nft load / validate
|   |-- models/                 # Pydantic models (lazy import via try/except)
|   |   |-- test_request.py     # PacketSpec, TestRequest, TopologyType
|   |   `-- trace_event.py      # TraceEvent
|   `-- cli/
|       `-- runner.py           # nse-runner entrypoint
|
|-- gui/                        # Not on PyPI - GUI daemon only
|   |-- server.py               # FastAPI + Uvicorn entrypoint
|   |-- api/                    # REST routes and WebSocket
|   `-- daemon/                 # trace_harvester, mock_listener
|       `-- gui_svelte/         # Svelte + Vite frontend
|
|-- tests/
|   `-- test_netns.py           # 20 unit tests (2 skipped without root)
|
|-- pyproject.toml              # Build config - packages only nse/
|-- Makefile                    # make setup | test | lint | release
`-- conftest.py                 # Root sys.path for pytest
```

---

## Key Features

### 1. Stateful Packet Sequences and Conntrack

Ordered lists of packets simulate TCP flows. NSE polls `/proc/net/nf_conntrack` and streams live connection states (`SYN_SENT`, `ESTABLISHED`, `TIME_WAIT`) after each injection.

### 2. Automatic Mock Listeners

Destination ports in incoming packets receive a background echo listener spawned inside the namespace, completing TCP handshakes and generating valid conntrack entries without manual setup.

### 3. Gateway Routing Topology

The Gateway Topology spawns a three-namespace chain: Host - Router - Server. Rules are loaded into the Router namespace to test `forward` chain hooks, routing decisions, and NAT.

### 4. Dual-Stack IPv4 and IPv6

ICMPv6 echo, dual-stack veth links, and DAD disabled for instant address availability inside namespaces.

### 5. PCAP Assertions

`PCAPAsserter` wraps Scapy's `AsyncSniffer` to arm a BPF filter on a veth interface and assert captured packets. It is usable independently of the full pipeline.

---

## Testing

Unit tests (no root required):

```bash
make test
# 20 passed, 2 skipped (root-only integration tests)
```

Integration tests (root required):

```bash
sudo -E .venv/bin/pytest tests/ -v
```

CLI test suite (root required):

```bash
sudo -E .venv/bin/python -m nse.cli.runner --file tests/fixtures/test_suite.yaml
```

---

## Production Deployment

### Package Extras

| Mode           | Install command                             | Dependencies           |
| :------------- | :------------------------------------------ | :--------------------- |
| Headless core  | `pip install network-sandbox-engine`        | `scapy`                |
| With CLI runner | `pip install "network-sandbox-engine[cli]"` | + `pydantic`, `pyyaml` |

The GUI daemon is not distributed via PyPI. It is run from a repository clone.

### Building Release Artifacts

```bash
make release
```

This target performs the following steps:

1. Runs `make lint` and `make test`; fails on any error.
2. Builds `.whl` and `.tar.gz` with `python -m build`.
3. Copies `Dockerfile` and `scripts/nse.service` into `release/`.
4. Generates `SHA256SUMS`.
5. Signs `SHA256SUMS` with GPG, producing `SHA256SUMS.asc`. The signing key is auto-detected from the keyring; it can be overridden with `GPG_KEY_ID=<id>`.

Output in `release/`:

```
release/
|-- network_sandbox_engine-1.0.0-py3-none-any.whl
|-- network_sandbox_engine-1.0.0.tar.gz
|-- Dockerfile
|-- nse.service
|-- SHA256SUMS
`-- SHA256SUMS.asc
```

### Native Installation with Systemd

```bash
sudo pip install release/network_sandbox_engine-1.0.0-py3-none-any.whl
sudo cp release/nse.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now nse
```

### Docker

```bash
docker build -t nse -f release/Dockerfile .
docker run --privileged -p 8000:8000 -d --name nse-container nse
```

---

## License

MIT. See [LICENSE](LICENSE).
