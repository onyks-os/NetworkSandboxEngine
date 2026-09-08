# Quickstart Tutorial

Get started with Network Sandbox Engine (NSE) in 5 minutes.

---

## Prerequisites

NSE requires a Linux environment with kernel netns support and standard network utilities:

- **Linux OS** (Kernel 5.4+)
- **Python** 3.10+
- **nftables** (`nft`)
- **iproute2** (`ip`)
- **Root privileges** (required for `ip netns` and kernel trace operations)

---

## 1. Installation

Install the package with CLI support via `pip`:

```bash
pip install "network-sandbox-engine[cli]"
```

Or for development / editable setup:

```bash
git clone https://github.com/onyks-os/NetworkSandboxEngine.git
cd NetworkSandboxEngine
make setup
```

---

## 2. Running a Test via CLI

NSE includes a headless runner for YAML test suites.

Create a file named `my_test.yaml`:

```yaml
tests:
  - name: "Allow HTTP port 80"
    topology: simple
    rules: |
      table ip filter {
        chain input {
          type filter hook input priority 0; policy drop;
          tcp dport 80 accept
        }
      }
    packets:
      - protocol: tcp
        src_ip: 10.0.0.1
        dst_ip: 10.0.0.2
        dst_port: 80
        expected_verdict: ACCEPT
      - protocol: tcp
        src_ip: 10.0.0.1
        dst_ip: 10.0.0.2
        dst_port: 22
        expected_verdict: DROP
```

Run the test suite with root privileges:

```bash
sudo .venv/bin/python -m nse.cli.runner --file my_test.yaml
```

**Output:**

```text
[NSE] Loading test suite from: my_test.yaml
Found 1 test cases.
------------------------------------------------------------
Running test: Allow HTTP port 80...
  [OK] Packet 1: expected ACCEPT, got ACCEPT
  [OK] Packet 2: expected DROP, got DROP
  => SUCCESS: Allow HTTP port 80
------------------------------------------------------------
Test Suite Summary: 1 passed, 0 failed.
```

---

## 3. Running via Python API

You can also run pipelines directly from Python code:

```python
import asyncio
from nse.core.netns_controller import NetnsController
from nse.core.pipeline import run_test_pipeline
from nse.models.test_request import TestRequest, PacketSpec

async def test_ruleset():
    request = TestRequest(
        rules="""
        table ip filter {
            chain input {
                type filter hook input priority 0; policy drop;
                tcp dport 80 accept
            }
        }
        """,
        packets=[
            PacketSpec(protocol="tcp", src_ip="10.0.0.1", dst_ip="10.0.0.2", dst_port=80)
        ],
    )
    controller = NetnsController()
    events = await run_test_pipeline(request=request, controller=controller)
    print(f"Captured {len(events)} trace events.")

asyncio.run(test_ruleset())
```

---

## Next Steps

- Explore **[Test Suite YAML Format](test-suites.md)** for advanced test definitions.
- Read **[Architecture Overview](../explanation/architecture.md)** to understand in-process netns execution.
