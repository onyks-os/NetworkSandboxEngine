# Reference: Dependencies & System Requirements

Network Sandbox Engine (NSE) requires minimal system packages and Python dependencies.

---

## Core Python Dependencies

| Package | Minimum Version | Purpose |
| :--- | :--- | :--- |
| `pydantic` | `>= 2.0.0` | Core request/event data models & validation |
| `scapy` | `>= 2.5.0` | Layer 2 / Layer 3/4 packet forging and injection |
| `pyyaml` | `>= 6.0` | YAML test suite file parsing |

---

## Web & Development Dependencies (`[cli]`, `dev`)

| Package | Purpose |
| :--- | :--- |
| `fastapi` | Web server REST API framework |
| `uvicorn` | ASGI web server |
| `pytest`, `pytest-asyncio` | Unit & integration test runners |
| `ruff` | Formatting & static analysis |
| `mypy` | Strict static type checking |
| `import-linter` | Architectural boundary enforcement |
| `mkdocs-material` | Material web documentation generator |
| `mkdocstrings[python]` | Automatic Python API documentation generator |

---

## System Requirements

- **Linux Kernel**: 5.4+ (with network namespace and `nftables` support)
- **Utilities**: `nft` (nftables), `ip` (iproute2), `nsenter` (optional fallback inside containers)
