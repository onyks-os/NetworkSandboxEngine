# Reference: Dependencies & System Requirements

Network Sandbox Engine (NSE) requires minimal system packages and Python dependencies.

---

## Core Python Dependencies

| Package | Minimum Version | Purpose |
| :--- | :--- | :--- |
| `pydantic` | `>= 2.0.0` | Core request/event data models & validation |
| `scapy` | `>= 2.5.0` | Layer 2 / Layer 3/4 packet forging and injection |

Two runtime dependencies, both for the engine itself. NSE has no web framework,
no ASGI server and no JavaScript toolchain: the web interface was archived in
2.1.0.

---

## Optional extras

### `[cli]` — the YAML suite runner

| Package | Purpose |
| :--- | :--- |
| `pyyaml` | YAML test suite file parsing |

### `[dev]` — contributing

| Package | Purpose |
| :--- | :--- |
| `pytest`, `pytest-asyncio` | Unit & integration test runners |
| `pytest-cov` | Coverage measurement and the `make test-cov` ratchet |
| `ruff` | Formatting & static analysis |
| `mypy` | Strict static type checking |
| `import-linter` | Architectural boundary enforcement |
| `mkdocs-material` | Material web documentation generator |
| `mkdocstrings[python]` | Automatic Python API documentation generator |

---

## System Requirements

- **Linux Kernel**: 5.4+ (with network namespace and `nftables` support)
- **Root privileges**: required for `ip netns` and kernel trace operations
- **Utilities**: `nft` (nftables), `ip` (iproute2), `conntrack`, and `nsenter`
  (used automatically inside containers, where `ip netns exec` cannot mount
  `/sys`)

The nftables version matters: the trace output format has changed across
releases before. NSE's CI runs its privileged suite on more than one image for
that reason, and the Dockerfile exists so you can pin the version your rules are
tested against.
