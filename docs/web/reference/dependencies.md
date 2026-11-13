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

### Runtime pins and compatibility checks

`pyproject.toml` declares the library's supported dependency ranges.
`requirements.txt` records a concrete runtime dependency set for development
and verification; it does not replace those ranges in the published package.
To install that set with the development tools in a fresh virtual environment:

```bash
python -m pip install -r requirements.txt -e ".[dev]"
python -m pip check
```

Pydantic requires an exact matching `pydantic-core` version. Update them together
using the resolver, rather than editing their pins independently:

```bash
pip-compile --upgrade-package pydantic --upgrade-package pydantic-core \
    --output-file=requirements.txt pyproject.toml
```

`pip-compile` is provided by the separate `pip-tools` maintenance tool.
Dependabot groups these two packages. In addition to the Python 3.10–3.13 unit
matrix using the declared ranges, CI installs the runtime pins on Python 3.10
and 3.11 and exercises the minimum Scapy 2.5.0 on Python 3.10. Each compatibility
job checks the installed dependency metadata and runs the coverage gate.

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
| `pytest-cov` | Coverage measurement and the `make coverage` ratchet |
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
