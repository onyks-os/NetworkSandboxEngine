# Changelog

All notable changes to the Network Sandbox Engine (NSE) project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/). This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.0.0] - 2026-08-13

Single-Process In-Process Architecture, Pydantic Hard Dependency, Deterministic Verdict Oracle, and Strict Static Typing.

### Breaking Changes

- **Elimination of `rootd` Daemon**: Removed socket daemon `gui/rootd.py`, `gui/api/rootd_client.py`, and `gui/api/deps.py`. FastAPI web application and `NetnsController` now run directly in-process with root privileges.
- **Mandatory Pydantic Dependency**: `pydantic` promoted to a mandatory core dependency of `nse/`; eliminated all stdlib fallback dataclasses and stubs.
- **Consolidated Model Hierarchy**: Deleted `nse/models/base.py`. `TopologyType` and `PacketSpec` now collapse to a single source of truth in `nse.models.test_request`.
- **Target Orchestrator Signature**: Rewrote `run_test_pipeline` signature to target standard request-driven API returning `list[TraceEvent]`.
- **Purged Controller State**: Removed `enqueue_test`, `release_test`, `has_test`, `get_status`, `get_event_queue`, and `_tests` tracking methods from `NetnsController`.

### Added

- **Trace Harvester Readiness Probe**: Added `wait_ready()` in `TraceHarvester` using `asyncio.Event` readiness signal, eliminating hardcoded warm-up delay sleeps.
- **Uniform Naming & Startup Sweep**: Created `nse.core.naming` helper with `derive_names()` and automated orphan netns/veth startup sweep in `NetnsController`.
- **Teardown Retry & Subprocess Timeouts**: Implemented retry backoff in `destroy_netns` and enforced `timeout=` parameters across all `subprocess.run` calls.
- **Strict Static Typing & Import Boundaries**: Enforced `mypy --strict` across all 22 source files and configured `import-linter` contract preventing `nse/` from importing `gui/`.
- **MkDocs Web Documentation**: Created comprehensive web documentation site powered by MkDocs Material and `mkdocstrings`.
- **Local CI Automation**: Added `make ci-local` and `make docs` Makefile targets.

---

## [1.1.1] - 2026-08-05

Kernel tracing initialization fix, background noise filtering in YAML test runner, and Makefile dynamic binary resolution.

### Added

- **Automatic Kernel Tracing Prepending**: Automatically inject a high-priority `table inet nse_trace` prerouting chain (`meta nftrace set 1`) in `RuleEngine.load()` to guarantee `nft monitor trace` captures trace events for all test packets.

### Fixed

- **YAML Runner Trace Noise Filtering**: Filtered out background setup noise (IPv6 NDP, DAD, MLD, and socket init packets) in `nse.cli.runner` to accurately match verdicts (`ACCEPT`/`DROP`) to injected test packets.
- **`nft monitor trace` Regex Parser**: Updated `_PACKET_RE` in `gui/daemon/trace_harvester.py` to handle both quoted and unquoted `iif` strings in trace lines across different Linux kernel and `nftables` versions.
- **Dynamic Executable Resolution in Makefile**: Updated `Makefile` to dynamically detect `PYTHON`, `RUFF`, `TWINE`, and `PYTEST` in `.venv` with automatic fallbacks to `PATH` system binaries.
- **Ruff Code Quality Compliance**: Resolved all Ruff static analysis errors (`ASYNC221`, `I001`, `BLE001`, `UP037`, `TRY401`, `PIE790`) across `nse/`, `gui/`, and `tests/`.

---

## [1.1.0] - 2026-06-19

Introducing native container environments support and a Zero-Trust Privilege Separation architecture for the web server.

### Added

- **Native Container Support (`nsenter` fallback)**: Added robust container detection in `nse/core/utils.py` (checking `container` env, `/.dockerenv`, `/proc/1/environ`, and `cgroup` format). Dynamic fallback from `ip netns exec` to `nsenter --net` namespace switching prevents remount errors in container runtimes.
- **Zero-Trust Privilege Separation**:
  - `nse-rootd` UNIX domain socket server running as root and managing network namespaces, Scapy injection, and trace harvesting. Secure `/var/run/nse-core.sock` socket is automatically chowned to `SUDO_UID`/`SUDO_GID` when run via `sudo`.
  - `RootdClient` client proxy allowing unprivileged web server instances (`nse-web` / `gui/server.py`) to delegate low-level sandbox execution without running as root.
- **Dedicated RPC Unit Tests**: Added asynchronous mocking test `test_rootd_rpc_communication` to verify JSON-RPC protocol between client and daemon.

### Changed

- **Makefile and dev-setup**: Restructured commands (`make run-rootd`, `make run-web`, `make backend`, and `make dev`) and updated startup instructions to reflect the decoupled daemon architecture.

---

## [1.0.0] - 2026-06-18

First stable release of the Network Sandbox Engine.

### Summary

NSE v1.0.0 is published as a headless Python library (`network-sandbox-engine` on PyPI) with an optional GUI layer that lives in-repository. The core engine depends only on `scapy`; CLI tooling requires `pydantic` and `pyyaml` via the `[cli]` extra. The GUI daemon (FastAPI and Svelte) is excluded from the wheel by design and is run from a repository clone.

---

### Added

#### Core Headless Engine (`nse/`)

- `NetnsController`: async context manager for ephemeral Linux network namespace lifecycle (create, configure, teardown). Supports `simple` (host to sandbox) and `gateway` (host to router to server) topologies.
- `PCAPAsserter`: wraps Scapy `AsyncSniffer` to arm BPF-filtered captures on veth interfaces and assert captured packet counts in integration tests.
- `RuleEngine`: validates and loads `nftables` rulesets using `nft --check -f` and `nft -f`. Parses line-level error messages into structured `RuleValidationError` exceptions. Automatically arms kernel tracing via `meta nftrace set 1`.
- `ScapyInjector`: forges and injects IPv4/IPv6 TCP, UDP, ICMP, and ICMPv6 packets at Layer 2/3. Uses in-process `sendp()` for host-originating packets and `ip netns exec` subprocess for egress from inside a namespace.
- `run_test_pipeline()`: top-level orchestrator that chains validation, topology setup, mock listener spawning, rule loading, trace harvesting, sequential packet injection, conntrack polling, and namespace teardown.
- `parse_conntrack_line()`: parser for `/proc/net/nf_conntrack` entries. Extracts `proto`, `state`, `src`, `dst`, `sport`, and `dport` for both IPv4 and IPv6 flows.
- Stateful traffic and conntrack integration: `/proc/net/nf_conntrack` is polled after each packet injection and connection states (`SYN_SENT`, `ESTABLISHED`, `TIME_WAIT`) are streamed to consumers.
- Dual-stack IPv4/IPv6: all veth links are configured with both address families. DAD is disabled globally inside namespaces (`accept_dad=0`) for instant address availability.

#### Data Models (`nse/models/`)

- `PacketSpec`: Pydantic model (lazy import) defining protocol, IPs, ports, TCP flags, and packet size. Validates IPv4/IPv6 addresses and allowed flag values.
- `TestRequest`: Pydantic model with `rules`, `packets: list[PacketSpec]`, and `topology: TopologyType`.
- `TopologyType`: string enum with values `simple` and `gateway`.
- `TraceEvent`: Pydantic model for kernel trace output events of type `hook`, `match`, or `verdict`.
- `base.py`: pure stdlib dataclasses for use without Pydantic.

#### CLI Runner (`nse/cli/runner.py`)

- `nse-runner --file <yaml>` CLI entrypoint registered in `pyproject.toml`.
- Reads YAML test suites, invokes `run_test_pipeline()`, evaluates expected verdicts, and prints formatted results.
- Silent drops (no matching `TraceEvent`) are treated as `DROP`.
- Exits with `0` on full pass, `1` on any failure.
- Displays a clear install hint if `pydantic` or `pyyaml` is missing.

#### GUI Daemon (`gui/` - not on PyPI)

- `TraceHarvester`: async subprocess spawning `nft monitor trace` inside the evaluation namespace. Parsed events are pushed into an `asyncio.Queue`.
- `MockListener`: background TCP/UDP echo daemon spawner using `ip netns exec`. Enables complete TCP handshakes and valid conntrack state generation.
- FastAPI REST API: `POST /api/test` and `GET /api/status/{test_id}`.
- WebSocket streaming: `WS /ws/{test_id}` streams `TraceEvent` JSON messages to the frontend.

#### Frontend (`gui/gui_svelte/` - not on PyPI)

- Rule editor for `nftables` ruleset authoring.
- Multi-packet sequence crafter with topology selector.
- Real-time animated pipeline visualizer: hook, rule match, and verdict events.
- Conntrack table: live tabular view of active connection states.
- Offline documentation view at `#/docs`.

#### Packaging and Release

- `pyproject.toml` at repository root. Build backend: `setuptools`. Targets only `nse/` via `packages.find.include`. Hard dependency: `scapy>=2.5.0`. Optional extra `[cli]`: `pydantic>=2.0.0` and `pyyaml>=6.0`.
- `make release`: runs `lint + test`, builds the wheel and source distribution, copies deployment assets, generates `SHA256SUMS`, and signs it with GPG. The signing key is auto-detected from the keyring and can be overridden with `GPG_KEY_ID=<id>`.
- `Dockerfile`: multi-stage production image for containerized daemon deployment.
- `scripts/nse.service`: systemd unit template binding to `/run/nse.sock` in production.
- `tests/test_netns.py`: unified test suite with 20 unit tests and 2 root-only integration tests.
- `conftest.py`: root `sys.path` injection allowing pytest to discover both `nse/` and `gui/` packages.

#### Makefile Targets

| Target                  | Description                          |
| ----------------------- | ------------------------------------ |
| `make setup`            | Bootstrap venv and run npm install   |
| `make test`             | Run unit tests                       |
| `make integration-test` | Run root-level integration tests     |
| `make lint`             | Ruff static analysis                 |
| `make format`           | Ruff auto-format                     |
| `make verify`           | Run `lint` and `test`                |
| `make release`          | Build and sign all release artifacts |
| `make publish-test`     | Upload to TestPyPI via Twine         |
| `make publish`          | Upload to PyPI via Twine             |

---

### Changed

- Repository restructured from a monolithic `backend/nse/` layout to a root-level separation:
  - `nse/` is the headless PyPI package (replaces `backend/nse/`).
  - `gui/` is the GUI daemon (replaces GUI modules formerly in `backend/nse/` and the `frontend/` directory).
  - `tests/` is the unified test suite (replaces `backend/tests/`).
- `TraceHarvester` and `MockListener` moved to `gui/daemon/`. These components are part of the GUI layer and are not included in the wheel.
- Pydantic imports in `nse/` models are wrapped in `try/except ImportError` to allow the core to be imported with only `scapy` installed.
- `TestRequest.packet` changed to `TestRequest.packets: list[PacketSpec]` to support packet sequences. This is a breaking API change.
- `pyproject.toml` migrated from `backend/pyproject.toml` to the repository root. Build backend changed from Poetry to setuptools.
- `Makefile` updated with root-level paths.

---

### Fixed

- GPG signing in `make release` failed with "no default secret key" in non-interactive shells. Fixed by adding `--local-user $(GPG_KEY_ID)` with automatic key detection from the keyring.
- Interface name assertion in `test_create_namespace_lifecycle_mocked` was off by one character for 8-character namespace names.
- Svelte compilation crash caused by raw curly braces in code blocks. Fixed by escaping them as `&#123;` and `&#125;`.

---

[2.0.0]: https://github.com/onyks-os/NetworkSandboxEngine/releases/tag/v2.0.0
[1.1.1]: https://github.com/onyks-os/NetworkSandboxEngine/releases/tag/v1.1.1
[1.1.0]: https://github.com/onyks-os/NetworkSandboxEngine/releases/tag/v1.1.0
[1.0.0]: https://github.com/onyks-os/NetworkSandboxEngine/releases/tag/v1.0.0
