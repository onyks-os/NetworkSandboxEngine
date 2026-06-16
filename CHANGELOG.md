# Changelog

All notable changes to the Network Sandbox Engine (NSE) project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-06-16

This major release upgrades the Network Sandbox Engine from an experimental single-packet evaluator to a full-featured stateful flow validation suite. It introduces multi-packet sequences, active stateful mock listeners, multi-namespace topologies, native dual-stack IPv6, headless CI/CD testing tools, high-contrast Svelte UI views, and automated production packaging tools.

### Added

#### Core & Backend
- **Stateful Traffic Support (Conntrack):** Added parser for `/proc/net/nf_conntrack` inside sandbox namespaces. It extracts connection details (IPs, protocol, ports, states like `SYN_SENT` or `ESTABLISHED`) and streams them over WebSockets.
- **Active Mock Listeners:** Auto-spawns background socket servers (TCP and UDP echo daemons) inside target namespaces during test execution. This completes TCP handshakes and returns UDP traffic to populate the conntrack tables.
- **Gateway Routing Topology:** Added support for routed networks simulating a **Host ◄─► Router ◄─► Server** setup. Rulesets are evaluated on the intermediate Router namespace to test forward chains and NAT rules.
- **Native Dual-Stack IPv6 Support:** Enabled IPv6 address bindings on virtual links. Added Scapy injection for IPv6/ICMPv6 flows, and disabled Duplicate Address Detection (DAD) inside namespaces (`accept_dad=0`) to ensure instant interface availability.
- **Headless Test Runner (`nse test`):** Added a CLI command to run YAML/JSON-defined test suites. Validates packet verdicts (handling silent drops as `DROP`), prints formatted results, and returns exit code `0`/`1` for CI/CD integrations.

#### Frontend UI
- **Conntrack Table Tab:** Renders a live grid of active connections inside the Svelte interface.
- **Multi-Packet Sequence Crafter:** Redesigned the packet builder to allow adding, ordering, and configuring sequences of packets.
- **Offline Docs View (`#/docs`):** Added a high-contrast, offline-accessible documentation page containing the complete guide. Opened in a new tab to avoid losing current rule states.
- **Rule Editor UX:** Improved color contrast and resolved typing visibility bugs inside the Monaco/Ruleset text editor.

#### Release & Deployment
- **Automated Packaging (`make release`):** Combines Svelte compiling, Python packaging (`build`), and deployment asset aggregation (`Dockerfile`, `nse.service`).
- **Automatic GPG Signing:** Automatically computes `SHA256SUMS` and prompts the GPG agent to clear-sign it (`SHA256SUMS.asc`) during the release process.
- **Self-Contained Wheel:** Embedded Svelte frontend files (`nse/dist/`) directly inside the Python wheel distribution for self-contained native installations.
- **Docker Image Setup:** Configured multi-stage production `Dockerfile` for containerized runtimes.
- **Systemd Unit Template:** Created `nse.service` for service lifecycle management.

### Changed
- **API Model Break:** Changed `TestRequest` payload to accept `packets: list[PacketSpec]` instead of a single `packet` to support packet sequences.

### Fixed
- Fixed Svelte compilation crash caused by curly braces inside raw code blocks by escaping them as HTML entities (`&#123;` / `&#125;`).
- Fixed layout alignment issues and low-contrast color tokens in the Svelte stylesheet.

---

[1.0.0]: https://github.com/onyks-os/NetworkSandboxEngine/releases/tag/v1.0.0
