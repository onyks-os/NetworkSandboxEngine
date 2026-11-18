# Reference: Python API

Auto-generated Python API documentation powered by `mkdocstrings`.

---

## Core Pipeline & Orchestration

::: nse.core.pipeline
    options:
      show_root_heading: true
      show_source: true

---

## Netns Controller

::: nse.core.netns_controller
    options:
      show_root_heading: true
      show_source: true

---

## Managed Processes

`NamespaceSandbox.start_process()` / `run_process()` return the handle and result
documented here; `ProcessIdentity`, `ProcessResult` and the errors are exported
from `nse`. See
[managed processes](../how-to/in-process-integration.md#managed-processes-identity-timeouts-process-trees).

::: nse.core.process
    options:
      show_root_heading: true
      show_source: true

::: nse.models.process
    options:
      show_root_heading: true
      show_source: true

---

## Rule Engine

::: nse.core.rule_engine
    options:
      show_root_heading: true
      show_source: true

---

## Trace Harvester

::: nse.core.trace_harvester
    options:
      show_root_heading: true
      show_source: true

---

## Scapy Packet Injector

::: nse.core.scapy_injector
    options:
      show_root_heading: true
      show_source: true

---

## Wire Capture (`PCAPAsserter`)

Exported from the package root as `nse.PCAPAsserter`. Note `DEFAULT_FILTER`: it
suppresses ARP and ICMPv6 Neighbour Discovery only, and it is compiled into BPF,
so anything it excludes never reaches userspace.

`stop_report()` returns the `CaptureReport` documented below; `stop()` keeps
returning `list[Packet]` and raises `CaptureError` for an unhealthy capture.

`output=` writes the capture progressively to a PCAP file and keeps only a
bounded sample in memory; `limits=` takes a `CaptureLimits` (also exported from
`nse`). See [bounded captures](../how-to/in-process-integration.md#long-captures-with-bounded-memory).

::: nse.core.sniffer
    options:
      show_root_heading: true
      show_source: true

---

## Data Models

::: nse.models.test_request
    options:
      show_root_heading: true
      show_source: true

::: nse.models.trace_event
    options:
      show_root_heading: true
      show_source: true

::: nse.models.network_config
    options:
      show_root_heading: true
      show_source: true

::: nse.models.capture_report
    options:
      show_root_heading: true
      show_source: true
