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

`create_namespace(..., isolated_host=True)` puts the host end in its own
namespace; see
[the host endpoint](../how-to/in-process-integration.md#the-host-endpoint-and-the-hosts-firewall).

::: nse.core.netns_controller
    options:
      show_root_heading: true
      show_source: true

---

## Host Firewall Diagnostic

Read once per process by `create_namespace()` in the default topology. It only
warns; it never fails a setup.

::: nse.core.host_firewall
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

## Stimuli and Observation

Real sockets in a process running as a chosen identity, and `observe()`, which
keeps sent, on the wire, received and reply seen apart. See
[stimuli](../how-to/stimuli.md) and
[observing a stimulus](../how-to/observing-a-stimulus.md).

::: nse.stimuli
    options:
      show_root_heading: true
      show_source: true

::: nse.models.stimulus
    options:
      show_root_heading: true
      show_source: true

::: nse.core.probe_packets
    options:
      show_root_heading: true
      show_source: true

---

## Streams

A stimulus sent at a fixed rate, and `correlate()`, which says what became of
each attempt. See [streams](../how-to/streams.md).

::: nse.streams
    options:
      show_root_heading: true
      show_source: true

::: nse.models.stream
    options:
      show_root_heading: true
      show_source: true

---

## Capture Beacons

Non-IP frames that prove a capture was reading across a window. See
[beacons](../how-to/beacons.md).

::: nse.core.beacons
    options:
      show_root_heading: true
      show_source: true

---

## Controlled Receivers

See [controlled receivers](../how-to/receivers.md).

::: nse.receivers
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

`TraceHarvester.prove_ready()` and `TraceReadiness` prove the monitor is
attached with a canary. See
[tracing a process's own traffic](../how-to/tracing-local-traffic.md).

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

`netns=` captures on an interface in another network namespace; only the
capture thread enters it.

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

::: nse.models.experiment_report
    options:
      show_root_heading: true
      show_source: true

::: nse.models.artifacts
    options:
      show_root_heading: true
      show_source: true

::: nse.core.verdicts
    options:
      show_root_heading: true
      show_source: true
