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
