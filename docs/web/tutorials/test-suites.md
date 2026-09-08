# Test Suite YAML Specification

NSE YAML test suites allow you to declare complex firewall test cases in a clean, human-readable format.

---

## YAML Structure

A test suite YAML file consists of a top-level `tests` array containing individual test cases:

<!-- A schema sketch, not a runnable suite: fenced as `text` so
     tests/test_docs_examples.py does not try to parse the placeholders. -->

```text
tests:
  - name: string               # Name of the test case
    topology: simple | gateway # Network topology type (default: simple)
    rules: string              # Raw nftables ruleset string
    packets:                   # Sequence of synthetic packets to inject
      - protocol: tcp | udp | icmp
        src_ip: string         # Optional, defaults per topology
        dst_ip: string         # Optional, defaults per topology
        src_port: integer      # Optional
        dst_port: integer      # Optional
        tcp_flags: list        # Optional (e.g. ["S", "A"])
        expected_verdict: ACCEPT | DROP | REJECT   # Optional, defaults to ACCEPT
```

Unknown keys — in a case or in a packet — are **rejected**, not defaulted. A
misspelled `expect_verdict` used to be absorbed into an implicit expectation of
`ACCEPT`; it now fails the suite.

A mock TCP/UDP listener is started automatically inside the sandbox for every
`dst_port` you inject to, so there is nothing to declare.

---

## Example: Multi-Packet Ruleset Validation

```yaml
tests:
  - name: "Web Server Allow TCP 80 & 443, Block SSH 22"
    topology: simple
    rules: |
      table ip filter {
        chain input {
          type filter hook input priority 0; policy drop;
          tcp dport { 80, 443 } accept
          tcp dport 22 drop
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
        dst_port: 443
        expected_verdict: ACCEPT
      - protocol: tcp
        src_ip: 10.0.0.1
        dst_ip: 10.0.0.2
        dst_port: 22
        expected_verdict: DROP
```

---

## Strictly Enforced Verdict Matching

The runner fails when the number of **observed** verdicts differs from the number
expected, in either direction:

- fewer observed than expected — the engine did not see something it should
  have, so the missing verdict is missing evidence, not a pass;
- more observed than expected — unfiltered traffic reached the ruleset, and the
  extras are not quietly discarded.

Either case is reported as an **oracle error** and exits `1`. Missing verdicts
are never padded with dummy values.

!!! warning "This was not true before 2.1.0"
    Releases up to 2.0.0 printed `[FAIL] Oracle Error` on a count mismatch and
    then reported the case as `SUCCESS` and exited `0`. A run that observed
    nothing at all passed. If you have a CI pipeline pinned below 2.1.0, its
    green builds do not mean what you think they mean.
