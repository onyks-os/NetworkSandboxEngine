# Test Suite YAML Specification

NSE YAML test suites allow you to declare complex firewall test cases in a clean, human-readable format.

---

## YAML Structure

A test suite YAML file consists of a top-level `tests` array containing individual test cases:

```yaml
tests:
  - name: string               # Name of the test case
    topology: simple | gateway # Network topology type (default: simple)
    rules: string              # Raw nftables ruleset string
    mock_listeners:            # (Optional) Mock background listeners inside netns
      - protocol: tcp | udp
        port: integer
    packets:                   # Sequence of synthetic packets to inject
      - protocol: tcp | udp | icmp
        src_ip: string
        dst_ip: string
        src_port: integer      # Optional
        dst_port: integer      # Optional
        tcp_flags: list        # Optional (e.g. ["SYN", "ACK"])
    expected_verdicts:         # Expected kernel verdicts per injected packet
      - ACCEPT | DROP | REJECT
```

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
    mock_listeners:
      - protocol: tcp
        port: 80
      - protocol: tcp
        port: 443
    packets:
      - protocol: tcp
        src_ip: 10.0.0.1
        dst_ip: 10.0.0.2
        dst_port: 80
      - protocol: tcp
        src_ip: 10.0.0.1
        dst_ip: 10.0.0.2
        dst_port: 443
      - protocol: tcp
        src_ip: 10.0.0.1
        dst_ip: 10.0.0.2
        dst_port: 22
    expected_verdicts:
      - ACCEPT
      - ACCEPT
      - DROP
```

---

## Strictly Enforced Verdict Matching

NSE v2.0.0 enforces **strict length and ordering validation**:

- The number of `expected_verdicts` **must match** the number of injected `packets`.
- Missing verdicts are **never automatically padded** with dummy `DROP` values.
- If a packet does not trigger a verdict, NSE flags a test failure immediately.
