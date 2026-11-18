# Worked Examples

The repository's [`examples/`](https://github.com/onyks-os/NetworkSandboxEngine/tree/main/examples)
directory holds complete experiments, each with its input and its expected
output. None needs anything but NSE. CI runs every one of them on a real
kernel, as separate processes in a clean environment, and checks their exit
code and artifacts (`tests/test_examples.py`). An example that stops working
fails the build.

All of them need root, like NSE itself.

---

## YAML suites

Run with the CLI; each prints one `[OK]` line per packet and exits 0.

| Suite | What it shows |
| :--- | :--- |
| `workstation.yaml` | Drop by default, SSH from the IPv4 LAN, ping answered, everything else closed. The same `table inet` policy is checked over IPv6, where the IPv4-only SSH rule leaves the port closed. |
| `ipv6.yaml` | A service published over IPv6 only. The same port over IPv4 is dropped: family matters, and NSE traces both. |
| `coexistence.yaml` | Two tables hook `input`. An accept in one does not override a drop in the other: every base chain at the hook must accept. |
| `gateway_nat.yaml` | The gateway topology forwards DNS and HTTP, masquerades them, and drops SSH. Verdicts are attributed at the first hook, before NAT rewrites the source. |

```bash
sudo nse-runner --file examples/gateway_nat.yaml --report-dir nse-report
```

```text
Running test: NAT gateway: forward and masquerade DNS and HTTP, drop SSH...
  [OK] Packet 1: expected ACCEPT, got ACCEPT
  [OK] Packet 2: expected ACCEPT, got ACCEPT
  [OK] Packet 3: expected DROP, got DROP
  => SUCCESS: NAT gateway: forward and masquerade DNS and HTTP, drop SSH
------------------------------------------------------------
Test Suite Summary: 1 passed, 0 failed.
```

---

## A real application, checked on the wire

`real_application.py` replaces synthetic packets with a real echo server:

- the server listens on TCP 80 and UDP 53, as `nobody` with only
  `CAP_NET_BIND_SERVICE`;
- a real client on the host talks to it;
- a capture writes the traffic to a PCAP file with bounded memory.

The ruleset allows HTTP and drops DNS. The claim "DNS gets no answer" is backed
by three positive controls:

1. without the ruleset, the same query is answered;
2. the capture sees the query go out;
3. the capture sees TCP replies come back, so it can see the sandbox answer.

```bash
sudo python3 examples/real_application.py --out nse-example-output
```

```text
1. The server starts with a verified, unprivileged identity
  [OK] runs as uid 65534: (65534, 65534, 65534, 65534)
  [OK] holds only net_bind_service: ('net_bind_service',)
2. Positive control, no ruleset yet: both services answer
  [OK] TCP 80 echoes
  [OK] UDP 53 echoes
3. With the ruleset: HTTP passes, DNS does not
  [OK] TCP 80 still echoes
  [OK] UDP 53 gets no answer
4. The wire agrees, and the capture is shown to be able to see it
  [OK] capture healthy: stopped []
  [OK] nothing dropped or cut off: 0
  [OK] memory held counters only (file mode)
  [OK] control: the DNS query is on the wire (1)
  [OK] control: replies from the sandbox are visible (5)
  [OK] no DNS answer left the sandbox (0)
All checks passed.
```

Artifacts: `wire.pcap`, `capture.json` (the `CaptureReport`) and `server.json`
(the server's `ProcessResult`, with its verified identity).

---

## Experiments that must fail

An instrument is only trustworthy if it can be seen to fail. These two
examples are broken on purpose, and exit 0 only when NSE catches the fault
**for the reason it was planted**.

### Wrong policy, sound observer: `broken_policy.py`

The ruleset accepts SSH by mistake, because a port set was copied from another
rule. The run completes and both canaries are observed, so the instrument is
known to work. The SSH verdict is then `ACCEPT` where `DROP` was expected.

```text
outcome=completed oracle=observed/observed
expected ['ACCEPT', 'DROP'], observed ['ACCEPT', 'ACCEPT']
FAILED AS EXPECTED: the oracle was watching, and SSH (packet 2) was accepted.
```

### Sound policy, broken observer: `broken_observer.py`

1. **Blind trace oracle.** The parser is made to understand nothing, as a
   kernel format change would. With no verdicts, "nothing was accepted" would
   look like "everything was dropped". The readiness canary is never observed,
   so the run is an instrument failure, not a pass.
2. **Capture on the wrong interface.** "Nothing leaves the sandbox on UDP 9" is
   checked on the host's loopback, and holds trivially. The positive control,
   a probe that must be captured, is missing there, so the claim is rejected.
   On the right interface the probe is seen: traffic does leave.

```text
1. Blind trace oracle
   outcome=instrument_failure readiness=missed verdicts=[]
   FAILED AS EXPECTED: no verdict is reported from an oracle that cannot see.
2. Capture on the wrong interface
   naive claim on lo: 'no UDP 9 left the sandbox' -> True
   positive control on lo: probe seen = False
   positive control on vhr-...: probe seen = True
   FAILED AS EXPECTED: the control rejects the claim; on the right interface
   the probe is seen, so traffic does leave the sandbox.
```

The second case is the reason behind a rule that runs through this
documentation: a negative assertion needs a positive control on the same path.
NSE checks its own trace oracle automatically. Whether a capture watches the
right path is evidence only the test can provide; see
[the verdict oracle](../explanation/deterministic-oracle.md#what-the-contract-proves-and-what-it-does-not).
