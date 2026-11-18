# Explanation: The Verdict Oracle

NSE decides pass/drop outcomes from kernel `nftables` trace events. This page is
about the part that matters more than the parsing: **how NSE knows it was
looking**.

---

## The problem this solves

A firewall test is a negative assertion — *"this packet did not get through"*.
Negative assertions have a failure mode that positive ones do not: if the
instrument stops working, the assertion still holds. A trace monitor that never
attached to the kernel produces exactly the same output as a firewall that
blocked everything.

Up to 2.0.0, NSE had that failure mode in three places at once:

* the readiness probe signalled when the *read loop* was scheduled, not when
  `nft monitor trace` had subscribed to the kernel;
* the trace deadline was fixed when the loop started, so a long packet sequence
  outlived it and the verdict stream was truncated with no error;
* the CLI runner treated a mismatch between expected and observed verdict counts
  as something to print, not something to fail on.

Together, a completely blind run exited 0.

---

## The contract

Every run carries its own positive control.

```mermaid
graph LR
    A["Load ruleset<br/>+ nse_trace scaffolding"] --> B["Start<br/>nft monitor trace"]
    B --> C{"Readiness canary<br/>observed?"}
    C -->|no, after N retries| X["ORACLE ERROR<br/>run reports nothing"]
    C -->|yes| D["Inject test packets<br/>(deadline extended per packet)"]
    D --> E{"Liveness canary<br/>observed?"}
    E -->|no| X
    E -->|yes| F{"Read loop ended cleanly?<br/>Every line parsed?"}
    F -->|no| X
    F -->|yes| G["Verdict stream<br/>(canaries removed by trace id)"]
```

1. **Trace scaffolding**: `RuleEngine.load()` prepends a `table inet nse_trace`
   prerouting chain with `meta nftrace set 1`, so every packet entering the
   namespace produces trace events.
2. **Readiness canary**: a probe packet is injected and re-injected until *its
   own* kernel trace event is observed. This is a proof, not a signal: nothing
   proceeds until the kernel has demonstrably delivered an event.
3. **Sequential injection**: test packets go in one at a time, and the trace
   deadline is pushed forward after each one. The read loop polls its deadline,
   so an extension takes effect even while it is parked on a read.
4. **Liveness canary**: a second probe after the last test packet. If it is not
   observed, the monitor stopped watching part-way through and the verdict stream
   is truncated by an unknown amount.
5. **Health check**: the harvester's terminal state must be a clean stop — not an
   unexpected EOF, a timeout or a crash — and its count of unparsed trace lines
   must be zero.
6. **Reporting**: canary trace ids are removed from the results, so probes never
   appear in your verdict stream. A canary counts as observed only when a trace
   **matching the canary's packet tuple** arrives, so unrelated traffic in the
   namespace cannot vouch for the oracle.

Any failure in steps 2, 4 or 5 emits an `error` event. The CLI runner fails on
error events, and reports them as **oracle errors**, kept separate from firewall
failures in the summary: a broken measurement and a broken ruleset are different
problems and want different fixes.

---

## Verdict reduction

`reduce_verdicts()` collapses a trace stream into one verdict per packet:

* events are grouped by `trace_id` — one packet's traversal of the netfilter
  stack shares an id across chains;
* events from the `nse_trace` scaffolding table are excluded, since they exist
  only to switch tracing on;
* only **stimulus** traces are counted. The pipeline attributes each trace from
  the addresses, protocol and ports of its first hook, which runs before any
  user NAT chain, and records them on every event as `packet_src_ip`,
  `packet_dst_ip`, `packet_protocol`, `packet_src_port`, `packet_dst_port` and
  `packet_role` (`stimulus`, `response` or `background`). Later hooks inherit
  the first role, so translated addresses cannot change it. A server reply, such
  as the gateway listener's UDP answer being dropped on the way back, is a
  `response`; spontaneous traffic, such as IPv6 neighbour discovery, is
  `background`. Both stay in the event stream for diagnosis, but neither adds a
  verdict. The exact count check is unchanged, so a missing or duplicated
  stimulus is still an oracle error;
* `DROP` and `REJECT` beat `ACCEPT`, because a packet accepted by one chain and
  dropped by another did not get through;
* a trace id that reached the user ruleset but produced **no** verdict is
  omitted. That makes the observed count differ from the expected count, which
  is an oracle error — deliberately, rather than being rounded up to a pass.

`REJECT` is indistinguishable from `DROP` in the reduced stream, so an
expectation of `REJECT` is compared as `DROP`.

---

## What the contract proves, and what it does not

The canary, parser and liveness checks are NSE's strongest guarantee, and the
reason a clean result can be trusted. Each is a positive control on the
instrument itself:

| Check | Proves |
| :--- | :--- |
| Readiness canary | The monitor delivers kernel events for packets on the injection path *before* the stimuli. |
| Liveness canary | It still delivers them *after* the last stimulus: the stream is not truncated. |
| Parser health | Every trace line was understood: a format change cannot hide verdicts. |
| Read-loop health | The monitor ended cleanly, not by EOF, timeout or crash. |
| Count check (CLI) | One verdict per expected stimulus, no more and no fewer. |

They prove that the **trace oracle** observed the path the canaries took. They
say nothing about a **capture**. `PCAPAsserter` readiness means its socket is
armed and filtering on one interface. It does not mean that the traffic you
care about crosses that interface.

An empty capture is evidence of "nothing left" only next to a positive control
that shows the same capture seeing the stimulus. Without one, it is no
evidence at all. `examples/broken_observer.py` runs both failure modes, a blind
oracle and a capture on the wrong interface, and shows each being caught for
its own reason. The experiment report keeps these questions apart:

* `result.oracle` and `outcome` describe the trace oracle;
* each attached `CaptureReport` describes a capture;
* caller-declared `PositiveControl` entries describe the evidence for the
  assertion.

---

## Proving the contract holds

The guarantee above is itself tested. Setting `NSE_FORCE_BLIND=1` makes the
parser understand nothing — which is what a kernel trace format change looks like
from the outside — and `make test-blind` asserts that the suite then **fails**.
That job runs in CI on every push.

Separately, `test_parser_understands_every_line_of_a_real_trace` asserts, against
whatever kernel the runner has, that a real run left zero trace lines unparsed.
CI runs it on more than one image so a format change breaks a build rather than
silently blinding the oracle.
