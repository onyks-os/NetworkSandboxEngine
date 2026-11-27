# How-To: Tracing a Process's Own Traffic

`nft monitor trace` names the rule that decided a packet's fate, which a
capture cannot. NSE's trace set-up enables tracing in a `prerouting` chain,
because its oracle injects packets from outside. A packet a process generates
inside the namespace never crosses `prerouting`: it goes out through `output`
and `postrouting`. Without an `output` trace chain, none of the rules it meets
ever appears in the trace.

---

## Turning it on

```python
from nse.core.rule_engine import RuleEngine

RuleEngine(trace_output=True).load(rules, ns.name)
```

This adds a chain `nse_trace_output` to NSE's `nse_trace` table, in the
`output` hook at priority -350. That is ahead of raw (-300), mangle (-150),
DNAT (-100) and filter (0), so the trace flag is set before any of your chains
sees the packet. By default it is off, and the trace is exactly what it was
before.

Every `load()` replaces the `nse_trace` table in the same transaction as your
rules, so it never accumulates. Loading three times still traces each packet
through one `meta nftrace set 1` per chain. A `load()` from an engine without
`trace_output` removes the output chain an earlier `load()` added.

!!! warning "`flush ruleset` turns tracing off"
    NSE's trace table is loaded in front of your rules. A ruleset that starts
    with `flush ruleset`, as many `nftables.conf` files do, deletes it again,
    and nothing is traced at all. Remove that line, and call
    `RuleEngine.flush(ns.name)` before `load()` if you need an empty ruleset.

---

## Proving the monitor is attached

`TraceHarvester.wait_ready()` proves only that this process is reading the
monitor's output, not that `nft monitor trace` has subscribed to the kernel. A
trace that is not attached is empty, and an empty trace reads as "no rule
matched".

`stimuli.trace_ready()` closes that. It sends a canary stimulus from the
sandbox until the canary's own trace comes back, up to `attempts` times. Only
an event for the canary's destination, transport and port counts, so
background traffic does not count as proof:

```python
import asyncio

from nse import ProcessIdentity, stimuli
from nse.core.rule_engine import RuleEngine
from nse.core.trace_harvester import TraceHarvester

DROP_NOBODY = """
table inet egress {
    chain out {
        type filter hook output priority 0; policy accept;
        meta skuid 65534 udp dport 9999 drop
    }
}
"""

async def test_the_drop_rule_is_what_stops_nobody() -> None:
    RuleEngine(trace_output=True).load(DROP_NOBODY, ns.name)
    harvester = TraceHarvester()
    events = []
    await harvester.start(ns.name, asyncio.Queue(), timeout=20.0, on_event=events.append)
    try:
        await harvester.wait_ready()
        readiness = await stimuli.trace_ready(
            harvester, ns, stimuli.udp("10.0.1.1", 7777),
            identity=ProcessIdentity(uid=1000, gid=1000),
        )
        assert readiness.ready, readiness.describe()

        await stimuli.udp("10.0.1.1", 9999).run(ns, identity=ProcessIdentity(uid=65534, gid=65534))
        await asyncio.sleep(0.5)
    finally:
        state = await harvester.aclose()

    subject = readiness.without(events)  # the canary's traces removed
    assert [e for e in subject if e.type == "match" and "drop" in (e.rule_text or "")]
```

`readiness.without(events)` drops every trace that touched the canary,
including traces whose lines arrived after readiness was decided. Give the
canary a destination that nothing else in the test uses.

An attempt that `could_not_run` is not a canary: it is listed in
`readiness.problems`, and it never counts as proof. If the monitor died, its
health errors are listed too. When readiness is not proven, the harvester also
lists `nse_trace` in the namespace and says what is missing: the whole table
(for example after a `flush ruleset`), the prerouting chain, or the output
chain that `trace_output=True` adds.

For a lower-level canary, call `harvester.prove_ready(send, predicate)` with
your own `send` coroutine. It returns `None`, or the reason it could not send.

---

## The blind case

Without `trace_output=True`, a canary sent from inside the sandbox is never
traced. `trace_ready()` then returns `ready=False` rather than an empty trace
that looks like a pass, and `problems` names the missing output chain. NSE's
own tests run both cases, and a ruleset that starts with `flush ruleset`.
