# How-To: Embedding NSE in Python

NSE is a library first. This guide covers calling the engine directly from your
own test suite, which is how you assert things about a ruleset that a YAML file
cannot express.

---

## Running one test

```python
import asyncio

from nse.core.netns_controller import NetnsController
from nse.core.pipeline import run_test_pipeline
from nse.models.test_request import PacketSpec, TestRequest

RULES = """
table ip filter {
    chain input {
        type filter hook input priority 0; policy drop;
        tcp dport 80 accept
    }
}
"""

async def main() -> None:
    request = TestRequest(
        rules=RULES,
        packets=[
            PacketSpec(protocol="tcp", dst_port=80),
            PacketSpec(protocol="tcp", dst_port=22),
        ],
    )
    events = await run_test_pipeline(request=request, controller=NetnsController())

    # ALWAYS check for oracle errors before reading verdicts.
    errors = [e.raw_message for e in events if e.type == "error"]
    if errors:
        raise AssertionError(f"the measurement failed, not the firewall: {errors}")

    for evt in events:
        if evt.verdict and evt.table != "nse_trace":
            print(f"[{evt.chain}] {evt.verdict}")

asyncio.run(main())
```

!!! danger "Check for `error` events first"
    `run_test_pipeline` returns an `error` event when its canary probes were not
    observed, i.e. when the kernel trace was not actually being read. If you skip
    that check and go straight to counting verdicts, an empty list looks exactly
    like "the firewall dropped everything" — which is the bug this whole design
    exists to prevent. Reuse `nse.cli.runner.collect_oracle_errors` if you like.

---

## Reducing a trace stream to verdicts

Rather than filtering events by hand, reuse the runner's logic:

```python
from nse.cli.runner import collect_oracle_errors, reduce_verdicts

errors = collect_oracle_errors(events)
assert not errors, errors

assert reduce_verdicts(events) == ["ACCEPT", "DROP"]
```

`reduce_verdicts` groups events by `trace_id`, drops NSE's own `nse_trace`
scaffolding, and resolves each packet to a single verdict with `DROP`/`REJECT`
taking precedence over `ACCEPT`.

---

## In pytest

```python
import os

import pytest

from nse.cli.runner import collect_oracle_errors, reduce_verdicts
from nse.core.netns_controller import NetnsController
from nse.core.pipeline import run_test_pipeline
from nse.models.test_request import PacketSpec, TestRequest

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(os.geteuid() != 0, reason="NSE needs root for netns and kernel tracing"),
]

async def test_ssh_is_blocked(my_ruleset: str) -> None:
    request = TestRequest(
        rules=my_ruleset,
        packets=[PacketSpec(protocol="tcp", dst_port=22)],
    )
    events = await run_test_pipeline(request=request, controller=NetnsController())

    assert not collect_oracle_errors(events)
    assert reduce_verdicts(events) == ["DROP"]
```

---

## Streaming events as they arrive

Pass a queue to consume events live — useful for progress output on a long suite:

```python
queue: asyncio.Queue = asyncio.Queue()
task = asyncio.create_task(run_test_pipeline(request=request, queue=queue))

while True:
    evt = await queue.get()
    if evt is None:  # sentinel: monitoring ended
        break
    print(evt.type, evt.trace_id, evt.verdict)

events = await task
```

The queue receives canary events too, since it is a raw feed; the list returned
by the coroutine is the filtered one.

---

## Tuning

Every timing knob is an environment variable, so you rarely need to touch code.
See [CLI reference](../reference/cli.md#environment-variables). The two that
matter most for slow machines and CI runners:

| Variable | Effect |
| :--- | :--- |
| `NSE_CANARY_ATTEMPTS` | Raise it if readiness canaries fail on a loaded runner. |
| `NSE_TRACE_IDLE_TIMEOUT` | Raise it if traces arrive slowly under heavy load. |

Do **not** work around a failing canary by ignoring the error. A canary that
never arrives means the engine could not see the kernel; whatever it would have
reported about your ruleset would have been fiction.

---

## Asserting that nothing left the interface

The trace oracle answers *what did the ruleset decide*. It cannot answer *what
reached the wire*, which is the question behind a zero-leak claim: a packet that
matches no rule at all produces no verdict to inspect. `PCAPAsserter` covers
that half.

```python
from nse import PCAPAsserter

asserter = PCAPAsserter(iface="veth-host")
await asserter.start()
# ... drive the stimulus ...
leaked = await asserter.stop()
assert not leaked, f"{len(leaked)} frame(s) escaped: {leaked}"
```

### Always pair it with a positive control

A sniffer that never attached and a firewall that blocks everything both return
an empty list. The assertion above distinguishes them only if you have shown,
in the same run, that the instrument can see the packet you are looking for:
flush the ruleset, send the same stimulus, and require it to be **captured**
before you trust the empty capture that follows. Without that, the test passes
hardest when it is most broken.

### The default filter, and when to replace it

`DEFAULT_FILTER` excludes ARP and ICMPv6 types 133-137 - Neighbour Discovery,
whose hop limit of 255 means it cannot reach a remote observer. Everything else
is captured, **including ICMPv6 echo to a globally routable address**.

A `filter` argument is combined with the default. Pass
`replace_default_filter=True` to use yours alone:

```python
# Combined: DEFAULT_FILTER and your expression.
PCAPAsserter(iface="veth-host", filter="ip6")

# Yours alone - you are now responsible for the noise.
PCAPAsserter(iface="veth-host", filter="ip6", replace_default_filter=True)
```

The escape hatch exists because the filter is compiled into BPF and evaluated in
the kernel. A packet it excludes never reaches userspace, so a caller cannot
compensate downstream by filtering the returned list - there is nothing in it to
filter. Until 2.1.2 the default read `not arp and not icmp6` and silently
discarded routable ICMPv6 for exactly that reason; see
[issue #14](https://github.com/onyks-os/NetworkSandboxEngine/issues/14).
