# How-To: Traffic Through a Window of Time (Streams)

A single probe says what happened at one instant. A rule reload, a service
restart or a teardown takes a window of time, and the question is what
happened to the traffic *throughout* it: did anything slip through while the
old rules were gone and the new ones not yet in place?

A `StimulusStream` sends the same [stimulus](stimuli.md) once per period from a
process inside the sandbox, numbering every attempt. `correlate()` joins the
stream's log with a capture and a [receiver](receivers.md)'s log and says, for
each sequence number, how far it got. It also says whether the stream covered
the whole window: a stream that paused says nothing about the pause.

---

## A worked example: a rule loaded mid-stream

The stream runs as UID 65534 toward a UDP echo receiver. Half-way through, a
rule that drops that user's traffic is loaded. Every attempt before the load
must be received, every attempt after it refused, and the window must be
conclusive on both sides.

```python
import asyncio
import time

from nse import NetnsController, PCAPAsserter, ProcessIdentity, receivers, stimuli
from nse.core.rule_engine import RuleEngine
from nse.streams import StimulusStream, correlate

DROP_NOBODY = """
table inet egress {
    chain out {
        type filter hook output priority 0; policy accept;
        meta skuid 65534 udp dport 9999 drop
    }
}
"""

async def test_the_drop_takes_effect_without_a_leak() -> None:
    controller = NetnsController()
    async with controller.create_namespace("nse_reload", isolated_host=True) as ns:
        async with await receivers.udp_echo("10.0.1.1", 9999).start(ns.host) as echo:
            capture = PCAPAsserter(iface=ns.ext_iface, netns=ns.ext_netns)
            await capture.start()
            await capture.mark("start")

            stream = StimulusStream(stimuli.udp("10.0.1.1", 9999), period=0.02)
            async with await stream.start(ns, identity=ProcessIdentity(uid=65534, gid=65534)) as running:
                await asyncio.sleep(0.3)
                load_started = time.monotonic()
                await asyncio.to_thread(RuleEngine().load, DROP_NOBODY, ns.name)
                load_done = time.monotonic()
                await asyncio.sleep(0.3)

            await capture.mark("end")
            packets = await capture.stop()
            report = await capture.stop_report()
            receipts = await echo.stop()

    joined = correlate(running.log(), packets, receipts, capture=report)
    assert joined.conclusive, joined.describe()

    before = joined.between(joined.window_start, load_started)
    after = joined.between(load_done, joined.window_end)
    assert set(before.counts()) == {"received"}, before.describe()
    assert set(after.counts()) == {"refused"}, after.describe()
```

Leaving the `async with` block stops the stream and waits for the attempts in
flight. The `start` and `end` [beacons](beacons.md) make the capture prove it
was reading across the whole window.

Attempts that start while the rule is being loaded can go either way. They are
in `joined` but in neither slice, which is why the slices are taken at
`load_started` and `load_done`.

---

## What became of each attempt

| Status | Meaning |
| --- | --- |
| `not_sent` | The attempt `could_not_run` (no packet can exist), or its record is missing from the log |
| `refused` | A socket call failed (`refused`, with its errno) and the capture did not see the packet |
| `sent_not_seen` | It left the socket, and the capture does not have it |
| `on_wire` | The capture has it; the receiver does not (or there is no receiver) |
| `received` | The receiver logged it |

The strongest evidence wins: a packet the capture saw is `on_wire` whatever the
process reported. Each `Fate` also keeps the attempt's `StimulusResult` and the
two facts it rests on, `on_wire` and `received`. As in
[`observe()`](observing-a-stimulus.md), each is `True`, `False` (a complete
instrument did not see it) or `None` (it cannot say). `fate.conclusive` is
`True` only when the status rests on facts the instruments can vouch for.

`joined.counts()`, `joined.with_status("on_wire", "received")` and
`joined.describe()` are there for assertions and their messages.

---

## When the window is inconclusive

`joined.conclusive` is `False`, and `joined.problems` or `joined.gaps` say why,
whenever an instrument cannot vouch for the window:

- **The stream paused.** No attempt that could run started for longer than
  `max_gap_periods` periods (default 3). The process was not scheduled, the
  machine stalled, or too many attempts were in flight. Each pause is a `Gap`
  with its start, end and the sequence numbers around it.
- **Attempts could not run.** An attempt that `could_not_run` produced no
  packet, so it covers no time. A stream of them is one long gap, and a stream
  with no attempt that could run tested nothing.
- **The stream's log is incomplete.** Sequence numbers are missing, a line was
  cut or unreadable, the output limit was hit, or the stream did not report its
  end. A log read while the stream is still running is not final either.
- **The capture cannot vouch for an absence.** There was no capture, no
  report, or the report is not healthy and complete, for instance with a
  missing beacon or kernel drops. Packets that *were* seen still count.
- **The receiver's log is incomplete.**
- **The instruments contradict each other.** The receiver logged what the
  capture missed, or the capture saw what the process says it never sent.

`between(start, end)` keeps these problems and adds gaps at the edges: a
slice the stream did not cover from end to end is not conclusive either.

---

## The schedule

```python
StimulusStream(stimulus, period=0.02, count=None, duration=None, max_in_flight=256)
```

- **Timing.** Attempts are scheduled from the stream's start on a fixed grid.
  Each one runs in its own thread with its own socket, so an attempt that waits
  (a reply timeout, a SYN to a dropped port) does not delay the next.
- **Slots that cannot be used.** A slot is skipped when `max_in_flight`
  attempts are already running, or when the process was not scheduled in time.
  Skipped slots are never made up with a burst: they show as a gap.
- **Ending.** `count` or `duration` end the stream by itself; wait for it with
  `await running.wait()`. Without them it runs until `await running.stop()`, or
  until the `async with` block ends.
- **Probe IDs.** Every attempt carries its own probe ID: a 16-digit stream ID
  followed by the sequence number in 8 hex digits. A bare-SYN stream binds
  a distinct source port per attempt instead, counting up from a random base
  and skipping any port that is busy, so no two attempts share one.
- **Times.** `StreamAttempt.started_monotonic` is `CLOCK_MONOTONIC`, the clock
  `time.monotonic()` reads, so it compares directly with times the test takes.

`stream.start()` raises `StreamStartError` if the program does not say it
started within `ready_timeout` seconds. A stream whose attempts all fail has
started; each failure is in its log.

### NAT

When a DNAT or redirect rewrites the stream's destination, pass
`correlate(..., nat=True)` to recognise each attempt by its probe ID wherever it
went. See [Observing a Stimulus](observing-a-stimulus.md#after-a-nat).
