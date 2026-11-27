# How-To: Observing Outside the Sandbox (VMs, ssh, External Captures)

Some phases happen on a machine NSE does not run on. A reload, a reboot, a
suspend or a teardown inside a VM is one example. The stream then runs in the
guest, started over ssh. The capture is a pcap file the hypervisor wrote, for
instance with QEMU's `filter-dump`. NSE can still say what happened to each
attempt, and whether the instruments can vouch for it. That takes three
pieces, all opt-in:

1. a [stream](streams.md) whose agent runs anywhere, with a log that says which
   boot and which clocks it is on;
2. a report for a pcap file NSE did not capture;
3. [beacons](beacons.md) that carry the sender's clocks, and a map from those
   clocks to the capture's clock.

---

## A worked example: a phase inside a VM

```python
import shlex
import subprocess

from nse import CaptureReport, ClockMap, StimulusStream, StreamLog, correlate, stimuli
from nse.core import beacons

GUEST = ["ssh", "guest", "--"]

def beacon(label: str):
    argv, _ = beacons.agent_command("eth0", label)
    out = subprocess.run([*GUEST, "sudo", *map(shlex.quote, argv)], capture_output=True, check=True)
    return beacons.agent_report(out.stdout)

stream = StimulusStream(stimuli.udp("10.0.2.2", 9999), period=0.02)
argv, stream_id = stream.command()

start = beacon("start")
running = subprocess.Popen([*GUEST, *map(shlex.quote, argv)], stdout=subprocess.PIPE)
# ... the phase under test: reload, suspend, teardown ...
phase_started, phase_done = ...   # when the phase began and ended, on the capture's clock
running.terminate()
output, _ = running.communicate()
end = beacon("end")

log = StreamLog.parse(output, stream_id, final=True, stream=stream)
report, packets = CaptureReport.from_pcap(
    "guest.pcap", required_bytes=128, expected_beacons=[start, end]
)
clock = ClockMap.from_beacons(report.beacons_seen)

joined = correlate(log, packets, capture=report, clock=clock)
assert joined.conclusive, joined.describe()
during = joined.between(phase_started, phase_done)
assert during.conclusive, during.describe()
assert not during.with_status("on_wire", "received")
```

Arguments sent over ssh go through the remote shell, so quote each one. The
agent's source is a single argument.

---

## 1. A stream that runs anywhere

`StimulusStream.command(python="python3")` returns `(argv, stream_id)`: the
command line of the stream's agent, and the ID its probes carry. The agent is
standard-library Python run with `-I -S`, so the guest needs only a Python 3
interpreter. It prints the log to standard output, and it stops on SIGTERM or
by itself with `count` or `duration`.

`StreamLog.parse(output, stream_id, *, final, stream)` reads that output.
*stream* is the `StimulusStream` that gave the command. Pass `final=True` once
no more output will come.

The log records the clocks it was written on:

- `StreamLog.boot_id`: `/proc/sys/kernel/random/boot_id` when the stream
  started. It changes on every reboot.
- `StreamAttempt.started_monotonic` and `StreamAttempt.started_boottime`:
  `CLOCK_MONOTONIC` and `CLOCK_BOOTTIME` when each attempt started.
  `CLOCK_MONOTONIC` stops while the machine is suspended, and
  `CLOCK_BOOTTIME` does not.

A log is never `complete` when:

- **it spans boots.** A log that holds more than one run of the stream, as a
  file appended to across a reboot does, says how many boots it saw;
- **it ends early.** A log that ends without the stream's end event, because
  the stream was killed or its machine shut down or rebooted, says so. So does
  a log whose last line was cut.

**A suspend is a gap.** Between two attempts, the elapsed time is measured on
`CLOCK_BOOTTIME`. A suspend therefore shows up as a `Gap`, with the time
spent suspended in `Gap.suspended`, even though `CLOCK_MONOTONIC` shows almost
nothing.

---

## 2. A pcap file NSE did not capture

```python
report, packets = CaptureReport.from_pcap(path, *, required_bytes=None, expected_beacons=())
```

`from_pcap` returns the report and the decoded packets, decoded according to
the file's link type. Beacon frames go to `report.beacons_seen` and never into
the packets.

**Damage is refused.** The file is checked record by record. It is refused if
the file header is empty or cut, the magic is not a classic pcap's (pcapng
included) or the version is not 2.4. It is also refused if a record header or
frame is cut short, or a record claims more bytes than the packet had
(`incl > orig`) or than the snap length allows (`incl > snaplen`). The records
before the damage are still returned, and the damage is listed in
`report.errors`. Such a report is not healthy, so an absence it shows never
counts.

**What it fills in:**

- `source="pcap_file"`, `link_type`, `snaplen` and `required_bytes`;
- `packets_truncated`: records that hold fewer bytes than the packet had;
- `snaplen_sufficient`, and `beacons_expected`, `beacons_seen` and
  `beacons_missing`.

`kernel_drops` and `kernel_packets` are `None`, because the capturing side's
counters are unknown.

**When the window is complete.** For a live capture, `window_complete` rests
on the kernel's drop counters. A pcap file has none, so its beacons stand in
for them. `window_complete` is `True` only when all of these hold:

- the file is intact;
- the snap length covers `required_bytes`, when it is given;
- at least one beacon was expected, and every expected beacon is in the file.

It is `False` when one of them fails. Without expected beacons it is `None`:
nothing shows that the file covers the window. `correlate()` accepts an
absence on the wire only when `window_complete` is `True`.

---

## 3. Clocked beacons and the clock map

A version 2 beacon carries the sender's `boot_id`, and its `CLOCK_MONOTONIC`
and `CLOCK_BOOTTIME` read just before the frame was sent. The values read just
after cannot be in the frame they time, so a *follow-up* frame with the same
token carries them. The capture records the pair as one sighting, whose
`clock` (a `SenderClock`) is `bracketed` once the follow-up is seen.

`beacons.agent_command(iface, label, python="python3")` returns
`(argv, token)`. It is the command line of a standard-library agent that sends
the beacon and its follow-up on *iface* and prints what it sent. It needs root,
or `CAP_NET_RAW`. `beacons.agent_report(output)` turns that output into the
`Beacon` to pass as `expected_beacons`.

`ClockMap.from_beacons(report.beacons_seen)` works one boot at a time. Each
bracketed beacon gives the offset from the sender's `CLOCK_BOOTTIME` to the
capture's clock, to within its before/after bracket. The boot's offset is the
middle of the range the beacons give. Its uncertainty is the widest bracket
plus the spread between the beacons' offsets.

The map never guesses:

- **Only for its own boot.** A reboot starts the clocks again, so beacons of
  one boot never map another.
- **Only between its beacons.** A time before the first or after the last
  beacon of its boot is not extrapolated. With a single beacon, the map covers
  only that beacon's instant.
- **Not mappable is `None`.** `clock.to_capture(boot_id, boottime)` returns a
  `MappedTime` (time and uncertainty), or `None`, never an estimate.
- **Unusable beacons are listed.** Beacons without a clock, without a
  follow-up, or with a clock that ran backwards are in `clock.problems`.

`CLOCK_BOOTTIME` is used because the host's clock keeps running while the
guest is suspended, and so does `CLOCK_BOOTTIME`.

### Correlating on the capture's clock

`correlate(..., clock=clock_map)` puts each attempt on the capture's clock,
with `Fate.capture_time` and `Fate.capture_uncertainty`. The correlation's
`clock` is then `"capture"`, and its window and gaps are in capture time.

`between(start, end)` takes capture times, such as the host's record of when a
phase began and ended. An attempt is inside only if its whole uncertainty is.
**An attempt whose uncertainty crosses `start` or `end` cannot be placed on
either side, and makes the slice inconclusive.** Gaps are computed with every
attempt's uncertainty added, so an uncertainty never hides a gap.

The window is inconclusive when:

- the stream's log has no `boot_id`;
- the map has no mapping for that boot;
- any attempt falls outside the beacons of its boot.

---

## The broken instruments, and what they give

NSE's own tests check that each of these comes out inconclusive, never clean:

| Broken instrument | What says so |
| --- | --- |
| A pcap file cut short | `report.errors`, `window_complete is False`, `correlate()` not conclusive |
| The closing beacon missing from the file | `beacons_missing`, `window_complete is False` |
| A reboot in the middle of the stream | `log.complete is False`; `problems` names the boots |
| A suspend: `CLOCK_MONOTONIC` stopped, `CLOCK_BOOTTIME` ran on | a `Gap` with `suspended` set |
| A clock map from a single beacon | no attempt can be placed; the window is inconclusive |
| An attempt whose uncertainty crosses a phase edge | `between()` is inconclusive and names the attempt |
