# How-To: Proving a Capture Saw the Whole Window (Beacons)

A capture's report can show that the kernel dropped nothing, but not that the
capture was reading the right link when it mattered. A sniffer that attached
late, or that watches an interface the traffic no longer crosses, produces a
clean, complete, empty window. That reads exactly like "nothing left".

A **beacon** closes that gap. It is a small Ethernet frame sent at a known
moment on a known link. A capture that sees a beacon before a window and
another after it was demonstrably reading across the window.

---

## A worked example

```python
from nse import PCAPAsserter

capture = PCAPAsserter(iface=ns.ext_iface, netns=ns.ext_netns)
await capture.start()
await capture.mark("start")                 # on the captured interface itself
# ... the stimuli under test ...
await capture.mark("from-sandbox", via=ns)  # from the sandbox's end of the link
packets = await capture.stop()
report = await capture.stop_report()

assert report.beacons_missing == [], report.beacons_missing
assert report.window_complete is True, report
```

`mark()` sends the frame and records it as expected. The report then lists:

- `beacons_expected`: every beacon sent for this capture;
- `beacons_seen`: every beacon frame the capture read, with its time and
  position among the frames;
- `beacons_missing`: the labels of expected beacons that were not seen.

**A missing beacon makes the window incomplete:** `window_complete` is `False`.
Every tool that reads that property, such as `observe()` and `correlate()`,
then refuses to turn an absence into `False`.

Beacon frames count in `packets_observed` and are written to the PCAP file, but
they are never in the list `stop()` returns, so they never match a stimulus.

---

## Where the frame comes from

| Call | Sent from | Proves |
| --- | --- | --- |
| `capture.mark(label)` | the captured interface, in the capture's namespace | the capture was reading at that moment |
| `capture.mark(label, via=sandbox)` | `sandbox.peer_iface`, inside the sandbox | that, and that the sandbox's link reaches the capture |
| `beacon = await sandbox.beacon(label)` then `capture.expect(beacon)` | the sandbox, at a moment of your choice | the same as `via=` |

`expect()` accepts any beacon, for instance one sent before a step that may
renumber or recreate the link.

---

## What a beacon is

The frame is an Ethernet broadcast with EtherType `0x88B5` (IEEE 802 local
experimental): never routed, and never IP. No IP firewall rule touches it, so
seeing it says nothing about the rules under test, only about the instrument.
Its payload is `NSE-BEACON`, a version byte, a 16-byte random token and the
label (up to 64 bytes of UTF-8). The token, not the label, identifies it.

Sending needs `CAP_NET_RAW` in the sending namespace, as capturing does. The
frame is sent from a thread created for the purpose, which enters that
namespace and ends with it.

Version 2 beacons also carry the sender's `boot_id` and clocks, and are
followed by a *follow-up* frame. They map a sender's clock onto the capture's:
see [Observing Outside the Sandbox](observing-outside-the-sandbox.md). A live
capture recognises both versions.

---

## Filters, and when mark() refuses

NSE's default capture filter admits beacons. A custom `filter=` may not, and
a beacon the filter drops would make every window incomplete. So
`mark()` raises `CaptureStateError` on a capture with a custom filter unless it
was created with `beacons=True`. That flag ORs `ether proto 0x88b5` into the
filter:

```python
capture = PCAPAsserter(iface=ns.ext_iface, filter="udp port 53", beacons=True)
# effective filter: ((<default>) and (udp port 53)) or (ether proto 0x88b5)
```

`mark()` also refuses on a capture that is not running, and on a link without
an Ethernet header (a `tun` device, for example), where the frame cannot exist.

NSE's own tests check the blind case explicitly. A beacon sent through a filter
that excludes it, or on a link the capture does not watch, comes out as
`beacons_missing` and `window_complete is False`.

---

## Snaplen and link type

The report also says what the capture could physically see:

| Field | Meaning |
| --- | --- |
| `hardware_type` | the interface's Linux `ARPHRD_*` type |
| `link_type` | the PCAP `LINKTYPE_*` of the frames (1: Ethernet, 101: raw IP), or `None` when unknown |
| `snaplen` | the most bytes of one frame the capture reads |
| `packets_truncated` | frames read at exactly `snaplen` bytes, so possibly cut short |
| `required_bytes` | what you declared you need, with `PCAPAsserter(required_bytes=...)` |
| `snaplen_sufficient` | `required_bytes <= snaplen`; `None` when nothing was declared |

If you declare `required_bytes` and the snaplen is smaller,
`window_complete` is `False`: an assertion about bytes the capture cannot hold
must not pass on what it truncated.
