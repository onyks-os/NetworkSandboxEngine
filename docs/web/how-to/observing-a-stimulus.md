# How-To: Observing a Stimulus

A test about a firewall is usually a test about an absence: "this packet did
not leave". An absence has many causes, and most of them are the instrument
failing, not the firewall working. `nse.observe()` runs a
[stimulus](stimuli.md) with a capture armed and, optionally, a
[receiver](receivers.md) listening, and reports four facts separately:

| Fact | Source | `True` | `False` | `None` (unknown) |
| --- | --- | --- | --- | --- |
| `sent` | the sending process | the send call succeeded | it did not | never |
| `on_wire` | the capture | the probe's packet was seen | a complete, healthy capture did not see it | the capture was incomplete or unhealthy and did not see it |
| `received` | the receiver's log | the receiver logged the probe | a complete log does not have it | no receiver, or an incomplete log without it |
| `reply_on_wire` | the capture | a reply was seen | as for `on_wire` | as for `on_wire` |

`None` is the instrument saying it cannot vouch for the absence. A test must
never read it as `False`: `assert not seen.on_wire` passes on `None`, so assert
`seen.on_wire is False`.

---

## A worked example: blocked, and provably so

```python
from nse import NetnsController, ProcessIdentity, receivers, stimuli
from nse.core.rule_engine import RuleEngine

DROP_NOBODY = """
table inet egress {
    chain out {
        type filter hook output priority 0; policy accept;
        meta skuid 65534 drop
    }
}
"""

async def test_nobody_cannot_reach_the_host() -> None:
    controller = NetnsController()
    async with controller.create_namespace("nse_obs", isolated_host=True) as ns:
        RuleEngine().load(DROP_NOBODY, ns.name)
        probe = stimuli.tcp_round_trip("10.0.1.1", 9999)

        async with await receivers.tcp_echo("10.0.1.1", 9999).start(ns.host) as echo:
            # Positive control: another user, the same path, the same instruments.
            control = await stimuli.observe(
                ns, probe, identity=ProcessIdentity(uid=1000, gid=1000), receiver=echo
            )
            blocked = await stimuli.observe(
                ns, probe, identity=ProcessIdentity(uid=65534, gid=65534), receiver=echo
            )

    assert control.on_wire is True, control.describe()
    assert control.received is True, control.describe()
    assert control.reply_on_wire is True, control.describe()

    assert blocked.on_wire is False, blocked.describe()    # not None: a complete window
    assert blocked.received is False, blocked.describe()   # not None: a complete log
    assert blocked.contradictions() == [], blocked.describe()
```

By default the capture is on the sandbox's host end (`ns.ext_iface` in
`ns.ext_netns`). Pass `iface=`, `netns=` or `capture_filter=` to change it, and
`settle=` for how long to keep capturing after the stimulus returns.

Here the SYN from UID 65534 never leaves, and `connect()` simply times out
(`no_reply` at `connect`). The process cannot tell a dropped SYN from a silent
server; the capture can, and only because its window was complete.

---

## Contradictions: a blind instrument fails visibly

Some combinations of facts cannot all be true. `contradictions()` lists them,
and `describe()` appends each as `CONTRADICTION: ...`:

- **received, but not on the wire:** the capture is blind to the path the
  traffic took (a wrong interface, a filter that excludes it). Its silence about
  anything else proves nothing.
- **answered, but no reply on the wire:** the capture is blind to the return
  path.
- **on the wire, but the process reported `could_not_run` or a refused
  send:** the probe's own report is wrong.

A refused `connect` or `receive` with the packet on the wire is not a
contradiction: a TCP RST or an ICMP error follows a packet that did leave.

A capture on the wrong interface is still a complete window that saw nothing,
so on its own it reports `on_wire=False`. A receiver, or a canary that must be
seen (below), is what exposes it. NSE's own tests run exactly that case with a
filter that excludes the probe.

---

## A canary in the same window

A positive control in its own capture proves the instrument worked a moment
ago, not that it was still working during the stimulus. Pass `canary=`: a
stimulus the rules under test let through, sent **after** the stimulus inside
the **same** capture window.

```python
seen = await stimuli.observe(
    ns,
    stimuli.tcp_connect("10.0.1.1", 8080),
    identity=nobody,
    canary=stimuli.udp("10.0.1.1", 7777),
    canary_identity=allowed,          # default: the stimulus's identity
)
assert seen.canary.on_wire is True, seen.describe()
assert seen.on_wire is False, seen.describe()
```

Unless the canary was seen on the wire, no absence is `False`: `on_wire`,
`reply_on_wire` and the other unseen facts become `None`, and `describe()`
says `canary: NOT seen`. A capture that stopped reading, or never watched the
traffic's link, cannot vouch for a silence it did not observe. The
[beacons](beacons.md) prove the same thing at the link level, and the two
combine.

---

## Several stimuli in one window

`observe_window()` runs several stimuli in order, then the optional canary,
inside one capture, and gives each stimulus its own `Observation`:

```python
window = await stimuli.observe_window(
    ns,
    [stimuli.udp("192.0.2.53", 53), stimuli.tcp_connect("192.0.2.80", 80)],
    identity=nobody,
    canary=stimuli.udp("10.0.1.1", 7777),
    canary_identity=allowed,
)
assert window.conclusive, window.describe()   # healthy, complete, canary seen, no contradiction
dns, web = window                              # one Observation per stimulus, in order
assert dns.on_wire is False
assert web.on_wire is False
```

`window.vouched` is the capture's part (healthy, complete, canary seen),
`window.contradictions()` gathers every observation's contradictions, and
`window.packets` holds the whole capture. Each stimulus is matched by its own
probe ID (or, for a bare SYN, its source port), so neither the canary nor
another stimulus can stand in for it.

To drive the capture yourself instead, find each result's packets with
`requests_in()` and `replies_in()`:

```python
asserter = PCAPAsserter(iface=ns.ext_iface, netns=ns.ext_netns)
await asserter.start()
probe = await stimuli.udp("192.0.2.53", 53).run(ns, identity=nobody)
control = await stimuli.udp("10.0.1.1", 9999).run(ns, identity=allowed)
report = await asserter.stop_report()
packets = await asserter.stop()

assert report.window_complete is True, report
assert stimuli.requests_in(control, packets), "the window was not open after the probe"
assert not stimuli.requests_in(probe, packets), "the probe left"
```

---

## After a NAT

By default a request must go to the stimulus's own destination address and
port. A DNAT or a redirect rewrites both, so the probe is no longer recognised.
With a receiver at the new destination this shows up as a contradiction:
received, but not on the wire.

Pass `nat=True` to `observe()`, `observe_window()`, `requests_in()`,
`replies_in()` or `correlate()`. The destination is then not compared: a
request counts wherever it goes, as long as it leaves from the probe's own
source and carries its probe ID (or, for a bare SYN, leaves from its bound
port). A reply counts from whatever source answered, as long as it is addressed
to the probe. Read where the probe really went from the packets:

```python
seen = await stimuli.observe(ns, stimuli.udp_round_trip("10.0.1.1", 5353), identity=nobody,
                             receiver=echo_on_9999, nat=True)
assert seen.on_wire is True
assert {pkt[UDP].dport for pkt in seen.requests} == {9999}   # redirected
```

A NAT that rewrites the *source* port of a bare SYN still hides it, since that
port is the SYN's only identity.
