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
so on its own it reports `on_wire=False`. A receiver, or a control stimulus you
know must be seen, is what exposes it. NSE's own tests run exactly that case
with a filter that excludes the probe.

---

## Several stimuli in one capture

`observe()` runs one stimulus per capture. When one window must hold several,
for instance the probe and then a control that proves the window was still open
after it, drive the capture yourself and find each result's packets with
`requests_in()` and `replies_in()`:

```python
from nse import PCAPAsserter, stimuli

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

Each result is matched by its own probe ID (or, for a bare SYN, its source
port), so the control never stands in for the probe or the other way round.
