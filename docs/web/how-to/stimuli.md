# How-To: Sending Traffic as a User (Stimuli)

A firewall usually decides on locally generated traffic in its `output` hook,
by UID, GID or cgroup. Packet injection cannot test that: an injected frame has
no owning socket. The traffic has to come from a real socket in a process
running as the identity under test.

`nse.stimuli` does that. Each stimulus is a small standard-library program
run inside the sandbox through `run_process()`, with an optional
`ProcessIdentity`. It opens a socket, sends, optionally waits for a reply, and
reports what happened as a typed `StimulusResult`.

---

## A worked example: a per-user egress rule

The sandbox drops everything UID 65534 sends to port 53, and nothing else.
The test proves both halves: the rule stops that user, and spares another user.

```python
import errno

from nse import NetnsController, ProcessIdentity, stimuli
from nse.core.rule_engine import RuleEngine

RULES = """
table inet egress {
    chain out {
        type filter hook output priority 0; policy accept;
        meta skuid 65534 udp dport 53 drop
    }
}
"""

NOBODY = ProcessIdentity(uid=65534, gid=65534)
USER = ProcessIdentity(uid=1000, gid=1000)

async def test_only_nobody_is_blocked() -> None:
    controller = NetnsController()
    async with controller.create_namespace("nse_egress") as ns:
        RuleEngine().load(RULES, ns.name)
        query = stimuli.udp("10.0.1.1", 53)

        blocked = await query.run(ns, identity=NOBODY)
        allowed = await query.run(ns, identity=USER)

    assert blocked.outcome == "refused", blocked.describe()
    assert blocked.stage == "send"
    assert blocked.errno == errno.EPERM          # the firewall, not a broken probe
    assert allowed.outcome == "sent", allowed.describe()
```

`describe()` gives one line for an assertion message, for example
`udp 10.0.1.1:53 probe 3f9c…: refused at send (EPERM: Operation not permitted)`.

---

## The outcomes are never folded together

| `outcome` | Meaning | Typical `stage` |
| --- | --- | --- |
| `sent` | The send call succeeded. Nothing was waited for. | none |
| `answered` | A reply came back (or, for `tcp_connect`, the handshake completed). | none |
| `no_reply` | The probe waited and nothing came: only for stimuli that wait. | `receive`, `connect` |
| `refused` | A socket call failed. `errno` and `error` say how. | `connect`, `send`, `receive` |
| `could_not_run` | No packet can have been produced. `reason` says why. | `launch`, `socket`, `bind`, `output` |

`could_not_run` is never a pass. It covers an interpreter that is missing, an
identity that cannot be applied, a socket that cannot be created (a raw socket
without `CAP_NET_RAW`), a source port that cannot be bound, and a program that
crashed or printed no report. A containment test that accepts it would pass with
no traffic at all.

`refused` and `no_reply` are kept apart for the same reason. A rejected
datagram comes back as `ECONNREFUSED` on receive (`refused`); a datagram that
was dropped further on is a timeout (`no_reply`).

### What the process cannot tell you

A UDP datagram dropped by an `output` rule fails `send()` with `EPERM`. A TCP
SYN dropped the same way does **not** fail `connect()`: the kernel retransmits
it until the stimulus gives up, so the result is `no_reply` at `connect`. Only a
capture can say the SYN never left. Use
[`observe()`](observing-a-stimulus.md) whenever the absence of a packet is the
claim.

---

## The stimuli

Every constructor takes the destination as an IP literal; the family (IPv4 or
IPv6) follows from it.

| Constructor | Sends | Waits for a reply |
| --- | --- | --- |
| `udp(host, port)` | one datagram | no |
| `udp_round_trip(host, port, timeout=2.0)` | one datagram | yes |
| `tcp_connect(host, port, timeout=1.0)` | a bare SYN (a handshake, no data) | the handshake |
| `tcp_round_trip(host, port, timeout=2.0)` | a connection and a payload | yes |
| `icmp_echo(host, timeout=None, socket="raw")` | an ICMP or ICMPv6 echo request | when `timeout` is set |
| `dns_query(server, transport="udp", qtype="A")` | a query for a unique name, over UDP or TCP | yes |
| `quic_initial(host, port=443)` | a 1200-byte datagram shaped like a QUIC Initial | when `timeout` is set |
| `stun_binding(host, port=3478)` | a STUN Binding Request | yes |

`Stimulus.with_reply(timeout)` turns any of them into one that waits (or, with
`None`, one that does not).

- **DNS:** the result's `dns` holds the parsed answer: `rcode_name`,
  `addresses`, `qname`. A reply that cannot be parsed is still `answered`,
  with the parse error in `error`.
- **STUN:** `mapped_address` is the source address and port the server saw,
  which is what a NAT or a proxy rewrites.
- **ICMP:** `socket="raw"` needs `CAP_NET_RAW`. Running as root has it; a
  non-root identity needs `capabilities={"net_raw"}`. `socket="dgram"` uses a
  ping socket instead, which works without the capability only for groups in
  `net.ipv4.ping_group_range`.

### Probe IDs and the 5-tuple

Every run gets a new probe ID (24 hex digits) carried in the packet itself: in
the payload for UDP, TCP and ICMP, in the query name
(`nse-<id>.nse.test`) for DNS, in the transaction ID for STUN and in the
connection ID for QUIC. A bare SYN has no payload, so it binds a distinct
source port from its own counter, and that port identifies it. The result
records the source address and port (`source`) the kernel chose, for every
kind that has one.

This is what lets a capture or a receiver say "this packet is that probe"
rather than "a packet like it went by".

---

## Requirements: `setpriv`

A stimulus with an `identity` is launched through `setpriv`, from util-linux.
Like every binary NSE runs as root, it is looked up only in trusted system
directories, never in `$PATH`. Minimal images may not have it: Fedora's
`util-linux-core` has `nsenter` but not `setpriv`. Install `util-linux`.

Without it, every stimulus run as another identity is `could_not_run` at
`launch`, with the reason naming the package, and `StimulusStream.start()`
raises `StreamStartError`. A stimulus without an identity does not need it.

---

## The interpreter

The programs need only the Python standard library. By default they run with
the interpreter running NSE, resolved through any virtualenv symlink, with
`-I -S` so nothing from the caller's environment is imported. Pass
`python="/usr/bin/python3"` to `run()` when the sandbox user cannot read that
interpreter.
