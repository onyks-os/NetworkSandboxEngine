# How-To: Controlled Receivers

A capture says a packet was on the wire. It does not say the packet arrived:
the destination's input path can still drop it, and a reply can only come from
something that received the request. A controlled receiver is a known server
that logs every arrival, with its probe ID, before answering it.

Run receivers on the host endpoint of an isolated sandbox
(`create_namespace(..., isolated_host=True)`, then `ns.host`). There, no
firewall on the machine running NSE sits between the sandbox and the receiver.
See [the host endpoint](in-process-integration.md#the-host-endpoint-and-the-hosts-firewall).

---

## A worked example: a DNS rule that must not answer for blocked users

```python
from nse import NetnsController, ProcessIdentity, receivers, stimuli

async def test_the_resolver_sees_the_query() -> None:
    controller = NetnsController()
    async with controller.create_namespace("nse_dns", isolated_host=True) as ns:
        server = receivers.dns("10.0.1.1", a=("192.0.2.10",))
        async with await server.start(ns.host) as resolver:
            result = await stimuli.dns_query("10.0.1.1").run(
                ns, identity=ProcessIdentity(uid=1000, gid=1000)
            )
            log = resolver.log()

    assert result.outcome == "answered", result.describe()
    assert result.dns.addresses == ("192.0.2.10",)
    assert log.complete, log.problems
    [receipt] = log.matching(result)            # the resolver got this very query
    assert receipt.source == result.source      # from the address the probe used
```

`start()` returns only once every socket is bound: the receiver says so
explicitly, so there is no sleep and no race with the first stimulus. If it
cannot bind (an address the namespace does not have, a port in use) `start()`
raises `ReceiverStartError` with the reason instead of returning a server that
will never answer.

---

## The receivers

| Constructor | Listens on | Answers |
| --- | --- | --- |
| `udp_echo(address, port=0)` | UDP | the datagram, unchanged |
| `tcp_echo(address, port=0, idle_timeout=5.0)` | TCP | every segment, unchanged |
| `dns(address, port=53, a=..., aaaa=..., mode="answer")` | UDP and TCP on one port | fixed A/AAAA records |
| `stun(address, port=3478)` | UDP | a Binding success with XOR-MAPPED-ADDRESS |

Port `0` picks a free port; `receiver.port` says which.

The DNS receiver's `mode` decides what happens to a query:

| `mode` | Response |
| --- | --- |
| `answer` | the configured `a` or `aaaa` records (NOERROR, empty for other types) |
| `servfail` | SERVFAIL |
| `refused` | REFUSED |
| `drop` | nothing: the query is logged and not answered |

`drop` is the negative control for a client's timeout handling: the query
arrived (`received`) and no reply was sent.

---

## The receipt log

`receiver.log()` is a snapshot while the receiver runs; `await receiver.stop()`
(or leaving the `async with` block) gives the final one. Each `Receipt` has:

- `seq`: a counter from 1, so a gap is visible;
- `probe_id`: extracted from the data, or `None` for data without one;
- `source` and `destination` (`Endpoint`s), `family`, `transport`;
- `kind`: `datagram`, `connection` (a TCP accept) or `data`;
- `monotonic` and `wall`: when it arrived;
- `size`, `data` (the first 512 bytes) and `response` (what the receiver did:
  `echo`, `answer`, `servfail`, `drop`, `binding` and so on).

Find receipts with `for_probe(probe_id)`, `from_source(endpoint)` or
`matching(result)`. `matching` uses the probe ID, or the source port for a
bare SYN, which carries no data.

### An incomplete log proves nothing

`log.complete` is `False`, with the reasons in `log.problems`, when:

- a sequence number is missing or a line cannot be read;
- the receiver's output exceeded the limit and was cut;
- the receiver exited on its own instead of being stopped;
- the final line was cut off.

A receipt found in an incomplete log still counts. An absence in an incomplete
log is not a finding: [`observe()`](observing-a-stimulus.md) reports it as
"received: unknown", never as "not received".
