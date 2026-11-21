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

## The experiment report

`run_test_pipeline_report()` runs the same experiment as `run_test_pipeline()`.
Instead of the event list it returns an `ExperimentReport`, from which a CI
artifact alone is enough to reconstruct the run:

```python
from nse.core.pipeline import run_test_pipeline_report

report = await run_test_pipeline_report(request, controller=controller, timeout=60)

report.result.outcome            # "completed", "rules_invalid", "setup_failure",
                                 # "instrument_failure", "execution_failure", "timeout"
report.result.verdicts           # ["ACCEPT", "DROP"] - what reduce_verdicts() returns
report.result.oracle             # readiness / liveness canary: observed, missed, not_reached
report.result.teardown_complete  # False if teardown failed or left resources behind
report.measurement_valid         # completed, cleaned up, every control and capture sound
report.write("artefacts/experiment.json")  # atomic, sorted keys
```

It never raises for a failed run. Rule, setup, oracle, execution and teardown
errors are recorded with the stage they happened in, so a broken instrument, a
timeout and an incomplete cleanup each have their own outcome. Cancellation
still propagates.

The sections separate what is reproducible from what is specific to one run:

| Section | Contents | Same on a re-run? |
| :--- | :--- | :--- |
| `input` | The request, with SHA-256 of the ruleset and of the request | Yes |
| `environment` | NSE, Python, dependency, kernel and tool versions | Yes, on the same host |
| `result` | Outcome, oracle status, verdicts per stimulus, errors by stage, residual resources, positive controls | Yes, for a deterministic ruleset |
| `observations` | Trace and canary events, canary attempts, injection times, managed processes with verified identity, captures | No: kernel trace ids differ |
| `run` | Test and ownership ids, namespace and interface names, timestamps, seconds per stage | No |

The report states what NSE measured, not what you expected: comparing the
verdicts is your test's job, as the CLI does.

### Linking captures and positive controls

Captures and positive controls happen around the pipeline, so attach them
afterwards. `attach()` returns a copy, hashes the files the captures wrote into
`report.artifacts`, and lets them count towards `measurement_valid`:

```python
from nse.models.experiment_report import PositiveControl

report = report.attach(
    captures=[await asserter.stop_report()],
    controls=[PositiveControl(name="probe seen with the ruleset flushed", passed=probe_seen)],
)
assert report.measurement_valid, report.result
```

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

## Running programs inside the namespace

`NetnsController.create_namespace()` yields a sandbox whose `exec_argv()` runs a
program inside the namespace with **exactly** the arguments you pass:

```python
async with controller.create_namespace("nse_app") as ns:
    result = await ns.exec_argv(["python3", "-c", "print('ciao mondo')"])
    assert result.stdout == b"ciao mondo\n"
```

Each list element reaches the process as one argument: spaces, quotes, empty
strings, Unicode and shell metacharacters such as `$HOME`, `*` or `;` are passed
literally, because no shell and no splitting is involved. A bare string, a
non-`str` element, an empty program name or an argument containing NUL is
rejected with `TypeError`/`ValueError` before anything starts.

The older `exec(command)` is kept unchanged for existing callers. It splits the
string on whitespace with `str.split()` and does **not** use a shell, so
`exec('python3 -c "print(1)"')` passes the quote characters to Python and
fails. Prefer `exec_argv()` for anything but the simplest commands.

Both methods return `subprocess.CompletedProcess[bytes]` whose `args` include
the namespace prefix, and raise `subprocess.CalledProcessError`, with stdout and
stderr attached, on a non-zero exit. Cancelling the call kills and reaps the
process it started. The process runs with NSE's privileges: entering a network
namespace changes the visible network, not the user. For a different identity,
a timeout or a long-running program, use the managed processes below.

### Managed processes: identity, timeouts, process trees

`start_process()` starts a program and returns a handle; `run_process()` runs
one to completion:

```python
from nse import ProcessIdentity

nobody = ProcessIdentity(uid=65534, gid=65534, capabilities={"net_bind_service"})

async with controller.create_namespace("nse_app") as ns:
    # A server that must bind port 80 without being root.
    server = await ns.start_process(["/usr/sbin/my-server", "--port", "80"], identity=nobody)
    await server.wait_for_output(b"listening", timeout=10)  # explicit readiness
    assert server.identity.uids == (65534, 65534, 65534, 65534)

    # A client with a deadline: on timeout it is stopped and the result says so.
    result = await ns.run_process(["curl", "-sf", "http://[fd00:1::2]/"], timeout=5)
    assert result.ok, (result.termination, result.stderr)
# Leaving the block stops the server, its children and anything else still in the namespace.
```

**Identity.** `ProcessIdentity` sets the UID, GID, supplementary groups and
capabilities. Every field defaults to "unchanged", so without it the program
runs as NSE does. A non-root `uid` requires an explicit `gid`, and changing
either clears the supplementary groups unless you list them. `capabilities`
is exactly the set the process keeps (effective, permitted, ambient and
bounding); it also works for root, for example to run root with `net_raw` only.

NSE enters the namespace with its own privileges and applies the identity
afterwards with `setpriv`. Before the program starts, it reads the identity the
kernel reports for that very process (same PID) and compares it with the
request:

- If anything differs, `IdentityError` is raised and **the program never
  runs**; there is no fallback to root.
- If `setpriv` itself refuses, for example a capability the kernel does not
  know, the start fails with `ProcessStartError`.

The verified identity is in `process.identity` and in the result.

**Output.** stdin is `/dev/null`. stdout and stderr are captured by default, up
to `max_output_bytes` each (1 MiB); the rest is counted in `stdout_dropped` /
`stderr_dropped`, not kept. Pass `"discard"`, or a path to write a new file
instead: it is created with mode 0600, since output may hold secrets, and an
existing file is never overwritten.

**Ending a process.**

- `wait(timeout)` returns a `ProcessResult` with `termination` set to
  `"exited"`, `"timeout"`, `"cancelled"` or `"terminated"`, plus the exit status
  (negative for a signal), the output and the identity.
- On a timeout, on cancellation, or when you call `terminate(grace)`, the
  process and its whole process group get SIGTERM, then SIGKILL after `grace`
  seconds.
- `result.check()` raises `CalledProcessError` unless the process exited with 0.

**The boundary.** Each managed process leads its own process group. A
descendant that leaves the group (`setsid`, a daemon that double-forks) is
still in the network namespace. That namespace is the boundary NSE enforces:
before it is deleted, at the end of the block or by crash recovery, every
process in it is stopped, managed or not.

Processes are identified by namespace membership through a pidfd, so a recycled
PID is never signalled, and recovery needs no record of PIDs. The one thing
outside the boundary is a process that moves itself to another network
namespace, which needs `CAP_SYS_ADMIN`. A dropped identity rules that out.

### The host endpoint and the host's firewall

By default the host end of the veth pair, `ext_iface` with `host_ip`, is in the
namespace NSE runs in. Traffic from the sandbox to `host_ip` is then local input
for that namespace and crosses its firewall. On Fedora, for example, firewalld
puts the new `vhr-*` interface in the default zone, which accepts almost
nothing. A server listening on `host_ip` never receives the request, and a test
reads the silence as the rules under test blocking it.

NSE reads the host's nftables ruleset once per process and logs a warning when
an `input` hook may filter that traffic: a `drop` policy, or a `drop`/`reject`
reached unconditionally. It cannot tell which port a test uses, so it only
warns. Rules loaded with `iptables-legacy` are not visible to it.

To take the host's firewall out of the path, pass `isolated_host=True`. The
host end then goes into a namespace of its own, `nsh_<name>`, created and
removed with the sandbox:

```python
from nse import PCAPAsserter

async with controller.create_namespace("nse_app", isolated_host=True) as ns:
    # The host endpoint is a sandbox too: run the server where host_ip lives.
    server = await ns.host.start_process(["python3", "echo_server.py", "10.0.1.1", "9999"])
    await server.wait_for_output(b"bound", timeout=10)

    # Capture on the host end, in its namespace.
    asserter = PCAPAsserter(iface=ns.ext_iface, netns=ns.ext_netns)
    await asserter.start()
    result = await ns.run_process(["python3", "client.py", "10.0.1.1", "9999"], timeout=5)
    report = await asserter.stop_report()
```

- `ns.ext_netns` is the namespace holding `ext_iface`: `None` by default,
  `nsh_<name>` when isolated.
- `ns.host` is the host end as a sandbox. It has the same `exec_argv()`,
  `start_process()`, `run_process()` and `inject_packet()`. Its `ext_iface` is
  the sandbox's `peer_iface`, and the reverse, so `ns.host.inject_packet()` sends
  from the sandbox towards the host end.
- `ns.inject_packet()` sends from inside `nsh_<name>`.
- No host route is involved, so `host_ip` may overlap a subnet the host already
  routes. The preflight check for overlapping routes is skipped.
- Processes on both ends are stopped when the block exits.

---

## Asserting that nothing left the interface

The trace oracle answers *what did the ruleset decide*. It cannot answer *what
reached the wire*, which is the question behind a zero-leak claim: a packet that
matches no rule at all produces no verdict to inspect. `PCAPAsserter` covers
that half.

```python
from nse import PCAPAsserter

asserter = PCAPAsserter(iface="veth-host")
await asserter.start()  # returns once the kernel socket is filtering and bound
# ... drive the stimulus: no sleep needed before it ...
leaked = await asserter.stop()
assert not leaked, f"{len(leaked)} frame(s) escaped: {leaked}"
```

The interface is looked up in the namespace NSE runs in. For one in another
namespace, pass `netns=`, for example
`PCAPAsserter(iface=ns.ext_iface, netns=ns.ext_netns)`. Only the capture thread
enters that namespace; the rest of the process stays where it is, and the report
records it in `netns`.

### Readiness and failures

`await start()` returns only when the packet socket exists, carries its BPF
filter and is bound to the interface. From that moment every matching packet is
queued for the capture, so the stimulus may follow immediately; the
`asyncio.sleep()` that older code put after `start()` is no longer needed.
`stop()` drains whatever the kernel has already queued before closing, so a
packet that reached the interface before `stop()` is not lost. A packet still in
flight (for example, queued in another namespace) is not yet on the interface:
wait for an observable effect of the stimulus, such as its arrival at a
receiver, rather than a fixed delay.

`start()` raises `CaptureStartError` when the capture cannot be armed. Its
`reason` is `interface_missing`, `filter_invalid`, `permission_denied`,
`backend_unavailable` (libpcap missing), `backend_error`, `timeout` (see the
optional `timeout` argument) or `cancelled`, and no thread or socket is left
behind. A filter that does not compile is always an error. Scapy before 2.6
would log it and capture **unfiltered**; NSE compiles the filter itself first.

`stop()` still returns `list[Packet]`, but raises `CaptureError` when the
instrument was not healthy: the backend crashed (for example, the interface
was deleted), the loop did not stop in time, or start had failed. An empty list
now only ever means *a working capture saw nothing*. Calling `stop()` before
`start()`, or `start()` twice, raises `CaptureStateError`. A capture is single
use; `stop()` and `stop_report()` may be called repeatedly and in any order.

### The capture report

`stop_report()` stops the capture (once) and returns a `CaptureReport` instead
of raising:

```python
report = await asserter.stop_report()
report.instrument_healthy   # armed, ran until asked to stop, no backend error
report.window_complete      # True / False / None (unknown: counters unavailable)
report.termination          # "stopped", "limit_reached", "start_failed", ...
report.kernel_drops         # PACKET_STATISTICS drops, or None - never a guessed 0
report.effective_filter     # the BPF expression actually attached
report.model_dump_json()    # for CI artefacts
```

The report separates three questions. **Instrument health** says whether the
capture worked. **Window completeness** says whether every matching packet
between readiness and stop was read: the kernel's drop counter is zero and
nothing remained unread. When the counters are unavailable this is `None`, not
`True`. **Evidence sufficiency** is not in the report at all. A healthy, complete
capture of an empty interface still does not prove that your stimulus took that
path, which is why the positive control below is still required.

### Long captures with bounded memory

By default every captured packet is kept in memory and returned by `stop()`,
exactly as before. For a capture that runs for minutes or sees heavy traffic,
write it to a file instead and keep only counters in memory:

```python
from nse import CaptureLimits, PCAPAsserter

asserter = PCAPAsserter(
    iface="veth-host",
    output="artefacts/leak-check.pcap",  # a new file: an existing one is never overwritten
    limits=CaptureLimits(max_duration=300, max_file_bytes=200_000_000),
)
await asserter.start()
# ... a long stimulus ...
report = await asserter.stop_report()

assert report.instrument_healthy, report.errors
assert report.window_complete is True, report       # nothing dropped, nothing cut off
assert report.packets_observed == 0, report.artifacts  # the leak assertion: on the counter
```

With `output=` the capture thread writes each packet to the PCAP file as it
reads it. The file header is on disk once `start()` returns, the file is
flushed whenever the capture is idle for a second, and it stays readable by
tcpdump, Wireshark or `scapy.utils.rdpcap` even when it is cut short. Memory
holds only a sample, which is **empty unless you declare one** with
`max_stored_packets` or `max_stored_bytes`. `stop()` then returns that sample,
so in file mode **assert on the report, never on the list**: `assert not await
asserter.stop()` would pass even if packets leaked.

Every limit is optional, and reaching one is listed in `report.limits_reached`:

| Limit | When it is reached | `window_complete` |
| :--- | :--- | :--- |
| `max_packets` | The capture ends itself after reading that many packets; later ones are not read. `termination` is `limit_reached`. | `False` |
| `max_duration` | The capture ends itself that many seconds after readiness, after draining what was already queued. `termination` is `limit_reached`. | `False` |
| `max_file_bytes` | File mode only. The first packet that would grow the file past the size, and every packet after it, is counted but not written: the file is a prefix of the capture. `artifact_complete` is `False`. | `False` |
| `max_stored_packets` | Later packets are counted (and written, in file mode) but not kept in memory. | `False` in memory mode; unaffected in file mode, where the file is the record |
| `max_stored_bytes` | Same, counted in bytes of packet data. | As above |

A capture ended by a limit is still a healthy instrument: `stop()` does not
raise, but it logs a warning and the report says the window is incomplete. A
file that cannot be written is a different matter. A full disk, or a write,
flush or close error, appears in `report.errors`, makes the instrument
unhealthy, and `stop()` raises `CaptureError`. The packets keep being counted,
and the partial file is listed in `report.artifacts` with
`artifact_complete=False`.

There is no queue between the socket and the file: the thread that reads the
socket also writes the file. A writer that cannot keep up therefore fills the
kernel socket buffer, and the kernel counts what it then drops (`kernel_drops`,
`window_complete=False`). A writer that hangs (for example on a stalled network
filesystem) makes `stop()` end with `termination="stop_timeout"`. Neither case
grows memory, and neither can produce a report that claims a complete capture.

The counters come from two places. `packets_observed` and `bytes_observed` are
what NSE read from the socket. `kernel_packets` and `kernel_drops` are the
kernel's `PACKET_STATISTICS` since readiness: every packet that passed the BPF
filter, and the ones dropped because the buffer was full. `packets_written` and
`bytes_written` describe the file. If the file is incomplete, it may hold fewer
packets than were handed to it.

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
