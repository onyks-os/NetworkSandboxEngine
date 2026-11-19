# Upgrading to 2.2

2.2.0 is a drop-in upgrade for code written against 2.1.x. Every module, name,
method, attribute and parameter of 2.1.2 is still there, with the same
positional order, the same defaults, the same sync or async nature and the same
return annotations. This is checked, not assumed: `tests/test_api_compat.py`
compares the source with a record of the 2.1.2 surface, and CI repeats the
check on the built wheel and sdist, installed in clean virtualenvs on Python
3.10 to 3.13 (`scripts/check-dist.sh`).

What changes is behaviour that used to fail silently. Each change below turns
a result that could be wrong without saying so into an error, or into a
guarantee you no longer have to approximate.

---

## Changes you may notice

**Startup no longer deletes resources by name prefix.** 2.1.x deleted every
namespace and veth whose name matched its prefixes when a controller started.
2.2.0 records what it creates in an ownership journal under `/run/nse` and
recovers only resources it can prove were abandoned by an NSE process that is
no longer running. Anything else is preserved and logged. Two consequences:

- Resources left behind by a *2.1.x* run are not removed automatically. If a
  test uses a fixed namespace name and a 2.1.x run was killed, setup fails with
  `OwnershipError` ("already active or reserved") instead of reusing or
  deleting the name. Inspect and remove the leftover by hand once.
- A 2.1.x controller still has its prefix sweep and can delete resources a
  2.2.0 run is using. Do not run the two versions concurrently on one host.

**`destroy_netns()` removes only what this controller created.** A name it does
not own is logged and left untouched.

**The simple topology has no fixed `veth-nse` peer any more.** Its in-namespace
peer is `vrh-<suffix>`, derived from the test ID so concurrent runs cannot
collide. Rules that matched `iifname "veth-nse"` must match `iifname "vrh-*"`
or the name from `derive_names()`.

**Capture failures are errors.** `PCAPAsserter.start()` raises
`CaptureStartError` with a classified `reason` (missing interface, invalid
filter, no permission, timeout) instead of succeeding and capturing nothing.
`stop()` still returns `list[Packet]`, but raises `CaptureError` when the
instrument was unhealthy, for example when the interface disappeared during the
capture. Calling `start()` twice, or `stop()` before `start()`, raises
`CaptureStateError`. A filter that does not compile fails `start()`; with Scapy
older than 2.6 it used to open the socket unfiltered.

**Deleting a namespace stops the processes inside it**, including descendants
that detached with `setsid`. NSE's own namespace and PID 1's are refused.

**`nse-runner` fails a case that did not clean up**, prints `[TEARDOWN ERROR]`,
and exits 1. Timeouts, invalid rules and setup failures print `[TIMEOUT]`,
`[RULES ERROR]` and `[SETUP ERROR]` instead of `[ORACLE ERROR]`.

---

## Code you can remove

**The `sleep()` after `PCAPAsserter.start()`.** In 2.2.0 `start()` returns once
the kernel socket is bound with its filter, so a stimulus can be sent
immediately. In 2.1.x the sleep was not decoration. The cycle below is the
pattern TransparentTorProxy uses (`start()`, a stimulus sent by a new process
in the namespace, 50 ms of settling, `stop()`), measured 300 times per row with
the CPU idle and with every core busy:

| NSE | Sleep after `start()` | Stimuli missed (idle / busy) | Median cycle (idle / busy) |
| :--- | :--- | :--- | :--- |
| 2.1.2 | 0.2 s | 0 / 0 | 281 / 300 ms |
| 2.1.2 | none | **13 (4.3%) / 1** | 80 / 102 ms |
| 2.2.0 | none | **0 / 0** | 92 / 110 ms |

On 2.1.2, removing the sleep loses about one capture in 25. To a positive
control that reads as a broken instrument; to a negative assertion without
one, as containment. On 2.2.0 the readiness wait itself takes a median of
11 ms and at most 20 ms, so each capture is about three times shorter than with
the 0.2 s sleep, with no misses. The first `start()` of a process also imports
Scapy (270 ms idle, 740 ms busy in this measurement), which 2.1.x did in the
constructor.

**A fixed wait after `start_mock_listener()`.** `start_mock_listener()` is kept
as it was: it waits a fixed 150 ms and cannot tell a failed bind from a
working one. `nse.core.mock_listener.start_listener()` returns once the
listener has confirmed its bind and raises `ListenerStartError` otherwise.

---

## What you can now assert

- **That a capture window was complete.** `stop_report()` returns a
  `CaptureReport` with the kernel's own packet and drop counters.
  `window_complete` is `False` if anything matching the filter was dropped or
  left unread, and `None` when the counters are unavailable, never a guessed
  zero. An assertion that nothing leaked is only as good as this field.
- **That a process ran with the identity you asked for.** `start_process()` and
  `run_process()` verify UID, GID, groups and capabilities in the kernel before
  the program starts, and refuse to run it otherwise.
- **That an experiment can be reproduced from its artifact.**
  `run_test_pipeline_report()` and `nse-runner --report-dir` record the input,
  the environment and every observation, and keep rule errors, setup failures,
  instrument failures and timeouts apart.

---

## Qualification

2.2.0 was qualified against TransparentTorProxy's zero-leak suite
(`tests/test_nse_rules.py`, TTP 0.4.11), installed exactly as TTP's CI installs
it, and against the NAT gateway example, which is independent of TTP. Only NSE
was swapped between runs, three runs per row:

| TTP suite | NSE 2.1.2 | NSE 2.2.0 |
| :--- | :--- | :--- |
| unchanged | 47 passed, 1 skipped (147 s) | 47 passed, 1 skipped (149 s) |
| without the `sleep(0.2)` after `start()` | **2 of 3 runs fail**, 4 positive controls each | 47 passed, 1 skipped (142 s) |

The skipped test needs nftables 1.1.6, which the runner did not have; that is
TTP's policy and the same with both versions. Every failure without the sleep
on 2.1.2 was one of TTP's own positive controls catching a capture that missed
its stimulus, which is the race measured above.
