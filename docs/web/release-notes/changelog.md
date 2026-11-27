# Release Notes & Changelog

All notable changes to the Network Sandbox Engine (NSE) project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/). This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [2.6.0] - 2026-11-27

### Added

Observing a phase on a machine NSE does not run on, such as a reload, reboot,
suspend or teardown inside a VM. All of it is opt-in, and existing APIs keep
their behaviour. See *Observing Outside the Sandbox*.

- **Portable streams.** `StimulusStream.command(python="python3")` returns the
  agent's command line and its stream ID, to run anywhere (over ssh, for
  instance). `StreamLog.parse(output, stream_id, *, final, stream)` reads what
  it printed. The log records the machine's `boot_id` (`StreamLog.boot_id`),
  and `CLOCK_BOOTTIME` alongside `CLOCK_MONOTONIC` for the stream and each
  attempt (`started_boottime`).
  - A log that spans boots, holds more than one run, or ends without the
    stream's end event is never `complete`, and `problems` says why.
  - A suspend is a `Gap`: `CLOCK_MONOTONIC` stops while suspended and
    `CLOCK_BOOTTIME` does not, and `Gap.suspended` holds the difference.
- **`CaptureReport.from_pcap(path, *, required_bytes=None, expected_beacons=())`**
  returns the report and the packets of a pcap file NSE did not capture, such
  as one QEMU wrote.
  - **Refusals.** Any structural damage is refused: an empty or cut file
    header, a wrong magic (pcapng included) or version, a record header or
    frame cut short, and `incl > orig` or `incl > snaplen`. The records before
    the damage are kept, and the damage is in `errors`.
  - **Fields.** The report fills in `link_type`, `snaplen`,
    `packets_truncated`, `snaplen_sufficient` and the `beacons_*` fields, and
    sets the new `source="pcap_file"`. `kernel_drops` is `None`.
  - **Completeness.** `window_complete` is `True` only for an intact file
    whose snap length covers `required_bytes`, with at least one expected
    beacon and every expected beacon present. Without expected beacons it is
    `None`.
- **Clocked beacons (version 2).** The frame carries the sender's `boot_id`,
  `CLOCK_MONOTONIC` and `CLOCK_BOOTTIME` read just before it was sent. A
  follow-up frame with the same token carries the values read just after.
  - Live captures and `from_pcap` both record the pair as one sighting, with a
    `SenderClock`.
  - `beacons.agent_command()` and `beacons.agent_report()` run a portable
    standard-library agent that sends them as root on the far side.
  - Version 1 beacons are unchanged.
- **`ClockMap.from_beacons(sightings)`** maps each boot's `CLOCK_BOOTTIME`
  onto the capture's clock. The uncertainty is the widest before/after
  bracket plus the spread between beacons. The map is valid only for its own
  boot, and only between that boot's first and last beacon; outside it,
  `to_capture()` returns `None`, never an estimate.
- **`correlate(..., clock=clock_map)`** places every attempt on the capture's
  clock (`Fate.capture_time` and `capture_uncertainty`), and `between()` then
  takes capture times. An attempt whose uncertainty crosses the edge of the
  slice, or one the map cannot place, makes it inconclusive.
- `nse.formats`, a leaf package with the pcap reader and writer and the beacon
  frame codec. The models can use it, which they cannot do with `nse.core`.

---

## [2.5.2] - 2026-11-27

### Fixed

- **`RuleEngine.load()` no longer accumulates NSE's trace rules.** `nft -f`
  appends to a chain that already exists, so every `load()` into the same
  namespace added another `meta nftrace set 1` to `nse_trace_prerouting` (and
  `nse_trace_output`). Verdicts were unaffected, but each packet's trace
  repeated NSE's rule once per load. A `load()` without `trace_output` also
  kept the output chain of an earlier `load()` with it. The trace block now
  starts with `table inet nse_trace` and `delete table inet nse_trace` in the
  same transaction: after every `load()` the table holds exactly the chains
  that call asked for.
- **Cancelling `spawn_process()` while the child is being created no longer
  leaves part of it running.** The child exists before
  `asyncio.create_subprocess_exec()` returns. A cancel in that window reached
  asyncio, which killed only the group leader, so whatever the launch chain had
  already started survived, adopted by init. This made
  `test_cancelling_the_start_leaves_nothing_running` fail intermittently on
  Ubuntu, where `/bin/sh` forks a command it could have replaced itself with.
  Creation now finishes, shielded from the cancel, and then the whole process
  group is killed.

### Added

- When `TraceHarvester.prove_ready()` (and so `stimuli.trace_ready()`) cannot
  prove readiness, `TraceReadiness.problems` says whether `inet nse_trace` is
  missing from the namespace, as after a ruleset that starts with
  `flush ruleset`, or lacks its prerouting or output chain.

---

## [2.5.1] - 2026-11-23

### Fixed

- **Two attempts of a bare-SYN stream could leave from the same source port.**
  Attempt *n* bound `base + n - 1`; when that port was busy it moved to the
  next one, which was attempt *n + 1*'s. A bare SYN is identified only by its
  source port, so `correlate()` could credit one attempt's packet to the
  other. Ports now come from one counter per stream: a busy port is skipped
  and never shared. Ports are distinct, ascending, and no longer necessarily
  consecutive.
- The release workflow's TestPyPI smoke test now installs with
  `--no-cache-dir` and waits up to 10 minutes. pip had kept re-reading the
  index page it cached on its first attempt, so v2.5.0 never appeared and was
  not published to PyPI. 2.5.1 is the first 2.5 release on PyPI.

---

## [2.5.0] - 2026-11-23

Traffic through a window of time, and captures that prove they saw it. A rule
reload or a restart is not an instant: the question is what happened to the
traffic throughout it. NSE now sends a numbered stimulus at a fixed rate,
says what became of every attempt, and calls a window inconclusive whenever
the stream paused, the capture cannot prove it was reading, or a log is
incomplete. Observations gain a canary in the same window and NAT-aware
matching, and the trace oracle can follow traffic a process generates.
Everything is opt-in; code written against 2.4.0 keeps working unchanged.

### Added

- **`nse.streams.StimulusStream(stimulus, period, count=None, duration=None,
  max_in_flight=256)`**: one program inside the sandbox sends the stimulus once
  per period, each attempt in its own thread, with a sequence number and its
  own probe ID (a bare-SYN stream binds consecutive source ports). `await
  stream.start(sandbox, identity=...)` returns a `RunningStream` with `log()`,
  `stop()` and `wait()`; slots that cannot be used are skipped, never made up
  with a burst. `StreamStartError` when it does not start.
- **`correlate(log, packets, receipts=None, *, capture=None,
  max_gap_periods=3.0)`** gives each sequence number a `Fate`: `not_sent`,
  `refused`, `sent_not_seen`, `on_wire` or `received`, with the facts it rests
  on as `True`, `False` or `None`. The `Correlation` is not `conclusive` when
  no attempt that could run started for more than `max_gap_periods` periods,
  when the stream's log, the capture or the receiver's log is incomplete, when
  nothing was tested, or when the instruments contradict each other.
  `between(start, end)` slices it and adds gaps at the edges.
- **Window beacons**: `await asserter.mark(label)` (optionally `via=sandbox`)
  and `await sandbox.beacon(label)` with `asserter.expect(beacon)` send an
  Ethernet frame with EtherType `0x88B5` at a known moment. A `CaptureReport`
  with an expected beacon missing is not `window_complete`. Beacons are written
  to the PCAP file but never returned by `stop()`. `mark()` refuses on a
  custom filter unless `PCAPAsserter(..., beacons=True)`, and on a link without
  an Ethernet header.
- **`CaptureReport`** gains `hardware_type`, `link_type`, `snaplen`,
  `packets_truncated`, `required_bytes` (from `PCAPAsserter(required_bytes=...)`)
  and `snaplen_sufficient`, plus `beacons_expected`, `beacons_seen` and
  `beacons_missing`. A declared `required_bytes` larger than the snaplen makes
  the window incomplete.
- **A canary in the same window**: `observe(..., canary=stimulus,
  canary_identity=...)` sends the canary after the stimulus inside the same
  capture. Unless the canary was seen on the wire, no absence is `False`.
  `Observation.canary` holds the canary's own observation.
- **`observe_window(sandbox, stimuli, ...)`** runs several stimuli and an
  optional canary in one capture and returns a `Window` with one `Observation`
  per stimulus, `vouched`, `conclusive`, `contradictions()` and `describe()`.
- **NAT-aware matching**: `nat=True` on `observe()`, `observe_window()`,
  `requests_in()`, `replies_in()` and `correlate()` recognises a probe after a
  DNAT or redirect rewrote its destination: by probe ID (or a bare SYN's
  source port) and the probe's own source, wherever it went.
- **Tracing locally generated traffic**: `RuleEngine(trace_output=True)` adds an
  `output`-hook trace chain at priority -350, so packets a process sends from
  inside the namespace are traced. `TraceHarvester.prove_ready(send,
  predicate)` and `stimuli.trace_ready(harvester, sandbox, canary)` send a
  canary until its own trace comes back and return a `TraceReadiness`;
  `without(events)` removes the canary's traces. Without the output chain a
  local canary is never traced, and readiness is `False`.
- The new names are exported from `nse`: `StimulusStream`, `RunningStream`,
  `StreamStartError`, `StreamAttempt`, `StreamLog`, `Correlation`, `Fate`,
  `Gap`, `correlate`, `Beacon`, `BeaconSighting`, `Window` and
  `observe_window`.
- Documentation: [streams](https://onyks-os.github.io/nse/how-to/streams/),
  [beacons](https://onyks-os.github.io/nse/how-to/beacons/),
  [tracing a process's own traffic](https://onyks-os.github.io/nse/how-to/tracing-local-traffic/),
  and [observing a stimulus](https://onyks-os.github.io/nse/how-to/observing-a-stimulus/)
  for canaries, windows and NAT.

### Fixed

- A missing `setpriv` (util-linux) made `Stimulus.run(..., identity=...)` raise
  `BinaryNotFoundError` instead of returning `could_not_run`, as its contract
  says. It is now `could_not_run` at `launch`. The error for any missing binary
  NSE runs now names the package that provides it, for instance util-linux for
  `setpriv`, which Fedora's minimal `util-linux-core` lacks. The dependency is
  documented in the requirements and the stimuli guide.

### Notes

- Each feature has a test in which a deliberately blind setup fails visibly:
  a filter that drops a beacon, a beacon on a link the capture does not watch,
  a frozen stream, a stream that cannot run, a strict match after a DNAT, a
  capture that cannot see its canary, and a trace without an output chain.

---

## [2.4.0] - 2026-11-23

Stimuli from a real user, controlled receivers, and observations that keep
each fact apart. A firewall filters locally generated traffic by the identity
of the socket that sent it, which packet injection cannot reproduce. NSE now
sends traffic from a process running as a chosen UID/GID inside the sandbox,
runs known servers that log every arrival, and reports what the process, the
capture and the receiver each saw, saying "unknown" whenever an instrument
cannot vouch for an absence. Everything is opt-in; code written against 2.3.0
keeps working unchanged.

### Added

- **`nse.stimuli`**: UDP send, UDP round trip, TCP connect (a bare SYN), TCP
  round trip, ICMP and ICMPv6 echo, a DNS query over UDP or TCP for a unique
  name, a 1200-byte UDP datagram shaped like a QUIC Initial, and a STUN
  Binding Request, on IPv4 and IPv6. `await stimulus.run(sandbox,
  identity=ProcessIdentity(...))` runs a standard-library program through
  `run_process()` and returns a `StimulusResult`.
- **Typed outcomes, never folded together**: `sent`, `answered`, `no_reply`
  (only for a stimulus that waits), `refused` with the errno and the socket
  call that failed (`connect`, `send`, `receive`), and `could_not_run` when no
  packet can have been produced: no interpreter, an identity that cannot be
  applied, a socket that cannot be created (a raw socket without
  `CAP_NET_RAW`) or bound, or a program with no report. `run()` never raises
  for a failure of the stimulus itself.
- **Probe IDs**: every run carries a new ID in the packet (payload, DNS name,
  STUN transaction ID, QUIC connection ID). A bare SYN binds a distinct source
  port instead, and the result records the source address and port.
- **`nse.receivers`**: UDP echo, TCP accept-and-echo, DNS with fixed A/AAAA
  answers and the modes `answer`, `drop`, `servfail` and `refused` on UDP and
  TCP, and STUN returning XOR-MAPPED-ADDRESS. `start()` returns once every
  socket is bound and raises `ReceiverStartError` if one cannot be.
- **Receipt logs**: every arrival is logged before it is answered, with its
  sequence number, probe ID, source, destination, family, transport and
  monotonic and wall time. `ReceiptLog.complete` is `False`, with the reasons,
  on a missing sequence number, an unreadable or cut line, dropped output, or a
  receiver that exited on its own.
- **`nse.observe()`** runs one stimulus inside a capture window, optionally
  with a receiver, and returns an `Observation` with `sent`, `on_wire`,
  `received` and `reply_on_wire` kept apart. A fact the capture or the log
  cannot vouch for is `None`, never `False`. `contradictions()` names
  combinations that mean an instrument is blind, such as a probe the receiver
  logged but the capture did not see, and `describe()` includes them.
- `nse.stimuli.requests_in()` and `replies_in()` find a result's packets in a
  capture that holds several stimuli.
- `ManagedProcess.output_dropped()` says how many bytes of a stream were
  dropped past `max_output_bytes`.
- The new names are exported from `nse`: `Stimulus`, `StimulusResult`,
  `Observation`, `observe`, `Receiver`, `ReceiverSpec`, `ReceiverStartError`,
  `Receipt`, `ReceiptLog` and `Endpoint`.
- Documentation: [sending traffic as a user](https://onyks-os.github.io/nse/how-to/stimuli/),
  [controlled receivers](https://onyks-os.github.io/nse/how-to/receivers/) and
  [observing a stimulus](https://onyks-os.github.io/nse/how-to/observing-a-stimulus/).

### Notes

- A TCP SYN dropped by an `output` rule does not fail `connect()`: the kernel
  retransmits it, and the stimulus reports `no_reply` at `connect`. Only the
  capture can tell that it never left; use `observe()` for that claim.

---

## [2.3.0] - 2026-11-21

The host endpoint without the host's firewall. In the simple topology,
traffic from the sandbox to `host_ip` used to cross the host's own firewall, and
a test could blame the rules under test for what firewalld dropped. NSE now
warns when that can happen, and `isolated_host=True` takes the host endpoint out
of the host altogether. Everything is opt-in; code written against 2.2.0 and
2.1.x keeps working unchanged.

### Added

- **`create_namespace(..., isolated_host=True)`** puts the host end of the veth
  pair in a namespace of its own, `nsh_<name>`, instead of the namespace NSE
  runs in. Traffic from the sandbox to `host_ip` then no longer crosses the
  host's firewall. On Fedora, firewalld puts a new `vhr-*` interface in its
  default zone and drops it, so a test server on `host_ip` never answered and
  the test blamed the rules under test. The namespace is reserved, recorded and
  removed with the sandbox, and `host_ip` may overlap a host subnet. The default
  is unchanged.
- `NamespaceSandbox.ext_netns` names the namespace holding `ext_iface` (`None`
  by default). `NamespaceSandbox.host` is the isolated host end as a sandbox of
  its own, for running a server on `host_ip` or injecting towards the host end.
  Processes on both ends are stopped when the block exits.
- `PCAPAsserter(..., netns=...)` captures on an interface in another network
  namespace. Only the capture thread enters it. `CaptureReport.netns` records
  it.
- **A warning when the host firewall may filter the host endpoint.** With the
  default topology, `create_namespace()` reads the host's nftables ruleset once
  per process. It logs a warning naming the chain when an `input` hook drops by
  policy or reaches an unconditional `drop`/`reject`, and suggests
  `isolated_host=True`. It never fails a setup.

### Changed

- `ScapyInjector.inject(..., host_netns=...)` now also sends an incoming packet
  from inside `host_netns`. Until now it only looked up the host MAC there and
  sent from NSE's own namespace, where that interface does not exist. NSE's own
  callers pass `None` and are unaffected.

### Maintenance

- **The documentation site is published by the release itself.** The Release
  workflow creates the GitHub Release with `GITHUB_TOKEN`, and events caused by
  that token start no other workflow. *Publish Documentation* (`release:
  published`) therefore never ran for 2.1.1 to 2.2.0, and
  <https://onyks-os.github.io/nse/> still showed 2.1.0. `release.yml` now calls
  `publish-docs.yml` once PyPI has the version.

### Documentation

- The host endpoint and the host's firewall: what is on the path by default,
  the warning, and `isolated_host=True`. Covered in the in-process integration
  guide, the namespace lifecycle (`nsh_<name>`), the README's list of what a
  run changes on the host, the architecture pages (with the isolated topology)
  and the API reference (`nse.core.host_firewall`, `PCAPAsserter(netns=...)`).
- *Releasing* lists the documentation step and how to rerun it on a tag.
- The README has a *Project statistics* section: stars, PyPI downloads (monthly
  and total) and the star history, read from outside, with what the counts
  include.

---

## [2.2.0] - 2026-11-19

Results you can verify: who owns each resource, whether the observer was
ready, and whether what it recorded is complete.

Code written against 2.1.x keeps working. The 2.1.2 API surface is checked by a
test and on the installed packages. What changes is behaviour that used to fail
silently: a prefix sweep that could delete someone else's namespace, a capture
that could start without listening, a listener that could fail to bind
unnoticed. Each now fails explicitly or is replaced by a guarantee. See
[Upgrading to 2.2](https://onyks-os.github.io/nse/release-notes/upgrading-to-2.2/) for what to
check and what you can remove. Qualified against TransparentTorProxy's
zero-leak suite and the independent NAT gateway example.

### Fixed

- Replace prefix-based startup deletion with private ownership journals,
  lifetime owner locks and coordinated recovery. Live controllers, unmarked
  legacy resources, replaced names and uncertain metadata are preserved.
- Route ordinary teardown through the same ownership checks, including the
  pipeline's host veth cleanup. A failed setup cannot remove another controller's
  link; deletion failures retain their records for retry. Namespace and veth
  method signatures and return types are unchanged, but `destroy_netns()` now
  removes only resources owned by that controller.
- Add real two-process traffic tests for normal teardown, SIGKILL and recovery
  before veth alias application, plus regressions for corrupt metadata,
  concurrent recoverers and fork/exec lock inheritance. Integration CI now
  explicitly elevates privileges so these tests execute instead of skipping.
- Make topology setup transactional: namespaces are reserved under the shared
  lock before any kernel change, a duplicate run ID in the same controller fails
  without tearing down the active run, and a failure or cancellation at any
  setup step rolls back every resource created so far. Cancellation now waits
  for work already running in a thread before cleanup.
- Remove name collisions between concurrent runs: interface suffixes are a
  digest of the whole test ID within Linux's 15 byte limit, and the simple
  topology no longer creates a fixed `veth-nse` peer in the host namespace (its
  in-namespace peer is now `vrh-<suffix>`). **Behaviour change:** rules that
  matched `iifname "veth-nse"` inside the simple sandbox must match
  `iifname "vrh-*"` or the name from `derive_names()`; `veth-nse` will not
  return. Setup rejects interface names in use
  and subnets overlapping existing host routes before touching the kernel.
- Derive gateway host routes from the configured server subnets and record them
  as owned resources; pre-existing routes are never replaced or removed.
- Fix the gateway YAML case reporting three verdicts for two packets: the
  listener's dropped UDP reply was counted as a verdict. Traces are attributed
  to stimuli from their first hook; replies and background traffic are kept but
  not counted, and canaries must match their own packet. Oracle count checks are
  unchanged.
- ICMP traffic other than an echo request between the injected addresses (for
  example an ICMPv6 neighbour solicitation used for reachability probing) is no
  longer attributed as a stimulus, fixing an intermittent extra verdict in the
  IPv6 example.
- `NamespaceSandbox.inject_packet()` now honours the controller's `use_nsenter`
  choice, fixing injection in containers.
- A capture filter that fails to compile (invalid expression or libpcap missing)
  now fails `start()`. With Scapy < 2.6 it was logged and the socket opened
  **unfiltered**.
- A namespace whose creation fails because it cannot be entered (for example
  `ip netns exec` inside some containers) is now rolled back. The failed
  inspection used to replace the original error and leave the namespace behind.
- `NamespaceSandbox.exec()` documented accurately: it splits on whitespace and
  never uses a shell. Its behaviour is unchanged. Cancelling `exec()` or
  `exec_argv()` now kills and reaps the started process instead of leaving it
  running.
- Two packets to the same port no longer start two mock listeners, the second
  of which failed to bind unnoticed. Listeners used to be given a fixed 150 ms
  instead of confirming their bind.

### Added

- `TestRequest.network` (`SimpleNetwork` / `GatewayNetwork`) and the YAML
  `network:` key, for explicit dual stack addresses so independent topologies
  can run side by side. Defaults are unchanged.
- `TraceEvent` fields `packet_src_ip`, `packet_dst_ip`, `packet_protocol`,
  `packet_src_port`, `packet_dst_port` and `packet_role`.
- `PCAPAsserter.stop_report()` and `nse.CaptureReport`: interface, requested and
  effective filter, backend and version, timestamps, termination cause, packets
  and bytes observed/stored, kernel `PACKET_STATISTICS` packets and drops (or
  `None` with a reason, never an invented zero), errors, and the derived
  `instrument_healthy` / `window_complete` verdicts.
- `PCAPAsserter.start(timeout=...)` and `stop(timeout=...)`, plus
  `nse.CaptureError`, `nse.CaptureStartError` (classified `reason`) and
  `nse.CaptureStateError`.
- `NamespaceSandbox.exec_argv(argv)`: runs a program in the namespace with
  exactly the given arguments (no shell, no splitting), validated before
  anything starts. Same result and `CalledProcessError` contract as `exec()`.
- Bounded captures: `PCAPAsserter(output=...)` writes a readable PCAP file
  progressively and keeps only a declared in-memory sample (none by default).
  `limits=nse.CaptureLimits(...)` bounds packets, duration, file size and
  stored packets/bytes. The report gains `output_mode`, `limits`,
  `limits_reached`, `bytes_stored`, `packets_written`, `bytes_written`,
  `artifacts` and `artifact_complete`, the termination `limit_reached` and the
  start failure `output_unavailable`. Without `output=` or `limits=` every
  packet is kept, as before. A full disk or a write, flush or close error makes
  the instrument unhealthy, and no limit, slow writer or file error can produce
  a report that claims a complete window.
- Managed application processes: `NamespaceSandbox.start_process()` returns a
  `nse.ManagedProcess` handle, and `run_process()` runs a program to
  completion. Both take an exact argv and an optional `nse.ProcessIdentity`
  (UID, GID, groups, capabilities, no_new_privs), applied with `setpriv` after
  entering the namespace. Before the program runs, the kernel-reported identity
  of the process itself is compared with the request. A mismatch raises
  `nse.IdentityError` and never runs the program, with no fallback to root.
  - Results: `wait(timeout)`, `terminate(grace)` and cancellation stop the
    whole process group (SIGTERM, then SIGKILL). `nse.ProcessResult` carries
    the termination cause, exit status, verified identity and output.
  - Output: captured up to a limit (the excess is counted), discarded or
    written to a new file.
  - Readiness: `wait_for_output()` waits for an explicit signal from the
    process.
- Reproducible experiment reports: `nse.core.pipeline.run_test_pipeline_report()`
  runs the same experiment as `run_test_pipeline()` and returns an
  `nse.ExperimentReport`, which can be rebuilt from a CI artifact alone.
  - Sections: `input` (request, ruleset and request hashes), `environment`
    (NSE, Python, dependency, kernel and tool versions), `result`,
    `observations` and `run`.
  - `result.outcome` keeps completed, rules invalid, setup failure, instrument
    failure, execution failure and timeout apart. Errors are recorded with
    their stage, and teardown errors and residual resources are recorded too.
  - Captures and caller-declared `nse.PositiveControl` checks are linked with
    `attach()`, which also hashes the capture files.
  - JSON output has sorted keys and is written atomically.
  - `timeout=` stops a run that overruns, then tears it down.
- `nse-runner --report-dir DIR` writes `report.json` (status, expected and
  observed verdicts, and the experiment report of every case) and
  `manifest.json` (SHA-256 of every artifact). Both are written atomically, also
  for a failed, unreadable or interrupted suite. `--timeout SECONDS` bounds
  each case.
- `examples/`: complete experiments with their expected output, which need
  nothing but NSE:
  - YAML suites: a workstation firewall, an IPv6-only service, coexisting
    tables and a NAT gateway;
  - a real TCP/UDP application running as `nobody`, with a bounded file
    capture and positive controls;
  - two experiments that must fail: a wrong policy with a sound observer, and a
    sound policy with a blind oracle or a misplaced capture.

  CI runs all of them on a real kernel (`tests/test_examples.py`) and checks
  their exit codes and artifacts. ruff and mypy check them as well.
- Mock listeners are managed processes that confirm their bind
  (`nse.core.mock_listener.start_listener`). The pipeline starts one per
  protocol and port and reports a bind failure as a setup error, never as an
  unobserved stimulus.

### Changed

- **`nse-runner` fails a case that did not clean up.** A teardown error, or a
  resource of the run still recorded afterwards, prints `[TEARDOWN ERROR]` and
  exits 1, even when every verdict matched. Previously a cleanup that left
  resources behind was only logged. Timeouts, invalid rules and setup failures
  print `[TIMEOUT]`, `[RULES ERROR]` and `[SETUP ERROR]` instead of
  `[ORACLE ERROR]`. Output and exit codes are otherwise unchanged.
- `reduce_verdicts()` lives in `nse.core.verdicts`, so the engine and the CLI
  share one implementation; `nse.cli.runner.reduce_verdicts` still works.
- **Deleting a namespace stops every process still inside it**, whether
  started by NSE or left behind. This includes descendants that detached with
  `setsid`, which used to keep running in an unnamed namespace. It applies to
  normal teardown and to crash recovery. Processes are identified by namespace
  membership through a pidfd, never by a PID that may have been recycled.
  NSE's own namespace and PID 1's are refused outright.

- **`PCAPAsserter.start()` now returns only when capture is ready.** The kernel
  socket is filtering and bound when it returns, so a stimulus may be sent
  immediately; the `sleep()` that callers added after `start()` is no longer
  needed. The
  capture loop is NSE's own thread over Scapy's `L2ListenSocket` instead of
  `AsyncSniffer`, and `stop()` drains packets the kernel already queued instead
  of discarding them.
- **Capture failures are errors.** `start()` raises `CaptureStartError` instead of
  succeeding and failing later; `stop()` keeps returning `list[Packet]` but
  raises `CaptureError` when the instrument was unhealthy (start failure, backend
  crash such as a deleted interface, stop timeout). Kernel drops are logged and
  reported, not raised. Calling `start()` twice, or `stop()` before `start()`,
  raises `CaptureStateError` (previously a silent no-op returning `[]`). Scapy is
  now imported at `start()`, not in the constructor.

### Maintenance

- **The 2.1.2 API is a tested contract.** `scripts/api_surface.py` reads the
  public surface from source (modules, names, methods, attributes, parameter
  order, kinds and defaults, sync or async, return annotations), and
  `tests/test_api_compat.py` compares the checkout with the record of the v2.1.2
  tag in `tests/data/api-2.1.2.json`. The checker's own tests prove it reports
  each kind of break. `_get_mac_address`, private but used by
  TransparentTorProxy, is covered as if public.
- **CI installs the packages it would publish.** The `smoke-pypi` job used an
  editable install, which imports from the checkout. It now builds the wheel and
  sdist and installs each in a clean virtualenv outside the checkout, on Python
  3.10 to 3.13 (`scripts/check-dist.sh`, also `make dist-check` and part of
  `make release-dry`). It runs the core alone, then the `[cli]` extra, with
  `pip check`, the 2.1.2 API check against the installed files, the runner's
  message when PyYAML is missing, and every example suite. ruff and mypy now
  check `scripts/`.
- Python 3.13, already tested in CI, is declared in the classifiers.
- The privileged CI jobs run in a dedicated, empty network namespace
  (`scripts/isolated-netns.sh`). Some runner hosts route part of NSE's default
  subnet, which NSE correctly refuses to shadow.
- `make test-blind` (`scripts/check-blind.sh`) first requires a passing positive
  control and then requires the blind failure to come from the unobserved
  canaries. A host where the suite could not run at all used to pass it.

- Update Pydantic and pydantic-core together to 2.14.2 and 2.50.2 using the
  resolver. Their separate dependency PRs each left an incompatible pair of
  runtime pins, which the existing installs from `pyproject.toml` did not test.
- Group Pydantic/core updates in Dependabot and add CI coverage for installation
  of `requirements.txt` on Python 3.10/3.11 and the minimum Scapy 2.5.0 on Python
  3.10, including `pip check` and the coverage gate.

### Documentation

- **Upgrading to 2.2** lists the behaviour changes a 2.1.x caller may notice,
  the code that can be removed, and what can now be asserted. It includes a
  measured comparison of the capture readiness race in 2.1.2 and 2.2.0.
- **Benchmarks** records the measurements behind the 2.2.0 qualification: the
  capture readiness race, TransparentTorProxy's suite on both versions, and the
  concurrency checks with the host state compared before and after each run.
- The generic "Zero Host Mutation" claim is replaced by the exact guarantee.
  The ruleset under test, forwarding and DAD settings stay inside the
  namespaces, and the host firewall is never touched. A run does create, and
  journal, temporary namespaces, the host end of its veth links with their
  addresses, gateway routes, and ownership records under `/run/nse`.
- The oracle explanation now presents the canary, parser and liveness checks as
  the guarantee they are. It also states that capture readiness does not prove
  a stimulus crossed the captured interface.
- The namespace lifecycle documents the process boundary.
- A new "Worked Examples" page shows the expected output of each example.
- The README names NSE's qualifying consumers, TransparentTorProxy and the NAT
  gateway example, and lists the decisions that stay with consumers.

- **The README no longer opens with a screenshot of the web interface this
  project removed.** `assets/preview.png` showed the FastAPI/Svelte GUI archived
  in 2.1.0, directly above the paragraph explaining that it was gone. Replaced
  with an SVG mark that renders on both GitHub themes, and referenced by its raw
  URL so it also renders on PyPI, where a repository-relative path does not
  resolve.
- **`PCAPAsserter` is documented.** It is half of `nse.__all__` and appeared in
  no README section, no API reference page and no how-to. Added to all three,
  together with the rule its consumers actually need: an empty capture proves
  nothing without a positive control, and `DEFAULT_FILTER` is compiled into BPF,
  so what it excludes cannot be recovered downstream.
- **Corrected commands that do not exist.** The coverage ratchet is `make
  coverage`, not `make test-cov`; `make ci-local` builds no frontend and is not
  "the complete 5-job CI pipeline" — it omits `integration`, `blindness` and
  `smoke-pypi`, all of which need root or the network.
- The documentation homepage announced v2.0.0. The version was removed rather
  than bumped: nothing kept it honest.

---

## [2.1.2] - 2026-09-22

The default capture filter no longer hides routable ICMPv6 from consumers.

This is cut now rather than batched, because the fix is unreachable until it is
published. TransparentTorProxy has a leak-containment test for routable ICMPv6
that cannot pass on 2.1.1 — the packet is discarded in the kernel before any
consumer can classify it — and its investigation lost two CI cycles to the
assumption that the merged fix was the installed one. A fix that exists only on
`main` does not protect anyone.

### Added

- **`PCAPAsserter(..., replace_default_filter=True)`** — a caller-supplied
  `filter` was previously ANDed with the default, which made the default a
  ceiling rather than a starting point: no consumer could widen the capture back
  out to see a packet the default excluded. Combining stays the default
  behaviour; replacing is the escape hatch.

- **Behavioural tests for the default filter.** The existing tests asserted on
  the filter *string*; the defect was not a typo in the string but the string
  meaning more than its author intended. The new tests compile it with libpcap
  and replay packets through it from a pcap file — no interface and no
  privileges — asserting that a global-destination ICMPv6 echo now survives,
  that ND and ARP still do not, and that ordinary WAN traffic does. Both ends of
  the suppressed type range are pinned: widening it in either direction
  re-creates the original defect, and a first version of these tests did not
  catch that.

- **`publish-docs.yml`** — the documentation site is rebuilt and pushed to
  `onyks-os.github.io/nse` when a release is published, from the released tag.
  Publication was a manual step: 2.1.1 shipped on 2026-09-09 and the published
  site still did not mention it two days later.

### Fixed

- **`PCAPAsserter`'s default filter no longer discards routable ICMPv6.** It read
  `not arp and not icmp6`, which is broader than the noise its own comment
  described. ICMPv6 is not only Neighbour Discovery: the expression also excluded
  echo request/reply to a **globally routable** address — cleartext traffic
  leaving the host, which is exactly what a class documented as "asserting that
  no traffic leaks outside sandbox boundaries" exists to catch. Because the
  filter is compiled into BPF and evaluated in the kernel, those packets never
  reached userspace, so no consumer could see them or compensate downstream.
  Narrowed to ICMPv6 types 133-137, the Router Solicitation / Advertisement /
  Neighbour Solicitation / Advertisement / Redirect set the comment always
  claimed — all link-local, all discarded by the first router, none able to
  reach a remote observer. See
  [#14](https://github.com/onyks-os/NetworkSandboxEngine/issues/14).

- **The `S607` migration guard was linting a package that does not exist here.**
  It ran `ruff check --select S607 ttp/` — TTP's package name, copied across with
  the test. `ruff check` on a missing path warns on stderr, then prints "All
  checks passed!" and exits 0, so the guard reported success while reading no
  source at all. It now lints `nse/`, asserts the directory exists, and treats a
  lint that could not open its target as a failure.
- **The guard has a positive control.** "All checks passed!" is worth nothing
  unless the rule would have said otherwise, so a file with a bare-binary call is
  fed to ruff and `S607` must be reported.
- **CI could not find ruff.** The test invoked a bare `ruff`, which resolves
  through `$PATH`; `make setup` installs it into the virtualenv, which CI does not
  put on `$PATH`. A missing bare name raises `FileNotFoundError` rather than
  returning 127, so the "ruff is not available" skip never ran and all four unit
  jobs errored. Ruff is now invoked as `sys.executable -m ruff`.

---

## [2.1.1] - 2026-09-10

Security: the engine no longer resolves a root-executed binary through `$PATH`.

### Security

- **PATH hijacking closed.** NSE creates network namespaces and reads kernel
  trace events, so it runs as root - and it invoked `ip`, `nft` and `nsenter`
  **by bare name**, leaving the kernel to resolve them through `$PATH`. Anyone
  able to influence the environment of the `sudo` invocation could place their
  own `ip` earlier in the search order and have it executed with full
  privileges.

  This is the same defect that TTP closed in its 0.4.8 cycle, and it mattered
  more here than it looks: NSE is the instrument TTP's zero-leak claim rests on.
  A verification engine with a privilege-escalation path is a strange thing to
  trust about a firewall.

  New `nse/core/paths.py` resolves every binary against a fixed list of
  root-owned system directories, never `$PATH`, and refuses one that is group-
  or world-writable, or that sits in a writable directory - write access there
  is enough to replace the file by rename. `BinaryNotFoundError` is a
  `FileNotFoundError`, so callers that already handled a missing tool keep
  working unchanged.

  66 call sites migrated. The deliverable is
  `test_a_hostile_nft_on_path_is_not_executed` and
  `test_the_engine_really_invokes_the_trusted_binary`, which plant a hostile
  binary first on `$PATH` and assert the argv handed to `subprocess` still names
  the trusted absolute path - the second catches a call site the migration
  missed, which asserting on `resolve()` alone would not.

### Changed

- Test coverage 98.45% → 98.09% across a larger surface: 239 → 259 tests.

---

## [2.1.0] - 2026-09-08

Trustworthy oracle, archived web interface, and a test suite that can fail.

The theme of this release is one defect repeated in several places: **a check
that could not fail**. The CLI runner reported success when it observed nothing,
the readiness probe signalled readiness before the kernel was listening, an
unparsed trace line vanished at DEBUG level, and the parser's only test
disappeared if its fixture directory were emptied. Each of those made a green
result compatible with a blind instrument.

### ⚠️ Breaking Changes

- **Archived the web interface (`gui/`)**: the FastAPI + Svelte application, its
  Uvicorn server, the `gui` extra and the `nse.service` unit are removed. Since
  2.0.0 that server ran in-process **as root**, which is a large attack surface
  for a testing tool with no external users. The code remains in git history at
  tag `v2.0.0`. NSE is now a library and a CLI: no socket, no port, no RPC.
- **Stricter suite-file schema**: unknown keys in a test case or a packet entry
  are now errors instead of being silently defaulted. A misspelled
  `expect_verdict` used to become an implicit expectation of `ACCEPT`. The
  README's own YAML example was invalid under the real schema and has been
  corrected.
- **`REJECT` normalises to `DROP` in expectations**: the trace stream cannot
  distinguish them, so an expectation of `REJECT` is compared as `DROP` rather
  than never matching.
- **`ScapyInjector.inject()` takes `host_netns`**: the namespace owning the
  sending interface is now passed by the caller. It used to be derived from the
  interface name as `nse_router_<suffix>`, a namespace nothing has ever created,
  so gateway-topology MAC lookups could only fail.
- **`match` events report upper-cased verdicts**, consistent with `verdict`
  events. The same verdict previously had two spellings depending on the line it
  came from.

### Fixed

- **The runner could report PASSED having observed nothing** (`nse/cli/runner.py`).
  The count-mismatch branch printed `[FAIL] Oracle Error` without setting the
  failure flag, and `zip(..., strict=False)` truncated the comparison in both
  directions. A run with zero observed verdicts printed `=> SUCCESS` and exited
  0 — including in this project's own CI, where the YAML runner is the
  end-to-end gate.
- **The readiness probe proved nothing** (`nse/core/trace_harvester.py`).
  `wait_ready()` fired when the read loop was scheduled, not when `nft monitor
  trace` had subscribed to the kernel, so packets injected in that window were
  lost. It is retained for diagnostics and documented as insufficient.
- **The trace deadline could expire mid-run** (`nse/core/pipeline.py`). A fixed
  5-second budget, set when the loop started, truncated the verdict stream at
  roughly 33 packets. The deadline is now extended after every injection, and
  the read loop polls it so an extension actually takes effect.
- **A crashed read loop was indistinguishable from a clean one**. Both pushed the
  same `None` sentinel. The harvester now records a terminal state.
- **Unparsed trace lines vanished silently**. They are counted; any line that
  looks like trace output but matches no pattern is an oracle error.
- **The parser could not read valid nftables identifiers**. Table and chain names
  were matched with `\w+`, so any name containing `-`, `.` or `/`, or any quoted
  name, failed to parse — silently. Quoted names containing spaces now parse too.
- **Deleting the parser's fixtures deleted its tests**. `parametrize` over an
  empty glob collects zero tests and reports success.
- **`PacketSpec` validation errors escaped as tracebacks** instead of being
  reported as a failed test case.

### Added

- **Canary probes as a permanent positive control** (`nse/core/pipeline.py`). A
  probe packet is injected before the test packets and again after them; the run
  is reported only if both were observed in the kernel trace. Canaries are
  excluded from results by trace id. This is what makes a "no leak" result
  evidence rather than a hope.
- **`HarvestState` and `TraceHarvester.health_errors()`**: the read loop's
  outcome (clean stop, unexpected EOF, timeout, crash) is explicit, and the
  pipeline turns anything unhealthy into an `error` event the runner fails on.
- **`NSE_FORCE_BLIND` and `make test-blind`**: a test hook that makes the parser
  understand nothing, plus a CI job asserting the suite then *fails*. This is the
  meta-test that guards the guard.
- **Oracle errors are reported separately from firewall failures** in the runner
  summary: a broken measurement and a broken ruleset are different problems.
- **Golden corpus of six `nft monitor trace` fixtures** covering IPv6, gateway
  forwarding and NAT, NSE's own scaffolding table, hyphenated and quoted
  identifiers, and the quoted/unquoted `iif` variants — plus
  `scripts/capture_trace_fixture.sh` for adding captures from new kernels.
- **`test_parser_understands_every_line_of_a_real_trace`**: asserts on the actual
  kernel under test that zero trace lines were unparsed. CI runs it on
  `ubuntu-22.04` and `ubuntu-24.04`, so a format change breaks a build instead of
  blinding the oracle.
- **Coverage ratchet**: `make test-cov` enforces a floor (currently 98%), with
  `pytest-cov` a declared dev dependency rather than something you happen to have.
- **Runner logic is unit-testable**: `reduce_verdicts`, `build_case`,
  `evaluate_case` and `load_suite` are pure functions. `nse/cli/runner.py` went
  from **0%** to 98% coverage.
- **`nse.core.mock_listener.main()`**: the CLI entry point is a function, so it
  can be tested.
- **Container runner image**: the Dockerfile now builds a CLI image for running a
  suite against a pinned nftables version.

### Changed

- **Test coverage: 51% → 98%** across `nse/`, 21 tests → 232. The three modules
  that carry correctness were the three least covered: `runner.py` 0% → 98%,
  `pipeline.py` 30% → 99%, `trace_harvester.py` 35% → 98%.
- **Import contracts rewritten** now that `gui/` is gone: `nse.core` and
  `nse.models` may not import `nse.cli`, and `nse.models` may not import the
  engine.
- **`--strict-markers`**: a typo in a pytest marker silently deselected the test
  it was meant to tag.
- CI gained coverage, multi-image integration and blindness jobs, and lost the
  Node 24 frontend job.

---

## [2.0.0] - 2026-08-13

Single-Process In-Process Architecture, Pydantic Hard Dependency, Deterministic Verdict Oracle, and Strict Static Typing.

### ⚠️ Breaking Changes

- **Elimination of `rootd` Daemon**: Removed socket daemon `gui/rootd.py`, `gui/api/rootd_client.py`, and `gui/api/deps.py`. FastAPI web application and `NetnsController` now run directly in-process with root privileges.
- **Mandatory Pydantic Dependency**: `pydantic` promoted to a mandatory core dependency of `nse/`; eliminated all stdlib fallback dataclasses and stubs.
- **Consolidated Model Hierarchy**: Deleted `nse/models/base.py`. `TopologyType` and `PacketSpec` now collapse to a single source of truth in `nse.models.test_request`.
- **Target Orchestrator Signature**: Rewrote `run_test_pipeline` signature to target standard request-driven API returning `list[TraceEvent]`.
- **Purged Controller State**: Removed `enqueue_test`, `release_test`, `has_test`, `get_status`, `get_event_queue`, and `_tests` tracking methods from `NetnsController`.

### Added

- **Trace Harvester Readiness Probe**: Added `wait_ready()` in `TraceHarvester` using `asyncio.Event` readiness signal, eliminating hardcoded warm-up delay sleeps.
- **Uniform Naming & Startup Sweep**: Created `nse.core.naming` helper with `derive_names()` and automated orphan netns/veth startup sweep in `NetnsController`.
- **Teardown Retry & Subprocess Timeouts**: Implemented retry backoff in `destroy_netns` and enforced `timeout=` parameters across all `subprocess.run` calls.
- **Strict Static Typing & Import Boundaries**: Enforced `mypy --strict` across all 22 source files and configured `import-linter` contract preventing `nse/` from importing `gui/`.
- **MkDocs Web Documentation**: Created comprehensive web documentation site powered by MkDocs Material and `mkdocstrings`.
- **Local CI Automation**: Added `make ci-local` and `make docs` Makefile targets.

---

## [1.1.1] - 2026-08-05

Kernel tracing initialization fix, background noise filtering in YAML test runner, and Makefile dynamic binary resolution.

### Added

- **Automatic Kernel Tracing Prepending**: Automatically inject a high-priority `table inet nse_trace` prerouting chain (`meta nftrace set 1`) in `RuleEngine.load()` to guarantee `nft monitor trace` captures trace events for all test packets.

### Fixed

- **YAML Runner Trace Noise Filtering**: Filtered out background setup noise (IPv6 NDP, DAD, MLD, and socket init packets) in `nse.cli.runner` to accurately match verdicts (`ACCEPT`/`DROP`) to injected test packets.
- **`nft monitor trace` Regex Parser**: Updated `_PACKET_RE` in `gui/daemon/trace_harvester.py` to handle both quoted and unquoted `iif` strings in trace lines across different Linux kernel and `nftables` versions.
- **Dynamic Executable Resolution in Makefile**: Updated `Makefile` to dynamically detect `PYTHON`, `RUFF`, `TWINE`, and `PYTEST` in `.venv` with automatic fallbacks to `PATH` system binaries.
- **Ruff Code Quality Compliance**: Resolved all Ruff static analysis errors (`ASYNC221`, `I001`, `BLE001`, `UP037`, `TRY401`, `PIE790`) across `nse/`, `gui/`, and `tests/`.

---

## [1.1.0] - 2026-06-19

Introducing native container environments support and a Zero-Trust Privilege Separation architecture for the web server.

### Added

- **Native Container Support (`nsenter` fallback)**: Added robust container detection in `nse/core/utils.py` (checking `container` env, `/.dockerenv`, `/proc/1/environ`, and `cgroup` format). Dynamic fallback from `ip netns exec` to `nsenter --net` namespace switching prevents remount errors in container runtimes.
- **Zero-Trust Privilege Separation**:
  - `nse-rootd` UNIX domain socket server running as root and managing network namespaces, Scapy injection, and trace harvesting. Secure `/var/run/nse-core.sock` socket is automatically chowned to `SUDO_UID`/`SUDO_GID` when run via `sudo`.
  - `RootdClient` client proxy allowing unprivileged web server instances (`nse-web` / `gui/server.py`) to delegate low-level sandbox execution without running as root.
- **Dedicated RPC Unit Tests**: Added asynchronous mocking test `test_rootd_rpc_communication` to verify JSON-RPC protocol between client and daemon.

### Changed

- **Makefile and dev-setup**: Restructured commands (`make run-rootd`, `make run-web`, `make backend`, and `make dev`) and updated startup instructions to reflect the decoupled daemon architecture.

---

## [1.0.0] - 2026-06-18

First stable release of the Network Sandbox Engine.

### Summary

NSE v1.0.0 is published as a headless Python library (`network-sandbox-engine` on PyPI) with an optional GUI layer that lives in-repository. The core engine depends only on `scapy`; CLI tooling requires `pydantic` and `pyyaml` via the `[cli]` extra. The GUI daemon (FastAPI and Svelte) is excluded from the wheel by design and is run from a repository clone.

---

### Added

#### Core Headless Engine (`nse/`)

- `NetnsController`: async context manager for ephemeral Linux network namespace lifecycle (create, configure, teardown). Supports `simple` (host to sandbox) and `gateway` (host to router to server) topologies.
- `PCAPAsserter`: wraps Scapy `AsyncSniffer` to arm BPF-filtered captures on veth interfaces and assert captured packet counts in integration tests.
- `RuleEngine`: validates and loads `nftables` rulesets using `nft --check -f` and `nft -f`. Parses line-level error messages into structured `RuleValidationError` exceptions. Automatically arms kernel tracing via `meta nftrace set 1`.
- `ScapyInjector`: forges and injects IPv4/IPv6 TCP, UDP, ICMP, and ICMPv6 packets at Layer 2/3. Uses in-process `sendp()` for host-originating packets and `ip netns exec` subprocess for egress from inside a namespace.
- `run_test_pipeline()`: top-level orchestrator that chains validation, topology setup, mock listener spawning, rule loading, trace harvesting, sequential packet injection, conntrack polling, and namespace teardown.
- `parse_conntrack_line()`: parser for `/proc/net/nf_conntrack` entries. Extracts `proto`, `state`, `src`, `dst`, `sport`, and `dport` for both IPv4 and IPv6 flows.
- Stateful traffic and conntrack integration: `/proc/net/nf_conntrack` is polled after each packet injection and connection states (`SYN_SENT`, `ESTABLISHED`, `TIME_WAIT`) are streamed to consumers.
- Dual-stack IPv4/IPv6: all veth links are configured with both address families. DAD is disabled globally inside namespaces (`accept_dad=0`) for instant address availability.

#### Data Models (`nse/models/`)

- `PacketSpec`: Pydantic model (lazy import) defining protocol, IPs, ports, TCP flags, and packet size. Validates IPv4/IPv6 addresses and allowed flag values.
- `TestRequest`: Pydantic model with `rules`, `packets: list[PacketSpec]`, and `topology: TopologyType`.
- `TopologyType`: string enum with values `simple` and `gateway`.
- `TraceEvent`: Pydantic model for kernel trace output events of type `hook`, `match`, or `verdict`.
- `base.py`: pure stdlib dataclasses for use without Pydantic.

#### CLI Runner (`nse/cli/runner.py`)

- `nse-runner --file <yaml>` CLI entrypoint registered in `pyproject.toml`.
- Reads YAML test suites, invokes `run_test_pipeline()`, evaluates expected verdicts, and prints formatted results.
- Silent drops (no matching `TraceEvent`) are treated as `DROP`.
- Exits with `0` on full pass, `1` on any failure.
- Displays a clear install hint if `pydantic` or `pyyaml` is missing.

#### GUI Daemon (`gui/` - not on PyPI)

- `TraceHarvester`: async subprocess spawning `nft monitor trace` inside the evaluation namespace. Parsed events are pushed into an `asyncio.Queue`.
- `MockListener`: background TCP/UDP echo daemon spawner using `ip netns exec`. Enables complete TCP handshakes and valid conntrack state generation.
- FastAPI REST API: `POST /api/test` and `GET /api/status/{test_id}`.
- WebSocket streaming: `WS /ws/{test_id}` streams `TraceEvent` JSON messages to the frontend.

#### Frontend (`gui/gui_svelte/` - not on PyPI)

- Rule editor for `nftables` ruleset authoring.
- Multi-packet sequence crafter with topology selector.
- Real-time animated pipeline visualizer: hook, rule match, and verdict events.
- Conntrack table: live tabular view of active connection states.
- Offline documentation view at `#/docs`.

#### Packaging and Release

- `pyproject.toml` at repository root. Build backend: `setuptools`. Targets only `nse/` via `packages.find.include`. Hard dependency: `scapy>=2.5.0`. Optional extra `[cli]`: `pydantic>=2.0.0` and `pyyaml>=6.0`.
- `make release`: runs `lint + test`, builds the wheel and source distribution, copies deployment assets, generates `SHA256SUMS`, and signs it with GPG. The signing key is auto-detected from the keyring and can be overridden with `GPG_KEY_ID=<id>`.
- `Dockerfile`: multi-stage production image for containerized daemon deployment.
- `scripts/nse.service`: systemd unit template binding to `/run/nse.sock` in production.
- `tests/test_netns.py`: unified test suite with 20 unit tests and 2 root-only integration tests.
- `conftest.py`: root `sys.path` injection allowing pytest to discover both `nse/` and `gui/` packages.

#### Makefile Targets

| Target                  | Description                          |
| ----------------------- | ------------------------------------ |
| `make setup`            | Bootstrap venv and run npm install   |
| `make test`             | Run unit tests                       |
| `make integration-test` | Run root-level integration tests     |
| `make lint`             | Ruff static analysis                 |
| `make format`           | Ruff auto-format                     |
| `make verify`           | Run `lint` and `test`                |
| `make release`          | Build and sign all release artifacts |
| `make publish-test`     | Upload to TestPyPI via Twine         |
| `make publish`          | Upload to PyPI via Twine             |

---

### Changed

- Repository restructured from a monolithic `backend/nse/` layout to a root-level separation:
  - `nse/` is the headless PyPI package (replaces `backend/nse/`).
  - `gui/` is the GUI daemon (replaces GUI modules formerly in `backend/nse/` and the `frontend/` directory).
  - `tests/` is the unified test suite (replaces `backend/tests/`).
- `TraceHarvester` and `MockListener` moved to `gui/daemon/`. These components are part of the GUI layer and are not included in the wheel.
- Pydantic imports in `nse/` models are wrapped in `try/except ImportError` to allow the core to be imported with only `scapy` installed.
- `TestRequest.packet` changed to `TestRequest.packets: list[PacketSpec]` to support packet sequences. This is a breaking API change.
- `pyproject.toml` migrated from `backend/pyproject.toml` to the repository root. Build backend changed from Poetry to setuptools.
- `Makefile` updated with root-level paths.

---

### Fixed

- GPG signing in `make release` failed with "no default secret key" in non-interactive shells. Fixed by adding `--local-user $(GPG_KEY_ID)` with automatic key detection from the keyring.
- Interface name assertion in `test_create_namespace_lifecycle_mocked` was off by one character for 8-character namespace names.
- Svelte compilation crash caused by raw curly braces in code blocks. Fixed by escaping them as `&#123;` and `&#125;`.

---

[1.1.1]: https://github.com/onyks-os/NetworkSandboxEngine/releases/tag/v1.1.1
[1.1.0]: https://github.com/onyks-os/NetworkSandboxEngine/releases/tag/v1.1.0
[1.0.0]: https://github.com/onyks-os/NetworkSandboxEngine/releases/tag/v1.0.0
