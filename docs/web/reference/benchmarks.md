# Benchmarks

Measurements taken to qualify 2.2.0 against 2.1.2. They answer three
questions: does removing the fixed wait after `PCAPAsserter.start()` lose
captures, does a real consumer's suite behave the same on both versions, and do
the concurrency and crash-recovery paths leave anything behind on the host.

All numbers come from one machine. They show the relative behaviour of the two
versions under the same conditions; they are not absolute performance figures
for other hosts.

---

## Environment

| Component | Version |
| :--- | :--- |
| Host kernel | 7.3.4-300.fc45.x86_64 |
| Container | Debian 12, privileged podman, `--network pasta` |
| nftables | 1.0.6 |
| iproute2 | 6.1.0 |
| Python | 3.12.16 (consumer suite), 3.11.2 (capture race, concurrency) |
| Scapy | 2.8.0 |
| NSE | 2.1.2 from PyPI, 2.2.0 from the release branch |

Every run started from a clean container. Only NSE was swapped between rows;
the test code, Scapy and the rest of the environment were identical.

---

## Capture readiness race

### What is measured

The cycle is the one TransparentTorProxy uses in its zero-leak suite: start a
capture, send a stimulus from a new process inside the namespace, let it settle
for 50 ms, stop the capture. A *miss* is a cycle in which the stimulus left the
namespace but is absent from the capture.

```python
asserter = PCAPAsserter(iface=ns.ext_iface)
await asserter.start()
if pre_sleep:
    await asyncio.sleep(pre_sleep)          # 0.2 s in TTP's suite
subprocess.run(["nsenter", f"--net=/var/run/netns/{ns.name}",
                "python3", "-c", send_udp_datagram], check=True)
await asyncio.sleep(0.05)
packets = await asserter.stop()
missed = not any(UDP in p and p[UDP].dport == 9999 for p in packets)
```

The namespace (`10.9.0.1/24` on the host side, `10.9.0.2/24` inside) is created
once with `NetnsController(use_nsenter=True).create_namespace()`. One uncaptured
datagram is sent first so that neighbour resolution is not part of any cycle.
Each row is 300 consecutive cycles in one process. The *busy* rows run one
`while True: pass` process per CPU for the whole measurement.

### Results

| NSE | Load | Sleep after `start()` | Misses / 300 | `start()` median | First `start()` | `start()` p95 / max (rest) | Cycle median |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 2.1.2 | idle | 0.2 s | 0 | 0.4 ms | 9.5 ms | 0.9 / 7.7 ms | 280.9 ms |
| 2.1.2 | idle | none | **13 (4.3%)** | 0.4 ms | 0.4 ms | 0.9 / 1.6 ms | 79.6 ms |
| 2.1.2 | busy | 0.2 s | 0 | 1.7 ms | 6.6 ms | 3.0 / 3.9 ms | 299.9 ms |
| 2.1.2 | busy | none | **1 (0.3%)** | 1.8 ms | 7.5 ms | 3.0 / 4.5 ms | 102.0 ms |
| 2.2.0 | idle | none | **0** | 11.6 ms | 269.5 ms | 16.9 / 19.5 ms | 92.0 ms |
| 2.2.0 | busy | none | **0** | 10.8 ms | 742.0 ms | 13.9 / 17.3 ms | 110.1 ms |

"First `start()`" is the first cycle of the process; "p95 / max (rest)" covers
the remaining 299.

### Reading the results

- **2.1.2's `start()` returns before the capture is listening.** It takes under
  2 ms because it only schedules the sniffer thread. Without a wait after it,
  about one stimulus in 25 is sent before the socket exists. Under load the
  miss rate drops, because the stimulus process itself starts more slowly; it
  does not reach zero.
- **2.2.0's `start()` returns once the kernel socket is bound with its filter.**
  That wait has a median of 11 ms and stayed under 20 ms in every cycle after
  the first. No stimulus was missed, idle or busy.
- **The first `start()` of a process imports Scapy.** 2.1.x paid that cost in
  the `PCAPAsserter` constructor; 2.2.0 pays it in the first `start()`
  (270 ms idle, 740 ms busy here). It is paid once per process.
- **Net effect on a capture cycle:** with the 0.2 s sleep that 2.1.2 needs,
  a cycle takes 281 ms idle and 300 ms busy; 2.2.0 without the sleep takes
  92 ms and 110 ms, about three times shorter, with no misses.

---

## Consumer qualification: TransparentTorProxy

### What is measured

TransparentTorProxy's zero-leak suite (`tests/test_nse_rules.py -m nse`,
TTP 0.4.11, commit `2c0e39e`) was installed exactly as TTP's CI installs it
(`scripts/install_locked.sh`, which pins NSE 2.1.2 and Scapy 2.8.0) and run with
`TTP_REQUIRE_NSE=1`, so that a missing NSE fails instead of skipping. Three
variants of the suite were run, three times each:

- **unchanged**: TTP as released, with its `sleep(0.2)` after every
  `PCAPAsserter.start()`;
- **without the sleep**: the same suite with that sleep removed;
- **adapted**: without the sleep and asserting `stop_report().window_complete`
  (2.2.0 only, since the API is new).

### Results

| TTP suite | NSE | Run 1 | Run 2 | Run 3 |
| :--- | :--- | :--- | :--- | :--- |
| unchanged | 2.1.2 | 47 passed, 1 skipped, 147.2 s | 47 passed, 1 skipped, 146.7 s | 47 passed, 1 skipped, 146.8 s |
| unchanged | 2.2.0 | 47 passed, 1 skipped, 149.1 s | 47 passed, 1 skipped, 147.5 s | 47 passed, 1 skipped, 149.1 s |
| without the sleep | 2.1.2 | **4 failed**, 43 passed, 1 skipped, 123.6 s | **4 failed**, 43 passed, 1 skipped, 127.3 s | 47 passed, 1 skipped, 137.9 s |
| without the sleep | 2.2.0 | 47 passed, 1 skipped, 140.8 s | 47 passed, 1 skipped, 141.0 s | 47 passed, 1 skipped, 140.9 s |
| adapted | 2.2.0 | 47 passed, 1 skipped, 141.0 s | 47 passed, 1 skipped, 140.8 s | 47 passed, 1 skipped, 140.5 s |

The skipped test requires nftables 1.1.6; it is skipped by TTP's own policy and
identically on both versions.

### Reading the results

- **TTP needs no change to run on 2.2.0.** The unchanged suite passes on both
  versions, within 2 s of each other.
- **On 2.1.2 the sleep is load-bearing.** Without it the suite failed in 2 of 3
  runs, each time on 4 of TTP's own positive controls detecting a capture that
  missed its stimulus: the race measured above.
- **On 2.2.0 the sleep can be removed.** All runs pass, and the suite is about
  7 s faster than the unchanged one. Asserting `window_complete` costs nothing
  measurable.
- No network namespace was left on the host after any run.

---

## Concurrency and host residue

### What is measured

The integration tests for concurrent topologies, resource lifecycle and crash
recovery, and process supervision (`tests/test_topology_concurrency.py`,
`tests/test_resource_lifecycle.py`, `tests/test_process_integration.py`,
`-m integration`) were run five times in a row on 2.2.0. Before and after each
repetition the host's network namespaces, links, and IPv4 and IPv6 routes (all
tables) were recorded and compared. The ownership records under `/run/nse`
were listed separately, since their lock files persist by design.

### Results

| Repetition | Result | Duration | Host state before vs after |
| :--- | :--- | :--- | :--- |
| 1 | 24 passed, 1 skipped | 56.0 s | identical (see note) |
| 2 | 24 passed, 1 skipped | 54.4 s | identical |
| 3 | 24 passed, 1 skipped | 55.5 s | identical |
| 4 | 24 passed, 1 skipped | 53.5 s | identical |
| 5 | 24 passed, 1 skipped | 55.4 s | identical |

Note: the raw comparison for the first repetition differed only because
`ip -j netns list` prints nothing when `/var/run/netns` does not exist yet and
`[]` once it does. No namespace, link or route was left behind.

---

## Reproducing

The measurements need root (or a privileged container) and a kernel with
network namespaces and nftables.

1. Build a privileged container with nftables, iproute2 and Python, and mount
   the NSE checkout read-only.
2. For the capture race, write the cycle above into a script that creates the
   namespace, runs it N times with and without a pre-sleep, and counts misses.
   Run it once with `pip install network-sandbox-engine==2.1.2` and once with
   the 2.2.0 checkout installed. For the busy rows, start one busy-loop process
   per CPU before the run and stop them after.
3. For the consumer suite, install TransparentTorProxy with its
   `scripts/install_locked.sh <python> ci`, then
   `pip install network-sandbox-engine==<version>` and run
   `TTP_REQUIRE_NSE=1 pytest tests/test_nse_rules.py -m nse`.
4. For the concurrency checks, run the three integration test files above with
   `-m integration` and compare `ip -j netns list`, `ip -j link show` and
   `ip -j route show table all` (IPv4 and IPv6) before and after.
5. After every run, `ip netns list` must be empty.
