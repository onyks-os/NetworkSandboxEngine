# Reference: CLI Command Line Options

---

## `nse-runner` (Headless Test Suite Runner)

Execute YAML or JSON test suite files from the command line:

```bash
sudo nse-runner --file <path-to-suite>
```

Equivalent to `sudo -E .venv/bin/python -m nse.cli.runner --file <path>` when
running from a source checkout.

### Options

| Flag | Type | Description |
| :--- | :--- | :--- |
| `--file` | Path (required) | Path to the test suite YAML or JSON file |
| `--verbose`, `-v` | Flag | Enable debug logging from the engine |
| `--report-dir` | Directory | Write `report.json` and `manifest.json` there (see below), also when the run fails |
| `--timeout` | Seconds | Stop and fail any case that runs longer (default: no limit) |
| `--help` | Flag | Display CLI help message |

### Exit codes

| Code | Meaning |
| :--- | :--- |
| `0` | Every packet's observed verdict matched its expectation, and every case cleaned up. |
| `1` | A verdict was wrong, the suite file was malformed, the engine could not observe a verdict it needed, a case timed out, a case did not clean up completely, **or** a requested report could not be written. |
| `2` | Invalid command line (for example `--timeout 0`). |

A case whose verdicts are right but whose teardown failed, or left resources of
the run on the host, prints `[TEARDOWN ERROR]` lines and fails: an incomplete
cleanup is never a pass.

The summary distinguishes the last case:

```text
Test Suite Summary: 1 passed, 1 failed.
1 of the failures are ORACLE errors: the engine could not observe what it
needed to. Treat these as a broken measurement, not as a firewall defect.
```

An oracle error means the instrument failed, not the ruleset. Investigate the
environment — is `nft monitor trace` available inside the namespace, does this
kernel emit a trace format the parser understands — before touching your rules.

### The JSON report (`--report-dir`)

`report.json` records the suite file (path and SHA-256), the summary with the
exit code, and one entry per case:

- `status`: one of the values below.
- `expected` and `observed`: the verdicts.
- `teardown_complete`.
- `lines`: the text the case printed.
- `experiment`: the full experiment report of that run, from
  [`run_test_pipeline_report()`](../how-to/in-process-integration.md#the-experiment-report).

| `status` | Meaning |
| :--- | :--- |
| `passed` | Verdicts as expected, cleaned up. |
| `failed` | The ruleset gave other verdicts. |
| `instrument_error` | The oracle was blind, truncated or saw the wrong number of verdicts. |
| `rules_invalid` | `nft` rejected the ruleset. |
| `setup_error` | Topology, a mock listener or the trace monitor could not be prepared. |
| `timeout` | The case exceeded `--timeout` and was stopped. |
| `teardown_incomplete` | Verdicts as expected, but the run did not clean up. |
| `invalid_case` | The suite entry is malformed. |
| `crashed` | The engine raised instead of reporting. |

`manifest.json` lists `report.json` and every artifact the experiments
recorded, each with its SHA-256 and size. Both files are written atomically.
They are written even when the suite cannot be read (`error` explains why),
and when the run is interrupted; in that case every case that finished is on
record. They are world-readable (0644), so a CI upload step running as another
user than root can collect them.

The text output is unchanged, apart from the `[NSE] Report written to ...` line.

---

## Environment variables

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `NSE_TRACE_IDLE_TIMEOUT` | `5.0` | Seconds of trace inactivity tolerated before a timeout. Extended after every injection. |
| `NSE_INJECT_SETTLE` | `0.15` | Delay between packet injections, so trace events keep packet order. |
| `NSE_DRAIN_DELAY` | `0.3` | Time given to the kernel to flush final verdicts. |
| `NSE_CANARY_ATTEMPTS` | `25` | Canary re-injections before the oracle is declared blind. |
| `NSE_CANARY_INTERVAL` | `0.2` | Seconds to wait for each canary attempt. |
| `NSE_FORCE_BLIND` | unset | **Test hook.** Makes the parser understand nothing, to prove a blind run fails. Never set this in a real run. |
