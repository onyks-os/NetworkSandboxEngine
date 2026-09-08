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
| `--help` | Flag | Display CLI help message |

### Exit codes

| Code | Meaning |
| :--- | :--- |
| `0` | Every packet's observed verdict matched its expectation. |
| `1` | A verdict was wrong, the suite file was malformed, **or** the engine could not observe a verdict it needed. |

The summary distinguishes the last case:

```text
Test Suite Summary: 1 passed, 1 failed.
1 of the failures are ORACLE errors: the engine could not observe what it
needed to. Treat these as a broken measurement, not as a firewall defect.
```

An oracle error means the instrument failed, not the ruleset. Investigate the
environment — is `nft monitor trace` available inside the namespace, does this
kernel emit a trace format the parser understands — before touching your rules.

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
