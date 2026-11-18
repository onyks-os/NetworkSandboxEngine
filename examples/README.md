# Examples

Complete experiments, each with its input and expected output. They need root,
like NSE itself, and nothing but NSE. CI runs every one of them on a real kernel
and checks its exit code and artifacts (`tests/test_examples.py`).

| Example | Run | Shows |
| :--- | :--- | :--- |
| `workstation.yaml` | `sudo nse-runner --file examples/workstation.yaml` | Drop-by-default workstation policy, IPv4 and IPv6 |
| `ipv6.yaml` | `sudo nse-runner --file examples/ipv6.yaml` | A service published over IPv6 only |
| `coexistence.yaml` | `sudo nse-runner --file examples/coexistence.yaml` | A drop in one table wins over an accept in another |
| `gateway_nat.yaml` | `sudo nse-runner --file examples/gateway_nat.yaml` | Forwarding and masquerade in the gateway topology |
| `real_application.py` | `sudo python3 examples/real_application.py` | A real TCP/UDP server as `nobody`, a bounded file capture, positive controls |
| `broken_policy.py` | `sudo python3 examples/broken_policy.py` | A wrong ruleset with a sound observer: NSE catches it |
| `broken_observer.py` | `sudo python3 examples/broken_observer.py` | A blind oracle and a misplaced capture: both caught |

Every example exits 0 when it behaves as documented.

- The YAML suites print `[OK]` for every packet.
- `real_application.py` prints `All checks passed.`
- The two `broken_*` examples print `FAILED AS EXPECTED`. They exit 1 only if
  the planted fault goes unnoticed, or is caught for the wrong reason.

Add `--report-dir DIR` to a suite run, or `--out DIR` to a script, to keep the
JSON reports and capture files. The
[worked examples](https://onyks-os.github.io/nse/tutorials/examples/) page
shows the expected output of each.
