# How-To: CI/CD Pipeline Setup

Integrate NSE into GitHub Actions or GitLab CI to automatically test firewall rulesets on every commit.

---

## GitHub Actions Workflow

Create `.github/workflows/ci.yml`:

```yaml
name: CI/CD Pipeline

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: make setup
      - run: make lint

  unit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: make setup
      - run: make test

  integration:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: |
          sudo apt-get update
          sudo apt-get install -y nftables iproute2 conntrack
      - run: make setup
      - run: |
          sudo .venv/bin/python -m pytest tests/ -v -m "integration"
          sudo .venv/bin/nse-runner --file tests/test_suite.yaml --report-dir nse-report
      # Keep the evidence, especially when the suite fails.
      - if: always()
        uses: actions/upload-artifact@v4
        with:
          name: nse-report
          path: nse-report/
```

The `nse-report` artifact holds `report.json` and `manifest.json` (see
[CLI reference](../reference/cli.md#the-json-report-report-dir)). From it you can
reconstruct each case:

- the request and its ruleset, with hashes;
- the NSE, Python, dependency, kernel and tool versions;
- every trace event, the canary checks, and the verified identity of the listeners;
- the outcome, and what teardown left behind.

!!! tip "Isolate the experiment from the runner's network"
    Some hosted runners route part of `10.0.0.0/24`, NSE's default subnet, to
    their own interface, and NSE refuses to build a topology that would shadow
    a host route. Run the privileged steps in an empty network namespace, as
    NSE's own CI does: `sudo unshare --net -- sh -c 'ip link set lo up; exec
    .venv/bin/nse-runner --file tests/test_suite.yaml --report-dir nse-report'`.
    Alternatively, give the cases an explicit `network:`.

---

## Local CI Verification (`make ci-local`)

Run the unprivileged part of the pipeline locally before pushing - lint,
type checks, import boundaries, unit tests, the docs build and the release
artifacts:

```bash
make ci-local
```

It is not the whole of CI. Three jobs are deliberately left out because they
need privileges or the network that a pre-push hook should not assume:
`integration` (root, real namespaces), `blindness` (`make test-blind`, which
proves the runner fails when the parser understands nothing) and `smoke-pypi`.
Run `sudo make integration-test` and `make test-blind` when you have touched
the harvester, the oracle or the CLI exit codes.
