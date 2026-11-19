# scripts/

Operational shell scripts. Everything here is linted by `make lint-shell` (ShellCheck) and must:

- start with `#!/usr/bin/env bash` and `set -euo pipefail`;
- resolve its own directory rather than assuming the caller's working directory;
- be idempotent, or refuse to run twice with a clear message;
- print what it is about to change to the system *before* changing it.

| Script | Purpose |
| :----- | :------ |
| `verify.sh` | Full local gate; invoked by `make verify` in CI and by hand. |
| `check-blind.sh` | Blindness meta-test behind `make test-blind`: positive control, then a blind run that must fail on its canaries. |
| `isolated-netns.sh` | Runs a command in a new, empty network namespace; CI uses it for the privileged jobs. |
<!-- TODO(template): add install.sh / uninstall.sh here if this project touches the host system. -->
