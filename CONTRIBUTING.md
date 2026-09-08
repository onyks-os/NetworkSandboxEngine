# Contributing to NSE

First off, thank you for considering contributing to NSE!

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How to Report Bugs](#how-to-report-bugs)
- [How to Propose Features](#how-to-propose-features)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Architectural Principles](#architectural-principles)
- [Testing](#testing)
- [Documentation Requirements](#documentation-requirements)
- [Developer Certificate of Origin (DCO)](#developer-certificate-of-origin-dco)
- [Pull Request Process](#pull-request-process)
- [Security Best Practices for GitHub Actions](#security-best-practices-for-github-actions)

## Code of Conduct

By participating in this project you agree to abide by the
[Code of Conduct](CODE_OF_CONDUCT.md). Report unacceptable behavior to `129986281+onyks-os@users.noreply.github.com`.

## How to Report Bugs

- **Check existing issues** — someone may have reported it already.
- **Use the issue template** and provide as much detail as possible.
- **Include diagnostics**: version, operating system, exact command, and full output.

## How to Propose Features

- Open an issue using the *Feature request* template.
- Explain **why** the feature is needed and how it fits the project's goals, not only what it does.
- Wait for maintainer feedback before investing significant implementation time.

## Development Setup

1. **Clone the repository**:

   ```bash
   git clone https://github.com/onyks-os/NetworkSandboxEngine.git
   cd NetworkSandboxEngine
   ```

2. **Bootstrap the environment**:

   ```bash
   make setup
   ```

3. **Install the Git pre-commit hook** (runs lint + unit tests before each commit):

   ```bash
   make install-hooks
   ```

4. **Run the test suite**:

   ```bash
   make test
   ```

## Coding Standards

All contributions must satisfy the following before being submitted. These checks are enforced
automatically by the CI pipeline.

- **Linting & formatting**: the code must pass `make lint` with no errors or warnings.
- **Shell scripts**: everything under `scripts/` must pass `shellcheck`.
- **Type annotations**: new functions and methods must be fully annotated, consistent with the
  existing codebase.
- **No dead code**: remove unused imports, variables, and commented-out blocks before submitting.
- **Commit messages**: follow [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`, `ci:`).

> Pull requests that fail `make lint` will not be merged.

## Architectural Principles

These are not style preferences. Each one exists because its absence caused a
real defect in this repository.

1. **A test that asserts an absence must first demonstrate it can detect a
   presence.** `assert no_leak` is also true when the instrument is broken. Every
   negative assertion needs a paired positive control, and a failing control
   fails the test. This is the single rule the 2.1.0 release is built around.
1. **Never fix a bug without adding the check that would have caught it.** No
   exceptions. If the check is hard to write, that is information about the
   design, not a reason to skip it.
1. **A gate that cannot fail is not a gate.** Before trusting a check, break the
   thing it guards and confirm it goes red. `make test-blind` does exactly this
   for the oracle, in CI, on every push.
1. **Silence is the worst failure mode.** An unparsed line, a missed event or a
   dead subprocess must produce an error, not a debug log. If you catch an
   exception, record why the operation ended - a caller that cannot distinguish
   "nothing happened" from "I stopped looking" cannot be correct.

1. **Single Responsibility Principle (SRP)**: each module does one thing. Keep presentation logic out
   of core logic.
1. **No UI coupling**: core modules must not import the CLI/UI layer. Use callbacks or return raw data.
1. **Atomic operations**: state-changing operations must be all-or-nothing; never leave the system
   half-configured.
1. **Crash safety**: always consider what happens if the process is killed mid-operation.
1. **Test-driven development**: every new feature or bug fix ships with a corresponding test.

## Testing

- **Unit tests** must pass on every pull request. They are fully mocked and require no privileges.
- **Integration tests** run in a container or VM and verify real system behavior.

### When Tests Run

- **Pull requests**: every pull request triggers the CI pipeline — linting, static analysis, and the
  unit test matrix.
- **Push to `main`**: the same suite runs on any push to the default branch.
- **Locally**: run `make verify` before opening a pull request.

### Interpreting Results

- **Green**: ready for review.
- **Red**: blocks the merge. Review the logs, fix, and push an update.

### Test Policy for Major Changes

A change is **major** if it adds a significant feature, alters a security boundary, or changes the
crash-safety architecture. For major changes the contributor **must**:

- Add new unit tests covering the functionality.
- Update existing tests when the expected behavior changes.
- Run the integration suite manually and report the result in the pull request.

Pull requests are blocked from merging if tests do not sufficiently cover the change.

## Documentation Requirements

Every change must keep the documentation in sync with the code. The exact files to update for each
type of change are defined in **[`docs/documentation-policy.md`](docs/documentation-policy.md)**.
At minimum, every user-visible change requires a [`CHANGELOG.md`](CHANGELOG.md) entry.

## Developer Certificate of Origin (DCO)

By contributing to NSE you certify that you have the right to submit the contribution
under the project's MIT license, and you agree to the
[Developer Certificate of Origin v1.1](https://developercertificate.org/).

**Every commit must include a `Signed-off-by` line** with your real name and email:

```text
Signed-off-by: Jane Doe <jane@example.com>
```

The easiest way to add it is the `-s` flag:

```bash
git commit -s -m "your commit message"
```

For multiple commits in a branch, sign them off at once:

```bash
git rebase --signoff HEAD~<number-of-commits>
```

> Pull requests with unsigned commits will not be merged. The DCO check is enforced by CI.

<details>
<summary>Full DCO text</summary>

```text
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.

Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

</details>

## Releasing

A release is one tag: `git push origin vX.Y.Z` runs build, signing, GitHub
Release, TestPyPI, an installed smoke test, and PyPI, in that order. Rehearse it
with `make release-dry` first.

Full procedure, including the one-time Trusted Publishing setup:
[docs/RELEASING.md](docs/RELEASING.md).

## Pull Request Process

1. Create a branch from `main`.
2. Ensure `make verify` passes locally.
3. Update the documentation required by [`docs/documentation-policy.md`](docs/documentation-policy.md).
4. Fill in the pull request template checklist honestly.
5. Submit the pull request and wait for review. Expect a first response within **7 days**.

Thank you for your help!

---

## Security Best Practices for GitHub Actions

When contributing workflows or modifying CI pipelines, follow these guidelines to prevent injection
attacks.

### 1. Never interpolate untrusted data directly into shell commands

**Bad** (vulnerable to script injection):

```yaml
- run: echo "PR title: ${{ github.event.pull_request.title }}"
```

**Good** (use environment variables):

```yaml
- env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: echo "PR title: $PR_TITLE"
```

### 2. Avoid `pull_request_target` unless strictly necessary

This trigger runs in the context of the base repository and can expose secrets to malicious code from
a fork. Prefer `pull_request`.

### 3. Pin actions to a full commit SHA

Third-party actions must be pinned to an immutable commit SHA, not a mutable tag:

```yaml
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
```

### 4. Limit `GITHUB_TOKEN` permissions

Declare the minimum permissions at workflow level:

```yaml
permissions:
  contents: read
```

### 5. Sanitize inputs from issue and comment bodies

If user-provided text must be used, validate it against an allowlist or escape it before passing it
to a script.

### 6. Run untrusted code in isolated containers

For actions that execute code from pull requests, run them inside a container with no access to
secrets.

### Reference

- [GitHub Security Hardening for Actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
