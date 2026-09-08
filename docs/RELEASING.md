<!--
Copyright (c) 2026 onyks
SPDX-License-Identifier: MIT
-->

# Releasing NSE

A release is one tag. Everything else is automation.

```bash
make release-dry          # rehearse locally: checks, lint, tests, build, SBOM, checksums
git tag -s v2.1.0 -m "NSE v2.1.0"
git push origin v2.1.0    # this is the whole release
```

Pushing the tag runs `.github/workflows/release.yml`, which:

1. **refuses to continue if the tag does not match `pyproject.toml`.** NSE has
   shipped 1.1.1 and 2.0.0 to PyPI with no git tag behind them; this is the check
   that makes that impossible;
2. lints, type-checks, enforces the import contracts, and runs the tests with the
   coverage floor;
3. builds the sdist and wheel, generates an SBOM and SHA256SUMS, and signs
   everything with Sigstore;
4. creates the GitHub Release, using the CHANGELOG section for that version as
   the release body;
5. uploads to **TestPyPI**;
6. **installs from TestPyPI and smoke-tests it** — `nse-runner --help` runs, the
   engine imports, and `nse.__version__` matches the tag;
7. only then uploads to **PyPI**.

The bytes PyPI receives are the bytes Sigstore signed: nothing is rebuilt between
steps. A broken distribution is caught on the index nobody depends on, not the
one TTP's zero-leak suite depends on.

## Before the first release: Trusted Publishing

There is no API token to store. Both indexes must be told, once, that this
workflow is allowed to publish. On each site, go to *Your projects → the project
→ Publishing → Add a new pending publisher* (or *Publishing* on an existing
project) and enter:

| Field | Value |
| :--- | :--- |
| PyPI Project Name | `network-sandbox-engine` |
| Owner | `onyks-os` |
| Repository name | `NetworkSandboxEngine` |
| Workflow name | `release.yml` |
| Environment name | `pypi` on pypi.org, `testpypi` on test.pypi.org |

- <https://pypi.org/manage/account/publishing/>
- <https://test.pypi.org/manage/account/publishing/>

The environment names matter: the workflow declares `environment: pypi` and
`environment: testpypi`, and PyPI checks that claim in the OIDC token. Getting
them wrong is the usual cause of a first release failing at the upload step with
`invalid-publisher`.

Optionally add the same environments under *Settings → Environments* in GitHub
with a required reviewer, which turns the PyPI upload into a step you approve.

## Checklist for the tag

`make release-check` enforces the first two; the rest is judgement.

- [ ] the working tree is clean
- [ ] `CHANGELOG.md` has a `## [X.Y.Z]` section — it becomes the release body
- [ ] `pyproject.toml` version equals the tag without its `v`
- [ ] `make oracle-test` and `make test-blind` pass on a real kernel
- [ ] breaking changes are marked as such and the major is bumped

## If something goes wrong

**The upload to PyPI failed but TestPyPI succeeded.** Fix the cause, bump to the
next patch version, and tag again. Do not delete and re-push a tag: the Sigstore
bundle attests to a specific workflow run, and a re-pushed tag makes the
attestation describe a build that no longer exists.

**The release job failed before publishing.** Delete the tag locally and
remotely, fix, tag again. Nothing was published, so nothing is stale.

**A version is already on PyPI.** The `publish-pypi` job deliberately has no
`skip-existing`. A duplicate version means something is wrong with the release
and it must fail loudly rather than silently do nothing.

## Verifying a published release

See [verification.md](verification.md).
