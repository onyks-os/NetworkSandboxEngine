# Release Verification

Every NSE release is published with checksums, a Sigstore signature, and a CycloneDX
SBOM. This guide shows how to verify an artifact before installing it.

## 1. Verify the Checksums

Download the artifact and `SHA256SUMS` from the
[Releases page](https://github.com/onyks-os/NetworkSandboxEngine/releases), then:

```bash
sha256sum --check --ignore-missing SHA256SUMS
```

Expected output: `<artifact>: OK`.

## 2. Verify the Sigstore Signature

Release artifacts are signed keylessly through GitHub Actions OIDC — there is no long-lived private
key to steal. Install [`sigstore`](https://pypi.org/project/sigstore/) and verify:

```bash
python -m pip install sigstore

sigstore verify identity \
  --cert-identity "https://github.com/onyks-os/NetworkSandboxEngine/.github/workflows/release.yml@refs/tags/v2.1.0" \
  --cert-oidc-issuer "https://token.actions.githubusercontent.com" \
  <artifact>
```

## 3. Verifying Signer Identity

The `--cert-identity` value must exactly match the release workflow path and the tag being verified.
A signature that verifies against a *different* identity is not a valid NSE release,
even if the cryptography checks out.

## 4. Inspect the SBOM

```bash
jq '.components[] | {name, version, licenses}' sbom.json
```

Compare the component list against [`DEPENDENCIES.md`](../DEPENDENCIES.md). Any component present in
the SBOM but absent from that file should be reported as an issue.

## 5. Reproducing the Build

```bash
git clone --branch v2.1.0 https://github.com/onyks-os/NetworkSandboxEngine.git
cd NetworkSandboxEngine
make build
sha256sum dist/*
```

NSE's build is **not yet verified as bit-for-bit reproducible**, and this
document will not claim otherwise until it is measured.

What is known: the wheel and sdist are built by `setuptools` from a fixed source
tree, so the file *contents* are deterministic; the archive metadata is not,
because both formats embed build timestamps. Setting `SOURCE_DATE_EPOCH` to the
tag's commit date normalises that, and comparing two builds of the same tag is
the check that would turn this paragraph into a claim:

```bash
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct v2.1.0) make build
sha256sum dist/*.whl dist/*.tar.gz
```

Until that comparison runs in CI, verify the *signature* rather than the build:
the Sigstore bundle binds each artifact to the workflow run and tag that
produced it, which is a weaker guarantee than reproducibility but a real one.
