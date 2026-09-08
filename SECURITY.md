# Security Policy

## Reporting a Vulnerability

We take the security of NSE seriously. If you discover a security vulnerability in this
project, please **do not open a public issue**.

### How to report (preferred method)

Use GitHub's **private vulnerability reporting**:

1. Go to [https://github.com/onyks-os/NetworkSandboxEngine/security/advisories](https://github.com/onyks-os/NetworkSandboxEngine/security/advisories)
2. Click **"Report a vulnerability"**
3. Fill out the form with as much detail as possible:
   - Description of the issue
   - Steps to reproduce
   - Affected versions
   - Potential impact

### Alternative contact

If you cannot use GitHub's private reporting, email the maintainers at `129986281+onyks-os@users.noreply.github.com`.

Email may have a lower response priority than GitHub advisories.

## What to expect

- You will receive an acknowledgment within **48 hours**.
- We will investigate and keep you informed of progress at least every **7 days**.
- Once a fix is ready, we will credit you in the release notes (unless you prefer to remain anonymous).

## Public Disclosure

When a vulnerability is confirmed and fixed, NSE publishes a public advisory containing:

- Affected versions
- Description of the issue
- Mitigation or upgrade instructions

The advisory is published on:

- **GitHub Security Advisories** — `https://github.com/onyks-os/NetworkSandboxEngine/security/advisories`
- **Release notes** of the fixed version

We do not currently assign CVEs, but may do so in the future.

## Scope

This policy applies to the NSE core modules and its public interfaces.

The following are considered **critical scope targets**:

NSE is a measurement instrument that other projects trust to tell them whether
their firewall leaks. Its worst failures are therefore not crashes but **silent
false negatives**: a run that reports a clean result it did not measure.

1. **Making the oracle report a pass it did not observe.** Any input, ruleset,
   kernel version or timing condition under which `nse-runner` exits `0` while
   the trace stream was empty, truncated, or unparsed. This is the defect class
   that shipped in 1.x-2.0.0 and that the canary probes and
   `make test-blind` exist to prevent. Downstream, it means a firewall test
   suite going green against a firewall that leaks.
2. **Escaping the sandbox onto the host.** Any path by which a ruleset, packet
   spec or suite file loads rules into, injects packets on, or leaves
   namespaces/veth interfaces in the **host** network namespace. NSE's core
   promise is zero host mutation; `RuleEngine.load()` refusing an empty
   namespace name is one guard, not a proof.

Out of scope:

- Vulnerabilities in third-party dependencies already tracked upstream (report them upstream, then
  open an issue here referencing the advisory).
- Findings that require an already-compromised host or physical access.

For the full STRIDE threat model, trust boundaries, risk severity ratings, and security controls
inventory, see **[`docs/security-assessment.md`](docs/security-assessment.md)**.

## Informal Bug Bounty & Hall of Fame

There is no financial budget for monetary rewards, but the project recognizes researchers who help
make NSE safer. For valid, in-scope reports that are confirmed and resolved:

- **Permanent inclusion** in [`HALL_OF_FAME.md`](HALL_OF_FAME.md), with a link to the researcher's
  GitHub profile or personal website.
- **Honorable mention** in the GitHub Release Notes of the fixed version.

## Release support policy

| Version   | Support status      | End of life                    |
| --------- | ------------------- | ------------------------------ |
| 2.1.0   | ✅ Security fixes   | When the next minor is released |
| < 2.1.0 | ❌ Unsupported      |                                |

- Security fixes are provided only for the latest minor version.
- If you need long-term support, contact the maintainers.

## Security Hardening of the Project Itself

- All dependencies are monitored by Dependabot; see [`SCA_POLICY.md`](SCA_POLICY.md).
- Static analysis runs on every pull request; see [`SAST_POLICY.md`](SAST_POLICY.md).
- Secrets are never committed; see [`SECRETS_POLICY.md`](SECRETS_POLICY.md).
- Release artifacts are signed and reproducible; see [`docs/verification.md`](docs/verification.md).

## Acknowledgments

We thank the community for responsibly disclosing security issues. Contributors who report valid
vulnerabilities are publicly acknowledged unless they request otherwise.
