#!/usr/bin/env bash
#
# verify.sh — the full local gate, callable from CI or by hand.
#
# `make verify` delegates here so that the same sequence runs in every context.
set -euo pipefail

# Declared and assigned separately: `readonly x="$(cmd)"` masks the command's
# exit status, so a failing cd would go unnoticed (ShellCheck SC2155).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly REPO_ROOT

cd "${REPO_ROOT}"

log() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
fail() { printf '\n\033[31m!!! %s\033[0m\n' "$*" >&2; exit 1; }

log "Linting"
make lint || fail "Lint failed."

log "Unit tests"
make test || fail "Unit tests failed."

log "Dependency audit"
make audit || fail "Dependency audit failed."

log "Documentation build"
make docs-build || fail "Documentation build failed."

# The privileged half. It is what makes a green run mean the oracle works, so it
# is listed here rather than left to memory - but it needs root, and a release
# rehearsal on a laptop should not demand a password. Announced when skipped.
if [ "$(id -u)" -eq 0 ] || sudo -n true 2>/dev/null; then
    log "Oracle integration tests"
    make oracle-test || fail "Oracle integration tests failed."

    log "Blindness meta-test"
    make test-blind || fail "A blind oracle did not fail the suite."
else
    printf '\n\033[33m==> SKIP: oracle-test and test-blind need root (run as root or with passwordless sudo)\033[0m\n'
fi

printf '\n\033[32m==> All checks passed.\033[0m\n'
