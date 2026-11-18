#!/usr/bin/env bash
# Blindness meta-test: a blind oracle must FAIL the suite, for the right reason.
#
# Usage: scripts/check-blind.sh <python> <suite.yaml>   (run as root)
#
# Any failure is not enough. A host where the suite cannot run at all (a routing
# conflict, a missing tool) would "fail" too, and the check would pass for the
# wrong reason. So:
#   1. positive control: the suite must PASS with a working oracle;
#   2. the same suite with NSE_FORCE_BLIND=1 must FAIL;
#   3. and that failure must come from the unobserved canaries.
set -euo pipefail

python=$1
suite=$2
reason="canary was never observed"

echo "==> Positive control: a working oracle must pass the suite..."
if ! "$python" -m nse.cli.runner --file "$suite"; then
    echo "!!! FAIL: the suite does not pass with a working oracle, so a blind failure would prove nothing."
    exit 1
fi

echo "==> Blind run: the suite must fail..."
log=$(mktemp)
trap 'rm -f "$log"' EXIT
status=0
NSE_FORCE_BLIND=1 "$python" -m nse.cli.runner --file "$suite" >"$log" 2>&1 || status=$?
cat "$log"

if [ "$status" -eq 0 ]; then
    echo "!!! FAIL: a blind oracle reported success. The runner is not trustworthy."
    exit 1
fi
if ! grep -q "$reason" "$log"; then
    echo "!!! FAIL: the blind run failed (exit $status), but not because the canaries went unobserved."
    exit 1
fi
echo "==> OK: a blind oracle correctly failed the suite, on its canaries."
