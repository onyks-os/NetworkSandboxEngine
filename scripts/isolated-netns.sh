#!/usr/bin/env bash
# Run a command in a new, empty network namespace with only loopback up.
#
# Usage: scripts/isolated-netns.sh <command> [args...]   (run as root)
#
# Used by CI so that NSE's topologies never meet the runner's own addresses and
# routes, and test traffic never reaches the runner's network.
set -euo pipefail

if [ "$#" -eq 0 ]; then
    echo "usage: $0 <command> [args...]" >&2
    exit 2
fi

echo "==> running in a new network namespace (loopback only): $*"
exec unshare --net -- bash -ec 'ip link set lo up; exec "$@"' isolated-netns "$@"
