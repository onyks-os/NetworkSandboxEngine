#!/usr/bin/env bash
# =============================================================================
# Capture a real `nft monitor trace` fixture for the golden corpus.
# =============================================================================
# Usage: sudo scripts/capture_trace_fixture.sh <name>
#
# Writes tests/fixtures/nft_trace/<name>.log plus a <name>.provenance.txt
# recording the kernel and nftables version it came from.
#
# Write the matching <name>.expected.json BY HAND, from the log. Do not generate
# it from the parser: a fixture produced by the code under test cannot detect a
# bug in that code.
# =============================================================================

set -euo pipefail

NAME="${1:-}"
if [ -z "$NAME" ]; then
  echo "usage: sudo $0 <fixture-name>" >&2
  exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "error: capturing kernel trace events requires root." >&2
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$REPO_ROOT/tests/fixtures/nft_trace"
NS="nse_fixture_$$"
VETH_HOST="vhr-fix$$"
VETH_PEER="veth-nse"

cleanup() {
  ip netns del "$NS" 2>/dev/null || true
  ip link del "$VETH_HOST" 2>/dev/null || true
}
trap cleanup EXIT

ip netns add "$NS"
ip link add "$VETH_HOST" type veth peer name "$VETH_PEER"
ip link set "$VETH_PEER" netns "$NS"
ip addr add 10.0.0.1/24 dev "$VETH_HOST"
ip link set "$VETH_HOST" up
ip netns exec "$NS" ip addr add 10.0.0.2/24 dev "$VETH_PEER"
ip netns exec "$NS" ip link set "$VETH_PEER" up
ip netns exec "$NS" ip link set lo up

ip netns exec "$NS" nft -f - <<'RULES'
table inet nse_trace {
  chain nse_trace_prerouting {
    type filter hook prerouting priority -300; policy accept;
    meta nftrace set 1
  }
}
table ip filter {
  chain input {
    type filter hook input priority 0; policy drop;
    tcp dport 80 accept
  }
}
RULES

ip netns exec "$NS" nft monitor trace > "$OUT_DIR/$NAME.log" &
MONITOR_PID=$!
sleep 1

# One packet that matches the accept rule, one that hits the drop policy.
ping -c1 -W1 10.0.0.2 >/dev/null 2>&1 || true
(exec 3<>/dev/tcp/10.0.0.2/80) 2>/dev/null || true
(exec 3<>/dev/tcp/10.0.0.2/22) 2>/dev/null || true
sleep 1

kill "$MONITOR_PID" 2>/dev/null || true
wait "$MONITOR_PID" 2>/dev/null || true

{
  echo "captured: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "kernel:   $(uname -r)"
  echo "nftables: $(nft --version)"
  echo "iproute2: $(ip -V)"
} > "$OUT_DIR/$NAME.provenance.txt"

LINES=$(wc -l < "$OUT_DIR/$NAME.log")
echo "Captured $LINES line(s) into $OUT_DIR/$NAME.log"
echo "Now write $OUT_DIR/$NAME.expected.json by hand, reading the log."
