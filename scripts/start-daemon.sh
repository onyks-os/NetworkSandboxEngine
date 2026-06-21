#!/usr/bin/env bash
# =============================================================================
# Start the NSE daemon in development mode.
#
# Requires root (sudo) so the daemon can create network namespaces.
# The -E flag preserves your user environment (including the venv) under sudo.
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_PYTHON="$REPO_ROOT/.venv/bin/python"

if [ ! -f "$VENV_PYTHON" ]; then
  echo "ERROR: venv not found. Run 'make setup' first."
  exit 1
fi

echo "[NSE] Starting daemon (dev mode)…"
exec sudo -E "$VENV_PYTHON" -m nse serve --dev "$@"
