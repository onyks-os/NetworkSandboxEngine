#!/usr/bin/env bash
# =============================================================================
# NSE Development Environment Bootstrap
# =============================================================================
# Usage: bash scripts/dev-setup.sh
#
# This script:
#   1. Checks for required system tools (nft, ip, python3, node)
#   2. Creates a Python virtual environment at .venv/
#   3. Installs backend Python dependencies
#   4. Installs frontend Node.js dependencies
#
# Run once after cloning. After that, use `make backend` and `make frontend`.
# =============================================================================

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
RESET='\033[0m'

info()    { echo -e "${GREEN}[setup]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[warn]${RESET}  $*"; }
error()   { echo -e "${RED}[error]${RESET} $*"; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# ---------------------------------------------------------------------------
# 1. Check required system tools
# ---------------------------------------------------------------------------
info "Checking system dependencies…"

MISSING=()
for cmd in python3 node npm; do
  if ! command -v "$cmd" &>/dev/null; then
    MISSING+=("$cmd")
  fi
done

for cmd in nft ip; do
  if ! command -v "$cmd" &>/dev/null; then
    warn "$cmd not found — the daemon will not run without it."
    warn "Install with: sudo apt install nftables iproute2"
  fi
done

if [ ${#MISSING[@]} -ne 0 ]; then
  error "Missing required tools: ${MISSING[*]}"
  error "Install them and re-run this script."
  exit 1
fi

# Check Python version >= 3.10
PY_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)
if [ "$PY_MAJOR" -lt 3 ] || ([ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 10 ]); then
  error "Python 3.10+ required (found $PY_VERSION)"
  exit 1
fi
info "Python $PY_VERSION ✓"

# ---------------------------------------------------------------------------
# 2. Python venv
# ---------------------------------------------------------------------------
if [ ! -d ".venv" ]; then
  info "Creating Python virtual environment at .venv/…"
  python3 -m venv .venv
fi

info "Activating virtual environment…"
# shellcheck disable=SC1091
source .venv/bin/activate

# ---------------------------------------------------------------------------
# 3. Python Package and Dependencies
# ---------------------------------------------------------------------------
info "Installing Python package and dependencies…"
pip install --quiet --upgrade pip
pip install --quiet -e ".[cli,gui,dev]"

info "Python dependencies installed ✓"

# ---------------------------------------------------------------------------
# 4. Frontend dependencies
# ---------------------------------------------------------------------------
info "Installing frontend Node.js dependencies…"
cd gui/gui_svelte
npm install --silent
cd ../..

info "Frontend dependencies installed ✓"

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${GREEN}  NSE dev environment ready!${RESET}"
echo ""
echo "  Start root daemon:    make run-rootd"
echo "  Start web server:     make run-web"
echo "  Start the frontend:   make frontend"
echo "  Or start all in tmux: make dev"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
