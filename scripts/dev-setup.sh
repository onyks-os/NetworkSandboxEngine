#!/usr/bin/env bash
# =============================================================================
# NSE Development Environment Bootstrap
# =============================================================================
# Usage: bash scripts/dev-setup.sh
#
# Creates .venv/ and installs the package with its cli and dev extras.
# Run once after cloning; after that use `make test`, `make lint`, `make verify`.
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

if ! command -v python3 &>/dev/null; then
  error "python3 is required."
  exit 1
fi

for cmd in nft ip; do
  if ! command -v "$cmd" &>/dev/null; then
    warn "$cmd not found - the engine cannot build namespaces without it."
    warn "Install with: sudo apt install nftables iproute2 conntrack"
  fi
done

PY_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=${PY_VERSION%%.*}
PY_MINOR=${PY_VERSION##*.}
if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 10 ]; }; then
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

info "Installing the package and its development dependencies…"
.venv/bin/pip install --quiet --upgrade pip
.venv/bin/pip install --quiet -e ".[cli,dev]"
info "Dependencies installed ✓"

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${GREEN}  NSE dev environment ready!${RESET}"
echo ""
echo "  Unit tests + coverage:  make test-cov"
echo "  Static analysis:        make lint"
echo "  Privileged oracle:      make integration-test"
echo "  Blindness meta-test:    make test-blind"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
