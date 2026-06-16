SHELL := /bin/bash

.PHONY: setup backend frontend dev test integration-test clean release help

# ============================================================
# Setup
# ============================================================

## setup: Bootstrap the full development environment (venv + npm install)
setup:
	@bash scripts/dev-setup.sh

# ============================================================
# Backend
# ============================================================

## backend: Start the NSE daemon in development mode (binds to 127.0.0.1:8000)
## NOTE: requires sudo -E to preserve venv for root
backend:
	@echo "[NSE] Starting daemon in dev mode (requires sudo -E)…"
	sudo -E .venv/bin/python -m nse serve --dev

## backend-reload: Same as backend, but with uvicorn --reload
backend-reload:
	@echo "[NSE] Starting daemon with auto-reload…"
	sudo -E .venv/bin/python -m nse serve --dev --reload

# ============================================================
# Frontend
# ============================================================

## frontend: Start the Vite dev server (runs as normal user on :5173)
frontend:
	@echo "[NSE] Starting Vite dev server…"
	cd frontend && npm run dev

# ============================================================
# Combined dev
# ============================================================

## dev: Launch both backend (in background) and frontend (in foreground)
## This requires tmux. Alternatively run in two separate terminals.
dev:
	@if command -v tmux &>/dev/null; then \
		tmux new-session -d -s nse-dev 2>/dev/null || true; \
		tmux send-keys -t nse-dev "make backend" Enter; \
		tmux split-window -h -t nse-dev; \
		tmux send-keys -t nse-dev "make frontend" Enter; \
		tmux attach -t nse-dev; \
	else \
		echo "tmux not found. Run 'make backend' and 'make frontend' in separate terminals."; \
		make frontend; \
	fi

# ============================================================
# Tests
# ============================================================

## test: Run Python unit tests (no root required)
test:
	@echo "[NSE] Running unit tests…"
	.venv/bin/python -m pytest backend/tests/ -v

## integration-test: Run full integration tests (requires Docker with --privileged)
integration-test:
	@echo "[NSE] Integration tests not yet implemented — placeholder."
	@echo "Future: docker run --privileged nse-test pytest backend/tests/integration/"

# ============================================================
# Build
# ============================================================

## build-frontend: Compile Svelte to static assets (for production)
build-frontend:
	cd frontend && npm run build

## release: Build frontend and package all backend & deployment files to release/ directory with SHA256 checksums
release: clean build-frontend
	@echo "[NSE] Preparing release artifacts…"
	rm -rf release/ backend/nse/dist/
	mkdir -p release/
	# Copy built frontend assets into location where FastAPI will pack them
	mkdir -p backend/nse/dist
	cp -r frontend/dist/* backend/nse/dist/
	# Ensure python packaging tools are installed
	.venv/bin/python -m pip install --upgrade build
	# Build Python package
	cd backend && ../.venv/bin/python -m build --outdir ../release/
	# Copy Dockerfile and systemd service file to release/
	cp Dockerfile release/
	cp scripts/nse.service release/
	# Generate SHA256 sums of the release files
	cd release && sha256sum * > SHA256SUMS
	# Generate GPG signature if gpg is available
	@if command -v gpg &>/dev/null; then \
		echo "[NSE] Signing SHA256SUMS with GPG…"; \
		gpg --clearsign --output release/SHA256SUMS.asc release/SHA256SUMS || echo "Warning: GPG signing failed. You can sign manually later."; \
	else \
		echo "Warning: gpg command not found. Skipping GPG signature."; \
	fi
	@echo "========================================================================"
	@echo "Release preparation complete!"
	@echo "Artifacts are stored in the 'release/' directory:"
	@ls -la release/
	@echo "========================================================================"

# Housekeeping
# ============================================================

## clean: Remove build artifacts, caches, and temp files
clean:
	rm -rf frontend/dist frontend/.vite release/
	rm -rf backend/dist/ backend/build/ backend/nse.egg-info/ backend/nse/dist/
	find backend -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find backend -name "*.pyc" -delete 2>/dev/null || true

## help: Show this help message
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /'
