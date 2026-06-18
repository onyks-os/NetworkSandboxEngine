SHELL := /bin/bash

# GPG key to use for signing release artifacts.
# Auto-detected from the first available secret key; override with:
#   make release GPG_KEY_ID=<fingerprint or email>
GPG_KEY_ID ?= $(shell gpg --list-secret-keys --keyid-format LONG 2>/dev/null | awk '/^sec/{print $$2}' | head -1 | cut -d'/' -f2)

.PHONY: setup backend frontend dev test integration-test clean lint format verify release publish-test publish help

# ============================================================
# Setup
# ============================================================

## setup: Bootstrap the full development environment (venv + npm install)
setup:
	@bash scripts/dev-setup.sh

# ============================================================
# Backend daemon (GUI server — requires GUI extras)
# ============================================================

## backend: Start the NSE daemon in development mode (binds to 127.0.0.1:8000)
## NOTE: requires sudo -E to preserve venv for root
backend:
	@echo "[NSE] Starting daemon in dev mode (requires sudo -E)…"
	sudo -E .venv/bin/python -m gui.server serve --dev

## backend-reload: Same as backend, but with uvicorn --reload
backend-reload:
	@echo "[NSE] Starting daemon with auto-reload…"
	sudo -E .venv/bin/python -m gui.server serve --dev --reload

# ============================================================
# Frontend
# ============================================================

## frontend: Start the Vite dev server (runs as normal user on :5173)
frontend:
	@echo "[NSE] Starting Vite dev server…"
	cd gui/gui_svelte && npm run dev

# ============================================================
# Combined dev
# ============================================================

## dev: Launch both backend (in background) and frontend (in foreground)
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
	.venv/bin/python -m pytest tests/ -v

## integration-test: Run full integration tests as root
integration-test:
	@echo "[NSE] Running integration tests (requires sudo)…"
	sudo -E .venv/bin/pytest tests/ -v -m "not skip"

# ============================================================
# Code Quality & Verification
# ============================================================

## lint: Check Python code styling using ruff
lint:
	@echo "[NSE] Running static analysis checks (ruff)…"
	.venv/bin/ruff check nse/ gui/ tests/
	.venv/bin/ruff format --check nse/ gui/ tests/

## format: Automatically format Python codebase
format:
	@echo "[NSE] Auto-formatting python codebase (ruff)…"
	.venv/bin/ruff check --fix nse/ gui/ tests/
	.venv/bin/ruff format nse/ gui/ tests/

## verify: Run static linting analysis and unit tests
verify: lint test

# ============================================================
# Build
# ============================================================

## build-frontend: Compile Svelte to static assets (for production)
build-frontend:
	cd gui/gui_svelte && npm run build

## release: Build the standalone nse/ headless core Python package
release: clean verify
	@echo "[NSE] Preparing release artifacts…"
	mkdir -p release/
	# Ensure python packaging tools are installed
	.venv/bin/python -m pip install --upgrade build twine
	# Build the root network-sandbox-engine package (nse/ only)
	.venv/bin/python -m build --outdir release/
	# Copy Dockerfile and systemd service file to release/
	cp Dockerfile release/
	cp scripts/nse.service release/
	# Generate SHA256 sums of the release files
	cd release && sha256sum * > SHA256SUMS
	# Generate GPG signature — always required
	@echo "[NSE] Signing SHA256SUMS with GPG… (key: $(GPG_KEY_ID))"
	gpg --clearsign --local-user $(GPG_KEY_ID) --output release/SHA256SUMS.asc release/SHA256SUMS
	@echo "========================================================================"
	@echo "Release preparation complete!"
	@echo "Artifacts are stored in the 'release/' directory:"
	@ls -la release/
	@echo "========================================================================"

# ============================================================
# Distribution & Publishing
# ============================================================

## publish-test: Upload the built python packages to TestPyPI
publish-test:
	@echo "[NSE] Uploading package to TestPyPI…"
	.venv/bin/twine upload --repository testpypi release/network_sandbox_engine-*.tar.gz release/network_sandbox_engine-*-py3-none-any.whl

## publish: Upload the built python packages to PyPI
publish:
	@echo "[NSE] Uploading package to PyPI…"
	.venv/bin/twine upload release/network_sandbox_engine-*.tar.gz release/network_sandbox_engine-*-py3-none-any.whl

# ============================================================
# Housekeeping
# ============================================================

## clean: Remove build artifacts, caches, and temp files
clean:
	rm -rf gui/gui_svelte/dist release/
	rm -rf dist/ build/ network_sandbox_engine.egg-info/
	find nse gui tests -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find nse gui tests -name "*.pyc" -delete 2>/dev/null || true

## help: Show this help message
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /'
