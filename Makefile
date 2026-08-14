SHELL := /bin/bash

# Executables discovery (prefer .venv if present, fallback to PATH)
PYTHON ?= $(shell if [ -f .venv/bin/python ]; then echo .venv/bin/python; else command -v python3 || echo python3; fi)
RUFF ?= $(shell if [ -f .venv/bin/ruff ]; then echo .venv/bin/ruff; else command -v ruff || echo ruff; fi)
MYPY ?= $(shell if [ -f .venv/bin/mypy ]; then echo .venv/bin/mypy; else command -v mypy || echo mypy; fi)
LINT_IMPORTS ?= $(shell if [ -f .venv/bin/lint-imports ]; then echo .venv/bin/lint-imports; else command -v lint-imports || echo lint-imports; fi)
TWINE ?= $(shell if [ -f .venv/bin/twine ]; then echo .venv/bin/twine; else command -v twine || echo twine; fi)

# GPG key to use for signing release artifacts.
# Auto-detected from the first available secret key; override with:
#   make release GPG_KEY_ID=<fingerprint or email>
GPG_KEY_ID ?= $(shell gpg --list-secret-keys --keyid-format LONG 2>/dev/null | awk '/^sec/{print $$2}' | head -1 | cut -d'/' -f2)

.PHONY: setup backend frontend dev test integration-test clean lint format verify release publish-test publish help ci-local docs docs-build build-web-docs docs-serve serve-docs

# ============================================================
# Documentation (MkDocs Material)
# ============================================================

## docs: Build the MkDocs web documentation
docs: docs-build

## docs-build: Build MkDocs HTML documentation site
docs-build: build-web-docs

## build-web-docs: Compile MkDocs Markdown & docstrings to HTML
build-web-docs:
	@echo "[NSE] Building MkDocs web documentation into ../onyks-os.github.io/NetworkSandboxEngine/…"
	$(PYTHON) -m mkdocs build

## docs-serve: Launch MkDocs live documentation preview server (http://127.0.0.1:8000)
docs-serve: serve-docs

## serve-docs: Start MkDocs dev server with hot-reload
serve-docs:
	@echo "[NSE] Starting MkDocs live documentation server (http://127.0.0.1:8000)…"
	$(PYTHON) -m mkdocs serve

# ============================================================
# Setup
# ============================================================

## setup: Bootstrap the full development environment (venv + npm install)
setup:
	@bash scripts/dev-setup.sh

# ============================================================
# Backend server
# ============================================================

## run-web: Start the NSE FastAPI server (requires root for netns)
run-web:
	@echo "[NSE] Starting web server…"
	sudo -E $(PYTHON) -m gui.server serve --dev

## run-web-reload: Start the NSE FastAPI server with auto-reload (requires root)
run-web-reload:
	@echo "[NSE] Starting web server with auto-reload…"
	sudo -E $(PYTHON) -m gui.server serve --dev --reload

## backend: Start the backend web server
backend: run-web

# ============================================================
# Frontend
# ============================================================

## frontend: Start the Vite dev server (runs on :5173)
frontend:
	@echo "[NSE] Starting Vite dev server…"
	cd gui/gui_svelte && npm run dev

# ============================================================
# Combined dev
# ============================================================

## dev: Launch web server and frontend (in tmux if available)
dev:
	@if command -v tmux &>/dev/null; then \
		tmux new-session -d -s nse-dev 2>/dev/null || true; \
		tmux send-keys -t nse-dev "make run-web" Enter; \
		tmux split-window -h -t nse-dev; \
		tmux send-keys -t nse-dev "make frontend" Enter; \
		tmux attach -t nse-dev; \
	else \
		echo "tmux not found. Run 'make run-web' and 'make frontend' in separate terminals."; \
		make frontend; \
	fi

# ============================================================
# Tests
# ============================================================

## test: Run Python unit tests (no root required)
test:
	@echo "[NSE] Running unit tests…"
	$(PYTHON) -m pytest tests/ -v

## integration-test: Run full integration tests as root
integration-test:
	@echo "[NSE] Running integration tests (requires sudo)…"
	sudo -E $(PYTHON) -m pytest tests/ -v -m "not skip"

# ============================================================
# Code Quality & Verification
# ============================================================

## lint: Check Python code styling (ruff), type hints (mypy), and import boundaries (import-linter)
lint:
	@echo "[NSE] Running static analysis checks (ruff)…"
	$(RUFF) check nse/ gui/ tests/
	$(RUFF) format --check nse/ gui/ tests/
	@echo "[NSE] Running static type checks (mypy)…"
	$(MYPY) nse/ gui/
	@echo "[NSE] Checking import boundaries (import-linter)…"
	$(LINT_IMPORTS)

## format: Automatically format Python codebase
format:
	@echo "[NSE] Auto-formatting python codebase (ruff)…"
	$(RUFF) check --fix nse/ gui/ tests/
	$(RUFF) format nse/ gui/ tests/

## verify: Run static linting analysis and unit tests
verify: lint test

## ci-local: Execute full local CI pipeline (lint, unit tests, frontend build, docs build, smoke pypi test, integration tests)
ci-local: verify build-frontend docs-build
	@echo "[NSE] Running PyPI smoke test…"
	@python3 -m venv .smoke_test_venv && \
		.smoke_test_venv/bin/pip install -e ".[cli]" >/dev/null && \
		.smoke_test_venv/bin/python -c "import nse; from nse.core.pipeline import run_test_pipeline; print('Smoke PyPI OK')" && \
		rm -rf .smoke_test_venv
	@echo "[NSE] Running privileged integration tests (requires sudo)…"
	@sudo -E $(PYTHON) -m pytest tests/ -v -m "integration"
	@sudo -E $(PYTHON) -m nse.cli.runner --file tests/test_suite.yaml
	@echo "========================================================================"
	@echo "[NSE] Local CI pipeline PASSED 100%!"
	@echo "========================================================================"

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
	$(PYTHON) -m pip install --upgrade build twine
	# Build the root network-sandbox-engine package (nse/ only)
	$(PYTHON) -m build --outdir release/
	# Copy Dockerfile and systemd service file to release/
	cp Dockerfile release/
	cp scripts/nse.service release/
	# Generate SHA256 sums of the release files
	cd release && sha256sum * > SHA256SUMS
	# Generate GPG signature — always required
	@echo "[NSE] Signing SHA256SUMS with GPG… (key: $(GPG_KEY_ID))"
	gpg --clearsign $(if $(GPG_KEY_ID),--local-user $(GPG_KEY_ID),) --output release/SHA256SUMS.asc release/SHA256SUMS
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
	$(TWINE) upload --repository testpypi release/network_sandbox_engine-*.tar.gz release/network_sandbox_engine-*-py3-none-any.whl

## publish: Upload the built python packages to PyPI
publish:
	@echo "[NSE] Uploading package to PyPI…"
	$(TWINE) upload release/network_sandbox_engine-*.tar.gz release/network_sandbox_engine-*-py3-none-any.whl

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
