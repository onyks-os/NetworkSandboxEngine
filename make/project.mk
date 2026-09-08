# ---------------------------------------------------------------------------
# project.mk — targets that exist only in NSE.
#
# Everything here is privileged, because everything here exercises the oracle
# against a real kernel. The unprivileged contract targets (lint, test,
# coverage, build, release-*) come from the shared fragments.
# ---------------------------------------------------------------------------

.PHONY: oracle-test test-blind lint-imports

##@ Oracle verification (requires root)

# `make integration-test` runs the same markers unprivileged, where they skip.
# This is the version that actually measures something: it needs real network
# namespaces and a live `nft monitor trace`.
oracle-test: ## Privileged oracle tests + the YAML runner against a real kernel
	@echo "==> [$(PROJECT_SHORT)] Oracle integration tests (requires sudo)..."
	@echo "    kernel:   $$(uname -r)"
	@echo "    nftables: $$(nft --version 2>/dev/null || echo 'MISSING')"
	@sudo -E $(PYTHON) -m pytest $(TEST_DIRS) -v -m integration
	@sudo -E $(PYTHON) -m nse.cli.runner --file tests/test_suite.yaml

# The meta-test that guards the guard. NSE_FORCE_BLIND makes the trace parser
# understand nothing, which is what a kernel format change looks like from the
# outside. The suite MUST fail. Up to 2.0.0 it passed, which is the defect this
# target exists to prevent from ever coming back.
test-blind: ## Prove a blind oracle FAILS the suite instead of passing it
	@echo "==> [$(PROJECT_SHORT)] Blindness meta-test: a blind parser must fail the run..."
	@if sudo -E NSE_FORCE_BLIND=1 $(PYTHON) -m nse.cli.runner --file tests/test_suite.yaml; then \
		echo "!!! FAIL: a blind oracle reported success. The runner is not trustworthy."; \
		exit 1; \
	else \
		echo "==> OK: a blind oracle correctly failed the suite."; \
	fi


##@ Architecture

LINT_IMPORTS ?= $(shell if [ -x $(VENV)/bin/lint-imports ]; then echo $(VENV)/bin/lint-imports; else command -v lint-imports || echo lint-imports; fi)

# Extends the contract target by adding a prerequisite rather than redefining
# its recipe, so the shared fragment stays replaceable from the template.
lint-code: lint-imports

lint-imports: ## Enforce the layering contracts in .importlinter
	@echo "==> [$(PROJECT_SHORT)] Checking import boundaries..."
	@$(LINT_IMPORTS)
