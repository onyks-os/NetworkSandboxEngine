# Network Sandbox Engine (NSE) — developer entrypoint.
#
# Every target is documented inline; run `make help` for the full list.
# Logic lives in the modular fragments under make/ so that this file stays readable:
#
#   make/common.mk   — environment, help, housekeeping, TODO tracking
#   make/quality.mk  — lint, format, audit, security gates
#   make/docs.mk     — MkDocs site and ADR scaffolding
#   make/release.mk  — versioning, build, SBOM, checksums, signing
#   make/python.mk  — language-specific implementation of the target contract
#   make/project.mk  — optional, committed, targets that exist only in this project
#   make/local.mk    — optional, git-ignored, machine-local overrides

SHELL := /bin/bash
.DEFAULT_GOAL := help

# ---------------------------------------------------------------------------
# Project identity — the single source of truth for scripts and workflows.
# ---------------------------------------------------------------------------
PROJECT_NAME  := Network Sandbox Engine
PROJECT_SHORT := NSE
PROJECT_SLUG  := NetworkSandboxEngine
PROJECT_PKG   := nse
PROJECT_DIST  := network-sandbox-engine
GITHUB_OWNER  := onyks-os
# Read from pyproject rather than restated here: two copies of a version number
# drift, and the one that drifts is always the one nobody edits. `release-check`
# printed "tag v2.1.0" while the package built as 2.1.1 - the release workflow
# would have caught it at tag time, which is later than anyone wants to find out.
VERSION       := $(shell grep -m1 '^version = ' pyproject.toml | cut -d '"' -f2)

# Directories that hold first-party source, tests, and shell scripts.
SRC_DIRS     := nse
TEST_DIRS    := tests
SCRIPT_DIRS  := scripts

include make/common.mk
include make/quality.mk
include make/docs.mk
include make/release.mk
include make/python.mk
-include make/project.mk
-include make/local.mk
