# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""
Integration tests for the deterministic verdict oracle.
"""

from __future__ import annotations

import os

import pytest

from nse.core.netns_controller import NetnsController
from nse.core.pipeline import run_test_pipeline
from nse.models.test_request import PacketSpec, TestRequest

IS_ROOT = os.geteuid() == 0


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.skipif(not IS_ROOT, reason="Requires root privileges and real network namespaces")
async def test_accept_on_match() -> None:
    """Ruleset allows tcp dport 22: packet on :22 must give ACCEPT verdict."""
    rules = """
    table ip filter {
        chain input {
            type filter hook input priority 0; policy drop;
            tcp dport 22 accept
        }
    }
    """
    request = TestRequest(
        rules=rules,
        packets=[
            PacketSpec(
                protocol="tcp",
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                dst_port=22,
            )
        ],
    )
    controller = NetnsController()
    events = await run_test_pipeline(request=request, controller=controller)

    verdicts = [
        e.verdict.upper() for e in events if e.table and e.table != "nse_trace" and e.verdict
    ]
    assert len(verdicts) >= 1, "Oracle failed to observe verdict for packet matching port 22"
    assert verdicts[-1] == "ACCEPT"


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.skipif(not IS_ROOT, reason="Requires root privileges and real network namespaces")
async def test_drop_on_miss() -> None:
    """Ruleset allows tcp dport 22: packet on :23 must give explicit DROP verdict."""
    rules = """
    table ip filter {
        chain input {
            type filter hook input priority 0; policy drop;
            tcp dport 22 accept
        }
    }
    """
    request = TestRequest(
        rules=rules,
        packets=[
            PacketSpec(
                protocol="tcp",
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                dst_port=23,
            )
        ],
    )
    controller = NetnsController()
    events = await run_test_pipeline(request=request, controller=controller)

    verdicts = [
        e.verdict.upper() for e in events if e.table and e.table != "nse_trace" and e.verdict
    ]
    assert len(verdicts) >= 1, (
        "Oracle failed to observe explicit DROP verdict for packet missing rule"
    )
    assert verdicts[-1] == "DROP"
