# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""
Integration tests for the deterministic verdict oracle.
"""

from __future__ import annotations

import os
from unittest.mock import patch

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


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.skipif(not IS_ROOT, reason="Requires root privileges and real network namespaces")
async def test_parser_understands_every_line_of_a_real_trace() -> None:
    """
    Cross-version guard for the parser, run against whatever kernel and nftables
    the machine actually has.

    Hand-written fixtures pin the grammar we know about; this pins the grammar
    the kernel in front of us emits. It is the test that turns "the parser broke
    on a new nftables release" from a silent blindness into a red build, which is
    why CI runs it on more than one image.
    """
    from nse.core.trace_harvester import TraceHarvester

    observed: list[TraceHarvester] = []
    original_init = TraceHarvester.__init__

    def spy(self: TraceHarvester) -> None:
        original_init(self)
        observed.append(self)

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
        packets=[PacketSpec(protocol="tcp", src_ip="10.0.0.1", dst_ip="10.0.0.2", dst_port=22)],
    )

    with patch.object(TraceHarvester, "__init__", spy):
        await run_test_pipeline(request=request, controller=NetnsController())

    assert observed, "the pipeline did not create a harvester"
    harvester = observed[0]
    assert harvester.unparsed_trace_lines == 0, (
        f"the parser did not understand {harvester.unparsed_trace_lines} line(s) of real "
        f"`nft monitor trace` output on this kernel: {harvester.unparsed_samples}. "
        f"Add a fixture for this format to tests/fixtures/nft_trace/ and widen the parser."
    )


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.skipif(not IS_ROOT, reason="Requires root privileges and real network namespaces")
async def test_a_blind_parser_fails_the_run_instead_of_passing_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    The meta-test. NSE_FORCE_BLIND makes the parser understand nothing, which is
    what a kernel format change looks like from the outside.

    Before the canary probes existed, this produced an empty verdict list that
    the runner reported as SUCCESS. It must now produce an oracle error.
    """
    monkeypatch.setenv("NSE_FORCE_BLIND", "1")

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
        packets=[PacketSpec(protocol="tcp", src_ip="10.0.0.1", dst_ip="10.0.0.2", dst_port=22)],
    )
    events = await run_test_pipeline(request=request, controller=NetnsController())

    errors = [e for e in events if e.type == "error"]
    assert errors, "a blind parser produced no error: the oracle would report a false pass"
    assert any("canary" in (e.raw_message or "") for e in errors)
