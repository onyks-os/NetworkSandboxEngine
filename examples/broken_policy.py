#!/usr/bin/env python3
"""
A deliberately failing experiment: the policy is wrong, the observer is sound.

The author meant "allow HTTP, block SSH" but copied the port set from another
rule, so SSH is accepted too. NSE must catch it: the run completes, both canary
checks prove the oracle was watching, and the verdict for SSH is ACCEPT instead
of DROP.

Run::

    sudo python3 examples/broken_policy.py [--out DIR]

Expected: ``FAILED AS EXPECTED`` and exit code 0. Exit code 1 means the demo
itself is broken: the bug went unnoticed, or the run failed for another reason.
DIR (default ``nse-example-output/broken_policy``) receives ``experiment.json``.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

from nse.core.pipeline import run_test_pipeline_report
from nse.models.test_request import PacketSpec, TestRequest

WRONG_RULES = """
table inet web {
    chain input {
        type filter hook input priority 0; policy drop;
        tcp dport { 22, 80 } accept   # meant: tcp dport 80 accept
    }
}
"""

PACKETS = [PacketSpec(protocol="tcp", dst_port=80), PacketSpec(protocol="tcp", dst_port=22)]
EXPECTED = ["ACCEPT", "DROP"]


async def main(out: Path) -> int:
    report = await run_test_pipeline_report(
        TestRequest(rules=WRONG_RULES, packets=PACKETS), timeout=120
    )
    out.mkdir(parents=True, exist_ok=True)
    report.write(out / "experiment.json")
    result = report.result

    print(f"outcome={result.outcome} oracle={result.oracle.readiness}/{result.oracle.liveness}")
    print(f"expected {EXPECTED}, observed {result.verdicts}")

    # The positive control: the instrument must be shown to work, or a wrong
    # verdict could just as well be a broken measurement.
    observer_sound = (
        result.outcome == "completed"
        and result.oracle.readiness == "observed"
        and result.oracle.liveness == "observed"
        and result.teardown_complete
    )
    if not observer_sound:
        print(f"UNEXPECTED: the observer was not sound ({result.outcome}): {result.errors}")
        return 1
    if result.verdicts == EXPECTED:
        print("UNEXPECTED: the wrong ruleset passed - the bug went unnoticed")
        return 1
    if result.verdicts != ["ACCEPT", "ACCEPT"]:
        print(f"UNEXPECTED: failed, but not on the SSH verdict: {result.verdicts}")
        return 1
    print("FAILED AS EXPECTED: the oracle was watching, and SSH (packet 2) was accepted.")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--out", type=Path, default=Path("nse-example-output/broken_policy"))
    args = parser.parse_args()
    if os.geteuid() != 0:
        sys.exit("run as root: sudo python3 examples/broken_policy.py")
    sys.exit(asyncio.run(main(args.out)))
