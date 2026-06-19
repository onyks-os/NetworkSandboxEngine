# Copyright (c) 2026 onyks
# Licensed under the MIT License.

import sys
import argparse
import time
import asyncio

try:
    import yaml
    from pydantic import ValidationError
    from nse.models.test_request import TestRequest, PacketSpec, TopologyType
    from nse.models.trace_event import TraceEvent
    from nse.core.netns_controller import NetnsController, TestRun
    from nse.core.pipeline import run_test_pipeline
except ImportError:
    yaml = None
    ValidationError = None
    TestRequest = None
    PacketSpec = None
    TopologyType = None
    TraceEvent = None
    NetnsController = None
    TestRun = None
    run_test_pipeline = None


def check_cli_dependencies() -> None:
    """Verify that CLI extras are installed."""
    if yaml is None or ValidationError is None or TestRequest is None:
        print("[FATAL ERROR] Missing dependencies for CLI runner.", file=sys.stderr)
        print("To use the YAML test runner, install the CLI extras:", file=sys.stderr)
        print("    pip install 'network-sandbox-engine[cli]'", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    check_cli_dependencies()
    import logging

    logging.basicConfig(
        level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s", force=True
    )

    parser = argparse.ArgumentParser(
        prog="nse-runner",
        description="Network Sandbox Engine YAML/JSON test runner",
    )
    parser.add_argument(
        "--file",
        required=True,
        help="Path to the test suite YAML or JSON file",
    )

    args = parser.parse_args()

    print(f"[NSE] Loading test suite from: {args.file}")
    try:
        with open(args.file, "r") as f:
            if args.file.endswith(".json"):
                import json

                data = json.load(f)
            else:
                data = yaml.safe_load(f)
    except Exception as e:
        print(f"Error reading test suite file: {e}", file=sys.stderr)
        sys.exit(1)

    test_cases = data.get("tests", [])
    if not test_cases:
        print("No test cases found in suite.", file=sys.stderr)
        sys.exit(0)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    controller = NetnsController()

    passed = 0
    failed = 0

    print(f"Found {len(test_cases)} test cases.")
    print("-" * 60)

    for tc_idx, tc in enumerate(test_cases):
        name = tc.get("name", f"Test case {tc_idx + 1}")
        print(f"Running test: {name}...")

        topology_str = tc.get("topology", "simple").lower()
        topology = TopologyType.GATEWAY if topology_str == "gateway" else TopologyType.SIMPLE

        rules = tc.get("rules", "")

        packets_data = tc.get("packets", [])
        packets = []
        expected_verdicts = []

        for p in packets_data:
            expected_verdicts.append(p.get("expected_verdict", "ACCEPT").upper())

            protocol = p.get("protocol", "tcp")
            src_ip = p.get("src_ip", "10.0.1.1" if topology == TopologyType.GATEWAY else "10.0.0.1")
            dst_ip = p.get("dst_ip", "10.0.2.2" if topology == TopologyType.GATEWAY else "10.0.0.2")
            src_port = p.get("src_port")
            dst_port = p.get("dst_port")
            tcp_flags = p.get("tcp_flags", [])

            packets.append(
                PacketSpec(
                    protocol=protocol,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    tcp_flags=tcp_flags,
                )
            )

        try:
            request = TestRequest(rules=rules, packets=packets, topology=topology)
        except ValidationError as e:
            print(f"  [FAIL] Test request validation failed:\n{e}")
            failed += 1
            continue

        test_id = f"cli_{tc_idx}_{int(time.time())}"
        run = TestRun(test_id=test_id, netns_name=f"nse_{test_id}", request=request)

        try:
            loop.run_until_complete(run_test_pipeline(controller, run))
        except Exception as e:
            print(f"  [FAIL] Pipeline crashed with error: {e}")
            failed += 1
            continue

        events = []
        while not run.event_queue.empty():
            evt = loop.run_until_complete(run.event_queue.get())
            if evt is None:
                continue
            events.append(evt)

        trace_id_to_verdicts = {}
        trace_id_to_hook = {}
        all_seen_trace_ids = []
        errors = []

        for evt in events:
            if evt.type == "error":
                errors.append(evt.raw_message)
            elif evt.trace_id:
                if evt.trace_id not in trace_id_to_verdicts:
                    trace_id_to_verdicts[evt.trace_id] = []
                    all_seen_trace_ids.append(evt.trace_id)

                if evt.type == "hook" and evt.hook:
                    if evt.trace_id not in trace_id_to_hook:
                        trace_id_to_hook[evt.trace_id] = evt.hook

                if evt.verdict:
                    trace_id_to_verdicts[evt.trace_id].append(evt.verdict.upper())

        if errors:
            print(f"  [FAIL] Test encountered errors: {', '.join(errors)}")
            failed += 1
            continue

        # Keep only trace IDs that enter on the expected injection hook interface
        ordered_trace_ids = []
        for tid in all_seen_trace_ids:
            hook = trace_id_to_hook.get(tid, "")
            is_valid = False
            if topology == TopologyType.GATEWAY:
                if hook.startswith("vrh-") or hook == "veth-nse":
                    is_valid = True
            else:
                if hook == "veth-nse":
                    is_valid = True

            if is_valid:
                ordered_trace_ids.append(tid)

        actual_verdicts = []
        for tid in ordered_trace_ids:
            v_list = trace_id_to_verdicts[tid]
            if any(v in ("DROP", "REJECT") for v in v_list):
                actual_verdicts.append("DROP")
            elif any(v == "ACCEPT" for v in v_list):
                actual_verdicts.append("ACCEPT")
            else:
                actual_verdicts.append("DROP")

        while len(actual_verdicts) < len(expected_verdicts):
            actual_verdicts.append("DROP")

        test_passed = True
        for idx, (exp, act) in enumerate(zip(expected_verdicts, actual_verdicts)):
            if exp != act:
                print(f"  [FAIL] Packet {idx + 1}: expected {exp}, got {act}")
                test_passed = False
            else:
                print(f"  [OK] Packet {idx + 1}: expected {exp}, got {act}")

        if test_passed:
            print(f"  => SUCCESS: {name}")
            passed += 1
        else:
            print(f"  => FAILURE: {name}")
            failed += 1

    print("-" * 60)
    print(f"Test Suite Summary: {passed} passed, {failed} failed.")
    if failed > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
