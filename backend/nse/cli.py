"""
nse serve [--dev]

CLI entry point for the NSE daemon.

  --dev   Bind to 127.0.0.1:8000 over TCP (development mode).
          Requires `sudo -E` so the venv libraries are visible to root.

  (no flag)  Bind to /run/nse.sock (Unix Domain Socket, production mode).
             Frontend static files are served by FastAPI itself.
"""

import argparse
import sys


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="nse",
        description="Network Sandbox Engine daemon",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    serve_parser = subparsers.add_parser("serve", help="Start the NSE daemon")
    serve_parser.add_argument(
        "--dev",
        action="store_true",
        default=False,
        help="Run in development mode: bind to 127.0.0.1:8000 instead of /run/nse.sock",
    )
    serve_parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind to in --dev mode (default: 127.0.0.1)",
    )
    serve_parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to bind to in --dev mode (default: 8000)",
    )
    serve_parser.add_argument(
        "--socket",
        default="/run/nse.sock",
        help="Unix socket path for production mode (default: /run/nse.sock)",
    )
    serve_parser.add_argument(
        "--reload",
        action="store_true",
        default=False,
        help="Enable uvicorn auto-reload (development only)",
    )

    test_parser = subparsers.add_parser("test", help="Run a YAML/JSON headless test suite")
    test_parser.add_argument(
        "--file",
        required=True,
        help="Path to the test suite YAML or JSON file",
    )

    args = parser.parse_args()

    if args.command == "serve":
        _run_server(args)
    elif args.command == "test":
        _run_test_suite(args)


def _run_server(args: argparse.Namespace) -> None:
    import uvicorn  # imported late so CLI --help works without uvicorn installed

    from nse.main import create_app

    app = create_app(dev_mode=args.dev)

    if args.dev:
        print(f"[NSE] Development mode — binding to http://{args.host}:{args.port}")
        uvicorn.run(
            app,
            host=args.host,
            port=args.port,
            reload=args.reload,
            log_level="debug",
        )
    else:
        import os

        socket_path = args.socket
        # Ensure the socket directory exists
        socket_dir = os.path.dirname(socket_path)
        if socket_dir:
            os.makedirs(socket_dir, exist_ok=True)

        # Remove stale socket from a previous run
        if os.path.exists(socket_path):
            os.unlink(socket_path)

        print(f"[NSE] Production mode — binding to unix:{socket_path}")
        uvicorn.run(
            app,
            uds=socket_path,
            log_level="info",
        )


def _run_test_suite(args: argparse.Namespace) -> None:
    import json
    import yaml
    import time
    import asyncio
    from nse.models.test_request import TestRequest, PacketSpec, TopologyType
    from nse.core.netns_controller import NetnsController, TestRun
    from nse.core.pipeline import run_test_pipeline

    print(f"[NSE] Loading test suite from: {args.file}")
    try:
        with open(args.file, "r") as f:
            if args.file.endswith(".json"):
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

    # We must run this in an asyncio loop
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
            
            packets.append(PacketSpec(
                protocol=protocol,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                tcp_flags=tcp_flags
            ))

        request = TestRequest(
            rules=rules,
            packets=packets,
            topology=topology
        )

        test_id = f"cli_{tc_idx}_{int(time.time())}"
        run = TestRun(
            test_id=test_id,
            netns_name=f"nse_{test_id}",
            request=request
        )

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
        ordered_trace_ids = []
        errors = []

        for evt in events:
            if evt.type == "error":
                errors.append(evt.raw_message)
            elif evt.trace_id and evt.type == "verdict":
                if evt.trace_id not in trace_id_to_verdicts:
                    trace_id_to_verdicts[evt.trace_id] = []
                    ordered_trace_ids.append(evt.trace_id)
                trace_id_to_verdicts[evt.trace_id].append(evt.verdict)

        if errors:
            print(f"  [FAIL] Test encountered errors: {', '.join(errors)}")
            failed += 1
            continue

        actual_verdicts = []
        for tid in ordered_trace_ids:
            v_list = trace_id_to_verdicts[tid]
            if any(v in ("DROP", "REJECT") for v in v_list):
                actual_verdicts.append("DROP")
            else:
                actual_verdicts.append("ACCEPT")

        # Silence drops handling (e.g. if a packet is dropped and no verdict event is emitted,
        # we treat it as DROP)
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
