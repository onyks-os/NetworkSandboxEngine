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

    args = parser.parse_args()

    if args.command == "serve":
        _run_server(args)


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


if __name__ == "__main__":
    main()
