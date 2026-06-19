"""
Mock Listeners for TCP/UDP servers inside namespaces.
Can be run as a standalone script or imported to manage Popen processes.
"""

from __future__ import annotations

import argparse
import logging
import socket
import sys
import threading
import time
import subprocess

logger = logging.getLogger("nse.core.mock_listener")


def run_tcp_server(host: str, port: int) -> None:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    s = socket.socket(family, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((host, port))
        s.listen(5)
        print(f"TCP server listening on {host}:{port}", flush=True)
    except Exception as e:
        print(f"Error binding TCP to {host}:{port}: {e}", file=sys.stderr, flush=True)
        sys.exit(1)

    while True:
        try:
            conn, addr = s.accept()

            # Handle client in a daemon thread
            def handle_client(c: socket.socket) -> None:
                try:
                    c.settimeout(5.0)
                    while True:
                        data = c.recv(1024)
                        if not data:
                            break
                        c.sendall(data)
                except Exception:
                    pass
                finally:
                    c.close()

            t = threading.Thread(target=handle_client, args=(conn,), daemon=True)
            t.start()
        except KeyboardInterrupt:
            break
        except Exception:
            time.sleep(0.1)


def run_udp_server(host: str, port: int) -> None:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    s = socket.socket(family, socket.SOCK_DGRAM)
    try:
        s.bind((host, port))
        print(f"UDP server listening on {host}:{port}", flush=True)
    except Exception as e:
        print(f"Error binding UDP to {host}:{port}: {e}", file=sys.stderr, flush=True)
        sys.exit(1)

    while True:
        try:
            data, addr = s.recvfrom(2048)
            s.sendto(data, addr)
        except KeyboardInterrupt:
            break
        except Exception:
            time.sleep(0.1)


def start_mock_listener(
    netns_name: str,
    proto: str,
    port: int,
    host: str = "::",
    use_nsenter: bool = False,
) -> subprocess.Popen:
    """Spawns a mock listener inside the namespace in a background process."""
    cmd = []
    if use_nsenter:
        cmd += ["nsenter", f"--net=/var/run/netns/{netns_name}", "--"]
    else:
        cmd += ["ip", "netns", "exec", netns_name]
    cmd += [
        sys.executable,
        "-u",
        "-m",
        "gui.daemon.mock_listener",
        "--proto",
        proto.lower(),
        "--port",
        str(port),
        "--host",
        host,
    ]
    logger.info("Spawning listener inside %s: %s", netns_name, " ".join(cmd))
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    # Give a tiny slice for the listener to bind and print the starting message
    time.sleep(0.15)
    return proc


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NSE Mock Listener Daemon")
    parser.add_argument("--proto", choices=["tcp", "udp"], default="tcp")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--host", default="::")
    args = parser.parse_args()

    # If dual-stack isn't enabled or is blocked, let's fallback to IPv4 if host is "::" and bind fails,
    # but since Linux typically supports IPv6 bind for dual-stack or explicitly IPv6, let's keep it direct.
    try:
        if args.proto == "tcp":
            run_tcp_server(args.host, args.port)
        else:
            run_udp_server(args.host, args.port)
    except KeyboardInterrupt:
        sys.exit(0)
