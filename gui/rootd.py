# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""
nse-rootd: privileged root daemon running JSON-RPC over UNIX socket.
"""

from __future__ import annotations

import asyncio
import os
import json
import logging
import signal
import argparse
from nse.core.netns_controller import NetnsController
from nse.core.rule_engine import RuleEngine, RuleValidationError
from nse.models.test_request import TestRequest

# Setup logger
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("nse.rootd")


class RootDaemon:
    def __init__(self, socket_path: str = "/var/run/nse-core.sock") -> None:
        self.socket_path = socket_path
        self.controller = NetnsController()
        self.server: asyncio.AbstractServer | None = None

    async def handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            while True:
                line_bytes = await reader.readline()
                if not line_bytes:
                    break
                line = line_bytes.decode("utf-8").strip()
                if not line:
                    continue

                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    writer.write(
                        json.dumps({"status": "error", "message": "Invalid JSON"}).encode("utf-8")
                        + b"\n"
                    )
                    await writer.drain()
                    continue

                action = data.get("action")
                if action == "validate_rules":
                    rules = data.get("rules", "")
                    engine = RuleEngine(use_nsenter=self.controller.use_nsenter)
                    try:
                        engine.validate(rules)
                        response = {"status": "ok"}
                    except RuleValidationError as exc:
                        response = {
                            "status": "error",
                            "message": "nftables syntax error",
                            "errors": exc.errors,
                        }
                    writer.write(json.dumps(response).encode("utf-8") + b"\n")
                    await writer.drain()

                elif action == "submit_test":
                    test_id = data.get("test_id")
                    request_dict = data.get("request")
                    if not test_id or not request_dict:
                        response = {"status": "error", "message": "Missing test_id or request"}
                    else:
                        try:
                            if hasattr(TestRequest, "model_validate"):
                                request_obj = TestRequest.model_validate(request_dict)
                            else:
                                request_obj = TestRequest.parse_obj(request_dict)
                            self.controller.enqueue_test(test_id=test_id, request=request_obj)
                            response = {"status": "ok"}
                        except Exception as e:
                            response = {"status": "error", "message": str(e)}
                    writer.write(json.dumps(response).encode("utf-8") + b"\n")
                    await writer.drain()

                elif action == "get_test_status":
                    test_id = data.get("test_id")
                    status_info = self.controller.get_status(test_id)
                    if status_info is None:
                        response = {"status": "error", "message": f"Test '{test_id}' not found."}
                    else:
                        if hasattr(status_info, "model_dump"):
                            status_dict = status_info.model_dump()
                        else:
                            status_dict = status_info.dict()
                        response = {"status": "ok", "data": status_dict}
                    writer.write(json.dumps(response).encode("utf-8") + b"\n")
                    await writer.drain()

                elif action == "stream_events":
                    test_id = data.get("test_id")
                    if not self.controller.has_test(test_id):
                        response = {"type": "error", "message": f"Unknown test_id: {test_id}"}
                        writer.write(json.dumps(response).encode("utf-8") + b"\n")
                        await writer.drain()
                        break

                    event_queue = self.controller.get_event_queue(test_id)
                    while True:
                        try:
                            event = await event_queue.get()
                            if event is None:
                                response = {"type": "done"}
                                writer.write(json.dumps(response).encode("utf-8") + b"\n")
                                await writer.drain()
                                break

                            if hasattr(event, "model_dump_json"):
                                event_str = event.model_dump_json()
                            else:
                                event_str = event.json()
                            writer.write(event_str.encode("utf-8") + b"\n")
                            await writer.drain()
                        except Exception as e:
                            response = {"type": "error", "message": str(e)}
                            writer.write(json.dumps(response).encode("utf-8") + b"\n")
                            await writer.drain()
                            break
                    break

                else:
                    writer.write(
                        json.dumps(
                            {"status": "error", "message": f"Unknown action: {action}"}
                        ).encode("utf-8")
                        + b"\n"
                    )
                    await writer.drain()

        except Exception as e:
            logger.exception("Error handling rootd client: %s", e)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def start(self) -> None:
        if os.path.exists(self.socket_path):
            os.unlink(self.socket_path)

        parent_dir = os.path.dirname(self.socket_path)
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)

        self.server = await asyncio.start_unix_server(
            self.handle_client,
            path=self.socket_path,
        )

        try:
            os.chmod(self.socket_path, 0o600)
        except Exception as e:
            logger.warning("Could not set socket permissions to 0600: %s", e)

        sudo_uid = os.environ.get("SUDO_UID")
        sudo_gid = os.environ.get("SUDO_GID")
        if sudo_uid and sudo_gid:
            try:
                os.chown(self.socket_path, int(sudo_uid), int(sudo_gid))
                logger.info(
                    "Chowned socket %s to UID %s, GID %s", self.socket_path, sudo_uid, sudo_gid
                )
            except Exception as e:
                logger.warning("Could not chown socket: %s", e)

        logger.info("Rootd listening on UNIX socket: %s", self.socket_path)

    async def run(self) -> None:
        await self.start()
        try:
            while True:
                await asyncio.sleep(3600)
        except asyncio.CancelledError:
            pass
        finally:
            await self.shutdown()

    async def shutdown(self) -> None:
        logger.info("Rootd shutting down...")
        if self.server:
            self.server.close()
            await self.server.wait_closed()

        logger.info("Cleaning up namespaces...")
        self.controller.cleanup_all()

        if os.path.exists(self.socket_path):
            os.unlink(self.socket_path)
        logger.info("Rootd shutdown complete.")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="nse-rootd",
        description="Network Sandbox Engine privileged root daemon",
    )
    parser.add_argument(
        "--socket",
        default="/var/run/nse-core.sock",
        help="Unix socket path to listen on (default: /var/run/nse-core.sock)",
    )
    args = parser.parse_args()

    daemon = RootDaemon(socket_path=args.socket)

    loop = asyncio.get_event_loop()

    # Register signals for clean shutdown
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, lambda: asyncio.create_task(daemon.shutdown()))
        except NotImplementedError:
            pass

    try:
        loop.run_until_complete(daemon.run())
    except KeyboardInterrupt:
        pass
    finally:
        loop.close()


if __name__ == "__main__":
    main()
