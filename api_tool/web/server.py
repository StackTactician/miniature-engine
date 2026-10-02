"""
Lightweight HTTP Server for api-tool Web Interface.
Pure Python standard library (http.server.ThreadingHTTPServer + asyncio background loop).
Zero external web framework dependencies.
"""

from __future__ import annotations

import asyncio
import http.server
import json
import logging
import os
import pathlib
import sys
import threading
import time
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlparse

from api_tool.web.runner import ScanRunner

logger = logging.getLogger(__name__)

STATIC_DIR = pathlib.Path(__file__).parent / "static"


class BackgroundAsyncLoop:
    """Manages a dedicated background thread running an asyncio event loop for scan tasks."""

    def __init__(self) -> None:
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._run, daemon=True, name="api-tool-async")
        self.thread.start()

    def _run(self) -> None:
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def submit(self, coro: Any) -> asyncio.Future:
        return asyncio.run_coroutine_threadsafe(coro, self.loop)

    def stop(self) -> None:
        self.loop.call_soon_threadsafe(self.loop.stop)


class APIToolHandler(http.server.BaseHTTPRequestHandler):
    """Handles REST API calls and serves static frontend assets."""

    server_runner: ScanRunner
    async_loop: BackgroundAsyncLoop

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress noisy standard HTTP access logs from polluting stdout
        pass

    def _send_json(self, data: Any, status: int = 200) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, message: str, status: int = 400) -> None:
        self._send_json({"error": message}, status=status)

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, HEAD")
        self.end_headers()

    def do_HEAD(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        # Static assets
        if path in ("/", "/index.html"):
            index_file = STATIC_DIR / "index.html"
            if not index_file.exists():
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"index.html not found.")
                return

            with open(index_file, "rb") as f:
                content = f.read()

            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return

        # API Endpoints
        if path == "/api/status":
            self._send_json(self.server_runner.get_status())
            return

        if path == "/api/results":
            self._send_json(self.server_runner.get_results())
            return

        if path == "/api/logs":
            offset = 0
            if "offset" in query and query["offset"]:
                try:
                    offset = int(query["offset"][0])
                except ValueError:
                    offset = 0
            logs = self.server_runner.get_logs(offset)
            self._send_json({
                "logs": logs,
                "next_offset": offset + len(logs),
                "total": len(self.server_runner.logs),
                "status": self.server_runner.status,
            })
            return

        if path == "/api/logs/stream":
            # Server-Sent Events (SSE) log streaming
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()

            offset = 0
            try:
                while True:
                    new_logs = self.server_runner.get_logs(offset)
                    if new_logs:
                        for entry in new_logs:
                            payload = f"data: {json.dumps(entry)}\n\n".encode("utf-8")
                            self.wfile.write(payload)
                        self.wfile.flush()
                        offset += len(new_logs)

                    if self.server_runner.status in ("completed", "error", "stopped") and offset >= len(self.server_runner.logs):
                        status_event = f"event: status\ndata: {json.dumps(self.server_runner.get_status())}\n\n".encode("utf-8")
                        self.wfile.write(status_event)
                        self.wfile.flush()
                        break

                    time.sleep(0.25)
            except (BrokenPipeError, ConnectionResetError):
                pass
            return

        self._send_error(f"Path not found: {path}", status=404)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        # Read JSON body
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = b""
        if content_length > 0:
            post_data = self.rfile.read(content_length)

        payload: Dict[str, Any] = {}
        if post_data:
            try:
                payload = json.loads(post_data.decode("utf-8"))
            except Exception as e:
                self._send_error(f"Invalid JSON payload: {e}", status=400)
                return

        if path == "/api/scan":
            target_url = payload.get("url", "").strip()
            if not target_url:
                self._send_error("Parameter 'url' is required.", status=400)
                return

            if self.server_runner.status == "running":
                self._send_error("A scan is already in progress. Stop it first.", status=409)
                return

            options = payload.get("options", {})

            # Launch scan in background asyncio loop
            coro = self.server_runner.run(target_url, options)
            future = self.async_loop.submit(coro)
            self.server_runner.active_task = future  # type: ignore

            self._send_json({
                "message": "Scan initiated",
                "target_url": target_url,
                "status": "running",
            })
            return

        if path == "/api/stop":
            stopped = self.server_runner.stop_scan()
            self._send_json({"stopped": stopped, "status": self.server_runner.status})
            return

        if path == "/api/clear":
            self.server_runner.clear()
            self._send_json({"cleared": True, "status": self.server_runner.status})
            return

        self._send_error(f"Unknown API endpoint: {path}", status=404)


class WebAppServer:
    """Wrapper that starts and manages the ThreadingHTTPServer and background asyncio loop."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8000) -> None:
        self.host = host
        self.port = port
        self.runner = ScanRunner()
        self.async_loop = BackgroundAsyncLoop()

        # Bind runner and loop to Handler class
        APIToolHandler.server_runner = self.runner
        APIToolHandler.async_loop = self.async_loop

        self.httpd = http.server.ThreadingHTTPServer((self.host, self.port), APIToolHandler)
        self.actual_port = self.httpd.server_port
        self._server_thread: Optional[threading.Thread] = None

    def start(self, block: bool = True) -> None:
        """Starts the server. If block=False, runs in a daemon thread."""
        logger.info(f"API Tool UI Server starting at http://{self.host}:{self.actual_port}")
        if block:
            try:
                self.httpd.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                self.stop()
        else:
            self._server_thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
            self._server_thread.start()

    def stop(self) -> None:
        self.runner.stop_scan()
        self.httpd.shutdown()
        self.httpd.server_close()
        self.async_loop.stop()


def run_server(host: str = "127.0.0.1", port: int = 8000) -> None:
    server = WebAppServer(host=host, port=port)
    print(f"\n=======================================================")
    print(f"  MINIATURE ENGINE // WEB INTERFACE")
    print(f"  URL: http://{host}:{server.actual_port}/")
    print(f"=======================================================\n")
    server.start(block=True)


if __name__ == "__main__":
    h = "127.0.0.1"
    p = 8000
    if len(sys.argv) > 1:
        for arg in sys.argv[1:]:
            if arg.startswith("--port="):
                p = int(arg.split("=")[1])
            elif arg.startswith("--host="):
                h = arg.split("=")[1]
    run_server(host=h, port=p)
