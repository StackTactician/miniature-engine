"""
mitmproxy addon for API Graph Mapper.

Usage (interactive TUI):
    mitmproxy --listen-port 8080 -s mitm_addon.py

Usage (headless / background):
    mitmdump  --listen-port 8080 -s mitm_addon.py

After starting, set your browser or device proxy to 127.0.0.1:8080.
On first use visit http://mitm.it to install the mitmproxy CA certificate
so HTTPS traffic is intercepted correctly.

Intercepted JSON API responses are streamed to the API Graph Mapper backend
in real time. Open the Proxy tab in the frontend to see the live counter
and click Build Graph when you're done browsing.
"""
from __future__ import annotations

import json
import urllib.request

from mitmproxy import http

INGEST_URL = "http://localhost:8000/ingest"


def _is_json(content_type: str) -> bool:
    return "application/json" in content_type or "text/json" in content_type


class ApiGraphMapper:
    def response(self, flow: http.HTTPFlow) -> None:
        if flow.response is None:
            return

        # Ignore our own API traffic and frontend polling to avoid feedback loops
        if "localhost" in flow.request.pretty_host or "127.0.0.1" in flow.request.pretty_host:
            return

        content_type = flow.response.headers.get("content-type", "")
        if not _is_json(content_type):
            return

        try:
            body = json.loads(flow.response.get_content())
        except Exception:
            return

        req_body = None
        if flow.request.content:
            try:
                req_body = json.loads(flow.request.content)
            except Exception:
                pass

        record = {
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "request_headers": dict(flow.request.headers),
            "request_body": req_body,
            "response_status": flow.response.status_code,
            "response_headers": dict(flow.response.headers),
            "response_body": body,
        }

        try:
            data = json.dumps(record).encode()
            req = urllib.request.Request(
                INGEST_URL,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            # Force bypass of system proxy to prevent mitmproxy from intercepting its own ingest requests
            proxy_handler = urllib.request.ProxyHandler({})
            opener = urllib.request.build_opener(proxy_handler)
            opener.open(req, timeout=2)
            from mitmproxy import ctx
            ctx.log.info(f"Captured API: {flow.request.method} {flow.request.pretty_url}")
        except Exception as e:
            from mitmproxy import ctx
            ctx.log.error(f"Failed to send to API Graph Mapper: {e}")


addons = [ApiGraphMapper()]
