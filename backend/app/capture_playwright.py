from __future__ import annotations

import json
import logging
from collections.abc import Callable

from playwright.sync_api import Response as PlaywrightResponse
from playwright.sync_api import sync_playwright

from app.models import TrafficRecord

logger = logging.getLogger(__name__)

_INTERCEPT_TYPES = {"fetch", "xhr"}
ProgressCallback = Callable[[str], None]


def _is_json(response: PlaywrightResponse) -> bool:
    content_type = response.headers.get("content-type", "")
    return "application/json" in content_type or "text/json" in content_type


def _parse_json_safe(text: str | None) -> object:
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        return None


def capture(
    url: str,
    timeout_ms: int = 20_000,
    on_progress: ProgressCallback | None = None,
) -> list[TrafficRecord]:
    """
    Launch a headless Chromium browser, navigate to `url`, and collect all
    XHR/fetch responses that return JSON. Returns a list of TrafficRecord objects.

    Uses a two-phase spider:
      1. Navigate and wait for network idle (catches initial SPA load requests).
      2. Scroll to bottom and wait briefly (catches lazy-loaded/paginated requests).
    """
    import sys
    import asyncio
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

    records: list[TrafficRecord] = []

    if on_progress:
        on_progress("Launching headless Chromium...")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        seen = 0

        def handle_response(response: PlaywrightResponse) -> None:
            nonlocal seen
            if response.request.resource_type not in _INTERCEPT_TYPES:
                return
            if not _is_json(response):
                return
            try:
                body = response.json()
            except Exception:
                return

            records.append(
                TrafficRecord(
                    method=response.request.method,
                    url=response.url,
                    request_headers=dict(response.request.headers),
                    request_body=_parse_json_safe(response.request.post_data),
                    response_status=response.status,
                    response_headers=dict(response.headers),
                    response_body=body,
                )
            )
            seen += 1
            if on_progress and seen % 5 == 0:
                on_progress(f"Captured {seen} JSON responses...")

        page.on("response", handle_response)

        try:
            if on_progress:
                on_progress("Navigating to target URL...")
            page.goto(url, wait_until="networkidle", timeout=timeout_ms)
            if on_progress:
                on_progress("Triggering lazy-loaded requests...")
            # Scroll to trigger lazy-loaded / infinite-scroll API calls.
            page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            page.wait_for_timeout(2_000)
        except Exception as exc:
            # Navigation timeout is expected on slow/heavy SPAs — return what we caught.
            logger.warning("Navigation ended early for %s: %s", url, exc)
        finally:
            browser.close()

    if on_progress:
        on_progress(f"Capture complete. Collected {len(records)} JSON responses.")

    return records
