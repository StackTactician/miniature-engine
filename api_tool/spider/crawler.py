"""
Async web crawler and link/asset discovery engine.
Built with pure-Python httpx and beautifulsoup4 (html.parser) for full Termux compatibility.
"""

from __future__ import annotations

import asyncio
import logging
import posixpath
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, unquote, urlencode, urljoin, urlsplit, urlunsplit

import httpx
from bs4 import BeautifulSoup

from api_tool.models import DiscoveredEndpoint, DiscoveredParameter

logger = logging.getLogger(__name__)


# Default tracking query parameters stripped by URLNormalizer
DEFAULT_TRACKING_PARAMS: Set[str] = {
    # Analytics & Ads
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "utm_id",
    "utm_source_platform",
    "utm_creative_format",
    "utm_marketing_tactic",
    "gclid",
    "gclsrc",
    "dclid",
    "wbraid",
    "gbraid",
    "fbclid",
    "fbadid",
    "twclid",
    "msclkid",
    "zanpid",
    "yclid",
    # Marketing automation / email
    "_hsenc",
    "_hsmi",
    "mc_cid",
    "mc_eid",
    "mkt_tok",
    "igshid",
    # Referral / session
    "ref",
    "referrer",
    "affiliate",
    "aff_id",
    "source",
}

# Non-HTML static asset extensions that should not be recursively crawled
STATIC_ASSET_EXTENSIONS: Set[str] = {
    "png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "bmp", "avif",
    "woff", "woff2", "ttf", "eot", "otf",
    "mp4", "webm", "ogg", "mp3", "wav", "flac",
    "pdf", "zip", "tar", "gz", "rar", "7z", "iso",
    "css", "map",
}


class URLNormalizer:
    """
    Normalizes URLs, strips tracking query parameters, and detects infinite path loops.
    """

    def __init__(self, tracking_params: Optional[Set[str]] = None) -> None:
        self.tracking_params = {p.lower() for p in (tracking_params or DEFAULT_TRACKING_PARAMS)}

    def normalize(self, url: str, base_url: Optional[str] = None) -> str:
        """
        Normalize URL:
        - Resolve relative URLs against base_url
        - Scheme and host lowercasing
        - Default port removal (:80, :443)
        - Collapse multiple slashes in path
        - Remove tracking query parameters and sort remaining query parameters
        - Strip client-side fragments (#...)
        """
        if not url:
            return ""

        url = url.strip()

        # Resolve relative URLs
        if base_url:
            url = urljoin(base_url, url)

        parsed = urlsplit(url)

        # Only handle http/https
        scheme = parsed.scheme.lower()
        if scheme not in ("http", "https"):
            return ""

        netloc = parsed.netloc.lower()
        if not netloc:
            return ""

        # Remove default ports
        if ":" in netloc:
            host, _, port = netloc.partition(":")
            if (scheme == "http" and port == "80") or (scheme == "https" and port == "443"):
                netloc = host

        # Normalize path
        raw_path = parsed.path or "/"
        # Replace multiple consecutive slashes with single slash
        raw_path = re.sub(r"/{2,}", "/", raw_path)

        # Preserve trailing slash indicator before normpath
        has_trailing_slash = raw_path.endswith("/") and raw_path != "/"

        # Resolve . and .. in path
        normalized_path = posixpath.normpath(raw_path)
        if normalized_path == ".":
            normalized_path = "/"
        elif has_trailing_slash and not normalized_path.endswith("/"):
            normalized_path += "/"

        # Filter query params
        query_items = parse_qsl(parsed.query, keep_blank_values=True)
        filtered_query = [
            (k, v) for k, v in query_items
            if k.lower() not in self.tracking_params
        ]
        # Sort query keys and values for canonical representation
        filtered_query.sort(key=lambda item: (item[0], item[1]))
        new_query = urlencode(filtered_query)

        # Fragment is stripped
        return urlunsplit((scheme, netloc, normalized_path, new_query, ""))

    def is_loop(
        self,
        url: str,
        max_segment_repeats: int = 3,
        max_depth: int = 15,
        max_cycle_repeats: int = 2,
    ) -> bool:
        """
        Detect path repetition loops (e.g. /blog/blog/blog/..., /en/en/en/..., /a/b/a/b/a/b).
        Returns True if a loop or excessive depth is detected.
        """
        parsed = urlsplit(url)
        segments = [s for s in parsed.path.split("/") if s]

        if len(segments) > max_depth:
            return True

        # Check single segment occurrence count
        counts = defaultdict(int)
        for s in segments:
            counts[s] += 1
            if counts[s] > max_segment_repeats:
                return True

        # Check cyclic patterns like [a, b, a, b, a, b]
        n = len(segments)
        for cycle_len in range(1, (n // (max_cycle_repeats + 1)) + 1):
            for start in range(n - cycle_len * (max_cycle_repeats + 1) + 1):
                pattern = segments[start:start + cycle_len]
                match_count = 1
                pos = start + cycle_len
                while pos + cycle_len <= n and segments[pos:pos + cycle_len] == pattern:
                    match_count += 1
                    pos += cycle_len
                if match_count > max_cycle_repeats:
                    return True

        return False

    @staticmethod
    def is_same_domain(url: str, base_url_or_domain: str, allow_subdomains: bool = True) -> bool:
        """
        Check if url belongs to the same domain as base_url_or_domain.
        """
        parsed_target = urlsplit(url)
        target_host = parsed_target.netloc.split(":")[0].lower()

        if "://" in base_url_or_domain:
            base_host = urlsplit(base_url_or_domain).netloc.split(":")[0].lower()
        else:
            base_host = base_url_or_domain.split(":")[0].lower()

        if not target_host or not base_host:
            return False

        if target_host == base_host:
            return True

        if allow_subdomains:
            return target_host.endswith("." + base_host)

        return False

    @staticmethod
    def is_static_asset(url: str) -> bool:
        """
        Returns True if the URL points to a static media/font/binary asset.
        """
        path = urlsplit(url).path.lower()
        if "." in path:
            ext = path.rsplit(".", 1)[-1]
            return ext in STATIC_ASSET_EXTENSIONS
        return False


class RoutePatternCollapser:
    """
    Collapses dynamic path parameters in URLs into route patterns (e.g. /users/123 -> /users/{id})
    to limit crawling cardinality and prevent combinatorial explosion.
    """

    # Regex patterns for matching common dynamic ID segments
    UUID_PATTERN = re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        re.IGNORECASE,
    )
    HEX_HASH_PATTERN = re.compile(r"^[0-9a-f]{24,64}$", re.IGNORECASE)  # MongoDB ObjectId / hashes
    INT_PATTERN = re.compile(r"^\d+$")
    DATE_SEGMENT_PATTERN = re.compile(r"^(19|20)\d{2}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])$")
    SLUG_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]+-(\d{3,})$")  # e.g., post-slug-98765

    @classmethod
    def collapse_segment(cls, segment: str) -> str:
        """Collapse a single path segment if it matches a dynamic pattern."""
        if not segment:
            return ""
        if cls.INT_PATTERN.match(segment):
            return "{id}"
        if cls.UUID_PATTERN.match(segment):
            return "{uuid}"
        if cls.HEX_HASH_PATTERN.match(segment):
            return "{hex_id}"
        if cls.DATE_SEGMENT_PATTERN.match(segment):
            return "{date}"
        if cls.SLUG_ID_PATTERN.match(segment):
            return "{slug_id}"
        return segment

    @classmethod
    def collapse_path(cls, path: str) -> str:
        """
        Collapses a path into a canonical route template.
        Example: /api/v1/users/42/orders/a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d
              -> /api/v1/users/{id}/orders/{uuid}
        """
        if not path or path == "/":
            return "/"

        segments = path.split("/")
        collapsed = [cls.collapse_segment(seg) for seg in segments]
        return "/".join(collapsed)

    @classmethod
    def collapse_url(cls, url: str) -> str:
        """Returns collapsed template for the URL (ignoring scheme/host/query)."""
        parsed = urlsplit(url)
        return cls.collapse_path(parsed.path)


@dataclass
class DiscoveredAsset:
    url: str
    asset_type: str  # "script", "preload", "prefetch", "modulepreload", "style", "image", "other"
    tag_name: str
    attributes: Dict[str, str] = field(default_factory=dict)


@dataclass
class CrawlResult:
    target_url: str
    endpoints: List[DiscoveredEndpoint] = field(default_factory=list)
    scripts: List[str] = field(default_factory=list)
    assets: List[str] = field(default_factory=list)
    visited_urls: List[str] = field(default_factory=list)
    failed_urls: Dict[str, str] = field(default_factory=dict)
    template_counts: Dict[str, int] = field(default_factory=dict)
    rate_limited_count: int = 0
    total_backoff_seconds: float = 0.0


class AsyncSpider:
    """
    High-performance async web crawler for discovering API endpoints, routes, and scripts.
    Pure Python httpx + BeautifulSoup, fully compatible with Termux.
    """

    def __init__(
        self,
        allowed_domains: Optional[List[str]] = None,
        max_depth: int = 3,
        max_pages: int = 50,
        concurrency: int = 5,
        max_per_template: int = 3,
        request_timeout: float = 10.0,
        max_retries: int = 3,
        backoff_factor: float = 1.0,
        max_backoff_delay: float = 60.0,
        user_agent: str = (
            "Mozilla/5.0 (Linux; Android 10; Mobile) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36 api-tool/0.1.0"
        ),
        custom_headers: Optional[Dict[str, str]] = None,
        client: Optional[httpx.AsyncClient] = None,
    ) -> None:
        self.allowed_domains = allowed_domains or []
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.concurrency = concurrency
        self.max_per_template = max_per_template
        self.request_timeout = request_timeout
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.max_backoff_delay = max_backoff_delay
        self.user_agent = user_agent
        self.custom_headers = custom_headers or {}
        self._external_client = client

        self.normalizer = URLNormalizer()
        self.collapser = RoutePatternCollapser()

    def _parse_retry_after(self, retry_after: Optional[str], default_delay: float = 1.0) -> float:
        """
        Parses the Retry-After HTTP header value.
        Supports integer/float seconds and HTTP-date strings (RFC 7231 / RFC 9110).
        """
        if not retry_after:
            return default_delay

        clean_val = retry_after.strip()
        # 1. Try numeric seconds (integer or float)
        try:
            val = float(clean_val)
            return max(0.0, val)
        except ValueError:
            pass

        # 2. Try HTTP-date format
        try:
            import email.utils
            from datetime import datetime, timezone
            dt = email.utils.parsedate_to_datetime(clean_val)
            now = datetime.now(timezone.utc)
            delta = (dt - now).total_seconds()
            return max(0.0, delta)
        except Exception:
            pass

        return default_delay

    def _extract_links_and_assets(
        self, html: str, page_url: str
    ) -> Tuple[List[str], List[str], List[str]]:
        """
        Parses HTML and extracts:
        1. Anchor links (<a href>)
        2. Script URLs (<script src>)
        3. Preloaded assets (<link rel="preload|modulepreload|prefetch" href>)
        """
        links: List[str] = []
        scripts: List[str] = []
        assets: List[str] = []

        try:
            soup = BeautifulSoup(html, "html.parser")
        except Exception as e:
            logger.debug("Failed to parse HTML for %s: %s", page_url, e)
            return links, scripts, assets

        # 1. <script src="...">
        for script in soup.find_all("script"):
            src = script.get("src")
            if src:
                norm_src = self.normalizer.normalize(src, base_url=page_url)
                if norm_src:
                    scripts.append(norm_src)

        # 2. <link rel="...">
        for link in soup.find_all("link"):
            href = link.get("href")
            if not href:
                continue

            rel_attr = link.get("rel", [])
            rel_list = [r.lower() for r in (rel_attr if isinstance(rel_attr, list) else [rel_attr])]
            norm_href = self.normalizer.normalize(href, base_url=page_url)
            if not norm_href:
                continue

            if any(r in rel_list for r in ("preload", "prefetch", "modulepreload")):
                as_type = link.get("as", "").lower()
                if as_type == "script" or norm_href.endswith(".js"):
                    scripts.append(norm_href)
                else:
                    assets.append(norm_href)
            elif "stylesheet" in rel_list:
                assets.append(norm_href)

        # 3. <a href="...">
        for a in soup.find_all("a"):
            href = a.get("href")
            if not href:
                continue

            # Ignore javascript:, mailto:, tel:, # fragments
            href_clean = href.strip()
            if href_clean.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
                continue

            norm_link = self.normalizer.normalize(href_clean, base_url=page_url)
            if norm_link and not self.normalizer.is_static_asset(norm_link):
                links.append(norm_link)

        # 4. Form actions (<form action="...">)
        for form in soup.find_all("form"):
            action = form.get("action")
            if action:
                norm_action = self.normalizer.normalize(action, base_url=page_url)
                if norm_action:
                    links.append(norm_action)

        return links, scripts, assets

    async def crawl(self, start_url: str) -> CrawlResult:
        """
        Crawl target starting from start_url.
        Limits cardinality using route pattern templates and anti-loop detection.
        """
        norm_start = self.normalizer.normalize(start_url)
        if not norm_start:
            raise ValueError(f"Invalid start URL: {start_url}")

        start_parsed = urlsplit(norm_start)
        base_domain = start_parsed.netloc.split(":")[0]
        if not self.allowed_domains:
            self.allowed_domains = [base_domain]

        headers = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,application/json;q=0.8,*/*;q=0.7",
            "Accept-Language": "en-US,en;q=0.9",
            **self.custom_headers,
        }

        result = CrawlResult(target_url=norm_start)
        visited_urls: Set[str] = set()
        queued_urls: Set[str] = {norm_start}
        discovered_scripts: Set[str] = set()
        discovered_assets: Set[str] = set()
        discovered_endpoints: List[DiscoveredEndpoint] = []
        template_counts: Dict[str, int] = defaultdict(int)

        # Queue entries: (url, depth)
        queue: asyncio.Queue[Tuple[str, int]] = asyncio.Queue()
        start_template = self.collapser.collapse_url(norm_start)
        template_counts[start_template] += 1
        await queue.put((norm_start, 0))

        client_provided = self._external_client is not None
        client = self._external_client or httpx.AsyncClient(
            headers=headers,
            timeout=httpx.Timeout(self.request_timeout),
            follow_redirects=True,
            verify=False,
            limits=httpx.Limits(max_keepalive_connections=10, max_connections=self.concurrency),
        )

        semaphore = asyncio.Semaphore(self.concurrency)

        active_workers = 0

        async def worker() -> None:
            nonlocal active_workers
            while True:
                try:
                    url, depth = await asyncio.wait_for(queue.get(), timeout=0.05)
                except asyncio.TimeoutError:
                    if active_workers == 0:
                        break
                    continue

                active_workers += 1
                try:
                    if len(visited_urls) >= self.max_pages:
                        break

                    visited_urls.add(url)

                    async with semaphore:
                        try:
                            retries_left = self.max_retries
                            attempt = 0
                            while True:
                                resp = await client.get(url, follow_redirects=True)
                                if resp.status_code == 429 and retries_left > 0:
                                    retries_left -= 1
                                    attempt += 1
                                    raw_retry_after = resp.headers.get("retry-after")
                                    backoff = self._parse_retry_after(
                                        raw_retry_after,
                                        default_delay=self.backoff_factor * (2 ** (attempt - 1)),
                                    )
                                    backoff = min(backoff, self.max_backoff_delay)
                                    result.rate_limited_count += 1
                                    result.total_backoff_seconds += backoff
                                    logger.warning(
                                        "Rate-limited (HTTP 429) for %s. Backing off for %.2fs (attempt %d/%d).",
                                        url,
                                        backoff,
                                        attempt,
                                        self.max_retries,
                                    )
                                    await asyncio.sleep(backoff)
                                    continue
                                break

                            status_code = resp.status_code
                            content_type = resp.headers.get("content-type", "").lower()
                        except httpx.TooManyRedirects as loop_err:
                            logger.warning("Redirect loop detected for %s: %s", url, loop_err)
                            result.failed_urls[url] = f"Redirect loop detected: {loop_err}"
                            continue
                        except Exception as req_err:
                            result.failed_urls[url] = str(req_err)
                            continue

                    # Record as endpoint
                    parsed = urlsplit(url)
                    base_url = f"{parsed.scheme}://{parsed.netloc}"
                    path_with_query = parsed.path or "/"
                    if parsed.query:
                        path_with_query += f"?{parsed.query}"

                    # Extract query parameters for the model
                    query_params: List[DiscoveredParameter] = []
                    if parsed.query:
                        for q_key, q_val in parse_qsl(parsed.query, keep_blank_values=True):
                            query_params.append(
                                DiscoveredParameter(
                                    name=q_key,
                                    location="query",
                                    example=q_val,
                                    param_type="string",
                                )
                            )

                    endpoint = DiscoveredEndpoint(
                        path=path_with_query,
                        method="GET",
                        base_url=base_url,
                        source="crawler",
                        parameters=query_params,
                        active_status=status_code,
                    )
                    discovered_endpoints.append(endpoint)

                    # Only parse HTML responses
                    if "text/html" in content_type:
                        html_text = resp.text
                        links, scripts, assets = self._extract_links_and_assets(html_text, url)

                        for s in scripts:
                            discovered_scripts.add(s)
                        for a in assets:
                            discovered_assets.add(a)

                        # Enqueue unvisited links if within depth and template limit
                        if depth + 1 <= self.max_depth:
                            for link in links:
                                if link in visited_urls or link in queued_urls:
                                    continue

                                # Scope check
                                in_scope = any(
                                    self.normalizer.is_same_domain(link, d)
                                    for d in self.allowed_domains
                                )
                                if not in_scope:
                                    continue

                                # Anti-loop check
                                if self.normalizer.is_loop(link):
                                    continue

                                # Cardinality template check
                                link_template = self.collapser.collapse_url(link)
                                if template_counts[link_template] >= self.max_per_template:
                                    continue

                                template_counts[link_template] += 1
                                queued_urls.add(link)
                                await queue.put((link, depth + 1))

                finally:
                    active_workers -= 1
                    queue.task_done()

        try:
            workers = [asyncio.create_task(worker()) for _ in range(self.concurrency)]
            await asyncio.gather(*workers)
        finally:
            if not client_provided:
                await client.aclose()

        result.endpoints = discovered_endpoints
        result.scripts = sorted(list(discovered_scripts))
        result.assets = sorted(list(discovered_assets))
        result.visited_urls = sorted(list(visited_urls))
        result.template_counts = dict(template_counts)

        return result
