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
from api_tool.spider.scope_resolver import CDNScopeResolver
from api_tool.spider.filters import URLFilterEngine
from api_tool.spider.priority_queue import (
    PrioritizedRequest,
    PriorityURLScheduler,
    PurePythonBloomFilter,
    URLScorer,
)
from api_tool.spider.passive_seed import PassiveSeedHarvester
from api_tool.spider.extractors.dom_extractor import DOMExtractor
from api_tool.spider.extractors.form_extractor import FormExtractor
from api_tool.spider.extractors.hydration_extractor import FastHydrationScraper

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
    forms: List[DiscoveredEndpoint] = field(default_factory=list)
    hydration_endpoints: List[DiscoveredEndpoint] = field(default_factory=list)
    passive_seeds: List[str] = field(default_factory=list)
    disallowed_seeds: List[str] = field(default_factory=list)


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
        scope_resolver: Optional[CDNScopeResolver] = None,
        filter_engine: Optional[URLFilterEngine] = None,
        include_regex: Optional[str] = None,
        exclude_regex: Optional[str] = None,
        block_dangerous_actions: bool = True,
        block_rabbit_holes: bool = True,
        allow_private_ips: bool = False,
        crawl_forms: bool = True,
        crawl_hydration: bool = True,
        passive_seeds: bool = False,
        bloom_capacity: int = 1_000_000,
        bloom_fp_rate: float = 0.001,
    ) -> None:
        self.allowed_domains = allowed_domains or []
        self.scope_resolver = scope_resolver
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

        self.filter_engine = filter_engine
        self.include_regex = include_regex
        self.exclude_regex = exclude_regex
        self.block_dangerous_actions = block_dangerous_actions
        self.block_rabbit_holes = block_rabbit_holes
        self.allow_private_ips = allow_private_ips
        self.crawl_forms = crawl_forms
        self.crawl_hydration = crawl_hydration
        self.passive_seeds = passive_seeds
        self.bloom_capacity = bloom_capacity
        self.bloom_fp_rate = bloom_fp_rate

        self.normalizer = URLNormalizer()
        self.collapser = RoutePatternCollapser()
        self.bloom_filter = PurePythonBloomFilter(
            capacity=bloom_capacity, false_positive_rate=bloom_fp_rate
        )
        self.scheduler = PriorityURLScheduler(bloom_filter=self.bloom_filter)

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

        resolver = self.scope_resolver
        if resolver is None:
            targets = list(self.allowed_domains) if self.allowed_domains else [urlsplit(page_url).netloc.split(":")[0]]
            resolver = CDNScopeResolver(target_domains=targets)

        # Dynamically discover CSP from meta tags
        for meta in soup.find_all("meta"):
            http_equiv = meta.get("http-equiv", "").lower()
            if http_equiv in ("content-security-policy", "content-security-policy-report-only"):
                csp_content = meta.get("content")
                if csp_content:
                    resolver.update_from_csp(csp_content)

        # 1. <script src="...">
        for script in soup.find_all("script"):
            src = script.get("src")
            if src:
                norm_src = self.normalizer.normalize(src, base_url=page_url)
                if norm_src and resolver.is_asset_in_scope(norm_src):
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
                    if resolver.is_asset_in_scope(norm_href):
                        scripts.append(norm_href)
                else:
                    if resolver.is_asset_in_scope(norm_href):
                        assets.append(norm_href)
            elif "stylesheet" in rel_list:
                if resolver.is_asset_in_scope(norm_href):
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
                if resolver.is_page_in_scope(norm_link):
                    links.append(norm_link)

        # 4. Form actions (<form action="...">)
        for form in soup.find_all("form"):
            action = form.get("action")
            if action:
                norm_action = self.normalizer.normalize(action, base_url=page_url)
                if norm_action and resolver.is_page_in_scope(norm_action):
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

        if self.scope_resolver is None:
            self.scope_resolver = CDNScopeResolver(target_domains=self.allowed_domains)
        else:
            for d in self.allowed_domains:
                self.scope_resolver.add_target_domain(d)

        if self.filter_engine is None:
            self.filter_engine = URLFilterEngine(
                scope_resolver=self.scope_resolver,
                include_regex=self.include_regex,
                exclude_regex=self.exclude_regex,
                block_dangerous_actions=self.block_dangerous_actions,
                block_rabbit_holes=self.block_rabbit_holes,
                allow_private_ips=self.allow_private_ips,
            )
        elif self.scope_resolver and self.filter_engine.scope_resolver is None:
            self.filter_engine.scope_resolver = self.scope_resolver

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
        discovered_forms: List[DiscoveredEndpoint] = []
        discovered_hydration: List[DiscoveredEndpoint] = []
        template_counts: Dict[str, int] = defaultdict(int)

        # Fresh bloom filter and priority scheduler
        self.bloom_filter.clear()
        self.scheduler = PriorityURLScheduler(bloom_filter=self.bloom_filter)

        self.bloom_filter.add(norm_start)
        start_template = self.collapser.collapse_url(norm_start)
        template_counts[start_template] += 1
        await self.scheduler.push(norm_start, depth=0, template=start_template, template_count=1, source_tag="start_url")

        client_provided = self._external_client is not None
        client = self._external_client or httpx.AsyncClient(
            headers=headers,
            timeout=httpx.Timeout(self.request_timeout),
            follow_redirects=True,
            verify=False,
            limits=httpx.Limits(max_keepalive_connections=10, max_connections=self.concurrency),
        )

        # Passive Seed Harvester phase
        if self.passive_seeds:
            try:
                harvester = PassiveSeedHarvester(client=client, normalizer=self.normalizer)
                passive_seeds_list, disallow_urls_list = await harvester.discover_seeds(
                    norm_start, include_gateway_probes=False
                )
                result.passive_seeds = passive_seeds_list
                result.disallowed_seeds = disallow_urls_list

                # Disallow directives in robots.txt have high API discovery value (+75 score)
                for dis_url in disallow_urls_list:
                    if dis_url in self.bloom_filter or dis_url in queued_urls:
                        continue
                    if not self.filter_engine.should_crawl_page(dis_url):
                        continue
                    t = self.collapser.collapse_url(dis_url)
                    if template_counts[t] >= self.max_per_template:
                        continue
                    template_counts[t] += 1
                    queued_urls.add(dis_url)
                    self.bloom_filter.add(dis_url)
                    await self.scheduler.push(
                        url=dis_url,
                        depth=1,
                        template=t,
                        template_count=template_counts[t],
                        is_disallowed_robots=True,
                        source_tag="robots_disallow",
                    )

                # Sitemap and gateway probes
                for seed_url in passive_seeds_list:
                    if seed_url in self.bloom_filter or seed_url in queued_urls:
                        continue
                    if not self.filter_engine.should_crawl_page(seed_url):
                        continue
                    t = self.collapser.collapse_url(seed_url)
                    if template_counts[t] >= self.max_per_template:
                        continue
                    template_counts[t] += 1
                    queued_urls.add(seed_url)
                    self.bloom_filter.add(seed_url)
                    await self.scheduler.push(
                        url=seed_url,
                        depth=1,
                        template=t,
                        template_count=template_counts[t],
                        source_tag="passive_seed",
                    )
            except Exception as passive_err:
                logger.debug("Passive seed harvesting encountered an error: %s", passive_err)

        semaphore = asyncio.Semaphore(self.concurrency)
        active_workers = 0

        async def worker() -> None:
            nonlocal active_workers
            while True:
                if len(visited_urls) >= self.max_pages:
                    break

                try:
                    req: PrioritizedRequest = await asyncio.wait_for(self.scheduler.pop(), timeout=0.05)
                except asyncio.TimeoutError:
                    if active_workers == 0 and self.scheduler.empty():
                        break
                    continue

                active_workers += 1
                try:
                    url = req.url
                    depth = req.depth

                    if len(visited_urls) >= self.max_pages:
                        break

                    if url in visited_urls:
                        continue

                    visited_urls.add(url)
                    self.bloom_filter.add(url)

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

                            # Dynamically update scope resolver with CSP headers
                            csp_header = resp.headers.get("content-security-policy")
                            if csp_header and self.scope_resolver:
                                self.scope_resolver.update_from_csp(csp_header)
                            csp_report = resp.headers.get("content-security-policy-report-only")
                            if csp_report and self.scope_resolver:
                                self.scope_resolver.update_from_csp(csp_report)
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

                        # Deep DOM, Form, and Hydration extraction
                        try:
                            soup = BeautifulSoup(html_text, "html.parser")
                        except Exception:
                            soup = None

                        dom_candidate_links: List[str] = []
                        if soup is not None:
                            # 1. DOMExtractor (multimedia, frames, data-*, htmx, comments)
                            d_links, d_scripts, d_assets, htmx_eps = DOMExtractor.extract(soup, url)
                            for s in d_scripts:
                                if self.scope_resolver.is_asset_in_scope(s):
                                    discovered_scripts.add(s)
                            for a in d_assets:
                                if self.scope_resolver.is_asset_in_scope(a):
                                    discovered_assets.add(a)
                            for lk in d_links:
                                if not self.normalizer.is_static_asset(lk) and self.scope_resolver.is_page_in_scope(lk):
                                    dom_candidate_links.append(lk)

                            for h_url, h_verb in htmx_eps:
                                p_h = urlsplit(h_url)
                                h_base = f"{p_h.scheme}://{p_h.netloc}" if p_h.netloc else base_url
                                ep = DiscoveredEndpoint(
                                    path=p_h.path or "/",
                                    method=h_verb,
                                    base_url=h_base,
                                    source="crawler",
                                    tags=["htmx", h_verb.lower()],
                                    summary=f"HTMX {h_verb} endpoint: {h_url}",
                                )
                                discovered_endpoints.append(ep)
                                if h_verb == "GET" and self.scope_resolver.is_page_in_scope(h_url):
                                    dom_candidate_links.append(h_url)

                            # 2. FormExtractor (inputs, dummy payloads, method overrides)
                            if self.crawl_forms:
                                form_eps = FormExtractor.extract(soup, url)
                                for f_ep in form_eps:
                                    discovered_forms.append(f_ep)
                                    discovered_endpoints.append(f_ep)
                                    if f_ep.method == "GET" and f_ep.full_url:
                                        if self.scope_resolver.is_page_in_scope(f_ep.full_url):
                                            dom_candidate_links.append(f_ep.full_url)

                        # 3. FastHydrationScraper (Next.js App/Pages, Nuxt 3, Remix, SvelteKit)
                        if self.crawl_hydration:
                            hydration_eps = FastHydrationScraper.extract_all(html_text, url)
                            for hyd_ep in hydration_eps:
                                discovered_hydration.append(hyd_ep)
                                discovered_endpoints.append(hyd_ep)
                                if hyd_ep.method == "GET" and hyd_ep.path and "{" not in hyd_ep.path:
                                    hyd_url = urljoin(url, hyd_ep.path)
                                    if self.scope_resolver.is_page_in_scope(hyd_url) and not self.normalizer.is_static_asset(hyd_url):
                                        dom_candidate_links.append(hyd_url)

                        all_candidate_links = list(dict.fromkeys(links + dom_candidate_links))

                        # Enqueue unvisited links if within depth and template limit
                        if depth + 1 <= self.max_depth:
                            for link in all_candidate_links:
                                if link in visited_urls or link in queued_urls or link in self.bloom_filter:
                                    continue

                                # Scope and safety filter check
                                if not self.filter_engine.should_crawl_page(link):
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
                                self.bloom_filter.add(link)
                                await self.scheduler.push(
                                    url=link,
                                    depth=depth + 1,
                                    template=link_template,
                                    template_count=template_counts[link_template],
                                    source_tag="crawler",
                                )

                finally:
                    active_workers -= 1
                    self.scheduler.task_done()

        try:
            workers = [asyncio.create_task(worker()) for _ in range(self.concurrency)]
            await asyncio.gather(*workers)
        finally:
            if not client_provided:
                await client.aclose()

        # Deduplicate endpoints by (method, base_url, path) and merge rich metadata
        deduped_endpoints: Dict[Tuple[str, str, str], DiscoveredEndpoint] = {}
        for ep in discovered_endpoints:
            norm_path = ep.path or "/"
            clean_base = ep.base_url.rstrip("/") if ep.base_url else ""
            key = (ep.method.upper(), clean_base, norm_path)
            if key not in deduped_endpoints:
                deduped_endpoints[key] = ep
            else:
                existing = deduped_endpoints[key]
                for tag in ep.tags:
                    if tag not in existing.tags:
                        existing.tags.append(tag)
                if ep.headers:
                    existing.headers.update(ep.headers)
                if ep.request_body_sample and not existing.request_body_sample:
                    existing.request_body_sample = ep.request_body_sample
                existing_param_names = {p.name for p in existing.parameters}
                for p in ep.parameters:
                    if p.name not in existing_param_names:
                        existing.parameters.append(p)
                        existing_param_names.add(p.name)
                if existing.active_status is None and ep.active_status is not None:
                    existing.active_status = ep.active_status

        result.endpoints = list(deduped_endpoints.values())
        result.forms = discovered_forms
        result.hydration_endpoints = discovered_hydration
        result.scripts = sorted(list(discovered_scripts))
        result.assets = sorted(list(discovered_assets))
        result.visited_urls = sorted(list(visited_urls))
        result.template_counts = dict(template_counts)

        return result

    async def fetch_chunks(self, chunk_urls: List[str]) -> Dict[str, str]:
        """
        Concurrently downloads newly discovered chunk scripts using configured rate-limits and backoff.
        Returns mapping of chunk_url -> script_content for successfully downloaded chunks.
        """
        if not chunk_urls:
            return {}

        # Deduplicate and filter out out-of-scope assets if scope_resolver is available
        unique_urls: List[str] = []
        seen: Set[str] = set()
        for u in chunk_urls:
            norm_u = self.normalizer.normalize(u)
            if not norm_u or norm_u in seen:
                continue
            seen.add(norm_u)
            if self.scope_resolver and not self.scope_resolver.is_asset_in_scope(norm_u):
                logger.debug("Skipping out-of-scope chunk URL: %s", norm_u)
                continue
            unique_urls.append(norm_u)

        if not unique_urls:
            return {}

        results: Dict[str, str] = {}
        headers = {
            "User-Agent": self.user_agent,
            "Accept": "*/*",
            **self.custom_headers,
        }

        client_provided = self._external_client is not None
        client = self._external_client or httpx.AsyncClient(
            headers=headers,
            timeout=httpx.Timeout(self.request_timeout),
            follow_redirects=True,
            verify=False,
            limits=httpx.Limits(max_keepalive_connections=10, max_connections=self.concurrency),
        )

        semaphore = asyncio.Semaphore(self.concurrency)

        async def fetch_single(url: str) -> None:
            async with semaphore:
                retries_left = self.max_retries
                attempt = 0
                while True:
                    try:
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
                            logger.warning(
                                "Rate-limited (HTTP 429) fetching chunk %s. Backing off for %.2fs (attempt %d/%d).",
                                url,
                                backoff,
                                attempt,
                                self.max_retries,
                            )
                            await asyncio.sleep(backoff)
                            continue

                        if resp.status_code == 200:
                            results[url] = resp.text
                        else:
                            logger.debug("Failed to fetch chunk %s: status %d", url, resp.status_code)
                        break
                    except Exception as req_err:
                        if retries_left > 0:
                            retries_left -= 1
                            attempt += 1
                            backoff = min(self.backoff_factor * (2 ** (attempt - 1)), self.max_backoff_delay)
                            logger.warning(
                                "Request error fetching chunk %s: %s. Backing off for %.2fs.",
                                url,
                                req_err,
                                backoff,
                            )
                            await asyncio.sleep(backoff)
                            continue
                        logger.debug("Giving up on chunk %s: %s", url, req_err)
                        break

        try:
            tasks = [asyncio.create_task(fetch_single(u)) for u in unique_urls]
            await asyncio.gather(*tasks)
        finally:
            if not client_provided:
                await client.aclose()

        return results
