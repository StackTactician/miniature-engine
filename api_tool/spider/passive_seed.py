"""
Passive Seed and Gateway Harvester for api-tool spider.

Discovers high-value seed URLs passively from:
1. robots.txt Disallow directives (high-priority hidden paths/endpoints),
   Sitemap directives, and Crawl-delay directives.
2. Low-memory streaming XML Sitemap parser (linear byte-regex scan over raw bytes,
   avoiding heavy DOM parsing, with auto-decompression for .xml.gz and recursive
   <sitemapindex> traversal).
3. Standard well-known and API gateway candidate probes.

Pure Python 3, Termux-compatible, zero C-dependencies.
"""

from __future__ import annotations

import gzip
import html
import logging
import re
from typing import Any, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlsplit

logger = logging.getLogger(__name__)

# Linear byte regex scanning over raw response bytes (strictly O(N), no backtracking)
LOC_BYTE_REGEX: re.Pattern[bytes] = re.compile(
    rb"<loc>\s*(https?://[^<\s]+)\s*</loc>",
    re.IGNORECASE,
)
CDATA_LOC_BYTE_REGEX: re.Pattern[bytes] = re.compile(
    rb"<loc>\s*<!\[CDATA\[\s*(https?://[^<\s\]]+)\s*\]\]>\s*</loc>",
    re.IGNORECASE,
)
SITEMAP_INDEX_REGEX: re.Pattern[bytes] = re.compile(
    rb"<sitemapindex[\s>]",
    re.IGNORECASE,
)

# Standard Well-Known and API Gateway Seed Probes
STANDARD_GATEWAY_PROBES: List[str] = [
    "/.well-known/security.txt",
    "/.well-known/openid-configuration",
    "/.well-known/assetlinks.json",
    "/.well-known/apple-app-site-association",
    "/openapi.json",
    "/swagger.json",
    "/v3/api-docs",
    "/api-docs",
]


class PassiveSeedHarvester:
    """
    Passive Seed and Gateway Harvester.

    Discovers seed endpoints from robots.txt, streaming sitemap parsers,
    and standard API gateway / well-known discovery probes.
    """

    def __init__(self, client: Any = None, normalizer: Any = None) -> None:
        """
        Initialize harvester.

        Args:
            client: Optional httpx.AsyncClient or compatible async HTTP client.
            normalizer: Optional URLNormalizer or object with normalize(url, base_url).
        """
        self.client = client
        self.normalizer = normalizer

        # State tracked during harvest
        self.crawl_delay: Optional[float] = None
        self.disallow_urls: List[str] = []
        self.sitemap_urls: List[str] = []
        self.allow_urls: List[str] = []

    def _normalize_url(self, url: str, base_url: Optional[str] = None) -> str:
        """Helper to normalize a URL using the configured normalizer or urljoin."""
        if not url:
            return ""
        if self.normalizer and hasattr(self.normalizer, "normalize"):
            return self.normalizer.normalize(url, base_url=base_url)
        if base_url:
            return urljoin(base_url, url)
        return url

    def parse_robots_txt(
        self,
        content: str | bytes,
        base_url: str,
    ) -> Tuple[List[str], List[str], Optional[float]]:
        """
        Parse robots.txt content.

        Extracts:
        - Disallow directives: strips trailing wildcards (*) and anchors ($),
          normalizing against target base URL as high-priority seed candidates.
        - Sitemap directives: extracts Sitemap URLs.
        - Crawl-delay directives: extracts optional integer/float crawl delay.

        Returns:
            (disallow_urls, sitemap_urls, crawl_delay)
        """
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="replace")

        # Strip optional UTF-8 BOM
        content = content.lstrip("\ufeff")

        disallow_urls: List[str] = []
        sitemap_urls: List[str] = []
        allow_urls: List[str] = []
        crawl_delay: Optional[float] = None

        current_user_agent = "*"

        for raw_line in content.splitlines():
            # Strip comments and surrounding whitespace
            line = raw_line.split("#", 1)[0].strip()
            if not line or ":" not in line:
                continue

            directive, _, value = line.partition(":")
            directive = directive.strip().lower()
            val = value.strip()

            if directive == "user-agent":
                current_user_agent = val.lower()

            elif directive == "disallow":
                if not val:
                    # Empty Disallow means "allow all", skip
                    continue

                # Strip trailing wildcards (*) and anchors ($)
                cleaned_path = re.sub(r"[\*\$]+$", "", val).strip()
                if not cleaned_path:
                    continue

                normalized = self._normalize_url(cleaned_path, base_url=base_url)
                if normalized and normalized not in disallow_urls:
                    disallow_urls.append(normalized)

            elif directive == "allow":
                if not val:
                    continue
                cleaned_path = re.sub(r"[\*\$]+$", "", val).strip()
                if not cleaned_path:
                    continue
                normalized = self._normalize_url(cleaned_path, base_url=base_url)
                if normalized and normalized not in allow_urls:
                    allow_urls.append(normalized)

            elif directive == "sitemap":
                if not val:
                    continue
                normalized = self._normalize_url(val, base_url=base_url)
                if normalized and normalized not in sitemap_urls:
                    sitemap_urls.append(normalized)

            elif directive in ("crawl-delay", "crawldelay"):
                try:
                    delay = float(val)
                    if delay >= 0:
                        # Prioritize wildcard user-agent or first encounter
                        if crawl_delay is None or current_user_agent in ("*", "api-tool", "bot", "crawler"):
                            crawl_delay = delay
                except ValueError:
                    pass

        self.allow_urls = allow_urls
        return disallow_urls, sitemap_urls, crawl_delay

    def parse_sitemap_content(
        self,
        content: bytes,
        base_url: Optional[str] = None,
    ) -> Tuple[List[str], bool]:
        """
        Low-Memory Streaming XML Sitemap Parser.

        Uses linear byte-regex scanning over raw response bytes (avoiding heavy DOM parsing).
        Auto-decompresses gzip if content starts with gzip magic bytes.

        Returns:
            (extracted_urls, is_sitemap_index)
        """
        if not content:
            return [], False

        # Auto-decompress gzipped sitemap bytes
        if content.startswith(b"\x1f\x8b"):
            try:
                content = gzip.decompress(content)
            except Exception as exc:
                logger.warning("Failed to decompress gzipped sitemap content: %s", exc)
                return [], False

        is_index = bool(SITEMAP_INDEX_REGEX.search(content))

        extracted_urls: List[str] = []
        seen: Set[str] = set()

        def process_match(raw_bytes: bytes) -> None:
            raw_str = raw_bytes.decode("utf-8", errors="replace").strip()
            # Decode XML entities like &amp; -> &, &lt; -> <, etc.
            decoded_str = html.unescape(raw_str)
            norm_url = self._normalize_url(decoded_str, base_url=base_url)
            if norm_url and norm_url not in seen:
                seen.add(norm_url)
                extracted_urls.append(norm_url)

        # 1. Standard <loc> tags
        for match in LOC_BYTE_REGEX.finditer(content):
            process_match(match.group(1))

        # 2. CDATA <loc> tags if any
        for match in CDATA_LOC_BYTE_REGEX.finditer(content):
            process_match(match.group(1))

        return extracted_urls, is_index

    def generate_gateway_probes(self, base_url: str) -> List[str]:
        """
        Generate candidate seed URLs for standard Well-Known and API Gateway probes.

        Probes include:
        - /.well-known/security.txt
        - /.well-known/openid-configuration
        - /.well-known/assetlinks.json
        - /.well-known/apple-app-site-association
        - /openapi.json
        - /swagger.json
        - /v3/api-docs
        - /api-docs
        """
        parsed = urlsplit(base_url)
        origin = f"{parsed.scheme or 'https'}://{parsed.netloc}"
        if not parsed.netloc:
            # Fallback if base_url was a path or bare domain without scheme
            if "://" not in base_url:
                parsed = urlsplit(f"https://{base_url}")
                origin = f"https://{parsed.netloc}"
            else:
                origin = base_url.rstrip("/")

        probes: List[str] = []
        for path in STANDARD_GATEWAY_PROBES:
            norm_url = self._normalize_url(path, base_url=origin)
            if norm_url and norm_url not in probes:
                probes.append(norm_url)

        return probes

    async def harvest_sitemaps(
        self,
        sitemap_urls: List[str],
        base_url: str,
        max_sitemaps: int = 50,
        max_depth: int = 5,
    ) -> List[str]:
        """
        Recursively fetch and parse sitemaps (including <sitemapindex> child sitemaps and .xml.gz).

        Returns:
            Discovered page URLs from all parsed sitemaps.
        """
        if not self.client or not sitemap_urls:
            return []

        discovered_pages: List[str] = []
        seen_pages: Set[str] = set()
        visited_sitemaps: Set[str] = set()

        # Queue contains tuples of (sitemap_url, current_depth)
        queue: List[Tuple[str, int]] = [(url, 0) for url in sitemap_urls]

        while queue and len(visited_sitemaps) < max_sitemaps:
            current_sitemap_url, depth = queue.pop(0)
            if current_sitemap_url in visited_sitemaps:
                continue
            visited_sitemaps.add(current_sitemap_url)

            try:
                resp = await self.client.get(current_sitemap_url, follow_redirects=True)
                if resp.status_code != 200:
                    logger.debug("Sitemap returned status %s: %s", resp.status_code, current_sitemap_url)
                    continue

                raw_bytes = resp.content
                # If URL ends with .gz and not already decompressed
                if current_sitemap_url.lower().endswith(".gz") and not raw_bytes.startswith(b"\x1f\x8b"):
                    try:
                        raw_bytes = gzip.decompress(raw_bytes)
                    except Exception:
                        pass

                extracted_urls, is_index = self.parse_sitemap_content(raw_bytes, base_url=base_url)

                if is_index:
                    if depth < max_depth:
                        for child_sitemap in extracted_urls:
                            if child_sitemap not in visited_sitemaps:
                                queue.append((child_sitemap, depth + 1))
                else:
                    for page_url in extracted_urls:
                        if page_url not in seen_pages:
                            seen_pages.add(page_url)
                            discovered_pages.append(page_url)

            except Exception as exc:
                logger.debug("Failed to harvest sitemap %s: %s", current_sitemap_url, exc)
                continue

        return discovered_pages

    async def discover_seeds(
        self,
        start_url: str,
        include_gateway_probes: bool = True,
    ) -> Tuple[List[str], List[str]]:
        """
        Discover passive seeds and disallowed paths for start_url.

        1. Fetches and parses robots.txt:
           - Disallow directives -> high-priority seed candidates (disallow_urls).
           - Sitemap directives -> extracted Sitemap URLs.
           - Crawl-delay directives -> sets self.crawl_delay.
        2. Fetches and parses Sitemaps streaming (including .xml.gz and recursive sitemap indexes).
        3. Generates standard Well-Known and API Gateway candidate seed probes.

        Returns:
            Tuple of (discovered_seeds, disallow_urls).
        """
        # Determine origin base URL
        if "://" not in start_url:
            start_url = f"https://{start_url}"
        parsed = urlsplit(start_url)
        scheme = parsed.scheme.lower() or "https"
        netloc = parsed.netloc.lower()
        base_url = f"{scheme}://{netloc}"

        disallow_urls: List[str] = []
        sitemap_urls: List[str] = []
        sitemap_seed_urls: List[str] = []

        # 1. Harvest robots.txt if client is available
        robots_url = f"{base_url}/robots.txt"
        if self.client:
            try:
                resp = await self.client.get(robots_url, follow_redirects=True)
                if resp.status_code == 200:
                    disallows, sitemaps, delay = self.parse_robots_txt(resp.text, base_url=base_url)
                    disallow_urls.extend(disallows)
                    sitemap_urls.extend(sitemaps)
                    if delay is not None:
                        self.crawl_delay = delay
            except Exception as exc:
                logger.debug("Failed to fetch robots.txt from %s: %s", robots_url, exc)

        self.disallow_urls = disallow_urls
        self.sitemap_urls = sitemap_urls

        # 2. Harvest XML Sitemaps
        if sitemap_urls and self.client:
            sitemap_seed_urls = await self.harvest_sitemaps(sitemap_urls, base_url=base_url)

        # 3. Generate Well-Known and API Gateway probes
        gateway_probes: List[str] = []
        if include_gateway_probes:
            gateway_probes = self.generate_gateway_probes(base_url)

        # Combine all discovered seeds (preserving order and deduplicating)
        discovered_seeds: List[str] = []
        seen_seeds: Set[str] = set()

        for u in sitemap_seed_urls:
            if u and u not in seen_seeds:
                seen_seeds.add(u)
                discovered_seeds.append(u)

        for u in gateway_probes:
            if u and u not in seen_seeds:
                seen_seeds.add(u)
                discovered_seeds.append(u)

        return discovered_seeds, disallow_urls
