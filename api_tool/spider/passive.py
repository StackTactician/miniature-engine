"""
Passive historical endpoint harvester using Wayback Machine CDX API and AlienVault OTX API.
Allows discovering hidden, forgotten, or historical API endpoints without actively probing the target.
Pure Python httpx, Termux-compatible.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlsplit

import httpx

from api_tool.models import DiscoveredEndpoint, DiscoveredParameter
from api_tool.spider.crawler import URLNormalizer, STATIC_ASSET_EXTENSIONS

logger = logging.getLogger(__name__)

# Ignored binary/media MIME types in Wayback CDX responses
IGNORED_WAYBACK_MIMES: Set[str] = {
    "image/png",
    "image/jpeg",
    "image/jpg",
    "image/gif",
    "image/svg+xml",
    "image/webp",
    "image/x-icon",
    "text/css",
    "font/woff",
    "font/woff2",
    "font/ttf",
    "application/font-woff",
    "application/font-woff2",
    "application/x-font-ttf",
    "video/mp4",
    "video/webm",
    "audio/mpeg",
    "application/pdf",
    "application/zip",
}


@dataclass
class PassiveHarvestResult:
    target_domain: str
    endpoints: List[DiscoveredEndpoint] = field(default_factory=list)
    scripts: List[str] = field(default_factory=list)
    total_urls: int = 0
    sources: Dict[str, int] = field(default_factory=dict)
    errors: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_domain": self.target_domain,
            "total_urls": self.total_urls,
            "sources": self.sources,
            "scripts": self.scripts,
            "endpoints": [e.to_dict() for e in self.endpoints],
            "errors": self.errors,
        }


class PassiveHarvester:
    """
    Harvests historical and archived endpoints passively from public OSINT databases:
    - Wayback Machine CDX Server (web.archive.org/cdx/search/cdx)
    - AlienVault Open Threat Exchange (OTX) URL list
    """

    WAYBACK_CDX_URL = "https://web.archive.org/cdx/search/cdx"
    ALIENVAULT_OTX_URL_TEMPLATE = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list"

    def __init__(
        self,
        request_timeout: float = 15.0,
        user_agent: str = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 api-tool/0.1.0"
        ),
        client: Optional[httpx.AsyncClient] = None,
    ) -> None:
        self.request_timeout = request_timeout
        self.user_agent = user_agent
        self._external_client = client
        self._owns_client = False
        self.normalizer = URLNormalizer()

    async def __aenter__(self) -> "PassiveHarvester":
        if self._external_client is None:
            self._external_client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.request_timeout),
                follow_redirects=True,
                verify=False,
                headers={"User-Agent": self.user_agent},
            )
            self._owns_client = True
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self._owns_client and self._external_client is not None:
            await self._external_client.aclose()
            self._external_client = None
            self._owns_client = False

    def _extract_domain(self, domain_or_url: str) -> str:
        """Extract clean hostname/domain from domain string or URL."""
        domain_or_url = domain_or_url.strip()
        if "://" in domain_or_url:
            parsed = urlsplit(domain_or_url)
            host = parsed.netloc
        else:
            host = domain_or_url.split("/")[0]

        # Strip port if present
        host = host.split(":")[0].lower()
        return host

    def _url_to_endpoint(
        self,
        raw_url: str,
        source_tag: str,
        status_code: Optional[int] = None,
    ) -> Tuple[Optional[DiscoveredEndpoint], Optional[str]]:
        """
        Parses a discovered URL into a DiscoveredEndpoint and/or script URL.
        Returns (endpoint, script_url).
        """
        normalized = self.normalizer.normalize(raw_url)
        if not normalized:
            return None, None

        parsed = urlsplit(normalized)
        path = parsed.path or "/"

        # Check if it's a static image/media asset to discard
        if self.normalizer.is_static_asset(normalized):
            return None, None

        # Check if it's a JavaScript script
        is_js = path.lower().endswith(".js")
        script_url = normalized if is_js else None

        base_url = f"{parsed.scheme}://{parsed.netloc}"
        path_with_query = path
        if parsed.query:
            path_with_query += f"?{parsed.query}"

        # Extract query parameters
        parameters: List[DiscoveredParameter] = []
        if parsed.query:
            for q_name, q_val in parse_qsl(parsed.query, keep_blank_values=True):
                parameters.append(
                    DiscoveredParameter(
                        name=q_name,
                        location="query",
                        example=q_val,
                        param_type="string",
                    )
                )

        endpoint = DiscoveredEndpoint(
            path=path_with_query,
            method="GET",
            base_url=base_url,
            source="passive_osint",
            tags=[source_tag],
            parameters=parameters,
            active_status=status_code,
            summary=f"Discovered via {source_tag} archive",
        )

        return endpoint, script_url

    async def harvest_wayback(
        self,
        domain_or_url: str,
        limit: int = 1000,
        client: Optional[httpx.AsyncClient] = None,
    ) -> Tuple[List[DiscoveredEndpoint], List[str]]:
        """
        Queries Wayback Machine CDX API for archived URLs of the target domain.
        Returns (endpoints, script_urls).
        """
        domain = self._extract_domain(domain_or_url)
        if not domain:
            return [], []

        params = {
            "url": f"{domain}/*",
            "output": "json",
            "fl": "original,mimetype,statuscode,timestamp",
            "collapse": "urlkey",
            "limit": str(limit),
        }

        endpoints: List[DiscoveredEndpoint] = []
        scripts: List[str] = []
        seen_endpoints: Set[str] = set()
        seen_scripts: Set[str] = set()

        close_client = False
        c = client or self._external_client
        if c is None:
            c = httpx.AsyncClient(
                timeout=httpx.Timeout(self.request_timeout),
                follow_redirects=True,
                verify=False,
                headers={"User-Agent": self.user_agent},
            )
            close_client = True

        try:
            resp = await c.get(self.WAYBACK_CDX_URL, params=params)
            if resp.status_code != 200:
                logger.warning(
                    "Wayback CDX API responded with status %d for %s", resp.status_code, domain
                )
                return [], []

            data = resp.json()
            if not isinstance(data, list) or len(data) <= 1:
                return [], []

            # First row is headers: ["original", "mimetype", "statuscode", "timestamp"]
            rows = data[1:]
            for row in rows:
                if len(row) < 4:
                    continue
                original_url, mimetype, statuscode_str, _ = row[0], row[1], row[2], row[3]

                # Filter out unwanted MIME types
                if mimetype and mimetype.lower() in IGNORED_WAYBACK_MIMES:
                    continue

                status_code = int(statuscode_str) if (statuscode_str and statuscode_str.isdigit()) else None

                endpoint, script_url = self._url_to_endpoint(
                    original_url, source_tag="wayback", status_code=status_code
                )

                if endpoint:
                    key = f"{endpoint.base_url}{endpoint.path}"
                    if key not in seen_endpoints:
                        seen_endpoints.add(key)
                        endpoints.append(endpoint)

                if script_url and script_url not in seen_scripts:
                    seen_scripts.add(script_url)
                    scripts.append(script_url)

        except Exception as e:
            logger.warning("Error querying Wayback Machine for %s: %s", domain, e)
        finally:
            if close_client:
                await c.aclose()

        return endpoints, scripts

    async def harvest_alienvault(
        self,
        domain_or_url: str,
        limit: int = 500,
        max_pages: int = 3,
        client: Optional[httpx.AsyncClient] = None,
    ) -> Tuple[List[DiscoveredEndpoint], List[str]]:
        """
        Queries AlienVault OTX API indicator URL list for the target domain.
        Returns (endpoints, script_urls).
        """
        domain = self._extract_domain(domain_or_url)
        if not domain:
            return [], []

        endpoints: List[DiscoveredEndpoint] = []
        scripts: List[str] = []
        seen_endpoints: Set[str] = set()
        seen_scripts: Set[str] = set()

        close_client = False
        c = client or self._external_client
        if c is None:
            c = httpx.AsyncClient(
                timeout=httpx.Timeout(self.request_timeout),
                follow_redirects=True,
                verify=False,
                headers={"User-Agent": self.user_agent},
            )
            close_client = True

        try:
            url_template = self.ALIENVAULT_OTX_URL_TEMPLATE.format(domain=domain)
            page = 1

            while page <= max_pages:
                params = {
                    "limit": str(min(limit, 500)),
                    "page": str(page),
                }

                resp = await c.get(url_template, params=params)
                if resp.status_code != 200:
                    logger.debug(
                        "AlienVault OTX API returned status %d for domain %s (page %d)",
                        resp.status_code,
                        domain,
                        page,
                    )
                    break

                try:
                    payload = resp.json()
                except Exception:
                    break

                url_list = payload.get("url_list", [])
                if not url_list or not isinstance(url_list, list):
                    break

                for entry in url_list:
                    if not isinstance(entry, dict):
                        continue

                    raw_url = entry.get("url")
                    if not raw_url:
                        continue

                    http_code = entry.get("httpcode")
                    status_code = int(http_code) if (isinstance(http_code, int) or (isinstance(http_code, str) and http_code.isdigit())) else None

                    endpoint, script_url = self._url_to_endpoint(
                        raw_url, source_tag="alienvault_otx", status_code=status_code
                    )

                    if endpoint:
                        key = f"{endpoint.base_url}{endpoint.path}"
                        if key not in seen_endpoints:
                            seen_endpoints.add(key)
                            endpoints.append(endpoint)

                    if script_url and script_url not in seen_scripts:
                        seen_scripts.add(script_url)
                        scripts.append(script_url)

                if not payload.get("has_next", False):
                    break

                page += 1

        except Exception as e:
            logger.warning("Error querying AlienVault OTX for %s: %s", domain, e)
        finally:
            if close_client:
                await c.aclose()

        return endpoints, scripts

    async def harvest_all(
        self,
        domain_or_url: str,
        limit_wayback: int = 1000,
        limit_alienvault: int = 500,
        alienvault_max_pages: int = 3,
    ) -> PassiveHarvestResult:
        """
        Runs concurrent passive OSINT queries against Wayback Machine and AlienVault OTX.
        Deduplicates endpoints and extracts potential JavaScript scripts.
        """
        domain = self._extract_domain(domain_or_url)
        result = PassiveHarvestResult(target_domain=domain)

        if not domain:
            result.errors["general"] = "Invalid domain or URL provided"
            return result

        client = self._external_client or httpx.AsyncClient(
            timeout=httpx.Timeout(self.request_timeout),
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": self.user_agent},
        )
        close_client = self._external_client is None

        try:
            tasks = [
                self.harvest_wayback(domain, limit=limit_wayback, client=client),
                self.harvest_alienvault(
                    domain,
                    limit=limit_alienvault,
                    max_pages=alienvault_max_pages,
                    client=client,
                ),
            ]

            results = await asyncio.gather(*tasks, return_exceptions=True)

            wayback_endpoints: List[DiscoveredEndpoint] = []
            wayback_scripts: List[str] = []
            alien_endpoints: List[DiscoveredEndpoint] = []
            alien_scripts: List[str] = []

            # Process Wayback result
            if isinstance(results[0], Exception):
                result.errors["wayback"] = str(results[0])
            elif isinstance(results[0], tuple):
                wayback_endpoints, wayback_scripts = results[0]
                result.sources["wayback"] = len(wayback_endpoints)

            # Process AlienVault result
            if isinstance(results[1], Exception):
                result.errors["alienvault_otx"] = str(results[1])
            elif isinstance(results[1], tuple):
                alien_endpoints, alien_scripts = results[1]
                result.sources["alienvault_otx"] = len(alien_endpoints)

            # Merge and deduplicate
            merged_endpoints: Dict[Tuple[str, str, str], DiscoveredEndpoint] = {}
            for ep in wayback_endpoints:
                merged_endpoints[(ep.base_url, ep.path, ep.method)] = ep

            for ep in alien_endpoints:
                key = (ep.base_url, ep.path, ep.method)
                if key in merged_endpoints:
                    # Merge tags
                    existing = merged_endpoints[key]
                    for t in ep.tags:
                        if t not in existing.tags:
                            existing.tags.append(t)
                else:
                    merged_endpoints[key] = ep

            all_scripts = sorted(list(set(wayback_scripts + alien_scripts)))

            result.endpoints = list(merged_endpoints.values())
            result.scripts = all_scripts
            result.total_urls = len(result.endpoints)

            return result

        finally:
            if close_client:
                await client.aclose()
