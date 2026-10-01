"""
Manifest extraction engine for Next.js, Nuxt.js, and Webpack chunk maps.
Discovers route paths, API endpoints, and JavaScript chunk bundles without a browser.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlsplit

import httpx
from bs4 import BeautifulSoup

from api_tool.models import DiscoveredEndpoint, DiscoveredParameter

logger = logging.getLogger(__name__)


@dataclass
class ManifestResult:
    framework: Optional[str] = None  # "nextjs", "nuxt", "webpack", etc.
    build_id: Optional[str] = None
    routes: List[str] = field(default_factory=list)
    chunk_scripts: List[str] = field(default_factory=list)
    endpoints: List[DiscoveredEndpoint] = field(default_factory=list)
    rewrites: List[Dict[str, str]] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "framework": self.framework,
            "build_id": self.build_id,
            "routes": self.routes,
            "chunk_scripts": self.chunk_scripts,
            "endpoints": [e.to_dict() for e in self.endpoints],
            "rewrites": self.rewrites,
            "raw_data": self.raw_data,
        }


class ManifestExtractor:
    """
    Extracts build manifests, routes, and chunk scripts from SSR/SPA applications:
    - Next.js: __NEXT_DATA__, _buildManifest.js, _ssgManifest.js, _middlewareManifest.js
    - Nuxt.js: __NUXT_DATA__, window.__NUXT__, payload manifests
    - Webpack: runtime chunk maps and dynamic asset maps
    """

    # Regex patterns for Next.js buildId extraction
    NEXT_BUILD_ID_REGEX = re.compile(
        r"""(?:["']buildId["']\s*:\s*["']([^"']+)["']|/_next/static/([a-zA-Z0-9_\-\.]+)/_buildManifest\.js)"""
    )

    # Next.js route extraction regex from _buildManifest.js
    NEXT_ROUTE_KEY_REGEX = re.compile(
        r"""["'](/[^"'\s]*)["']\s*:\s*\[([^\]]*)\]"""
    )
    NEXT_SORTED_PAGES_REGEX = re.compile(
        r"""sortedPages\s*:\s*\[([^\]]+)\]"""
    )
    NEXT_REWRITE_REGEX = re.compile(
        r"""\{[^{}]*(?:(?:["']source["']|\bsource\b)\s*:\s*["']([^"']+)["'][^{}]*(?:["']destination["']|\bdestination\b)\s*:\s*["']([^"']+)["']|(?:["']destination["']|\bdestination\b)\s*:\s*["']([^"']+)["'][^{}]*(?:["']source["']|\bsource\b)\s*:\s*["']([^"']+)["'])[^{}]*\}"""
    )
    NEXT_CHUNK_REGEX = re.compile(
        r"""["'](static/chunks/[^"']+\.js)["']"""
    )

    # Webpack chunk pair extraction pattern (linear O(N), immune to catastrophic backtracking)
    WEBPACK_CHUNK_PAIR_REGEX = re.compile(
        r"""(?:["']([a-zA-Z0-9_\-\.]+)["']|(\b\d+\b))\s*:\s*["']([a-f0-9]{6,64})["']"""
    )
    WEBPACK_CHUNK_FILENAME_REGEX = re.compile(
        r"""["']([^"']*(?:static/js/|chunks/)[^"']*\.js)["']"""
    )

    def __init__(self, request_timeout: float = 10.0) -> None:
        self.request_timeout = request_timeout

    def _normalize_base_url(self, base_url: str) -> str:
        """Strip trailing slash and ensure valid scheme."""
        if not base_url.startswith(("http://", "https://")):
            base_url = "https://" + base_url
        return base_url.rstrip("/")

    def extract_from_html(self, html: str, base_url: str) -> ManifestResult:
        """
        Synchronously parses HTML for embedded Next.js or Nuxt.js manifest data.
        Does not perform network requests.
        """
        clean_base = self._normalize_base_url(base_url)
        result = ManifestResult()

        soup = BeautifulSoup(html, "html.parser")

        # 1. Check for Next.js __NEXT_DATA__
        next_data_script = soup.find("script", id="__NEXT_DATA__")
        if next_data_script and next_data_script.string:
            result.framework = "nextjs"
            try:
                data = json.loads(next_data_script.string)
                result.raw_data["__NEXT_DATA__"] = data
                build_id = data.get("buildId")
                if build_id:
                    result.build_id = build_id

                page = data.get("page")
                if page:
                    result.routes.append(page)

                query = data.get("query")
                if isinstance(query, dict):
                    result.raw_data["initial_query"] = query

            except json.JSONDecodeError as e:
                logger.debug("Failed to decode __NEXT_DATA__ JSON: %s", e)

        # Fallback check for buildId in HTML if __NEXT_DATA__ wasn't JSON or script tag was absent
        if not result.build_id:
            match = self.NEXT_BUILD_ID_REGEX.search(html)
            if match:
                result.framework = result.framework or "nextjs"
                result.build_id = match.group(1) or match.group(2)

        # 2. Check for Nuxt 3 __NUXT_DATA__
        nuxt_data_script = soup.find("script", id="__NUXT_DATA__")
        if nuxt_data_script and nuxt_data_script.string:
            result.framework = "nuxt"
            try:
                nuxt_data = json.loads(nuxt_data_script.string)
                result.raw_data["__NUXT_DATA__"] = nuxt_data
                self._extract_nuxt_data_routes(nuxt_data, result)
            except json.JSONDecodeError as e:
                logger.debug("Failed to decode __NUXT_DATA__ JSON: %s", e)

        # Check for Nuxt 2 window.__NUXT__
        if "window.__NUXT__" in html:
            result.framework = result.framework or "nuxt"
            nuxt2_routes = self._extract_nuxt2_routes(html)
            result.routes.extend(nuxt2_routes)

        # 3. Check for Webpack chunk maps in inline scripts
        for script in soup.find_all("script"):
            script_content = script.string or ""
            if "webpack" in script_content.lower() or "__webpack_require__" in script_content:
                chunks, _ = self._extract_webpack_chunk_maps(script_content, clean_base)
                result.chunk_scripts.extend(chunks)
                if not result.framework:
                    result.framework = "webpack"

        # Deduplicate routes & chunks
        result.routes = sorted(list(set(result.routes)))
        result.chunk_scripts = sorted(list(set(result.chunk_scripts)))

        # Convert routes to DiscoveredEndpoints
        result.endpoints = self._convert_routes_to_endpoints(
            result.routes, clean_base, framework=result.framework or "manifest"
        )

        return result

    def _extract_nuxt_data_routes(self, data: Any, result: ManifestResult) -> None:
        """Inspects Nuxt 3 serialized payload data array for routes and API paths."""
        if isinstance(data, list):
            for item in data:
                if isinstance(item, str):
                    # Route path pattern
                    if item.startswith("/") and len(item) > 1 and not item.startswith("//"):
                        if not any(item.endswith(ext) for ext in (".js", ".css", ".png", ".jpg", ".svg", ".json")):
                            result.routes.append(item)
                elif isinstance(item, dict):
                    # Search dict values
                    for val in item.values():
                        if isinstance(val, str) and val.startswith("/") and len(val) > 1:
                            if not any(val.endswith(ext) for ext in (".js", ".css", ".png", ".jpg", ".svg", ".json")):
                                result.routes.append(val)

    def _extract_nuxt2_routes(self, html: str) -> List[str]:
        """Extracts routePath and route names from Nuxt 2 inline state."""
        routes: List[str] = []
        route_matches = re.findall(r"""routePath\s*:\s*["']([^"']+)["']""", html)
        routes.extend(route_matches)

        path_matches = re.findall(r"""path\s*:\s*["'](/[^"']+)["']""", html)
        for p in path_matches:
            if not any(p.endswith(ext) for ext in (".js", ".css", ".png", ".jpg", ".svg", ".ico")):
                routes.append(p)
        return routes

    def _extract_webpack_chunk_maps(
        self, script_content: str, base_url: str
    ) -> Tuple[List[str], Dict[str, str]]:
        """Extracts chunk IDs, hashes, and resolved script URLs from webpack runtime code."""
        chunk_urls: List[str] = []
        chunk_map: Dict[str, str] = {}

        # Linear-time key-value pair extraction without ReDoS risk
        for match in self.WEBPACK_CHUNK_PAIR_REGEX.finditer(script_content):
            chunk_id = match.group(1) or match.group(2)
            chunk_hash = match.group(3)
            chunk_map[chunk_id] = chunk_hash

        # Extract direct chunk JS filenames referenced in script
        for match in self.WEBPACK_CHUNK_FILENAME_REGEX.finditer(script_content):
            rel_path = match.group(1)
            chunk_urls.append(urljoin(base_url, rel_path))

        return chunk_urls, chunk_map

    def parse_next_build_manifest(
        self, js_content: str, base_url: str
    ) -> Tuple[List[str], List[str], List[Dict[str, str]]]:
        """
        Parses Next.js `_buildManifest.js` content.
        Extracts:
        - Route paths
        - Chunk script URLs
        - Rewrite rules (proxy targets / backend APIs)
        """
        routes: List[str] = []
        chunk_scripts: List[str] = []
        rewrites: List[Dict[str, str]] = []

        # 1. Extract sortedPages
        sorted_match = self.NEXT_SORTED_PAGES_REGEX.search(js_content)
        if sorted_match:
            pages_raw = sorted_match.group(1)
            for page_match in re.finditer(r"""["']([^"']+)["']""", pages_raw):
                route = page_match.group(1)
                # Ignore internal Next.js pages like /_app, /_error
                if not route.startswith("/_"):
                    routes.append(route)
                elif route in ("/_error", "/_app"):
                    routes.append(route)

        # 2. Extract route keys from manifest object
        for match in self.NEXT_ROUTE_KEY_REGEX.finditer(js_content):
            route = match.group(1)
            if not route.startswith("/_") or route == "/_error":
                routes.append(route)

            # Chunk array for this route
            chunks_raw = match.group(2)
            for chunk_match in re.finditer(r"""["'](static/chunks/[^"']+\.js)["']""", chunks_raw):
                chunk_path = chunk_match.group(1)
                full_chunk_url = urljoin(f"{base_url}/_next/", chunk_path)
                chunk_scripts.append(full_chunk_url)

        # 3. Extract all static chunk scripts
        for match in self.NEXT_CHUNK_REGEX.finditer(js_content):
            chunk_path = match.group(1)
            full_chunk_url = urljoin(f"{base_url}/_next/", chunk_path)
            chunk_scripts.append(full_chunk_url)

        # 4. Extract rewrites (often exposes internal/backend APIs)
        for match in self.NEXT_REWRITE_REGEX.finditer(js_content):
            if match.group(1):
                source, dest = match.group(1), match.group(2)
            else:
                dest, source = match.group(3), match.group(4)
            rewrites.append({"source": source, "destination": dest})
            routes.append(source)

        return routes, chunk_scripts, rewrites

    def parse_next_ssg_manifest(self, js_content: str) -> List[str]:
        """
        Parses Next.js `_ssgManifest.js` content.
        Extracts pre-rendered static routes (e.g. from `new Set([...])`).
        """
        routes: List[str] = []
        for match in re.finditer(r"""["'](/[^"']*)["']""", js_content):
            route = match.group(1)
            if not route.startswith("/_"):
                routes.append(route)
        return routes

    def _convert_routes_to_endpoints(
        self, routes: List[str], base_url: str, framework: str
    ) -> List[DiscoveredEndpoint]:
        """
        Converts Next.js / Nuxt route templates (e.g. /users/[id], /docs/[...slug])
        into normalized DiscoveredEndpoint instances with typed parameters.
        """
        endpoints: List[DiscoveredEndpoint] = []
        seen_paths: Set[str] = set()

        for route in routes:
            if not route or route in seen_paths:
                continue

            seen_paths.add(route)
            parameters: List[DiscoveredParameter] = []

            # Next.js dynamic routes: [id], [...slug], [[...optional]]
            # Convert [param] -> {param}
            def replace_param(m: re.Match) -> str:
                param_name = m.group(1)
                is_catch_all = False
                if param_name.startswith("..."):
                    is_catch_all = True
                    param_name = param_name[3:]

                parameters.append(
                    DiscoveredParameter(
                        name=param_name,
                        location="path",
                        required=not is_catch_all,
                        param_type="array" if is_catch_all else "string",
                        description="Route parameter extracted from framework manifest",
                    )
                )
                if is_catch_all:
                    return f"{{{param_name}*}}"
                return f"{{{param_name}}}"

            normalized_path = re.sub(r"\[+([a-zA-Z0-9_\-\.]+)\]+", replace_param, route)

            endpoints.append(
                DiscoveredEndpoint(
                    path=normalized_path,
                    method="GET",
                    base_url=base_url,
                    source="manifest",
                    tags=[framework],
                    parameters=parameters,
                    summary=f"Manifest route: {route}",
                )
            )

        return endpoints

    async def fetch_and_extract(
        self,
        base_url: str,
        html: Optional[str] = None,
        client: Optional[httpx.AsyncClient] = None,
    ) -> ManifestResult:
        """
        Comprehensive manifest discovery:
        1. Inspects HTML (or fetches homepage HTML if not provided)
        2. If Next.js buildId is found:
           - Fetches /_next/static/{buildId}/_buildManifest.js
           - Fetches /_next/static/{buildId}/_ssgManifest.js
           - Fetches /_next/static/{buildId}/_middlewareManifest.js
        3. If Nuxt is detected:
           - Fetches /_nuxt/manifest.json or payload metadata if present
        4. Reconstructs all routes and chunk scripts into DiscoveredEndpoint models.
        """
        clean_base = self._normalize_base_url(base_url)
        client_provided = client is not None
        c = client or httpx.AsyncClient(
            timeout=httpx.Timeout(self.request_timeout),
            follow_redirects=True,
            verify=False,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Linux; Android 10; Mobile) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36 api-tool/0.1.0"
                ),
                "Accept": "*/*",
            },
        )

        try:
            # Step 1: Fetch HTML if not provided
            if html is None:
                try:
                    resp = await c.get(clean_base)
                    html = resp.text
                except Exception as e:
                    logger.debug("Failed to fetch initial HTML for %s: %s", clean_base, e)
                    html = ""

            # Extract from HTML first
            result = self.extract_from_html(html, clean_base)

            # Step 2: Next.js manifests fetch
            if result.build_id:
                build_id = result.build_id

                # A. Fetch _buildManifest.js
                build_manifest_url = f"{clean_base}/_next/static/{build_id}/_buildManifest.js"
                try:
                    bm_resp = await c.get(build_manifest_url)
                    if bm_resp.status_code == 200:
                        bm_routes, bm_chunks, bm_rewrites = self.parse_next_build_manifest(
                            bm_resp.text, clean_base
                        )
                        result.routes.extend(bm_routes)
                        result.chunk_scripts.extend(bm_chunks)
                        result.rewrites.extend(bm_rewrites)
                        result.raw_data["_buildManifest_url"] = build_manifest_url
                except Exception as e:
                    logger.debug("Failed fetching %s: %s", build_manifest_url, e)

                # B. Fetch _ssgManifest.js
                ssg_manifest_url = f"{clean_base}/_next/static/{build_id}/_ssgManifest.js"
                try:
                    ssg_resp = await c.get(ssg_manifest_url)
                    if ssg_resp.status_code == 200:
                        ssg_routes = self.parse_next_ssg_manifest(ssg_resp.text)
                        result.routes.extend(ssg_routes)
                        result.raw_data["_ssgManifest_url"] = ssg_manifest_url
                except Exception as e:
                    logger.debug("Failed fetching %s: %s", ssg_manifest_url, e)

                # C. Check _middlewareManifest.js (Next.js Edge middleware routing rules)
                mw_manifest_url = f"{clean_base}/_next/static/{build_id}/_middlewareManifest.js"
                try:
                    mw_resp = await c.get(mw_manifest_url)
                    if mw_resp.status_code == 200:
                        mw_routes = re.findall(r"""["'](/[^"']*)["']""", mw_resp.text)
                        result.routes.extend([r for r in mw_routes if not r.startswith("/_")])
                        result.raw_data["_middlewareManifest_url"] = mw_manifest_url
                except Exception as e:
                    logger.debug("Failed fetching %s: %s", mw_manifest_url, e)

            # Step 3: Nuxt manifest probes
            if result.framework == "nuxt":
                nuxt_manifest_urls = [
                    f"{clean_base}/_nuxt/manifest.json",
                    f"{clean_base}/_nuxt/builds/meta/latest.json",
                ]
                for n_url in nuxt_manifest_urls:
                    try:
                        n_resp = await c.get(n_url)
                        if n_resp.status_code == 200:
                            n_json = n_resp.json()
                            result.raw_data[n_url] = n_json
                            if isinstance(n_json, dict):
                                for key, val in n_json.items():
                                    if key.endswith(".js"):
                                        result.chunk_scripts.append(urljoin(clean_base, f"/_nuxt/{key}"))
                                    if isinstance(val, dict) and "src" in val:
                                        result.chunk_scripts.append(urljoin(clean_base, f"/_nuxt/{val['src']}"))
                    except Exception as e:
                        logger.debug("Probe failed for %s: %s", n_url, e)

            # Deduplicate and sort routes & scripts
            result.routes = sorted(list(set(result.routes)))
            result.chunk_scripts = sorted(list(set(result.chunk_scripts)))

            # Re-generate endpoints with complete route list
            result.endpoints = self._convert_routes_to_endpoints(
                result.routes, clean_base, framework=result.framework or "manifest"
            )

            return result

        finally:
            if not client_provided:
                await c.aclose()
