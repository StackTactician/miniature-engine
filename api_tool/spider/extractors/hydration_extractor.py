"""
Sub-millisecond Hydration and Single-Page Application (SPA) Harvester.
Extracts client-side routes, API dependencies, loader endpoints, Server Actions,
and SSR hydrated responses across modern frontend frameworks:
- Next.js App Router (RSC Flight Streams & Server Actions)
- Next.js Pages Router (__NEXT_DATA__ & Data Loaders)
- Nuxt 3 (__NUXT_DATA__ Devalue flattened serialization & Payload Loaders)
- Remix & React Router v7 (window.__remixContext / manifest hierarchical routes & loader data)
- SvelteKit (data-sveltekit-fetched serialized HTTP responses & schema inference)
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlsplit

from bs4 import BeautifulSoup

from api_tool.models import DiscoveredEndpoint, DiscoveredParameter, DiscoveredResponse

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Compiled High-Performance Regex Patterns (Module-Level Precompilation)
# ---------------------------------------------------------------------------

# Next.js App Router (RSC Flight stream push)
# Matches self.__next_f.push([1, "..."]), (self.__next_f=self.__next_f||[]).push([1, "..."]), etc.
NEXT_F_PUSH_REGEX = re.compile(
    r"""__next_f(?:\s*=\s*[^)]+\))?\.push\(\s*\[\s*1\s*,\s*["']([\s\S]*?)["']\s*\]\s*\)"""
)

# Next.js Server Action RPC IDs (40-hex SHA or action identifiers)
SERVER_ACTION_REGEX = re.compile(
    r"""(?:\$ACTION_ID_([a-zA-Z0-9_\-]{16,64})|createServerReference[^a-zA-Z0-9_\-]{0,50}?["'\x60]([a-zA-Z0-9_\-]{16,64})["'\x60])"""
)

# Next.js Pages Router (__NEXT_DATA__)
NEXT_DATA_SCRIPT_REGEX = re.compile(
    r"""<script[^>]*\bid=["']__NEXT_DATA__["'][^>]*>(.*?)</script>""",
    re.DOTALL | re.IGNORECASE,
)

# Nuxt 3 (__NUXT_DATA__)
NUXT_DATA_SCRIPT_REGEX = re.compile(
    r"""<script[^>]*\bid=["']__NUXT_DATA__["'][^>]*>(.*?)</script>""",
    re.DOTALL | re.IGNORECASE,
)

# SvelteKit data-sveltekit-fetched scripts
SVELTEKIT_SCRIPT_REGEX = re.compile(
    r"""<script\b([^>]*\bdata-sveltekit-fetched\b[^>]*)>(.*?)</script>""",
    re.DOTALL | re.IGNORECASE,
)
SVELTEKIT_URL_REGEX = re.compile(
    r"""\bdata-url\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE,
)

# Generic candidate path / API regex for fallback inside scripts
API_PATH_REGEX = re.compile(
    r"""["'](/api/[a-zA-Z0-9_\-\./?=&%]+)["']"""
)

# Static asset extensions to exclude from path candidate discovery
STATIC_ASSET_EXTENSIONS = (
    ".js",
    ".css",
    ".map",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".webp",
    ".avif",
    ".mp4",
    ".mp3",
    ".webm",
)


def _decode_unicode_escapes(raw: str) -> str:
    """Decodes JavaScript unicode escapes and standard escape sequences safely."""
    # Attempt native C-level json.loads decoding if string matches JSON string format
    try:
        return json.loads(f'"{raw}"')
    except Exception:
        pass

    def _replace_unicode(match: re.Match) -> str:
        try:
            return chr(int(match.group(1), 16))
        except Exception:
            return match.group(0)

    # Decode unicode escape sequences \uXXXX
    s = re.sub(r"\\u([0-9a-fA-F]{4})", _replace_unicode, raw)
    # Decode standard string escapes
    s = s.replace(r"\/", "/")
    s = s.replace(r'\"', '"')
    s = s.replace(r"\'", "'")
    s = s.replace(r"\n", "\n")
    s = s.replace(r"\r", "\r")
    s = s.replace(r"\t", "\t")
    s = s.replace(r"\\", "\\")
    return s


def _infer_schema(data: Any) -> Dict[str, Any]:
    """Infers an OpenAPI / JSON Schema definition from an arbitrary Python object."""
    if data is None:
        return {"type": "null"}
    if isinstance(data, bool):
        return {"type": "boolean"}
    if isinstance(data, int):
        return {"type": "integer"}
    if isinstance(data, float):
        return {"type": "number"}
    if isinstance(data, str):
        return {"type": "string"}
    if isinstance(data, list):
        if data:
            return {"type": "array", "items": _infer_schema(data[0])}
        return {"type": "array"}
    if isinstance(data, dict):
        properties = {str(k): _infer_schema(v) for k, v in data.items()}
        return {"type": "object", "properties": properties}
    return {"type": "string"}


def _parse_url_params(url: str) -> List[DiscoveredParameter]:
    """Extracts DiscoveredParameter objects from URL query parameters."""
    params: List[DiscoveredParameter] = []
    if "?" not in url:
        return params
    query = url.split("?", 1)[1]
    parsed = parse_qs(query, keep_blank_values=True)
    for key, values in parsed.items():
        example_val = values[0] if values else ""
        params.append(
            DiscoveredParameter(
                name=key,
                location="query",
                required=False,
                param_type="string",
                example=example_val,
            )
        )
    return params


class FastHydrationScraper:
    """
    Sub-millisecond static DOM and Hydration metadata scraper.
    Detects and parses SSR/SPA state envelopes directly from HTML without a browser.
    """

    @classmethod
    def _normalize_base_url(cls, base_url: str) -> str:
        """Strip trailing slash and ensure valid scheme."""
        if not base_url:
            return ""
        if not base_url.startswith(("http://", "https://")):
            base_url = "https://" + base_url
        return base_url.rstrip("/")

    @classmethod
    def _is_valid_path_candidate(cls, s: str) -> bool:
        """Checks if a string is a plausible client route or API path candidate."""
        if not isinstance(s, str):
            return False
        if not s.startswith("/") or len(s) < 2 or s.startswith("//"):
            return False
        # Reject internal React/RSC identifiers and template variables
        if s.startswith(("$", "_next/static")):
            return False
        # Reject strings with control characters, spaces, quotes, or HTML brackets
        if any(c in s for c in " \t\r\n\"'<>\\|^~`"):
            return False
        # Exclude static assets
        clean_ext = s.lower().split("?")[0].split("#")[0]
        if any(clean_ext.endswith(ext) for ext in STATIC_ASSET_EXTENSIONS):
            return False
        return True

    # -----------------------------------------------------------------------
    # 1. Next.js App Router (RSC Flight Stream & Server Actions)
    # -----------------------------------------------------------------------
    @classmethod
    def extract_nextjs_app_router(
        cls, html: str, base_url: str = ""
    ) -> List[DiscoveredEndpoint]:
        """
        Scans Next.js App Router RSC Flight Streams (self.__next_f.push([1, "..."]))
        Decodes unicode-escaped chunks, detects Server Action RPC IDs ($ACTION_ID_40hex
        or createServerReference) -> DiscoveredEndpoint(path="/", method="POST",
        headers={"Next-Action": action_id}), and extracts candidate paths/APIs.
        """
        if "__next_f" not in html:
            return []

        clean_base = cls._normalize_base_url(base_url)
        endpoints: List[DiscoveredEndpoint] = []
        seen_actions: Set[str] = set()
        seen_paths: Set[str] = set()

        # Find all __next_f.push([1, "..."]) matches
        for match in NEXT_F_PUSH_REGEX.finditer(html):
            raw_chunk = match.group(1)
            decoded = _decode_unicode_escapes(raw_chunk)

            # 1. Server Action RPC IDs
            for action_match in SERVER_ACTION_REGEX.finditer(decoded):
                action_id = action_match.group(1) or action_match.group(2)
                if not action_id or action_id in seen_actions:
                    continue
                seen_actions.add(action_id)

                endpoints.append(
                    DiscoveredEndpoint(
                        path="/",
                        method="POST",
                        base_url=clean_base,
                        headers={"Next-Action": action_id},
                        source="hydration",
                        tags=["hydration", "nextjs", "server_action"],
                        summary=f"Next.js Server Action: {action_id}",
                        description=f"Server Action RPC endpoint invoked via Next-Action header '{action_id}'",
                    )
                )

            # 2. Extract path and API candidates from component JSON trees
            for line in decoded.splitlines():
                line = line.strip()
                if not line:
                    continue

                # Lines often start with 'id:' or 'id:I[...]' or 'id:{...}'
                if ":" in line:
                    _, json_part = line.split(":", 1)
                    json_part = json_part.strip()
                    if json_part.startswith("I[") or json_part.startswith("M["):
                        json_part = json_part[1:]

                    if json_part.startswith(("{", "[")):
                        try:
                            parsed_tree = json.loads(json_part)
                            cls._walk_component_tree(parsed_tree, clean_base, endpoints, seen_paths)
                        except Exception:
                            pass

            # 3. Fallback regex for explicit /api/ endpoints in the decoded chunk
            for api_match in API_PATH_REGEX.finditer(decoded):
                api_path = api_match.group(1)
                if cls._is_valid_path_candidate(api_path) and api_path not in seen_paths:
                    seen_paths.add(api_path)
                    endpoints.append(
                        DiscoveredEndpoint(
                            path=api_path,
                            method="GET",
                            base_url=clean_base,
                            source="hydration",
                            tags=["hydration", "nextjs", "api"],
                            parameters=_parse_url_params(api_path),
                            summary=f"Next.js RSC API endpoint: {api_path}",
                        )
                    )

        return endpoints

    @classmethod
    def _walk_component_tree(
        cls,
        obj: Any,
        base_url: str,
        endpoints: List[DiscoveredEndpoint],
        seen_paths: Set[str],
    ) -> None:
        """Recursively inspects parsed RSC JSON component trees for paths and APIs."""
        if isinstance(obj, str):
            if cls._is_valid_path_candidate(obj) and obj not in seen_paths:
                seen_paths.add(obj)
                is_api = obj.startswith("/api/") or "/api/" in obj
                tags = ["hydration", "nextjs", "api" if is_api else "route"]
                endpoints.append(
                    DiscoveredEndpoint(
                        path=obj,
                        method="GET",
                        base_url=base_url,
                        source="hydration",
                        tags=tags,
                        parameters=_parse_url_params(obj),
                        summary=f"Next.js RSC component path: {obj}",
                    )
                )
        elif isinstance(obj, dict):
            for k, v in obj.items():
                cls._walk_component_tree(v, base_url, endpoints, seen_paths)
        elif isinstance(obj, list):
            for item in obj:
                cls._walk_component_tree(item, base_url, endpoints, seen_paths)

    # -----------------------------------------------------------------------
    # 2. Next.js Pages Router (__NEXT_DATA__)
    # -----------------------------------------------------------------------
    @classmethod
    def extract_nextjs_pages_router(
        cls, html: str, base_url: str = ""
    ) -> List[DiscoveredEndpoint]:
        """
        Scrapes <script id="__NEXT_DATA__">, extracts page route and
        auto-derives JSON loader: /_next/data/{buildId}{page}.json
        """
        if "__NEXT_DATA__" not in html:
            return []

        clean_base = cls._normalize_base_url(base_url)
        endpoints: List[DiscoveredEndpoint] = []

        script_content: Optional[str] = None
        match = NEXT_DATA_SCRIPT_REGEX.search(html)
        if match:
            script_content = match.group(1).strip()
        else:
            soup = BeautifulSoup(html, "html.parser")
            tag = soup.find("script", id="__NEXT_DATA__")
            if tag and tag.string:
                script_content = tag.string.strip()

        if not script_content:
            return []

        try:
            data = json.loads(script_content)
        except json.JSONDecodeError:
            logger.debug("Failed to decode __NEXT_DATA__ JSON")
            return []

        page = data.get("page")
        build_id = data.get("buildId")

        # Extract page query parameters if present
        page_params: List[DiscoveredParameter] = []
        raw_query = data.get("query")
        if isinstance(raw_query, dict):
            for qk, qv in raw_query.items():
                page_params.append(
                    DiscoveredParameter(
                        name=qk,
                        location="query",
                        required=False,
                        param_type="string",
                        example=qv,
                    )
                )

        if page:
            clean_page = page if page.startswith("/") else f"/{page}"
            endpoints.append(
                DiscoveredEndpoint(
                    path=clean_page,
                    method="GET",
                    base_url=clean_base,
                    source="hydration",
                    tags=["hydration", "nextjs", "page_route"],
                    parameters=page_params,
                    summary=f"Next.js Page: {clean_page}",
                )
            )

            # Auto-derive JSON loader: /_next/data/{buildId}{page}.json
            if build_id:
                if clean_page == "/":
                    # In Next.js, root page loader is /index.json (also support /.json)
                    loader_primary = f"/_next/data/{build_id}/index.json"
                    endpoints.append(
                        DiscoveredEndpoint(
                            path=loader_primary,
                            method="GET",
                            base_url=clean_base,
                            source="hydration",
                            tags=["hydration", "nextjs", "data_loader"],
                            summary=f"Next.js Data Loader: {loader_primary}",
                        )
                    )
                    loader_alt = f"/_next/data/{build_id}/.json"
                    endpoints.append(
                        DiscoveredEndpoint(
                            path=loader_alt,
                            method="GET",
                            base_url=clean_base,
                            source="hydration",
                            tags=["hydration", "nextjs", "data_loader"],
                            summary=f"Next.js Data Loader: {loader_alt}",
                        )
                    )
                else:
                    loader_path = f"/_next/data/{build_id}{clean_page}.json"
                    endpoints.append(
                        DiscoveredEndpoint(
                            path=loader_path,
                            method="GET",
                            base_url=clean_base,
                            source="hydration",
                            tags=["hydration", "nextjs", "data_loader"],
                            summary=f"Next.js Data Loader: {loader_path}",
                        )
                    )

        # Also inspect dynamicRoutes in __NEXT_DATA__
        dynamic_routes = data.get("dynamicRoutes") or []
        for dr in dynamic_routes:
            dr_page = dr.get("page") if isinstance(dr, dict) else dr
            if isinstance(dr_page, str) and dr_page != page:
                clean_dr = dr_page if dr_page.startswith("/") else f"/{dr_page}"
                endpoints.append(
                    DiscoveredEndpoint(
                        path=clean_dr,
                        method="GET",
                        base_url=clean_base,
                        source="hydration",
                        tags=["hydration", "nextjs", "dynamic_route"],
                        summary=f"Next.js Dynamic Route: {clean_dr}",
                    )
                )

        return endpoints

    # -----------------------------------------------------------------------
    # 3. Nuxt 3 (__NUXT_DATA__)
    # -----------------------------------------------------------------------
    @classmethod
    def extract_nuxt3(cls, html: str, base_url: str = "") -> List[DiscoveredEndpoint]:
        """
        Fast O(N) parser for Nuxt 3's Devalue flattened array serialization.
        Extracts string paths and nested dict URLs.
        Auto-derives Nuxt 3 payload loaders: {route}/_payload.json
        """
        if "__NUXT_DATA__" not in html:
            return []

        clean_base = cls._normalize_base_url(base_url)
        endpoints: List[DiscoveredEndpoint] = []

        script_content: Optional[str] = None
        match = NUXT_DATA_SCRIPT_REGEX.search(html)
        if match:
            script_content = match.group(1).strip()
        else:
            soup = BeautifulSoup(html, "html.parser")
            tag = soup.find("script", id="__NUXT_DATA__")
            if tag and tag.string:
                script_content = tag.string.strip()

        if not script_content:
            return []

        try:
            data = json.loads(script_content)
        except json.JSONDecodeError:
            logger.debug("Failed to decode __NUXT_DATA__ JSON")
            return []

        if not isinstance(data, list):
            return []

        n = len(data)
        discovered_routes: Set[str] = set()
        discovered_apis: Set[str] = set()

        def _evaluate_candidate(candidate: str) -> None:
            if not isinstance(candidate, str):
                return
            # Handle absolute URLs
            if candidate.startswith(("http://", "https://")):
                split_url = urlsplit(candidate)
                p = split_url.path or "/"
                if split_url.query:
                    p = f"{p}?{split_url.query}"
                if cls._is_valid_path_candidate(p):
                    discovered_apis.add(p)
                return

            if cls._is_valid_path_candidate(candidate) or candidate == "/":
                if candidate.startswith("/api/") or "/api/" in candidate:
                    discovered_apis.add(candidate)
                else:
                    discovered_routes.add(candidate)

        # Fast single O(N) pass across the flattened array
        for item in data:
            if isinstance(item, str):
                _evaluate_candidate(item)
            elif isinstance(item, dict):
                for k, v in item.items():
                    if isinstance(v, str):
                        _evaluate_candidate(v)
                    elif isinstance(v, int) and 0 <= v < n:
                        # Devalue pointer dereference
                        dereferenced = data[v]
                        if isinstance(dereferenced, str):
                            _evaluate_candidate(dereferenced)

        # Convert discovered routes into endpoints and derive payload loaders
        for route in sorted(discovered_routes):
            endpoints.append(
                DiscoveredEndpoint(
                    path=route,
                    method="GET",
                    base_url=clean_base,
                    source="hydration",
                    tags=["hydration", "nuxt", "route"],
                    parameters=_parse_url_params(route),
                    summary=f"Nuxt 3 Route: {route}",
                )
            )

            # Auto-derive Nuxt 3 payload loaders: {route}/_payload.json
            payload_path = "/_payload.json" if route == "/" else f"{route.rstrip('/')}/_payload.json"
            endpoints.append(
                DiscoveredEndpoint(
                    path=payload_path,
                    method="GET",
                    base_url=clean_base,
                    source="hydration",
                    tags=["hydration", "nuxt", "payload_loader"],
                    summary=f"Nuxt 3 Payload Loader: {payload_path}",
                )
            )

        # Convert API endpoints
        for api_path in sorted(discovered_apis):
            endpoints.append(
                DiscoveredEndpoint(
                    path=api_path,
                    method="GET",
                    base_url=clean_base,
                    source="hydration",
                    tags=["hydration", "nuxt", "api"],
                    parameters=_parse_url_params(api_path),
                    summary=f"Nuxt 3 API: {api_path}",
                )
            )

        # If no routes were found but Nuxt 3 is active, always supply root payload loader
        if not discovered_routes:
            endpoints.append(
                DiscoveredEndpoint(
                    path="/_payload.json",
                    method="GET",
                    base_url=clean_base,
                    source="hydration",
                    tags=["hydration", "nuxt", "payload_loader"],
                    summary="Nuxt 3 Payload Loader: /_payload.json",
                )
            )

        return endpoints

    # -----------------------------------------------------------------------
    # 4. Remix & React Router v7
    # -----------------------------------------------------------------------
    @classmethod
    def extract_remix(cls, html: str, base_url: str = "") -> List[DiscoveredEndpoint]:
        """
        Extracts routes map from window.__remixContext or window.__remixManifest,
        reconstructs hierarchical nested routes (parent/child path joining),
        converts :param into OpenAPI {param}, and auto-derives loader data
        endpoints ({path}?_data={routeId}).
        """
        if not any(k in html for k in ("__remix", "__reactRouter")):
            return []

        clean_base = cls._normalize_base_url(base_url)
        endpoints: List[DiscoveredEndpoint] = []
        decoder = json.JSONDecoder()

        for marker in ("__remixContext", "__remixManifest", "__reactRouterContext", "__reactRouterManifest"):
            idx = 0
            while True:
                pos = html.find(marker, idx)
                if pos == -1:
                    break
                eq_pos = html.find("=", pos)
                if eq_pos != -1:
                    brace_pos = html.find("{", eq_pos)
                    if brace_pos != -1 and brace_pos - eq_pos < 30:
                        try:
                            data, _ = decoder.raw_decode(html, brace_pos)
                            if isinstance(data, dict):
                                routes_map: Dict[str, Any] = {}
                                if "manifest" in data and isinstance(data["manifest"], dict):
                                    routes_map = data["manifest"].get("routes") or {}
                                elif "routes" in data and isinstance(data["routes"], dict):
                                    routes_map = data["routes"]

                                if routes_map:
                                    cls._process_remix_routes(routes_map, clean_base, endpoints)
                        except Exception:
                            pass
                idx = pos + len(marker)

        return endpoints

    @classmethod
    def _process_remix_routes(
        cls,
        routes_map: Dict[str, Any],
        base_url: str,
        endpoints: List[DiscoveredEndpoint],
    ) -> None:
        """Reconstructs nested hierarchical routes and emits OpenAPI & loader endpoints."""
        seen_routes: Set[str] = set()

        for route_id, route in routes_map.items():
            if not isinstance(route, dict):
                continue

            # Reconstruct full path by walking up the parentId hierarchy
            segments: List[str] = []
            curr: Optional[Dict[str, Any]] = route
            visited_ids: Set[str] = set()

            while curr and curr.get("id") not in visited_ids:
                curr_id = str(curr.get("id", ""))
                visited_ids.add(curr_id)
                p = curr.get("path")
                if p and isinstance(p, str):
                    clean_p = p.strip("/")
                    if clean_p:
                        segments.append(clean_p)
                parent_id = curr.get("parentId")
                curr = routes_map.get(parent_id) if parent_id else None

            segments.reverse()
            joined_path = "/" + "/".join(segments) if segments else "/"

            # Convert :param into OpenAPI {param}
            openapi_path = re.sub(r":([a-zA-Z_][a-zA-Z0-9_]*)", r"{\1}", joined_path)

            # Extract path parameters
            param_names = re.findall(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}", openapi_path)
            path_parameters = [
                DiscoveredParameter(
                    name=p_name,
                    location="path",
                    required=True,
                    param_type="string",
                )
                for p_name in param_names
            ]

            # 1. Discovered Route Endpoint
            route_key = f"GET:{openapi_path}"
            if route_key not in seen_routes:
                seen_routes.add(route_key)
                endpoints.append(
                    DiscoveredEndpoint(
                        path=openapi_path,
                        method="GET",
                        base_url=base_url,
                        source="hydration",
                        tags=["hydration", "remix", "route"],
                        parameters=path_parameters,
                        summary=f"Remix Route: {openapi_path}",
                    )
                )

            # 2. Auto-derive loader data endpoint: {path}?_data={routeId}
            loader_path = f"{openapi_path}?_data={route_id}"
            loader_key = f"GET:{loader_path}"
            if loader_key not in seen_routes:
                seen_routes.add(loader_key)
                loader_params = list(path_parameters) + [
                    DiscoveredParameter(
                        name="_data",
                        location="query",
                        required=True,
                        param_type="string",
                        example=route_id,
                    )
                ]
                endpoints.append(
                    DiscoveredEndpoint(
                        path=loader_path,
                        method="GET",
                        base_url=base_url,
                        source="hydration",
                        tags=["hydration", "remix", "loader_data"],
                        parameters=loader_params,
                        summary=f"Remix Loader Data: {route_id}",
                    )
                )

    # -----------------------------------------------------------------------
    # 5. SvelteKit (data-sveltekit-fetched)
    # -----------------------------------------------------------------------
    @classmethod
    def extract_sveltekit(
        cls, html: str, base_url: str = ""
    ) -> List[DiscoveredEndpoint]:
        """
        Scrapes <script type="application/json" data-sveltekit-fetched data-url="...">
        Extracts exact API URLs and parsed response schemas into DiscoveredEndpoint.responses.
        """
        if "data-sveltekit-fetched" not in html:
            return []

        clean_base = cls._normalize_base_url(base_url)
        endpoints: List[DiscoveredEndpoint] = []
        seen_urls: Set[str] = set()

        # Regex scan is sub-millisecond (< 0.05ms)
        matched_tags: List[Tuple[str, str]] = []
        for match in SVELTEKIT_SCRIPT_REGEX.finditer(html):
            attrs = match.group(1)
            body_text = match.group(2).strip()
            url_match = SVELTEKIT_URL_REGEX.search(attrs)
            url = url_match.group(1) if url_match else ""
            if url:
                matched_tags.append((url, body_text))

        # Fallback to BeautifulSoup if regex misses malformed tag
        if not matched_tags:
            soup = BeautifulSoup(html, "html.parser")
            for tag in soup.find_all("script", attrs={"data-sveltekit-fetched": True}):
                url = tag.get("data-url")
                if url and tag.string:
                    matched_tags.append((url, tag.string.strip()))

        for url, body_text in matched_tags:
            if url in seen_urls:
                continue
            seen_urls.add(url)

            # Parse JSON body
            raw_json: Any = None
            if body_text:
                try:
                    raw_json = json.loads(body_text)
                except Exception:
                    raw_json = body_text

            status_code = 200
            resp_headers: Dict[str, str] = {"content-type": "application/json"}
            sample_body: Any = None

            # Handle SvelteKit response envelope: {"status": 200, "headers": {...}, "body": "..."}
            if isinstance(raw_json, dict) and ("status" in raw_json or "body" in raw_json):
                status_code = int(raw_json.get("status", 200))
                if isinstance(raw_json.get("headers"), dict):
                    resp_headers = {str(k): str(v) for k, v in raw_json["headers"].items()}
                body_val = raw_json.get("body")
                if isinstance(body_val, str):
                    try:
                        sample_body = json.loads(body_val)
                    except Exception:
                        sample_body = body_val
                elif body_val is not None:
                    sample_body = body_val
                else:
                    sample_body = raw_json
            else:
                sample_body = raw_json

            content_type = resp_headers.get("content-type", "application/json")
            inferred_schema = _infer_schema(sample_body)

            discovered_response = DiscoveredResponse(
                status_code=status_code,
                content_type=content_type,
                headers=resp_headers,
                sample_body=sample_body,
                inferred_schema=inferred_schema,
            )

            endpoints.append(
                DiscoveredEndpoint(
                    path=url,
                    method="GET",
                    base_url=clean_base,
                    source="hydration",
                    tags=["hydration", "sveltekit", "api"],
                    parameters=_parse_url_params(url),
                    responses=[discovered_response],
                    active_status=status_code,
                    summary=f"SvelteKit Fetched API: {url}",
                    description="API endpoint captured from SvelteKit SSR data-sveltekit-fetched hydration script",
                )
            )

        return endpoints

    # -----------------------------------------------------------------------
    # Unified Public Entry Point
    # -----------------------------------------------------------------------
    @classmethod
    def extract_all(cls, html: str, base_url: str = "") -> List[DiscoveredEndpoint]:
        """
        Coordinates all SPA hydration scrapers across Next.js, Nuxt, Remix, and SvelteKit.
        Runs in < 1ms on typical HTML documents.
        """
        if not html:
            return []

        all_endpoints: List[DiscoveredEndpoint] = []

        # 1. Next.js App Router (RSC Flight & Server Actions)
        all_endpoints.extend(cls.extract_nextjs_app_router(html, base_url))

        # 2. Next.js Pages Router (__NEXT_DATA__)
        all_endpoints.extend(cls.extract_nextjs_pages_router(html, base_url))

        # 3. Nuxt 3 (__NUXT_DATA__)
        all_endpoints.extend(cls.extract_nuxt3(html, base_url))

        # 4. Remix & React Router v7
        all_endpoints.extend(cls.extract_remix(html, base_url))

        # 5. SvelteKit (data-sveltekit-fetched)
        all_endpoints.extend(cls.extract_sveltekit(html, base_url))

        # Deduplicate endpoints preserving rich data
        deduped: Dict[Tuple[str, str, str], DiscoveredEndpoint] = {}
        for ep in all_endpoints:
            action_header = ep.headers.get("Next-Action", "")
            key = (ep.method.upper(), ep.path, action_header)
            if key not in deduped:
                deduped[key] = ep
            else:
                existing = deduped[key]
                # Merge tags
                for t in ep.tags:
                    if t not in existing.tags:
                        existing.tags.append(t)
                # Merge responses if new ones exist
                if ep.responses and not existing.responses:
                    existing.responses.extend(ep.responses)
                # Merge parameters
                existing_param_names = {p.name for p in existing.parameters}
                for p in ep.parameters:
                    if p.name not in existing_param_names:
                        existing.parameters.append(p)
                        existing_param_names.add(p.name)

        return list(deduped.values())
