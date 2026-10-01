"""
api_tool.prober.graphql_prober: Non-destructive GraphQL Prober and Introspection Engine.

Features:
- Non-destructive `__typename` query probing via HTTP POST and GET.
- Detection of embedded GraphQL IDE interfaces (Apollo Sandbox, GraphiQL, GraphQL Playground, Altair).
- Standard GraphQL introspection query execution via `graphql-core`.
- High-fidelity SDL (`schema.graphql`) string generation.
- Root field (query, mutation, subscription) and type enumeration.
- Resilient error handling for disabled, restricted, or partial introspection without crashing.
- Pure Python 3, 100% portable for Termux and standard Linux environments.
"""

import asyncio
from dataclasses import asdict, dataclass, field
import json
import logging
import re
import ssl
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx
from graphql import (
    GraphQLSchema,
    build_client_schema,
    get_introspection_query,
    print_schema,
)

logger = logging.getLogger(__name__)


@dataclass
class GraphQLProbeResult:
    """Represents the discovery, probing, and introspection outcome for a GraphQL endpoint."""

    endpoint_url: str
    is_active: bool = False
    supports_post: bool = False
    supports_get: bool = False
    introspection_enabled: bool = False
    schema_sdl: Optional[str] = None
    types_count: int = 0
    query_fields: List[str] = field(default_factory=list)
    mutation_fields: List[str] = field(default_factory=list)
    subscription_fields: List[str] = field(default_factory=list)
    error: Optional[str] = None
    detected_ui: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the probe result to a dictionary."""
        return asdict(self)

    def to_discovered_endpoint(self) -> Any:
        """Converts probe result into an api_tool DiscoveredEndpoint model if active."""
        from api_tool.models import DiscoveredEndpoint

        method = "POST" if self.supports_post else ("GET" if self.supports_get else "POST")
        status_desc = "active" if self.is_active else "inactive"
        ui_desc = f", UI: {self.detected_ui}" if self.detected_ui else ""
        intro_desc = "introspection enabled" if self.introspection_enabled else "introspection blocked"

        q_names = f" [{', '.join(self.query_fields[:5])}]" if self.query_fields else ""
        return DiscoveredEndpoint(
            path=self.endpoint_url,
            method=method,
            source="graphql_prober",
            tags=["graphql", "api"],
            summary=f"GraphQL endpoint ({status_desc}, {intro_desc}{ui_desc})",
            description=(
                f"GraphQL service at {self.endpoint_url}. Types: {self.types_count}, "
                f"Queries: {len(self.query_fields)}{q_names}, Mutations: {len(self.mutation_fields)}"
            ),
            active_status=200 if self.is_active else None,
        )


class GraphQLProber:
    """
    High-performance GraphQL endpoint prober and schema introspection engine.
    """

    CANDIDATE_PATHS: List[str] = [
        "/graphql",
        "/api/graphql",
        "/v1/graphql",
        "/v2/graphql",
        "/query",
        "/api/query",
        "/gql",
        "/graphql/v1",
        "/api/v1/graphql",
    ]

    # Regex patterns for identifying GraphQL IDE HTML interfaces
    _UI_PATTERNS: List[Tuple[str, re.Pattern]] = [
        (
            "Apollo Sandbox",
            re.compile(
                r"(?:apollo-sandbox|EmbeddedSandbox|EmbeddedExplorer|window\.__APOLLO_SANDBOX__|embeddable-sandbox\.cdn\.apollographql\.com|Apollo\s+Sandbox)",
                re.IGNORECASE,
            ),
        ),
        (
            "GraphiQL",
            re.compile(
                r"""(?:id=["']graphiql["']|<title>[^<]*GraphiQL|GraphiQL\.createFetcher|graphiql\.min\.js|React\.createElement\(GraphiQL|GraphQL\s+IDE)""",
                re.IGNORECASE,
            ),
        ),
        (
            "GraphQL Playground",
            re.compile(
                r"(?:graphql-playground-react|window\.GraphQLPlayground|GraphQLPlayground\.init|<title>[^<]*GraphQL\s+Playground)",
                re.IGNORECASE,
            ),
        ),
        (
            "Altair GraphQL",
            re.compile(
                r"(?:altair-static|altair-graphql|Altair\s+GraphQL|<title>[^<]*Altair)",
                re.IGNORECASE,
            ),
        ),
    ]

    def __init__(
        self,
        timeout: float = 10.0,
        headers: Optional[Dict[str, str]] = None,
        verify_ssl: bool = False,
    ) -> None:
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 api-tool/0.1.0"
            ),
            "Accept": "application/json, application/graphql-response+json, text/html;q=0.9, */*;q=0.8",
        }
        if headers:
            self.headers.update(headers)

    def detect_graphql_ui(self, html_text: str) -> Optional[str]:
        """
        Inspects HTML source code for signatures of embedded GraphQL development IDEs
        (Apollo Sandbox, GraphiQL, GraphQL Playground, Altair).
        """
        if not html_text or not isinstance(html_text, str):
            return None

        # Quick check for HTML-like content before scanning
        sample = html_text[:10000].lower()
        if "<!doctype" not in sample and "<html" not in sample and "<div" not in sample and "<script" not in sample:
            return None

        for name, pattern in self._UI_PATTERNS:
            if pattern.search(html_text):
                return name
        return None

    async def probe_endpoint(
        self, url: str, client: Optional[httpx.AsyncClient] = None
    ) -> GraphQLProbeResult:
        """
        Probes an endpoint URL for active GraphQL service using non-destructive __typename queries:
        1. Tests POST with `{"query": "{ __typename }"}` and checks for `data.__typename`.
        2. Tests GET with `?query={ __typename }` to determine GET support.
        3. Inspects HTML response for Apollo Sandbox, GraphiQL, or GraphQL Playground.
        """
        url = url.strip()
        result = GraphQLProbeResult(endpoint_url=url)

        # SSRF guard: validate URL before making any HTTP request (unless using MockTransport in tests)
        is_mock = client is not None and isinstance(getattr(client, "_transport", None), httpx.MockTransport)
        if not is_mock:
            from api_tool.prober.http_prober import is_safe_target  # lazy to avoid circular import
            safe, reason = is_safe_target(url)
            if not safe:
                result.error = f"SSRF protection blocked target: {reason}"
                logger.warning("SSRF blocked GraphQL probe for %s: %s", url, reason)
                return result

        client_provided = client is not None
        c = client or httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout),
            follow_redirects=True,
            verify=self.verify_ssl,
            headers=self.headers,
        )


        post_error: Optional[str] = None
        get_error: Optional[str] = None

        try:
            # 1. Probe via POST {"query": "{ __typename }"}
            try:
                post_headers = {
                    "Content-Type": "application/json",
                    "Accept": "application/json, application/graphql-response+json, */*",
                }
                resp_post = await c.post(
                    url,
                    json={"query": "{ __typename }"},
                    headers=post_headers,
                )
                post_body = resp_post.text
                post_ct = resp_post.headers.get("content-type", "").lower()

                # Check JSON for data.__typename
                if "application/json" in post_ct or "application/graphql-response+json" in post_ct or post_body.strip().startswith("{"):
                    try:
                        post_json = resp_post.json()
                        if isinstance(post_json, dict):
                            data = post_json.get("data")
                            if isinstance(data, dict) and "__typename" in data and data["__typename"] is not None:
                                result.is_active = True
                                result.supports_post = True
                            elif "errors" in post_json and isinstance(post_json["errors"], list):
                                # Structured GraphQL error array indicates an active GraphQL service
                                err_str = str(post_json["errors"]).lower()
                                if any(k in err_str for k in ("syntax", "query", "graphql", "unauthorized", "auth", "validation", "forbidden")):
                                    result.is_active = True
                                    result.supports_post = True
                    except Exception:
                        pass

                # Check if POST response contains GraphQL IDE UI
                if "text/html" in post_ct or "<html" in post_body.lower():
                    ui = self.detect_graphql_ui(post_body)
                    if ui:
                        result.is_active = True
                        result.detected_ui = ui

            except Exception as e:
                post_error = str(e)
                logger.debug("POST probe error for %s: %s", url, e)

            # 2. Probe via GET ?query={ __typename }
            try:
                get_headers = {
                    "Accept": "application/json, application/graphql-response+json, text/html;q=0.9, */*;q=0.8",
                }
                resp_get = await c.get(
                    url,
                    params={"query": "{ __typename }"},
                    headers=get_headers,
                )
                get_body = resp_get.text
                get_ct = resp_get.headers.get("content-type", "").lower()

                # Check JSON for data.__typename
                if "application/json" in get_ct or "application/graphql-response+json" in get_ct or get_body.strip().startswith("{"):
                    try:
                        get_json = resp_get.json()
                        if isinstance(get_json, dict):
                            data = get_json.get("data")
                            if isinstance(data, dict) and "__typename" in data and data["__typename"] is not None:
                                result.is_active = True
                                result.supports_get = True
                            elif "errors" in get_json and isinstance(get_json["errors"], list):
                                err_str = str(get_json["errors"]).lower()
                                if any(k in err_str for k in ("syntax", "query", "graphql", "unauthorized", "auth", "validation", "forbidden")):
                                    result.is_active = True
                                    result.supports_get = True
                    except Exception:
                        pass

                # Check if GET response contains GraphQL IDE UI
                if "text/html" in get_ct or "<html" in get_body.lower():
                    ui = self.detect_graphql_ui(get_body)
                    if ui:
                        result.is_active = True
                        result.detected_ui = ui

            except Exception as e:
                get_error = str(e)
                logger.debug("GET probe error for %s: %s", url, e)

            # 3. Fallback: GET without query string for IDEs that only serve HTML on clean URLs
            if not result.is_active and not result.detected_ui:
                try:
                    resp_ui = await c.get(url, headers={"Accept": "text/html, */*"})
                    if resp_ui.status_code < 400:
                        ui = self.detect_graphql_ui(resp_ui.text)
                        if ui:
                            result.is_active = True
                            result.detected_ui = ui
                except Exception:
                    pass

            # Consolidate errors if endpoint could not be reached / is not active
            if not result.is_active:
                if post_error and get_error:
                    result.error = f"Probing failed: POST ({post_error}); GET ({get_error})"
                elif post_error:
                    result.error = f"POST probe failed: {post_error}"
                elif get_error:
                    result.error = f"GET probe failed: {get_error}"
            else:
                result.error = None

            return result

        finally:
            if not client_provided:
                await c.aclose()

    async def run_introspection(
        self,
        url: str,
        client: Optional[httpx.AsyncClient] = None,
        probe_result: Optional[GraphQLProbeResult] = None,
    ) -> GraphQLProbeResult:
        """
        Executes standard GraphQL schema introspection on target endpoint:
        1. Probes endpoint if not already verified active.
        2. Issues standard IntrospectionQuery via POST (or GET fallback).
        3. Parses schema via `graphql-core`, compiles SDL schema.graphql string,
           and counts root query/mutation/subscription fields.
        4. Handles disabled introspection or error states cleanly without crashing.
        """
        url = url.strip()

        # SSRF guard: validate URL before making any HTTP request (unless using MockTransport in tests)
        is_mock = client is not None and isinstance(getattr(client, "_transport", None), httpx.MockTransport)
        if not is_mock:
            from api_tool.prober.http_prober import is_safe_target  # lazy to avoid circular import
            safe, reason = is_safe_target(url)
            if not safe:
                empty_result = GraphQLProbeResult(
                    endpoint_url=url,
                    error=f"SSRF protection blocked target: {reason}",
                )
                logger.warning("SSRF blocked GraphQL introspection for %s: %s", url, reason)
                return empty_result

        client_provided = client is not None
        c = client or httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout),
            follow_redirects=True,
            verify=self.verify_ssl,
            headers=self.headers,
        )


        try:
            # 1. Ensure endpoint is active first
            if probe_result is not None:
                result = probe_result
            else:
                result = await self.probe_endpoint(url, client=c)

            if not result.is_active:
                return result

            # 2. Prepare standard introspection query
            intro_query = get_introspection_query(descriptions=True)
            resp: Optional[httpx.Response] = None

            # Helper to execute introspection request
            async def _send_intro(q: str) -> Optional[httpx.Response]:
                res = None
                # Prefer POST if supported or untried
                if result.supports_post or not result.supports_get:
                    try:
                        res = await c.post(
                            url,
                            json={"query": q},
                            headers={
                                "Content-Type": "application/json",
                                "Accept": "application/json, application/graphql-response+json, */*",
                            },
                        )
                    except Exception as e:
                        logger.debug("Introspection POST failed: %s", e)

                # Fallback to GET if POST was not tried, returned 405, or failed
                if (res is None or res.status_code == 405) and (result.supports_get or not result.supports_post):
                    try:
                        res = await c.get(
                            url,
                            params={"query": q},
                            headers={
                                "Accept": "application/json, application/graphql-response+json, */*",
                            },
                        )
                    except Exception as e:
                        logger.debug("Introspection GET failed: %s", e)
                return res

            resp = await _send_intro(intro_query)

            # Retry with descriptions=False if older GraphQL engine rejects 'description' field
            if resp is not None and resp.status_code == 400:
                try:
                    check_json = resp.json()
                    err_txt = str(check_json.get("errors", "")).lower()
                    if "description" in err_txt and ("unknown field" in err_txt or "cannot query field" in err_txt):
                        fallback_query = get_introspection_query(descriptions=False)
                        fallback_resp = await _send_intro(fallback_query)
                        if fallback_resp is not None:
                            resp = fallback_resp
                except Exception:
                    pass

            if resp is None:
                result.introspection_enabled = False
                result.error = "Introspection request failed: network or protocol error"
                return result

            # 3. Check for forbidden, blocked, or disabled introspection
            if resp.status_code in (401, 403):
                result.introspection_enabled = False
                result.error = f"HTTP {resp.status_code}: Introspection forbidden or unauthorized"
                return result

            try:
                resp_json = resp.json()
            except Exception:
                result.introspection_enabled = False
                result.error = f"HTTP {resp.status_code}: Non-JSON introspection response ({resp.text[:100]})"
                return result

            if not isinstance(resp_json, dict):
                result.introspection_enabled = False
                result.error = f"Unexpected introspection response format: {type(resp_json).__name__}"
                return result

            errors = resp_json.get("errors")
            data = resp_json.get("data")

            # Check if errors indicate disabled introspection
            if errors and not (isinstance(data, dict) and data.get("__schema")):
                err_messages = []
                if isinstance(errors, list):
                    for err in errors:
                        if isinstance(err, dict) and "message" in err:
                            err_messages.append(str(err["message"]))
                        elif isinstance(err, str):
                            err_messages.append(err)
                err_summary = "; ".join(err_messages) if err_messages else str(errors)
                result.introspection_enabled = False
                result.error = f"Introspection disabled or blocked: {err_summary}"
                return result

            if not isinstance(data, dict) or not data.get("__schema"):
                result.introspection_enabled = False
                if errors:
                    result.error = f"Introspection blocked: {str(errors)}"
                else:
                    result.error = f"Introspection returned null __schema (HTTP {resp.status_code})"
                return result

            # 4. Successful Introspection: Build Client Schema & Generate SDL
            schema_data = data if "__schema" in data else resp_json
            client_schema: Optional[GraphQLSchema] = None

            try:
                try:
                    client_schema = build_client_schema(schema_data)
                except Exception:
                    # Retry with assume_valid=True for non-strict schemas
                    client_schema = build_client_schema(schema_data, assume_valid=True)

                sdl_str = print_schema(client_schema)
                result.schema_sdl = sdl_str
                result.introspection_enabled = True
                result.types_count = len(client_schema.type_map)

                if client_schema.query_type and hasattr(client_schema.query_type, "fields"):
                    result.query_fields = sorted(list(client_schema.query_type.fields.keys()))
                if client_schema.mutation_type and hasattr(client_schema.mutation_type, "fields"):
                    result.mutation_fields = sorted(list(client_schema.mutation_type.fields.keys()))
                if client_schema.subscription_type and hasattr(client_schema.subscription_type, "fields"):
                    result.subscription_fields = sorted(list(client_schema.subscription_type.fields.keys()))

                result.error = None

            except Exception as e:
                # Resilient fallback: parse raw schema dict directly if build_client_schema/print_schema raises
                try:
                    inner_schema = schema_data.get("__schema", {})
                    types_list = inner_schema.get("types", [])
                    result.types_count = len(types_list)
                    type_by_name = {
                        t.get("name"): t for t in types_list if isinstance(t, dict) and t.get("name")
                    }

                    q_type = (inner_schema.get("queryType") or {}).get("name")
                    if q_type and q_type in type_by_name:
                        result.query_fields = sorted([
                            f.get("name") for f in type_by_name[q_type].get("fields", [])
                            if isinstance(f, dict) and f.get("name")
                        ])

                    m_type = (inner_schema.get("mutationType") or {}).get("name")
                    if m_type and m_type in type_by_name:
                        result.mutation_fields = sorted([
                            f.get("name") for f in type_by_name[m_type].get("fields", [])
                            if isinstance(f, dict) and f.get("name")
                        ])

                    s_type = (inner_schema.get("subscriptionType") or {}).get("name")
                    if s_type and s_type in type_by_name:
                        result.subscription_fields = sorted([
                            f.get("name") for f in type_by_name[s_type].get("fields", [])
                            if isinstance(f, dict) and f.get("name")
                        ])

                    result.introspection_enabled = True
                    result.error = f"Partial schema recovered (SDL generation failed: {str(e)})"

                except Exception as fallback_err:
                    result.introspection_enabled = False
                    result.error = f"Introspection schema parsing failed: {str(e)}"

            return result

        finally:
            if not client_provided:
                await c.aclose()

    async def discover_and_probe(
        self,
        base_url: str,
        candidate_endpoints: Optional[List[str]] = None,
        client: Optional[httpx.AsyncClient] = None,
        active_only: bool = True,
    ) -> List[GraphQLProbeResult]:
        """
        Combines candidate paths with any provided discovered endpoints,
        probes endpoints, and attempts introspection on all active GraphQL services.

        Args:
            base_url: Base target URL (e.g. 'https://api.example.com').
            candidate_endpoints: Optional list of discovered endpoints or paths.
            client: Optional reusable httpx.AsyncClient.
            active_only: If True (default), filters results to active GraphQL services only.
                         If False, returns probe results for all tested paths.
        """
        clean_base = base_url.strip().rstrip("/")

        # SSRF guard on the base URL (unless using MockTransport in tests)
        is_mock = client is not None and isinstance(getattr(client, "_transport", None), httpx.MockTransport)
        if not is_mock:
            from api_tool.prober.http_prober import is_safe_target  # lazy to avoid circular import
            safe, reason = is_safe_target(clean_base)
            if not safe:
                logger.warning("SSRF blocked GraphQL discover_and_probe for %s: %s", clean_base, reason)
                return []

        all_paths: List[str] = []

        # Discovered endpoints first
        if candidate_endpoints:
            for ep in candidate_endpoints:
                if ep and ep not in all_paths:
                    all_paths.append(ep)

        # Standard candidate paths next
        for cp in self.CANDIDATE_PATHS:
            if cp not in all_paths:
                all_paths.append(cp)

        # Resolve to deduplicated full URLs
        target_urls: List[str] = []
        for path in all_paths:
            path_str = path.strip()
            if path_str.startswith("http://") or path_str.startswith("https://"):
                full_url = path_str
            else:
                full_url = f"{clean_base}/{path_str.lstrip('/')}"
            if full_url not in target_urls:
                target_urls.append(full_url)

        client_provided = client is not None
        c = client or httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout),
            follow_redirects=True,
            verify=self.verify_ssl,
            headers=self.headers,
        )


        try:
            # Concurrently probe and introspect endpoints with bounded concurrency
            sem = asyncio.Semaphore(5)

            async def _probe_single(u: str) -> GraphQLProbeResult:
                async with sem:
                    return await self.run_introspection(u, client=c)

            results = await asyncio.gather(*(_probe_single(u) for u in target_urls))

            if active_only:
                return [r for r in results if r.is_active]
            return list(results)

        finally:
            if not client_provided:
                await c.aclose()
