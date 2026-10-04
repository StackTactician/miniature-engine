"""
HAR 1.2 Ingestion Engine for api-tool.
Pure Python standard library implementation with zero external dependencies.

Parses HTTP Archive (HAR) 1.2 files and transforms recorded network transactions
into the unified intermediate representation (IR): ScanResult, DiscoveredEndpoint,
DiscoveredParameter, DiscoveredResponse, and GraphQLOperation.
"""

import base64
import json
import logging
import os
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from api_tool.exporter.schema_inference import OpenAPISchemaInferrer
from api_tool.models import (
    DiscoveredEndpoint,
    DiscoveredParameter,
    DiscoveredResponse,
    GraphQLOperation,
    ScanResult,
)

logger = logging.getLogger(__name__)

# Extensions strictly filtered out from endpoint discovery
DEFAULT_BLOCKED_EXTENSIONS: Set[str] = {
    # Images
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".bmp", ".tiff", ".tif", ".avif",
    # Styles
    ".css", ".scss", ".less",
    # Fonts
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    # Media
    ".mp4", ".webm", ".mp3", ".wav", ".ogg", ".m4a", ".flac", ".aac", ".avi", ".mkv", ".mov",
    # Archives / Executables / Docs
    ".pdf", ".zip", ".gz", ".tar", ".bz2", ".7z", ".rar", ".exe", ".bin", ".dmg", ".iso",
    # Static scripts & maps
    ".js", ".mjs", ".map", ".wasm",
}

# Static MIME types filtered out
DEFAULT_BLOCKED_MIME_PREFIXES: Tuple[str, ...] = (
    "image/",
    "font/",
    "audio/",
    "video/",
    "text/css",
    "application/javascript",
    "text/javascript",
)

# Known analytics, advertising, and APM tracking domains
DEFAULT_BLOCKED_TRACKERS: Set[str] = {
    # Google Analytics, GTM, DoubleClick, Ads
    "google-analytics.com",
    "googletagmanager.com",
    "doubleclick.net",
    "googleadservices.com",
    "google.analytics.com",
    # Sentry error reporting
    "sentry.io",
    "browser.sentry-cdn.com",
    # Datadog APM & RUM
    "datadoghq.com",
    "datadoghq-browser-agent.com",
    # Segment / Mixpanel / Amplitude / Heap / Hotjar
    "segment.io",
    "segment.com",
    "mixpanel.com",
    "amplitude.com",
    "heap.io",
    "heapanalytics.com",
    "hotjar.com",
    "fullstory.com",
    "intercom.io",
    "crisp.chat",
    "clarity.ms",
    "facebook.net",
    "connect.facebook.net",
    "tiktok.com",
    "analytics.tiktok.com",
    "bing.com",
    "bat.bing.com",
    "newrelic.com",
    "nr-data.net",
    "bugsnag.com",
    "rollbar.com",
    "loggly.com",
    "optimizely.com",
    "branch.io",
    "appsflyer.com",
    "adjust.com",
    "criteo.com",
    "criteo.net",
}

# Common header names used for API Key authentication
API_KEY_HEADERS: Set[str] = {
    "x-api-key",
    "api-key",
    "apikey",
    "x-auth-token",
    "x-access-token",
    "x-token",
    "x-app-key",
    "x-api-token",
    "x-gitlab-token",
    "x-github-token",
}

# Common session cookie names
SESSION_COOKIE_NAMES: Set[str] = {
    "session",
    "sessionid",
    "session_id",
    "jsessionid",
    "phpsessid",
    "connect.sid",
    "token",
    "auth_token",
    "jwt",
    "access_token",
    "auth",
    "remember_token",
    "csrftoken",
    "_csrf",
    "sid",
    "logged_in",
    "user_session",
    "session-id",
}


def _infer_scalar_type(val: Any) -> str:
    """Infers parameter scalar type for query/path/form parameters."""
    if val is None:
        return "string"
    s = str(val).strip()
    if s.lower() in ("true", "false"):
        return "boolean"
    if re.match(r"^-?\d+$", s):
        return "integer"
    if re.match(r"^-?\d+\.\d+$", s):
        return "number"
    return "string"


class HARImporter:
    """
    Ingests HAR 1.2 log files and converts them into normalized ScanResult models.
    Supports OpenAPI 3.1.0 schema inference, GraphQL operation detection,
    authentication extraction, and multi-request endpoint merging.
    """

    def __init__(
        self,
        filter_static: bool = True,
        filter_trackers: bool = True,
        blocked_extensions: Optional[Set[str]] = None,
        blocked_trackers: Optional[Set[str]] = None,
        schema_inferrer: Optional[OpenAPISchemaInferrer] = None,
    ) -> None:
        self.filter_static = filter_static
        self.filter_trackers = filter_trackers
        self.blocked_extensions = (
            {ext.lower() for ext in blocked_extensions}
            if blocked_extensions is not None
            else set(DEFAULT_BLOCKED_EXTENSIONS)
        )
        self.blocked_trackers = (
            {tr.lower() for tr in blocked_trackers}
            if blocked_trackers is not None
            else set(DEFAULT_BLOCKED_TRACKERS)
        )
        self.schema_inferrer = schema_inferrer or OpenAPISchemaInferrer()

    def import_file(self, file_path: str) -> ScanResult:
        """
        Parses a HAR 1.2 file from disk and returns a ScanResult.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"HAR file not found: {file_path}")

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
        except UnicodeDecodeError:
            with open(file_path, "r", encoding="latin-1") as f:
                content = f.read()

        return self.import_json(content)

    def import_json(self, raw_har: Union[str, Dict[str, Any]]) -> ScanResult:
        """
        Parses a HAR 1.2 JSON string or dictionary and returns a ScanResult.
        """
        if isinstance(raw_har, str):
            if not raw_har.strip():
                raise ValueError("Empty HAR content provided.")
            har_data = json.loads(raw_har)
        elif isinstance(raw_har, dict):
            har_data = raw_har
        else:
            raise TypeError(f"Expected str or dict for raw_har, got {type(raw_har).__name__}")

        log_data = har_data.get("log", {}) if isinstance(har_data, dict) else {}
        entries = log_data.get("entries") or har_data.get("entries") or []
        if not isinstance(entries, list):
            entries = []

        # Target URL and base URLs resolution
        pages = log_data.get("pages", []) if isinstance(log_data, dict) else []
        target_url = ""
        if isinstance(pages, list) and pages:
            first_page = pages[0]
            if isinstance(first_page, dict):
                title = first_page.get("title", "")
                if title and title.startswith(("http://", "https://")):
                    target_url = title

        discovered_base_urls: List[str] = []
        discovered_specs: List[str] = []
        graphql_ops_map: Dict[Tuple[str, str, str, str], GraphQLOperation] = {}
        endpoints_map: Dict[Tuple[str, str, str], DiscoveredEndpoint] = {}

        filtered_static_count = 0
        filtered_tracker_count = 0

        for entry in entries:
            if not isinstance(entry, dict):
                continue

            req = entry.get("request") or {}
            resp = entry.get("response") or {}
            if not isinstance(req, dict):
                continue

            raw_url = req.get("url", "")
            if not raw_url:
                continue

            parsed_url = urllib.parse.urlsplit(raw_url)
            host = (parsed_url.hostname or "").lower()

            # 1. Filter tracking domains
            if self.filter_trackers and self._is_tracker(host):
                filtered_tracker_count += 1
                continue

            # 2. Filter static asset extensions and content-types
            path = parsed_url.path or "/"
            if self.filter_static and self._is_static_asset(path, resp):
                filtered_static_count += 1
                continue

            # Record base URL
            if parsed_url.scheme and parsed_url.netloc:
                base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                if base_url not in discovered_base_urls:
                    discovered_base_urls.append(base_url)
            else:
                base_url = ""

            if not target_url:
                target_url = base_url or raw_url

            # Check if this request is a spec document (OpenAPI/Swagger)
            lower_path = path.lower()
            if any(lower_path.endswith(s) for s in ("swagger.json", "openapi.json", "swagger.yaml", "openapi.yaml", "/api-docs")):
                spec_full = raw_url.split("?")[0]
                if spec_full not in discovered_specs:
                    discovered_specs.append(spec_full)

            # 3. Detect embedded GraphQL operations
            gql_ops = self._detect_graphql(req, path)
            for op in gql_ops:
                key = (op.operation_type, op.operation_name, op.query_string, op.endpoint)
                if key not in graphql_ops_map:
                    graphql_ops_map[key] = op

            # 4. Extract authentication headers, cookies, and tokens
            auth_type, auth_header_or_param = self._extract_auth(req)

            # 5. Extract request parameters (Query, Headers, Form Body)
            params = self._extract_parameters(req, parsed_url)

            # 6. Extract request body and infer schema
            req_sample, req_schema = self._extract_request_body(req)

            # 7. Extract response and infer schema
            discovered_resp = self._extract_response(resp)

            # 8. Merge into endpoints_map by (method, base_url, path)
            method = (req.get("method") or "GET").upper()
            req_headers = {
                h.get("name", ""): h.get("value", "")
                for h in req.get("headers", [])
                if isinstance(h, dict) and "name" in h
            }

            merge_key = (method, base_url, path)
            if merge_key not in endpoints_map:
                tags: List[str] = []
                if gql_ops:
                    tags.append("graphql")
                # Add path segment tag if available (e.g. /v1/users -> "users")
                path_parts = [p for p in path.strip("/").split("/") if p and not p.startswith("v") and not p.isdigit()]
                if path_parts:
                    tags.append(path_parts[0])

                endpoint = DiscoveredEndpoint(
                    path=path,
                    method=method,
                    base_url=base_url,
                    source="har",
                    tags=tags,
                    parameters=params,
                    request_body_sample=req_sample,
                    request_body_schema=req_schema,
                    responses=[discovered_resp] if discovered_resp else [],
                    auth_type=auth_type,
                    auth_header_or_param=auth_header_or_param,
                    active_status=discovered_resp.status_code if discovered_resp else None,
                    headers=req_headers,
                )
                endpoints_map[merge_key] = endpoint
            else:
                # Merge into existing endpoint
                self._merge_endpoint(
                    existing=endpoints_map[merge_key],
                    incoming_params=params,
                    incoming_headers=req_headers,
                    incoming_req_sample=req_sample,
                    incoming_req_schema=req_schema,
                    incoming_resp=discovered_resp,
                    incoming_auth_type=auth_type,
                    incoming_auth_param=auth_header_or_param,
                    is_graphql=bool(gql_ops),
                )

        endpoints = list(endpoints_map.values())
        graphql_operations = list(graphql_ops_map.values())

        metadata = {
            "source": "har",
            "har_version": log_data.get("version", "1.2"),
            "creator": log_data.get("creator", {}),
            "total_entries": len(entries),
            "filtered_static_entries": filtered_static_count,
            "filtered_tracker_entries": filtered_tracker_count,
            "imported_endpoints_count": len(endpoints),
            "graphql_operations_count": len(graphql_operations),
        }

        return ScanResult(
            target_url=target_url,
            base_urls=discovered_base_urls,
            endpoints=endpoints,
            graphql_operations=graphql_operations,
            discovered_specs=discovered_specs,
            metadata=metadata,
        )

    # -------------------------------------------------------------------------
    # Filtering Helpers
    # -------------------------------------------------------------------------

    def _is_tracker(self, host: str) -> bool:
        if not host:
            return False
        host = host.split(":")[0].lower()
        for tracker in self.blocked_trackers:
            if host == tracker or host.endswith("." + tracker):
                return True
        return False

    def _is_static_asset(self, path: str, response: Dict[str, Any]) -> bool:
        # Check URL file extension
        _, ext = os.path.splitext(path.lower())
        if ext and ext in self.blocked_extensions:
            return True

        # Check Response Content-Type
        content = response.get("content") or {}
        if isinstance(content, dict):
            mime = (content.get("mimeType") or "").lower()
            if mime:
                clean_mime = mime.split(";")[0].strip()
                if clean_mime in ("image/x-icon", "image/vnd.microsoft.icon", "text/css"):
                    return True
                for prefix in DEFAULT_BLOCKED_MIME_PREFIXES:
                    if clean_mime.startswith(prefix):
                        return True

        return False

    # -------------------------------------------------------------------------
    # Auth Extraction
    # -------------------------------------------------------------------------

    def _extract_auth(self, req: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
        headers = req.get("headers", [])
        if not isinstance(headers, list):
            headers = []

        # 1. Authorization header (Bearer / Basic / Token)
        for h in headers:
            if not isinstance(h, dict):
                continue
            h_name = str(h.get("name", ""))
            h_val = str(h.get("value", "")).strip()
            if h_name.lower() == "authorization":
                lower_val = h_val.lower()
                if lower_val.startswith("bearer "):
                    return "bearer", h_name
                if lower_val.startswith("basic "):
                    return "basic", h_name
                if lower_val.startswith("token ") or lower_val.startswith("apikey "):
                    return "apikey", h_name
                return "bearer", h_name

        # 2. Custom API Key headers
        for h in headers:
            if not isinstance(h, dict):
                continue
            h_name = str(h.get("name", ""))
            if h_name.lower() in API_KEY_HEADERS:
                if str(h.get("value", "")).strip():
                    return "apikey", h_name

        # 3. Session Cookies
        cookies = req.get("cookies", [])
        if isinstance(cookies, list):
            for c in cookies:
                if not isinstance(c, dict):
                    continue
                c_name = str(c.get("name", ""))
                c_lower = c_name.lower()
                if c_lower in SESSION_COOKIE_NAMES or any(k in c_lower for k in ("session", "token", "auth")):
                    return "cookie", c_name

        # Check raw Cookie header if cookies list was omitted
        for h in headers:
            if not isinstance(h, dict):
                continue
            if str(h.get("name", "")).lower() == "cookie":
                raw_cookie = str(h.get("value", ""))
                parts = [p.strip() for p in raw_cookie.split(";") if p.strip()]
                for p in parts:
                    if "=" in p:
                        c_name = p.split("=", 1)[0].strip()
                        c_lower = c_name.lower()
                        if c_lower in SESSION_COOKIE_NAMES or any(k in c_lower for k in ("session", "token", "auth")):
                            return "cookie", c_name

        # 4. API Key in query string
        q_list = req.get("queryString", [])
        if isinstance(q_list, list):
            for q in q_list:
                if not isinstance(q, dict):
                    continue
                q_name = str(q.get("name", ""))
                if q_name.lower() in ("api_key", "apikey", "key", "access_token"):
                    return "apikey", q_name

        return None, None

    # -------------------------------------------------------------------------
    # GraphQL Detection
    # -------------------------------------------------------------------------

    def _detect_graphql(self, req: Dict[str, Any], path: str) -> List[GraphQLOperation]:
        ops: List[GraphQLOperation] = []
        is_graphql_path = path.rstrip("/").endswith("/graphql") or "/graphql" in path

        # Check POST data body
        post_data = req.get("postData") or {}
        if isinstance(post_data, dict):
            body_text = post_data.get("text") or ""
            if body_text and isinstance(body_text, str) and body_text.strip():
                try:
                    parsed_json = json.loads(body_text)
                    items = parsed_json if isinstance(parsed_json, list) else [parsed_json]
                    for item in items:
                        if isinstance(item, dict) and ("query" in item or "variables" in item or is_graphql_path):
                            query_str = item.get("query")
                            if query_str and isinstance(query_str, str) and query_str.strip():
                                op_name = item.get("operationName")
                                var_sample = item.get("variables") if isinstance(item.get("variables"), dict) else None
                                op = self._parse_graphql_query(query_str, path, op_name, var_sample)
                                ops.append(op)
                except Exception:
                    pass

        # Check GET query parameters (?query=...)
        if not ops:
            q_list = req.get("queryString", [])
            query_param: Optional[str] = None
            var_param: Optional[Dict[str, Any]] = None
            op_name_param: Optional[str] = None

            if isinstance(q_list, list):
                for q in q_list:
                    if not isinstance(q, dict):
                        continue
                    name = str(q.get("name", ""))
                    val = str(q.get("value", ""))
                    if name == "query" and val:
                        query_param = val
                    elif name == "variables" and val:
                        try:
                            var_param = json.loads(val)
                        except Exception:
                            pass
                    elif name == "operationName" and val:
                        op_name_param = val

            if query_param and (is_graphql_path or "{" in query_param or any(k in query_param for k in ("query", "mutation", "subscription"))):
                op = self._parse_graphql_query(query_param, path, op_name_param, var_param)
                ops.append(op)

        return ops

    def _parse_graphql_query(
        self,
        query_str: str,
        endpoint: str,
        preferred_name: Optional[str] = None,
        variables_sample: Optional[Dict[str, Any]] = None,
    ) -> GraphQLOperation:
        # Strip comments starting with '#'
        clean_lines = [line.split("#", 1)[0] for line in query_str.splitlines()]
        clean_text = "\n".join(clean_lines).strip()

        # Match operation type and operation name
        # e.g.: query GetUsers { ... } or mutation CreateUser($id: ID) { ... }
        match = re.search(r"^\s*(query|mutation|subscription)\s+([A-Za-z0-9_]+)?", clean_text)
        if match:
            op_type = match.group(1).lower()
            extracted_name = match.group(2)
        elif clean_text.startswith("{"):
            op_type = "query"
            extracted_name = None
        else:
            op_type = "query"
            extracted_name = None

        op_name = preferred_name or extracted_name or "GraphQLOperation"

        return GraphQLOperation(
            operation_type=op_type,
            operation_name=op_name,
            query_string=query_str.strip(),
            endpoint=endpoint,
            variables_sample=variables_sample,
        )

    # -------------------------------------------------------------------------
    # Parameter Extraction
    # -------------------------------------------------------------------------

    def _extract_parameters(
        self, req: Dict[str, Any], parsed_url: urllib.parse.SplitResult
    ) -> List[DiscoveredParameter]:
        params: List[DiscoveredParameter] = []
        seen_names: Set[Tuple[str, str]] = set()

        # 1. Query parameters
        q_list = req.get("queryString", [])
        if isinstance(q_list, list) and q_list:
            for q in q_list:
                if not isinstance(q, dict):
                    continue
                name = q.get("name")
                if not name:
                    continue
                val = q.get("value")
                pair = (name, "query")
                if pair not in seen_names:
                    seen_names.add(pair)
                    params.append(
                        DiscoveredParameter(
                            name=name,
                            location="query",
                            required=False,
                            param_type=_infer_scalar_type(val),
                            example=val,
                        )
                    )
        elif parsed_url.query:
            # Fallback to query string in URL
            for name, val in urllib.parse.parse_qsl(parsed_url.query, keep_blank_values=True):
                pair = (name, "query")
                if pair not in seen_names:
                    seen_names.add(pair)
                    params.append(
                        DiscoveredParameter(
                            name=name,
                            location="query",
                            required=False,
                            param_type=_infer_scalar_type(val),
                            example=val,
                        )
                    )

        # 2. Form data body parameters (postData.params)
        post_data = req.get("postData") or {}
        if isinstance(post_data, dict):
            post_params = post_data.get("params", [])
            if isinstance(post_params, list):
                for p in post_params:
                    if not isinstance(p, dict):
                        continue
                    name = p.get("name")
                    if not name:
                        continue
                    val = p.get("value")
                    pair = (name, "body")
                    if pair not in seen_names:
                        seen_names.add(pair)
                        params.append(
                            DiscoveredParameter(
                                name=name,
                                location="body",
                                required=False,
                                param_type=_infer_scalar_type(val),
                                example=val,
                            )
                        )

        return params

    # -------------------------------------------------------------------------
    # Request & Response Bodies and Schema Inference
    # -------------------------------------------------------------------------

    def _extract_request_body(
        self, req: Dict[str, Any]
    ) -> Tuple[Optional[Any], Optional[Dict[str, Any]]]:
        post_data = req.get("postData")
        if not isinstance(post_data, dict):
            return None, None

        raw_text = post_data.get("text")
        if not raw_text or not isinstance(raw_text, str) or not raw_text.strip():
            return None, None

        mime = (post_data.get("mimeType") or "").lower()
        stripped = raw_text.strip()

        if "json" in mime or stripped.startswith(("{", "[")):
            try:
                body_json = json.loads(stripped)
                schema = self.schema_inferrer.infer(body_json)
                return body_json, schema
            except Exception:
                pass

        return stripped, None

    def _extract_response(self, resp: Dict[str, Any]) -> Optional[DiscoveredResponse]:
        if not isinstance(resp, dict):
            return None

        status_code = resp.get("status")
        try:
            status_code = int(status_code)
        except (ValueError, TypeError):
            status_code = 200

        content = resp.get("content") or {}
        mime_type = "application/json"
        raw_text = None
        sample_body: Optional[Any] = None
        inferred_schema: Optional[Dict[str, Any]] = None

        if isinstance(content, dict):
            mime_type = content.get("mimeType") or "application/json"
            raw_text = content.get("text")
            encoding = (content.get("encoding") or "").lower()

            if encoding == "base64" and raw_text and isinstance(raw_text, str):
                try:
                    raw_text = base64.b64decode(raw_text).decode("utf-8", errors="replace")
                except Exception:
                    pass

            if raw_text and isinstance(raw_text, str) and raw_text.strip():
                stripped = raw_text.strip()
                if "json" in mime_type.lower() or stripped.startswith(("{", "[")):
                    try:
                        sample_body = json.loads(stripped)
                        inferred_schema = self.schema_inferrer.infer(sample_body)
                    except Exception:
                        sample_body = stripped
                else:
                    sample_body = stripped

        # Extract headers
        headers_list = resp.get("headers", [])
        resp_headers: Dict[str, str] = {}
        if isinstance(headers_list, list):
            for h in headers_list:
                if isinstance(h, dict) and "name" in h:
                    resp_headers[str(h["name"])] = str(h.get("value", ""))

        return DiscoveredResponse(
            status_code=status_code,
            content_type=mime_type,
            headers=resp_headers,
            sample_body=sample_body,
            inferred_schema=inferred_schema,
        )

    # -------------------------------------------------------------------------
    # Endpoint Merging
    # -------------------------------------------------------------------------

    def _merge_endpoint(
        self,
        existing: DiscoveredEndpoint,
        incoming_params: List[DiscoveredParameter],
        incoming_headers: Dict[str, str],
        incoming_req_sample: Optional[Any],
        incoming_req_schema: Optional[Dict[str, Any]],
        incoming_resp: Optional[DiscoveredResponse],
        incoming_auth_type: Optional[str],
        incoming_auth_param: Optional[str],
        is_graphql: bool,
    ) -> None:
        # 1. Aggregate parameters
        existing_params_map = {(p.name, p.location): p for p in existing.parameters}
        for p in incoming_params:
            key = (p.name, p.location)
            if key not in existing_params_map:
                existing.parameters.append(p)
                existing_params_map[key] = p
            else:
                curr = existing_params_map[key]
                if curr.example is None and p.example is not None:
                    curr.example = p.example

        # 2. Aggregate request headers
        for hk, hv in incoming_headers.items():
            if hk not in existing.headers:
                existing.headers[hk] = hv

        # 3. Update auth if not set
        if not existing.auth_type and incoming_auth_type:
            existing.auth_type = incoming_auth_type
            existing.auth_header_or_param = incoming_auth_param

        # 4. Merge request body schema
        if incoming_req_schema:
            if not existing.request_body_schema:
                existing.request_body_schema = incoming_req_schema
                existing.request_body_sample = incoming_req_sample
            else:
                existing.request_body_schema = self.schema_inferrer.merge(
                    existing.request_body_schema, incoming_req_schema
                )

        # 5. Aggregate responses by status code
        if incoming_resp:
            matched_resp = next(
                (r for r in existing.responses if r.status_code == incoming_resp.status_code),
                None,
            )
            if not matched_resp:
                existing.responses.append(incoming_resp)
                existing.responses.sort(key=lambda r: r.status_code)
            else:
                # Aggregate response headers
                matched_resp.headers.update(incoming_resp.headers)
                # Merge response schema
                if matched_resp.inferred_schema and incoming_resp.inferred_schema:
                    matched_resp.inferred_schema = self.schema_inferrer.merge(
                        matched_resp.inferred_schema, incoming_resp.inferred_schema
                    )
                elif not matched_resp.inferred_schema and incoming_resp.inferred_schema:
                    matched_resp.inferred_schema = incoming_resp.inferred_schema
                if matched_resp.sample_body is None and incoming_resp.sample_body is not None:
                    matched_resp.sample_body = incoming_resp.sample_body

        # 6. Add graphql tag if applicable
        if is_graphql and "graphql" not in existing.tags:
            existing.tags.append("graphql")
