"""
API Specification Finder and Parser for api-tool.
Discovers and parses OpenAPI 3.x, Swagger 2.0, Redoc, Scalar, RapiDoc, and SpringDoc endpoints.
Built with pure Python 3 standard library, httpx, and beautifulsoup4 for full Termux compatibility.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import ssl
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Union
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from api_tool.models import (
    DiscoveredEndpoint,
    DiscoveredParameter,
    DiscoveredResponse,
)

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore

logger = logging.getLogger(__name__)

# Maximum allowed response body size to prevent memory exhaustion (20 MB)
_MAX_RESPONSE_BYTES = 20 * 1024 * 1024  # 20 MB


@dataclass
class DiscoveredSpec:
    """Represents a discovered API specification (OpenAPI, Swagger, or docs UI)."""

    url: str
    spec_type: str  # 'openapi_3', 'openapi_2', 'swagger_ui', 'redoc', 'scalar', 'unknown'
    title: str = ""
    version: str = ""
    raw_spec: Dict[str, Any] = field(default_factory=dict)
    endpoints: List[DiscoveredEndpoint] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert specification and its endpoints to a serializable dictionary."""
        return {
            "url": self.url,
            "spec_type": self.spec_type,
            "title": self.title,
            "version": self.version,
            "raw_spec": self.raw_spec,
            "endpoints": [e.to_dict() for e in self.endpoints],
        }


class SpecFinder:
    """
    High-performance API Specification Finder and Parser.
    Probes common OpenAPI/Swagger/Docs routes, parses specifications, and extracts endpoints.
    """

    # Comprehensive candidate paths across modern 2026 conventions:
    # FastAPI, Spring Boot (SpringDoc / Actuator), NestJS, Django REST Framework,
    # ASP.NET Core, Express / Hono / Elysia Scalar, Redoc, Swagger UI, Stoplight Elements
    CANDIDATE_PATHS: List[str] = [
        # Standard root OpenAPI & Swagger
        "/openapi.json",
        "/openapi.yaml",
        "/openapi.yml",
        "/openapi",
        "/swagger.json",
        "/swagger.yaml",
        "/swagger.yml",
        "/swagger",
        "/api-docs",
        "/api-docs.json",
        "/api-docs.yaml",
        # Versioned Root Specs
        "/swagger/v1/swagger.json",
        "/swagger/v1/swagger.yaml",
        "/swagger/v2/swagger.json",
        "/swagger/v2/swagger.yaml",
        "/swagger/v3/swagger.json",
        "/swagger/v3/swagger.yaml",
        "/swagger/doc.json",
        "/swagger/api-docs",
        "/v1/swagger.json",
        "/v1/swagger.yaml",
        "/v2/swagger.json",
        "/v2/swagger.yaml",
        "/v3/swagger.json",
        "/v3/swagger.yaml",
        "/v1/openapi.json",
        "/v1/openapi.yaml",
        "/v2/openapi.json",
        "/v2/openapi.yaml",
        "/v3/openapi.json",
        "/v3/openapi.yaml",
        "/v1/api-docs",
        "/v2/api-docs",
        "/v3/api-docs",
        "/v3/api-docs.yaml",
        "/v3/api-docs/swagger-config",
        "/v2/api-docs/swagger-config",
        # /api/ Prefix Endpoints
        "/api/openapi.json",
        "/api/openapi.yaml",
        "/api/openapi.yml",
        "/api/openapi",
        "/api/swagger.json",
        "/api/swagger.yaml",
        "/api/swagger.yml",
        "/api/swagger",
        "/api/api-docs",
        "/api/api-docs.json",
        "/api/api-docs.yaml",
        "/api/swagger/doc.json",
        "/api/docs/swagger.json",
        "/api/docs/swagger.yaml",
        "/api/docs/openapi.json",
        "/api/docs/openapi.yaml",
        "/api/v1/swagger.json",
        "/api/v1/swagger.yaml",
        "/api/v2/swagger.json",
        "/api/v2/swagger.yaml",
        "/api/v3/swagger.json",
        "/api/v3/swagger.yaml",
        "/api/v1/openapi.json",
        "/api/v1/openapi.yaml",
        "/api/v2/openapi.json",
        "/api/v2/openapi.yaml",
        "/api/v3/openapi.json",
        "/api/v3/openapi.yaml",
        "/api/v1/api-docs",
        "/api/v2/api-docs",
        "/api/v3/api-docs",
        "/api/v3/api-docs/swagger-config",
        "/api/spec.json",
        "/api/spec.yaml",
        "/api/spec",
        "/api/schema.json",
        "/api/schema.yaml",
        "/api/schema",
        # /docs/ Prefix Endpoints
        "/docs/openapi.json",
        "/docs/openapi.yaml",
        "/docs/swagger.json",
        "/docs/swagger.yaml",
        "/docs/spec.json",
        "/docs/spec.yaml",
        # UI Documentation Endpoints
        "/docs",
        "/docs/",
        "/docs/index.html",
        "/swagger-ui.html",
        "/swagger-ui",
        "/swagger-ui/",
        "/swagger-ui/index.html",
        "/swagger",
        "/swagger/",
        "/swagger/index.html",
        "/redoc",
        "/redoc/",
        "/redoc/index.html",
        "/redoc.html",
        "/scalar",
        "/scalar/",
        "/scalar/index.html",
        "/rapidoc",
        "/rapidoc/",
        "/rapidoc/index.html",
        "/rapidoc.html",
        "/elements",
        "/elements/",
        "/elements.html",
        "/api-docs/",
        "/api-docs/index.html",
        "/api/docs",
        "/api/docs/",
        "/api/docs/index.html",
        "/api/documentation",
        "/api/documentation/",
        "/api/swagger-ui.html",
        "/api/swagger-ui",
        "/api/swagger-ui/",
        "/api/swagger-ui/index.html",
        "/documentation",
        "/documentation/",
        "/documentation/json",
        "/documentation/yaml",
        # Frameworks & Spring Boot Actuators
        "/swagger-resources",
        "/swagger-resources/configuration/ui",
        "/swagger-resources/configuration/security",
        "/actuator/openapi",
        "/actuator/openapi/springdocDefault",
        "/actuator/swagger",
        "/actuator/docs",
        "/spec.json",
        "/spec.yaml",
        "/spec",
        "/apispec.json",
        "/apispec.yaml",
        "/apispec_1.json",
        "/schema",
        "/schema.json",
        "/schema.yaml",
    ]

    # HTTP methods supported in OpenAPI specifications
    HTTP_METHODS = ("get", "post", "put", "delete", "patch", "options", "head")

    def __init__(self, candidate_paths: Optional[List[str]] = None) -> None:
        """Initialize SpecFinder with optional custom candidate paths."""
        self.candidate_paths = candidate_paths or list(self.CANDIDATE_PATHS)

    @classmethod
    async def probe(
        cls,
        base_url: str,
        client: Optional[httpx.AsyncClient] = None,
        concurrency: int = 5,
        method: str = "GET",
    ) -> List[DiscoveredSpec]:
        """Convenience class method to probe a base URL."""
        finder = cls()
        return await finder.probe_spec_urls(
            base_url, client=client, concurrency=concurrency, method=method
        )

    @staticmethod
    def extract_spec_url_from_html(html: str, base_url: str) -> List[str]:
        """
        Extracts OpenAPI/Swagger specification URLs embedded within HTML pages:
        - Swagger UI: SwaggerUIBundle({ url: '...' }), urls: [{url: '...'}], configUrl
        - Redoc: <redoc spec-url='...'>, Redoc.init('...')
        - Scalar: <script id='api-reference' data-url='...'>, data-configuration, spec-url
        - RapiDoc: <rapi-doc spec-url='...'>
        - Stoplight Elements: <elements-api apiDescriptionUrl='...'>
        - HTML link tags: <link rel='alternate' type='application/openapi+json' href='...'>

        Returns a list of resolved, absolute URLs in discovery order without duplicates.
        """
        if not html:
            return []

        found_urls: List[str] = []

        # 1. BeautifulSoup parsing for standard tags and custom elements
        try:
            soup = BeautifulSoup(html, "html.parser")

            # Extract from <link> tags
            for link in soup.find_all("link"):
                rel_attr = link.get("rel", [])
                rel = [r.lower() for r in rel_attr] if isinstance(rel_attr, list) else [str(rel_attr).lower()]
                ltype = str(link.get("type", "")).lower()
                href = link.get("href")
                if href and isinstance(href, str):
                    if any(r in rel for r in ("alternate", "service-desc", "openapi", "swagger", "describedby")):
                        if any(t in ltype for t in ("openapi", "swagger", "json", "yaml")) or "service-desc" in rel:
                            found_urls.append(href)

            # Extract from custom HTML tags & data attributes (Scalar, Redoc, RapiDoc, Elements)
            target_attrs = {
                "spec-url",
                "specurl",
                "data-spec-url",
                "data-url",
                "apidescriptionurl",
                "spec_url",
            }
            for tag in soup.find_all(True):
                attrs = getattr(tag, "attrs", {})
                for attr_key, attr_val in attrs.items():
                    k_lower = attr_key.lower()
                    if k_lower in target_attrs and isinstance(attr_val, str) and attr_val.strip():
                        found_urls.append(attr_val.strip())

                    # Scalar data-configuration JSON payload
                    if k_lower in ("data-configuration", "data-config") and isinstance(attr_val, str):
                        try:
                            cfg = json.loads(attr_val)
                            if isinstance(cfg, dict):
                                if "url" in cfg and isinstance(cfg["url"], str):
                                    found_urls.append(cfg["url"])
                                if "spec" in cfg and isinstance(cfg["spec"], dict) and "url" in cfg["spec"]:
                                    found_urls.append(cfg["spec"]["url"])
                                if "specUrl" in cfg and isinstance(cfg["specUrl"], str):
                                    found_urls.append(cfg["specUrl"])
                        except Exception:
                            pass

        except Exception as e:
            logger.debug("BeautifulSoup parsing failed in extract_spec_url_from_html: %s", e)

        # 2. Regex parsing for inline JavaScript configurations
        # Swagger UI: SwaggerUIBundle({ url: '...' }) or window.ui = SwaggerUI({ url: '...' })
        for match in re.finditer(r"url\s*:\s*['\"]([^'\"]+?\.(?:json|ya?ml)(?:\?[^'\"]*)?)['\"]", html, re.IGNORECASE):
            found_urls.append(match.group(1))

        # Swagger UI with /v3/api-docs or general path (not ending in .json/.yaml).
        # Two-step approach: locate the anchor, then search a bounded 2000-char window to
        # avoid O(N^2) backtracking from [^}]*?url on large JS blobs without a closing '}'.
        for match in re.finditer(r"SwaggerUI(?:Bundle)?\s*\(\s*\{", html, re.IGNORECASE):
            block_start = match.end()
            block_slice = html[block_start : block_start + 2000]
            url_match = re.search(r"url\s*:\s*['\"]([^'\"]+)['\"]", block_slice, re.IGNORECASE)
            if url_match:
                found_urls.append(url_match.group(1))

        # Swagger UI multi-spec: urls: [ {url: '...', name: '...'} ]
        for match in re.finditer(r"\{\s*url\s*:\s*['\"]([^'\"]+)['\"]", html, re.IGNORECASE):
            found_urls.append(match.group(1))

        # Swagger UI configUrl
        for match in re.finditer(r"configUrl\s*:\s*['\"]([^'\"]+)['\"]", html, re.IGNORECASE):
            found_urls.append(match.group(1))

        # Redoc: Redoc.init('...')
        for match in re.finditer(r"Redoc\.init\s*\(\s*['\"]([^'\"]+)['\"]", html, re.IGNORECASE):
            found_urls.append(match.group(1))

        # Scalar: Scalar.createApiReference(..., { url: '...' }) or createApiReference(...)
        # Two-step approach: locate the anchor, then search a bounded 2000-char window to
        # avoid O(N^2) backtracking from [^)]*?url on large JS blobs without a closing ')'.
        for match in re.finditer(r"createApiReference\s*\(", html, re.IGNORECASE):
            block_start = match.end()
            block_slice = html[block_start : block_start + 2000]
            url_match = re.search(r"url\s*:\s*['\"]([^'\"]+)['\"]", block_slice, re.IGNORECASE)
            if url_match:
                found_urls.append(url_match.group(1))

        # Generic embedded spec attributes in HTML or script
        for match in re.finditer(r"(?:spec-url|specUrl|spec_url)\s*[:=]\s*['\"]([^'\"]+)['\"]", html, re.IGNORECASE):
            found_urls.append(match.group(1))

        # 3. Resolve relative URLs, sanitize, and deduplicate
        resolved: List[str] = []
        seen: Set[str] = set()

        # Disallow non-spec asset extensions
        ignored_extensions = (
            ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
            ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map"
        )

        for raw_url in found_urls:
            raw_url = raw_url.strip()
            if not raw_url:
                continue

            # Strip fragment if present
            raw_url = raw_url.split("#")[0]

            # Filter non-HTTP schemes or invalid prefixes
            if raw_url.startswith(("javascript:", "mailto:", "data:", "tel:")):
                continue

            path_part = raw_url.split("?")[0].lower()
            if any(path_part.endswith(ext) for ext in ignored_extensions):
                continue

            # Resolve against base_url
            full_url = urljoin(base_url, raw_url)
            if full_url not in seen:
                seen.add(full_url)
                resolved.append(full_url)

        return resolved

    @staticmethod
    def parse_openapi_spec(
        spec_data: Union[str, bytes, Dict[str, Any]],
        spec_url: str = "",
    ) -> DiscoveredSpec:
        """
        Parses an OpenAPI 3.x or Swagger 2.0 specification payload.
        Handles JSON strings, dicts, bytes, and YAML strings.
        Extracts metadata, servers/basePath, operations, parameters, request bodies, and responses.
        Returns a populated DiscoveredSpec object.
        """
        data: Optional[Dict[str, Any]] = None

        # 1. Parse input payload into a Python dictionary
        if isinstance(spec_data, (str, bytes)):
            text = spec_data.decode("utf-8", errors="replace") if isinstance(spec_data, bytes) else spec_data
            text = text.strip()
            if not text:
                return DiscoveredSpec(url=spec_url, spec_type="unknown")

            # Try parsing as JSON first
            if text.startswith(("{", "[")):
                try:
                    data = json.loads(text)
                except Exception:
                    data = None

            # If JSON parsing failed or wasn't applicable, try YAML
            if data is None and yaml is not None:
                try:
                    data = yaml.safe_load(text)
                except Exception as e:
                    logger.debug("YAML safe_load failed for spec: %s", e)
                    data = None

            if data is None and yaml is None:
                # If yaml not installed, try lightweight regex check before giving up
                if not text.startswith(("{", "[")):
                    logger.warning("PyYAML not installed; unable to parse YAML specification.")
        elif isinstance(spec_data, dict):
            data = spec_data

        if not isinstance(data, dict):
            return DiscoveredSpec(url=spec_url, spec_type="unknown")

        # 2. Determine specification format and version
        spec_type = "unknown"
        spec_version_str = ""

        if "openapi" in data and isinstance(data["openapi"], str):
            spec_version_str = data["openapi"]
            spec_type = "openapi_3"
        elif "swagger" in data:
            spec_version_str = str(data["swagger"])
            spec_type = "openapi_2"
        elif "paths" in data:
            # Inferred OpenAPI
            if "components" in data:
                spec_type = "openapi_3"
            else:
                spec_type = "openapi_2"

        # 3. Extract title and version metadata
        info = data.get("info", {}) if isinstance(data.get("info"), dict) else {}
        title = str(info.get("title", "")) if info.get("title") is not None else ""
        doc_version = str(info.get("version", "")) if info.get("version") is not None else spec_version_str

        # 4. Determine base URL
        base_url = ""
        if spec_type == "openapi_3":
            servers = data.get("servers", [])
            if isinstance(servers, list) and servers:
                first_server = servers[0]
                if isinstance(first_server, dict):
                    server_url = first_server.get("url", "")
                    if server_url:
                        if spec_url:
                            base_url = urljoin(spec_url, server_url).rstrip("/")
                        else:
                            base_url = server_url.rstrip("/")
        elif spec_type == "openapi_2":
            host = data.get("host", "")
            base_path = data.get("basePath", "")
            schemes = data.get("schemes", [])
            scheme = schemes[0] if isinstance(schemes, list) and schemes else ("https" if spec_url.startswith("https") else "http")
            if host:
                base_url = f"{scheme}://{host}{base_path}".rstrip("/")
            elif base_path:
                if spec_url:
                    parsed = urlparse(spec_url)
                    base_url = f"{parsed.scheme}://{parsed.netloc}{base_path}".rstrip("/")
                else:
                    base_url = base_path.rstrip("/")

        # Fallback to origin of spec_url if base_url is still empty
        if not base_url and spec_url:
            parsed = urlparse(spec_url)
            if parsed.scheme and parsed.netloc:
                base_url = f"{parsed.scheme}://{parsed.netloc}"

        # 5. Extract security schemes
        security_schemes: Dict[str, Dict[str, Any]] = {}
        if spec_type == "openapi_3":
            components = data.get("components", {})
            if isinstance(components, dict):
                security_schemes = components.get("securitySchemes", {}) if isinstance(components.get("securitySchemes"), dict) else {}
        else:
            security_schemes = data.get("securityDefinitions", {}) if isinstance(data.get("securityDefinitions"), dict) else {}

        global_security = data.get("security", []) if isinstance(data.get("security"), list) else []

        def resolve_auth_info(sec_reqs: List[Dict[str, Any]]) -> tuple[Optional[str], Optional[str]]:
            if not sec_reqs:
                return None, None
            for req in sec_reqs:
                if not isinstance(req, dict):
                    continue
                for scheme_name in req:
                    s_def = security_schemes.get(scheme_name, {})
                    if not isinstance(s_def, dict):
                        continue
                    stype = str(s_def.get("type", "")).lower()
                    scheme = str(s_def.get("scheme", "")).lower()
                    if stype == "http" and scheme == "bearer":
                        return "bearer", "Authorization"
                    if stype == "http" and scheme == "basic":
                        return "basic", "Authorization"
                    if stype == "basic":
                        return "basic", "Authorization"
                    if stype == "apikey":
                        header_or_param = s_def.get("name", "X-API-Key")
                        return "apikey", header_or_param
                    if stype in ("oauth2", "openidconnect"):
                        return "bearer", "Authorization"
            return None, None

        # 6. Iterate through paths and methods to construct DiscoveredEndpoint objects
        endpoints: List[DiscoveredEndpoint] = []
        paths = data.get("paths", {})
        if isinstance(paths, dict):
            for path_pattern, path_item in paths.items():
                if not isinstance(path_item, dict):
                    continue

                # Common parameters defined at the path level
                path_level_params: List[Dict[str, Any]] = (
                    path_item.get("parameters", []) if isinstance(path_item.get("parameters"), list) else []
                )

                for method in SpecFinder.HTTP_METHODS:
                    op = path_item.get(method)
                    if not isinstance(op, dict):
                        continue

                    method_upper = method.upper()
                    summary = op.get("summary")
                    description = op.get("description")
                    tags = op.get("tags", []) if isinstance(op.get("tags"), list) else []

                    # Operation-level parameters override path-level parameters by (name, in)
                    op_level_params = op.get("parameters", []) if isinstance(op.get("parameters"), list) else []
                    if not path_level_params:
                        raw_param_items = [
                            (p["name"], str(p.get("in", "query")).lower(), p)
                            for p in op_level_params
                            if isinstance(p, dict) and "name" in p
                        ]
                    else:
                        merged_params: Dict[tuple[str, str], Dict[str, Any]] = {}
                        for p in path_level_params:
                            if isinstance(p, dict) and "name" in p:
                                loc = str(p.get("in", "query")).lower()
                                merged_params[(p["name"], loc)] = p
                        for p in op_level_params:
                            if isinstance(p, dict) and "name" in p:
                                loc = str(p.get("in", "query")).lower()
                                merged_params[(p["name"], loc)] = p
                        raw_param_items = [(k[0], k[1], v) for k, v in merged_params.items()]

                    # Parse parameters into DiscoveredParameter
                    parameters_list: List[DiscoveredParameter] = []
                    req_sample: Optional[Any] = None
                    req_schema: Optional[Dict[str, Any]] = None

                    for pname, ploc, pdata in raw_param_items:
                        req = bool(pdata.get("required", False))
                        p_desc = pdata.get("description")
                        p_example = pdata.get("example") or pdata.get("x-example")

                        # Determine parameter type and location
                        if ploc == "body":
                            # Swagger 2.0 body parameter
                            b_schema = pdata.get("schema")
                            req_schema = b_schema if isinstance(b_schema, dict) else None
                            p_type = req_schema.get("type", "object") if req_schema else "object"
                            req_sample = p_example
                            param_loc = "body"
                        elif ploc in ("query", "path", "header", "cookie"):
                            param_loc = ploc
                            if spec_type == "openapi_3":
                                s = pdata.get("schema", {})
                                if isinstance(s, dict):
                                    raw_t = s.get("type", "string")
                                    p_type = raw_t[0] if isinstance(raw_t, list) and raw_t else str(raw_t)
                                    if p_example is None:
                                        p_example = s.get("example") or s.get("default")
                                else:
                                    p_type = "string"
                            else:
                                p_type = str(pdata.get("type", "string"))
                        elif ploc == "formdata":
                            param_loc = "body"
                            p_type = str(pdata.get("type", "string"))
                        else:
                            param_loc = "query"
                            p_type = str(pdata.get("type", "string"))

                        parameters_list.append(
                            DiscoveredParameter(
                                name=pname,
                                location=param_loc,
                                required=req,
                                param_type=p_type,
                                example=p_example,
                                description=p_desc,
                            )
                        )

                    # OpenAPI 3.x requestBody handling
                    if spec_type == "openapi_3" and "requestBody" in op:
                        rb = op["requestBody"]
                        if isinstance(rb, dict):
                            rb_desc = rb.get("description")
                            rb_req = bool(rb.get("required", False))
                            rb_content = rb.get("content", {})
                            if isinstance(rb_content, dict) and rb_content:
                                # Prioritize application/json, then application/x-www-form-urlencoded, then first
                                pref_ct = (
                                    "application/json"
                                    if "application/json" in rb_content
                                    else next(iter(rb_content.keys()))
                                )
                                ct_dict = rb_content.get(pref_ct, {})
                                if isinstance(ct_dict, dict):
                                    req_schema = ct_dict.get("schema") if isinstance(ct_dict.get("schema"), dict) else None
                                    req_sample = ct_dict.get("example")
                                    if req_sample is None and "examples" in ct_dict:
                                        exs = ct_dict["examples"]
                                        if isinstance(exs, dict) and exs:
                                            first_ex = next(iter(exs.values()))
                                            req_sample = first_ex.get("value") if isinstance(first_ex, dict) else first_ex

                                    # Include body in parameters if not present
                                    existing_param_names = {p.name for p in parameters_list}
                                    if "body" not in existing_param_names:
                                        body_type = req_schema.get("type", "object") if req_schema else "object"
                                        if isinstance(body_type, list):
                                            body_type = body_type[0] if body_type else "object"
                                        parameters_list.append(
                                            DiscoveredParameter(
                                                name="body",
                                                location="body",
                                                required=rb_req,
                                                param_type=str(body_type),
                                                example=req_sample,
                                                description=rb_desc,
                                            )
                                        )

                    # Extract responses
                    responses_list: List[DiscoveredResponse] = []
                    raw_responses = op.get("responses", {})
                    if isinstance(raw_responses, dict):
                        for status_key, resp_obj in raw_responses.items():
                            if not isinstance(resp_obj, dict):
                                continue
                            try:
                                status_code = int(status_key)
                            except ValueError:
                                status_code = 200

                            sample_body: Optional[Any] = None
                            inferred_schema: Optional[Dict[str, Any]] = None
                            resp_content_type = "application/json"

                            if spec_type == "openapi_3" and "content" in resp_obj and isinstance(resp_obj["content"], dict):
                                c = resp_obj["content"]
                                if c:
                                    resp_content_type = "application/json" if "application/json" in c else next(iter(c.keys()))
                                    media_info = c.get(resp_content_type, {})
                                    if isinstance(media_info, dict):
                                        inferred_schema = media_info.get("schema") if isinstance(media_info.get("schema"), dict) else None
                                        sample_body = media_info.get("example")
                                        if sample_body is None and "examples" in media_info:
                                            exs = media_info["examples"]
                                            if isinstance(exs, dict) and exs:
                                                first_ex = next(iter(exs.values()))
                                                sample_body = first_ex.get("value") if isinstance(first_ex, dict) else first_ex
                            else:
                                # Swagger 2.0 responses
                                inferred_schema = resp_obj.get("schema") if isinstance(resp_obj.get("schema"), dict) else None
                                examples = resp_obj.get("examples", {})
                                if isinstance(examples, dict) and examples:
                                    resp_content_type = "application/json" if "application/json" in examples else next(iter(examples.keys()))
                                    sample_body = examples.get(resp_content_type)

                            # Headers from response
                            resp_headers: Dict[str, str] = {}
                            if "headers" in resp_obj and isinstance(resp_obj["headers"], dict):
                                for hk, hv in resp_obj["headers"].items():
                                    if isinstance(hv, dict):
                                        resp_headers[hk] = str(hv.get("description", ""))
                                    elif isinstance(hv, str):
                                        resp_headers[hk] = hv

                            responses_list.append(
                                DiscoveredResponse(
                                    status_code=status_code,
                                    content_type=resp_content_type,
                                    headers=resp_headers,
                                    sample_body=sample_body,
                                    inferred_schema=inferred_schema,
                                )
                            )

                    # Extract operation security
                    op_sec = op.get("security", global_security)
                    auth_type, auth_header_or_param = resolve_auth_info(op_sec if isinstance(op_sec, list) else [])

                    # Construct DiscoveredEndpoint
                    endpoint = DiscoveredEndpoint(
                        path=path_pattern,
                        method=method_upper,
                        base_url=base_url,
                        source="spec",
                        tags=tags,
                        parameters=parameters_list,
                        request_body_sample=req_sample,
                        request_body_schema=req_schema,
                        responses=responses_list,
                        auth_type=auth_type,
                        auth_header_or_param=auth_header_or_param,
                        summary=summary,
                        description=description,
                    )
                    endpoints.append(endpoint)

        return DiscoveredSpec(
            url=spec_url,
            spec_type=spec_type,
            title=title,
            version=doc_version,
            raw_spec=data,
            endpoints=endpoints,
        )

    async def probe_spec_urls(
        self_or_cls,
        base_url: str = "",
        client: Optional[httpx.AsyncClient] = None,
        concurrency: int = 5,
        method: str = "GET",
    ) -> List[DiscoveredSpec]:
        """
        Concurrently probes candidate OpenAPI, Swagger, and documentation paths against base_url.
        Uses lightweight GET or HEAD requests.
        Inspects Content-Type, parses specs when discovered, or extracts embedded URLs from HTML.
        Handles timeouts, SSL errors, redirects, and 404s gracefully.
        """
        if isinstance(self_or_cls, str):
            # Invoked as SpecFinder.probe_spec_urls("https://example.com", client=...)
            actual_base_url = self_or_cls
            actual_client = client
            finder = SpecFinder()
            return await finder.probe_spec_urls(
                actual_base_url, client=actual_client, concurrency=concurrency, method=method
            )

        self = self_or_cls
        clean_base = base_url.strip()
        if not clean_base:
            return []

        if not (clean_base.startswith("http://") or clean_base.startswith("https://")):
            clean_base = f"https://{clean_base}"

        clean_base = clean_base.rstrip("/")

        # Run with provided client or manage our own
        if client is None:
            async with httpx.AsyncClient(
                verify=False,
                follow_redirects=True,
                timeout=httpx.Timeout(8.0, connect=4.0),
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "Accept": "application/json, application/yaml, text/yaml, text/html, */*",
                },
            ) as own_client:
                return await self._probe_execution(clean_base, own_client, concurrency, method)
        else:
            return await self._probe_execution(clean_base, client, concurrency, method)

    async def _probe_execution(
        self,
        base_url: str,
        client: httpx.AsyncClient,
        concurrency: int,
        method: str,
    ) -> List[DiscoveredSpec]:
        semaphore = asyncio.Semaphore(concurrency)
        discovered_specs: List[DiscoveredSpec] = []
        discovered_urls: Set[str] = set()
        secondary_urls_to_fetch: Set[str] = set()

        async def probe_path(path: str) -> None:
            target_url = f"{base_url}/{path.lstrip('/')}"

            # SSRF guard: validate URL before issuing any HTTP request (unless using MockTransport in tests)
            is_mock = isinstance(getattr(client, "_transport", None), httpx.MockTransport)
            if not is_mock:
                from api_tool.prober.http_prober import is_safe_target  # lazy to avoid circular import
                safe, reason = is_safe_target(target_url)
                if not safe:
                    logger.debug("SSRF blocked spec probe for %s: %s", target_url, reason)
                    return

            async with semaphore:
                try:
                    if method.upper() == "HEAD":
                        resp = await client.head(target_url)
                        if resp.status_code == 200:
                            ct = resp.headers.get("content-type", "").lower()
                            if any(k in ct for k in ("json", "yaml", "html")):
                                # Switch to GET to read body
                                resp = await client.get(target_url)
                            else:
                                return
                        else:
                            return
                    else:
                        resp = await client.get(target_url)
                except (
                    httpx.TimeoutException,
                    httpx.ConnectError,
                    httpx.TooManyRedirects,
                    ssl.SSLError,
                    httpx.RequestError,
                    Exception,
                ) as exc:
                    logger.debug("Failed probe for %s: %s", target_url, exc)
                    return

                if resp.status_code != 200:
                    return

                # Content-length guard: reject bodies larger than _MAX_RESPONSE_BYTES
                content_length_hdr = resp.headers.get("content-length")
                if content_length_hdr is not None:
                    try:
                        if int(content_length_hdr) > _MAX_RESPONSE_BYTES:
                            logger.warning(
                                "Skipping %s: Content-Length %s exceeds %d byte limit",
                                target_url, content_length_hdr, _MAX_RESPONSE_BYTES,
                            )
                            return
                    except ValueError:
                        pass

                text = resp.text
                if not text or not text.strip():
                    return

                # Guard against bodies that slipped through without Content-Length
                if len(resp.content) > _MAX_RESPONSE_BYTES:
                    logger.warning(
                        "Skipping %s: response body %d bytes exceeds %d byte limit",
                        target_url, len(resp.content), _MAX_RESPONSE_BYTES,
                    )
                    return

                content_type = resp.headers.get("content-type", "").lower()
                final_url = str(resp.url)

                # Case A: JSON or YAML response
                if (
                    any(t in content_type for t in ("json", "yaml", "yml"))
                    or text.strip().startswith(("{", "["))
                    or ("openapi:" in text[:400] or "swagger:" in text[:400])
                ):
                    # Check if this is a SpringDoc swagger-config or swagger-resources pointer
                    try:
                        p_json = json.loads(text)
                    except Exception:
                        p_json = None

                    if isinstance(p_json, dict) and not any(k in p_json for k in ("openapi", "swagger", "paths")):
                        # Check for config links
                        if "url" in p_json and isinstance(p_json["url"], str):
                            secondary_urls_to_fetch.add(urljoin(final_url, p_json["url"]))
                        if "urls" in p_json and isinstance(p_json["urls"], list):
                            for u_item in p_json["urls"]:
                                if isinstance(u_item, dict) and "url" in u_item:
                                    secondary_urls_to_fetch.add(urljoin(final_url, u_item["url"]))
                    elif isinstance(p_json, list):
                        # e.g., /swagger-resources
                        for u_item in p_json:
                            if isinstance(u_item, dict) and "url" in u_item:
                                secondary_urls_to_fetch.add(urljoin(final_url, u_item["url"]))
                    else:
                        # Direct OpenAPI/Swagger specification
                        spec = self.parse_openapi_spec(text, spec_url=final_url)
                        if spec.spec_type != "unknown" or spec.endpoints:
                            if final_url not in discovered_urls:
                                discovered_urls.add(final_url)
                                discovered_specs.append(spec)

                # Case B: HTML documentation page
                elif (
                    "html" in content_type
                    or "<html" in text[:500].lower()
                    or "<!doctype" in text[:500].lower()
                ):
                    embedded_urls = self.extract_spec_url_from_html(text, final_url)
                    for emb_url in embedded_urls:
                        secondary_urls_to_fetch.add(emb_url)

                    # If no spec URL extracted, record the UI page itself if identified
                    if not embedded_urls:
                        t_lower = text.lower()
                        ui_type = "unknown"
                        if "swagger-ui" in t_lower or "swaggerui" in t_lower:
                            ui_type = "swagger_ui"
                        elif "redoc" in t_lower:
                            ui_type = "redoc"
                        elif "scalar" in t_lower:
                            ui_type = "scalar"

                        if ui_type != "unknown":
                            try:
                                soup = BeautifulSoup(text, "html.parser")
                                page_title = soup.title.string.strip() if soup.title and soup.title.string else ""
                            except Exception:
                                page_title = ""

                            if final_url not in discovered_urls:
                                discovered_urls.add(final_url)
                                discovered_specs.append(
                                    DiscoveredSpec(
                                        url=final_url,
                                        spec_type=ui_type,
                                        title=page_title,
                                        version="",
                                        raw_spec={},
                                        endpoints=[],
                                    )
                                )

        # Probe candidate paths concurrently
        await asyncio.gather(*(probe_path(p) for p in self.candidate_paths), return_exceptions=True)

        # Probe any secondary spec URLs extracted from HTML or config pointers
        async def fetch_secondary(sec_url: str) -> None:
            if sec_url in discovered_urls:
                return

            # SSRF guard: validate secondary URL before fetching (unless using MockTransport in tests)
            is_mock = isinstance(getattr(client, "_transport", None), httpx.MockTransport)
            if not is_mock:
                from api_tool.prober.http_prober import is_safe_target  # lazy to avoid circular import
                safe, reason = is_safe_target(sec_url)
                if not safe:
                    logger.debug("SSRF blocked secondary spec fetch for %s: %s", sec_url, reason)
                    return

            async with semaphore:
                try:
                    resp = await client.get(sec_url)
                    if resp.status_code == 200:
                        # Content-length guard before loading body
                        content_length_hdr = resp.headers.get("content-length")
                        if content_length_hdr is not None:
                            try:
                                if int(content_length_hdr) > _MAX_RESPONSE_BYTES:
                                    logger.warning(
                                        "Skipping secondary %s: Content-Length %s exceeds %d byte limit",
                                        sec_url, content_length_hdr, _MAX_RESPONSE_BYTES,
                                    )
                                    return
                            except ValueError:
                                pass

                        body_text = resp.text
                        if not body_text:
                            return

                        # Guard bodies without Content-Length header
                        if len(resp.content) > _MAX_RESPONSE_BYTES:
                            logger.warning(
                                "Skipping secondary %s: response body %d bytes exceeds %d byte limit",
                                sec_url, len(resp.content), _MAX_RESPONSE_BYTES,
                            )
                            return

                        spec = self.parse_openapi_spec(body_text, spec_url=str(resp.url))
                        if spec.spec_type != "unknown" or spec.endpoints:
                            if str(resp.url) not in discovered_urls:
                                discovered_urls.add(str(resp.url))
                                discovered_specs.append(spec)
                except (
                    httpx.TimeoutException,
                    httpx.ConnectError,
                    httpx.TooManyRedirects,
                    ssl.SSLError,
                    httpx.RequestError,
                    Exception,
                ) as exc:
                    logger.debug("Failed secondary spec fetch for %s: %s", sec_url, exc)


        if secondary_urls_to_fetch:
            await asyncio.gather(
                *(fetch_secondary(u) for u in secondary_urls_to_fetch),
                return_exceptions=True,
            )

        # Deduplicate specs by URL and endpoints count
        unique_specs: List[DiscoveredSpec] = []
        seen_keys: Set[tuple[str, int]] = set()
        for s in discovered_specs:
            key = (s.url, len(s.endpoints))
            if key not in seen_keys:
                seen_keys.add(key)
                unique_specs.append(s)

        return unique_specs
