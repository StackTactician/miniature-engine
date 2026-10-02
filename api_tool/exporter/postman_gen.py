"""
Postman Collection v2.1.0 Exporter for api-tool.
Pure Python 3.10+ standard library implementation (Termux compatible).
Zero external C dependencies. Zero-error import compatibility with Postman, Bruno, and Insomnia.
"""

from __future__ import annotations

import json
import re
import uuid
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

try:
    from api_tool.models import (
        DiscoveredEndpoint,
        DiscoveredParameter,
        GraphQLOperation,
        ScanResult,
    )
except ImportError:
    # Defensive fallbacks for standalone or testing environments
    DiscoveredEndpoint = Any  # type: ignore
    DiscoveredParameter = Any  # type: ignore
    GraphQLOperation = Any  # type: ignore
    ScanResult = Any  # type: ignore

POSTMAN_V21_SCHEMA = "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"

ROOT_ROUTE_CANDIDATES = {
    "health",
    "ping",
    "status",
    "version",
    "ready",
    "live",
    "healthz",
    "livez",
    "readyz",
    "metrics",
    "info",
    "docs",
    "favicon.ico",
    "robots.txt",
}


# ==============================================================================
# 1. Domain Dataclasses
# ==============================================================================

@dataclass
class PostmanVariable:
    """Variable definition for Postman collection or request."""
    key: str
    value: str = ""
    type: str = "string"
    description: Optional[str] = None

    def __post_init__(self) -> None:
        self.key = str(self.key)
        self.value = str(self.value)
        self.type = str(self.type)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "key": self.key,
            "value": self.value,
            "type": self.type,
        }
        if self.description:
            d["description"] = self.description
        return d


@dataclass
class PostmanHeader:
    """Header definition. All keys and values are strictly strings."""
    key: str
    value: str
    type: str = "text"
    description: Optional[str] = None
    disabled: bool = False

    def __post_init__(self) -> None:
        # Strict string enforcement required for Postman/Bruno/Insomnia parsing
        self.key = str(self.key)
        self.value = str(self.value)
        self.type = str(self.type)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "key": self.key,
            "value": self.value,
            "type": self.type,
        }
        if self.description:
            d["description"] = self.description
        if self.disabled:
            d["disabled"] = True
        return d


@dataclass
class PostmanQueryParam:
    """Query parameter definition."""
    key: str
    value: str = ""
    description: Optional[str] = None
    disabled: bool = False

    def __post_init__(self) -> None:
        self.key = str(self.key)
        self.value = str(self.value)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "key": self.key,
            "value": self.value,
        }
        if self.description:
            d["description"] = self.description
        if self.disabled:
            d["disabled"] = True
        return d


@dataclass
class PostmanPathVariable:
    """Path variable definition matching Postman :param syntax."""
    key: str
    value: str = ""
    description: Optional[str] = None

    def __post_init__(self) -> None:
        # Strip leading colon if mistakenly passed
        self.key = str(self.key).lstrip(":")
        self.value = str(self.value)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "key": self.key,
            "value": self.value,
        }
        if self.description:
            d["description"] = self.description
        return d


@dataclass
class PostmanUrl:
    """Full Postman v2.1.0 URL representation."""
    raw: str
    protocol: Optional[str] = None
    host: List[str] = field(default_factory=list)
    path: List[str] = field(default_factory=list)
    query: List[PostmanQueryParam] = field(default_factory=list)
    variable: List[PostmanPathVariable] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "raw": self.raw,
        }
        if self.protocol:
            d["protocol"] = self.protocol
        if self.host:
            d["host"] = list(self.host)
        if self.path:
            d["path"] = list(self.path)
        if self.query:
            d["query"] = [
                q.to_dict() if hasattr(q, "to_dict") else q
                for q in self.query
            ]
        if self.variable:
            d["variable"] = [
                v.to_dict() if hasattr(v, "to_dict") else v
                for v in self.variable
            ]
        return d


@dataclass
class PostmanBody:
    """Request body representation supporting raw JSON, formdata, and GraphQL."""
    mode: str = "raw"  # "raw", "graphql", "formdata", "urlencoded"
    raw: Optional[str] = None
    language: str = "json"
    formdata: List[Dict[str, Any]] = field(default_factory=list)
    graphql: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "mode": self.mode,
        }
        if self.mode == "raw":
            d["raw"] = self.raw if self.raw is not None else ""
            if self.language:
                d["options"] = {"raw": {"language": self.language}}
        elif self.mode == "graphql":
            gql_data = dict(self.graphql or {})
            # Postman schema strictly requires variables to be a string
            if "variables" in gql_data and isinstance(gql_data["variables"], (dict, list)):
                gql_data["variables"] = json.dumps(gql_data["variables"], indent=2)
            elif "variables" not in gql_data or gql_data["variables"] is None:
                gql_data["variables"] = ""
            d["graphql"] = gql_data
        elif self.mode == "formdata":
            d["formdata"] = list(self.formdata or [])
        elif self.mode == "urlencoded":
            d["urlencoded"] = list(self.formdata or [])
        return d


@dataclass
class PostmanRequest:
    """Postman request object."""
    method: str
    url: Union[PostmanUrl, Dict[str, Any], str]
    header: List[PostmanHeader] = field(default_factory=list)
    body: Optional[PostmanBody] = None
    auth: Optional[Dict[str, Any]] = None
    description: Optional[str] = None

    def __post_init__(self) -> None:
        self.method = str(self.method).upper()

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "method": self.method,
            "header": [
                h.to_dict() if hasattr(h, "to_dict") else h
                for h in self.header
            ],
            "url": self.url.to_dict() if hasattr(self.url, "to_dict") else self.url,
        }
        if self.body is not None:
            d["body"] = self.body.to_dict() if hasattr(self.body, "to_dict") else self.body
        if self.auth is not None:
            d["auth"] = self.auth
        if self.description:
            d["description"] = self.description
        return d


@dataclass
class PostmanItem:
    """Postman Item representation (can represent a leaf request or a folder)."""
    name: str
    request: Optional[PostmanRequest] = None
    item: Optional[List[PostmanItem]] = None
    response: List[Any] = field(default_factory=list)
    description: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "name": self.name,
        }
        if self.description:
            d["description"] = self.description

        if self.request is not None:
            d["request"] = self.request.to_dict() if hasattr(self.request, "to_dict") else self.request
            d["response"] = [
                r.to_dict() if hasattr(r, "to_dict") else r
                for r in self.response
            ]
        elif self.item is not None:
            d["item"] = [
                sub.to_dict() if hasattr(sub, "to_dict") else sub
                for sub in self.item
            ]
        else:
            # Default empty folder
            d["item"] = []
        return d


@dataclass
class PostmanCollection:
    """Postman v2.1.0 Collection root document."""
    name: str
    description: Optional[str] = None
    schema: str = POSTMAN_V21_SCHEMA
    id: Optional[str] = None
    variables: List[PostmanVariable] = field(default_factory=list)
    auth: Optional[Dict[str, Any]] = None
    items: List[PostmanItem] = field(default_factory=list)

    def __init__(
        self,
        name: str,
        description: Optional[str] = None,
        schema: str = POSTMAN_V21_SCHEMA,
        id: Optional[str] = None,
        variables: Optional[List[PostmanVariable]] = None,
        auth: Optional[Dict[str, Any]] = None,
        items: Optional[List[PostmanItem]] = None,
        **kwargs: Any,
    ) -> None:
        self.name = name
        self.description = description
        self.schema = schema
        self.id = id or str(uuid.uuid4())

        # Handle 'variables' / 'variable' aliases
        if variables is not None:
            self.variables = list(variables)
        elif "variable" in kwargs:
            self.variables = list(kwargs["variable"])
        else:
            self.variables = []

        self.auth = auth

        # Handle 'items' / 'item' aliases
        if items is not None:
            self.items = list(items)
        elif "item" in kwargs:
            self.items = list(kwargs["item"])
        else:
            self.items = []

    def to_dict(self) -> Dict[str, Any]:
        info: Dict[str, Any] = {
            "_postman_id": self.id or str(uuid.uuid4()),
            "name": self.name,
            "schema": self.schema,
        }
        if self.description:
            info["description"] = self.description

        d: Dict[str, Any] = {
            "info": info,
            "item": [
                it.to_dict() if hasattr(it, "to_dict") else it
                for it in self.items
            ],
        }

        # Ensure baseUrl variable exists for Bruno/Postman/Insomnia compatibility
        vars_to_export = list(self.variables)
        has_base_url = any(v.key == "baseUrl" for v in vars_to_export)
        if not has_base_url:
            vars_to_export.insert(
                0,
                PostmanVariable(
                    key="baseUrl",
                    value="http://localhost:3000",
                    type="string",
                    description="Target server base URL",
                ),
            )

        d["variable"] = [
            v.to_dict() if hasattr(v, "to_dict") else v
            for v in vars_to_export
        ]

        if self.auth is not None:
            d["auth"] = self.auth

        return d

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def export_file(self, output_path: Union[str, Path]) -> str:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        content = self.to_json(indent=2)
        path.write_text(content, encoding="utf-8")
        return str(path.resolve())

    @classmethod
    def from_scan_result(
        cls,
        scan_result: Any,
        name: Optional[str] = None,
        base_url: Optional[str] = None,
    ) -> PostmanCollection:
        exporter = PostmanCollectionExporter()
        return exporter.export_collection(
            scan_result=scan_result,
            collection_name=name,
            base_url=base_url,
        )

    @classmethod
    def from_endpoints(
        cls,
        endpoints: List[Any],
        name: str = "Discovered API",
        base_url: Optional[str] = None,
        graphql_operations: Optional[List[Any]] = None,
    ) -> PostmanCollection:
        exporter = PostmanCollectionExporter()
        return exporter.export_from_endpoints(
            endpoints=endpoints,
            collection_name=name,
            base_url=base_url,
            graphql_operations=graphql_operations,
        )


# ==============================================================================
# 2. Path & URL Utilities
# ==============================================================================

def is_parameter_segment(seg: str) -> bool:
    """Checks if a path segment represents a parameter (:id, {id}, <id>)."""
    if not seg:
        return False
    return (
        seg.startswith(":")
        or (seg.startswith("{") and seg.endswith("}"))
        or (seg.startswith("<") and seg.endswith(">"))
    )


def extract_parameter_name(seg: str) -> str:
    """Extracts raw parameter identifier without delimiters."""
    if seg.startswith("{") and seg.endswith("}"):
        return seg[1:-1]
    if seg.startswith("<") and seg.endswith(">"):
        return seg[1:-1]
    if seg.startswith(":"):
        return seg[1:]
    return seg


def normalize_path_parameter_syntax(path: str) -> str:
    """Converts OpenAPI {param} and Django/Flask <param> placeholders to :param."""
    path = re.sub(r"\{([a-zA-Z0-9_]+)\}", r":\1", path)
    path = re.sub(r"<([a-zA-Z0-9_]+)>", r":\1", path)
    return path


def build_postman_url(
    raw_path: str,
    parameters: Optional[List[Any]] = None,
    base_url_var: str = "{{baseUrl}}",
) -> PostmanUrl:
    """
    Constructs a fully-formed PostmanUrl object adhering strictly to Postman v2.1.0:
    - raw ALWAYS starts with {{baseUrl}}
    - Path parameters use colon syntax :param in both raw and path
    - Path parameters listed in url.variable
    - Query parameters listed in url.query
    """
    params = parameters or []
    cleaned_input = (raw_path or "").strip()

    # If already fully qualified with scheme/host, extract path
    if cleaned_input.startswith(("http://", "https://")):
        parsed = urllib.parse.urlsplit(cleaned_input)
        path_only = parsed.path
        query_string = parsed.query
    else:
        # Strip baseUrl if already prepended
        if cleaned_input.startswith("{{baseUrl}}"):
            cleaned_input = cleaned_input[len("{{baseUrl}}"):]
        path_only, _, query_string = cleaned_input.partition("?")

    # Normalize parameter delimiters in path
    path_only = normalize_path_parameter_syntax(path_only)
    if not path_only.startswith("/"):
        path_only = "/" + path_only

    segments = [s for s in path_only.strip("/").split("/") if s]

    # Map discovered path parameters
    path_param_map: Dict[str, Any] = {}
    query_param_map: Dict[str, Any] = {}
    for p in params:
        p_name = getattr(p, "name", str(p))
        p_loc = getattr(p, "location", "query")
        if p_loc == "path":
            path_param_map[p_name] = p
        elif p_loc == "query":
            query_param_map[p_name] = p

    # Build path variables
    variables: List[PostmanPathVariable] = []
    seen_vars = set()
    for seg in segments:
        if seg.startswith(":"):
            var_name = seg[1:]
            if var_name not in seen_vars:
                seen_vars.add(var_name)
                param_obj = path_param_map.get(var_name)
                val = str(getattr(param_obj, "example", "") if param_obj and getattr(param_obj, "example", None) is not None else "")
                desc = getattr(param_obj, "description", None) if param_obj else None
                variables.append(PostmanPathVariable(key=var_name, value=val, description=desc))

    # Add any path params from endpoint.parameters not explicitly found in path segments
    for p_name, param_obj in path_param_map.items():
        if p_name not in seen_vars:
            seen_vars.add(p_name)
            val = str(getattr(param_obj, "example", "") if getattr(param_obj, "example", None) is not None else "")
            desc = getattr(param_obj, "description", None)
            variables.append(PostmanPathVariable(key=p_name, value=val, description=desc))

    # Build query parameters
    query_params: List[PostmanQueryParam] = []
    seen_queries = set()

    if query_string:
        for k, v in urllib.parse.parse_qsl(query_string, keep_blank_values=True):
            seen_queries.add(k)
            desc = getattr(query_param_map.get(k), "description", None)
            query_params.append(PostmanQueryParam(key=k, value=v, description=desc))

    for p_name, param_obj in query_param_map.items():
        if p_name not in seen_queries:
            seen_queries.add(p_name)
            val = str(getattr(param_obj, "example", "") if getattr(param_obj, "example", None) is not None else "")
            desc = getattr(param_obj, "description", None)
            query_params.append(PostmanQueryParam(key=p_name, value=val, description=desc))

    # Construct fully-formed raw URL
    raw_url = f"{base_url_var}{path_only}"
    if query_params:
        q_str = "&".join(
            f"{q.key}={q.value}" if q.value else q.key
            for q in query_params
        )
        raw_url = f"{raw_url}?{q_str}"

    return PostmanUrl(
        raw=raw_url,
        protocol=None,
        host=[base_url_var],
        path=segments,
        query=query_params,
        variable=variables,
    )


# ==============================================================================
# 3. Trie / Radix Folder Tree Algorithm (FolderTree)
# ==============================================================================

class FolderNode:
    """Trie node representing a folder or hierarchy level."""
    def __init__(self, name: str = "") -> None:
        self.name: str = name
        self.children: Dict[str, FolderNode] = {}
        self.items: List[PostmanItem] = []
        self.description: Optional[str] = None


class FolderTree:
    """
    Trie / Radix tree algorithm for organizing API endpoints into structured Postman folders.

    Rules:
    - Prioritizes endpoint tags (e.g. 'Billing', 'Users').
    - Flattens / compacts common prefixes like 'api/v1' into 'api/v1/Users'.
    - Truncates folder nesting at parameter boundaries (so '/users/:id' and '/users'
      both live under 'Users', NEVER creating a folder named ':id').
    - Leaves single-segment root routes (e.g. '/health') directly in root items.
    """

    def __init__(
        self,
        flatten_prefixes: bool = True,
        root_route_names: Optional[Set[str]] = None,
    ) -> None:
        self.root = FolderNode(name="")
        self.root_items: List[PostmanItem] = []
        self.flatten_prefixes = flatten_prefixes
        self.folders: Dict[str, PostmanItem] = {}
        self.root_route_candidates = set(ROOT_ROUTE_CANDIDATES)
        if root_route_names:
            self.root_route_candidates.update(s.lower() for s in root_route_names)

    def is_single_segment_root_route(self, endpoint: Any) -> bool:
        """
        Determines if an endpoint is a single-segment root route (e.g. /health).
        Single segment routes matching known utility/system routes (/health, /ping, /)
        or tagged as root are left directly in the collection root items.
        """
        raw_path = getattr(endpoint, "path", "").strip()
        if "?" in raw_path:
            raw_path = raw_path.split("?")[0]

        segments = [s for s in raw_path.strip("/").split("/") if s]
        if len(segments) == 0:
            return True

        if len(segments) == 1:
            seg = segments[0].lower()
            if is_parameter_segment(seg):
                return False

            # Check if it matches known utility root routes (/health, /ping, etc.)
            if seg in self.root_route_candidates:
                return True

            tags = getattr(endpoint, "tags", []) or []
            if any(t.lower() in self.root_route_candidates for t in tags):
                return True

        return False

    def get_folder_name_for_endpoint(self, endpoint: Any) -> Optional[str]:
        """
        Computes the target folder name for an endpoint according to:
        1. Single-segment root check -> returns None (direct root item)
        2. Parameter boundary truncation
        3. Endpoint tag prioritization
        4. Common prefix flattening (e.g. 'api/v1' + 'Users' -> 'api/v1/Users')
        """
        if self.is_single_segment_root_route(endpoint):
            return None

        raw_path = getattr(endpoint, "path", "").strip()
        if "?" in raw_path:
            raw_path = raw_path.split("?")[0]

        segments = [s for s in raw_path.strip("/").split("/") if s]
        if not segments:
            return None

        # Truncate at parameter boundaries (:id, {id}, <id>)
        # so /users/:id and /users both live under 'Users', NEVER creating a folder named ':id'
        non_param_segments: List[str] = []
        for seg in segments:
            if is_parameter_segment(seg):
                break
            non_param_segments.append(seg)

        # Detect common REST prefixes like 'api/v1', 'api/v2', 'v1', 'api'
        common_prefix = ""
        resource_segments = list(non_param_segments)

        if len(non_param_segments) >= 2 and non_param_segments[0].lower() == "api" and re.match(r"^v\d+$", non_param_segments[1].lower()):
            common_prefix = f"{non_param_segments[0]}/{non_param_segments[1]}"
            resource_segments = non_param_segments[2:]
        elif len(non_param_segments) >= 1 and re.match(r"^v\d+$", non_param_segments[0].lower()):
            common_prefix = non_param_segments[0]
            resource_segments = non_param_segments[1:]
        elif len(non_param_segments) >= 1 and non_param_segments[0].lower() == "api":
            common_prefix = "api"
            resource_segments = non_param_segments[1:]

        # Determine resource category name: Prioritize endpoint tags (e.g. 'Billing', 'Users')
        tags = getattr(endpoint, "tags", []) or []
        filtered_tags = [t for t in tags if t.lower() not in ("server_action", "nextjs")]

        resource_name = ""
        if filtered_tags:
            # Tag priority!
            resource_name = filtered_tags[0]
        elif resource_segments:
            # Format segment nicely (e.g. users -> Users)
            resource_name = "/".join(s.capitalize() for s in resource_segments)
        elif non_param_segments:
            resource_name = "/".join(s.capitalize() for s in non_param_segments)
        else:
            resource_name = "Endpoints"

        # Flatten / compact common prefixes into resource name: 'api/v1' + 'Users' -> 'api/v1/Users'
        if self.flatten_prefixes and common_prefix:
            # If resource_name already contains the prefix, don't duplicate
            if resource_name.startswith(common_prefix):
                folder_name = resource_name
            else:
                folder_name = f"{common_prefix}/{resource_name}"
        else:
            folder_name = resource_name

        return folder_name

    def add_endpoint(self, endpoint: Any, item: Optional[PostmanItem] = None) -> None:
        """Adds an endpoint to the tree, creating the leaf item if not provided."""
        if item is None:
            item = endpoint_to_postman_item(endpoint)

        folder_name = self.get_folder_name_for_endpoint(endpoint)
        if folder_name is None:
            # Single-segment root route
            self.root_items.append(item)
        else:
            self.add_item(item, folder_path=[folder_name])

    def add_item(self, item: PostmanItem, folder_path: Optional[List[str]] = None) -> None:
        """Directly adds a PostmanItem to a specific folder path or root."""
        if not folder_path:
            self.root_items.append(item)
            return

        current_node = self.root
        for seg in folder_path:
            if seg not in current_node.children:
                current_node.children[seg] = FolderNode(name=seg)
            current_node = current_node.children[seg]
        current_node.items.append(item)

    def get_folder(self, name: str) -> Optional[PostmanItem]:
        """Lookup a top-level built folder by name."""
        return self.folders.get(name)

    def build(self) -> List[PostmanItem]:
        """
        Builds and returns the final flat-and-compacted list of root PostmanItem objects
        and folder PostmanItem objects.
        """
        result: List[PostmanItem] = []
        self.folders = {}

        # 1. Root items first (single-segment root routes like /health)
        result.extend(self.root_items)

        # 2. Folders
        def node_to_item(node: FolderNode) -> PostmanItem:
            folder_items: List[PostmanItem] = []
            for child in node.children.values():
                folder_items.append(node_to_item(child))
            folder_items.extend(node.items)
            return PostmanItem(
                name=node.name,
                item=folder_items,
                description=node.description,
            )

        for child_name, child_node in self.root.children.items():
            folder_item = node_to_item(child_node)
            self.folders[child_name] = folder_item
            result.append(folder_item)

        return result

    def to_items(self) -> List[PostmanItem]:
        """Alias for build()."""
        return self.build()


# ==============================================================================
# 4. Modern Framework Support: Next.js & GraphQL
# ==============================================================================

def is_nextjs_server_action(endpoint: Any) -> bool:
    """Detects Next.js 14/15 Server Actions by headers, tags, or description."""
    headers = getattr(endpoint, "headers", {}) or {}
    for k in headers.keys():
        if k.lower() == "next-action":
            return True

    tags = getattr(endpoint, "tags", []) or []
    if "server_action" in tags or "nextjs" in tags:
        return True

    summary = getattr(endpoint, "summary", "") or ""
    desc = getattr(endpoint, "description", "") or ""
    if "Next.js Server Action" in summary or "Next.js Server Action" in desc:
        return True

    return False


def extract_nextjs_action_id(endpoint: Any) -> str:
    """Extracts the 40-character action ID for a Next.js Server Action."""
    headers = getattr(endpoint, "headers", {}) or {}
    for k, v in headers.items():
        if k.lower() == "next-action":
            return str(v)

    summary = getattr(endpoint, "summary", "") or ""
    desc = getattr(endpoint, "description", "") or ""
    for text in (summary, desc):
        m = re.search(r"\b([0-9a-fA-F]{40})\b", text)
        if m:
            return m.group(1)

    return "unknown-action-id"


def build_nextjs_server_action_item(endpoint: Any) -> PostmanItem:
    """
    Constructs a PostmanItem for a Next.js 14/15 Server Action:
    - Emits POST request with Next-Action: <action_id> header
    - Emits Accept: text/x-component header
    - Emits appropriate formdata or raw body
    """
    action_id = extract_nextjs_action_id(endpoint)
    path = getattr(endpoint, "path", "/") or "/"
    url = build_postman_url(path, getattr(endpoint, "parameters", []))

    # Required headers
    headers: List[PostmanHeader] = [
        PostmanHeader(key="Next-Action", value=action_id),
        PostmanHeader(key="Accept", value="text/x-component"),
    ]

    # Preserve any additional custom headers
    existing_headers = getattr(endpoint, "headers", {}) or {}
    for hk, hv in existing_headers.items():
        if hk.lower() not in ("next-action", "accept"):
            headers.append(PostmanHeader(key=str(hk), value=str(hv)))

    # Request body: appropriate formdata or raw body
    body_sample = getattr(endpoint, "request_body_sample", None)
    if body_sample is not None:
        if isinstance(body_sample, dict) and "formdata" in body_sample:
            body = PostmanBody(mode="formdata", formdata=body_sample["formdata"])
        elif isinstance(body_sample, (dict, list)):
            body = PostmanBody(mode="raw", raw=json.dumps(body_sample, indent=2), language="json")
        else:
            body = PostmanBody(mode="raw", raw=str(body_sample), language="json")
    else:
        # Check if parameters specify form-data
        params = getattr(endpoint, "parameters", []) or []
        form_params = [
            p for p in params
            if getattr(p, "location", "") in ("formData", "formdata")
        ]
        if form_params:
            body = PostmanBody(
                mode="formdata",
                formdata=[
                    {
                        "key": getattr(p, "name", "field"),
                        "value": str(getattr(p, "example", "") or ""),
                        "type": "text",
                    }
                    for p in form_params
                ],
            )
        else:
            # Standard Next.js server action serialized payload format
            body = PostmanBody(mode="raw", raw='["$K1"]', language="json")

    # Item name
    summary = getattr(endpoint, "summary", None)
    name = summary or f"Next.js Server Action: {action_id[:8]}"
    desc = getattr(endpoint, "description", None) or f"Server Action invoked via Next-Action header on '{path}'"

    req = PostmanRequest(
        method="POST",
        url=url,
        header=headers,
        body=body,
        description=desc,
    )

    return PostmanItem(
        name=name,
        request=req,
        description=desc,
    )


def graphql_operation_to_postman_item(op: Any) -> PostmanItem:
    """
    Constructs a PostmanItem targeting a GraphQL endpoint:
    - POST request
    - mode: 'graphql' with query and variables
    """
    op_type = getattr(op, "operation_type", "query") or "query"
    op_name = getattr(op, "operation_name", "GraphQLOperation") or "GraphQLOperation"
    query_str = (getattr(op, "query_string", "") or "").strip()
    endpoint_path = getattr(op, "endpoint", "/graphql") or "/graphql"
    vars_sample = getattr(op, "variables_sample", None)

    url = build_postman_url(endpoint_path)

    variables_str = ""
    if vars_sample is not None:
        if isinstance(vars_sample, str):
            variables_str = vars_sample
        else:
            variables_str = json.dumps(vars_sample, indent=2)

    body = PostmanBody(
        mode="graphql",
        graphql={
            "query": query_str,
            "variables": variables_str,
        },
    )

    headers = [
        PostmanHeader(key="Content-Type", value="application/json"),
    ]

    item_name = f"{op_name} ({op_type})" if op_type else op_name
    desc = f"GraphQL {op_type.capitalize()}: {op_name}"

    request = PostmanRequest(
        method="POST",
        url=url,
        header=headers,
        body=body,
        description=desc,
    )

    return PostmanItem(
        name=item_name,
        request=request,
        description=desc,
    )


def build_graphql_folder(graphql_operations: List[Any]) -> PostmanItem:
    """Emits a dedicated 'GraphQL' folder containing all GraphQL operations."""
    items = [graphql_operation_to_postman_item(op) for op in graphql_operations]
    return PostmanItem(
        name="GraphQL",
        item=items,
        description="Discovered GraphQL Operations",
    )


# ==============================================================================
# 5. Endpoint to PostmanItem Conversion
# ==============================================================================

def endpoint_to_postman_item(endpoint: Any) -> PostmanItem:
    """Converts a DiscoveredEndpoint model into a PostmanItem."""
    if is_nextjs_server_action(endpoint):
        return build_nextjs_server_action_item(endpoint)

    method = getattr(endpoint, "method", "GET").upper()
    path = getattr(endpoint, "path", "/")
    params = getattr(endpoint, "parameters", [])
    url = build_postman_url(path, params)

    # Headers
    headers: List[PostmanHeader] = []
    raw_headers = getattr(endpoint, "headers", {}) or {}
    for k, v in raw_headers.items():
        headers.append(PostmanHeader(key=str(k), value=str(v)))

    # Request Body
    body: Optional[PostmanBody] = None
    if method in ("POST", "PUT", "PATCH", "DELETE"):
        body_sample = getattr(endpoint, "request_body_sample", None)
        if body_sample is not None:
            if isinstance(body_sample, (dict, list)):
                raw_json = json.dumps(body_sample, indent=2)
                body = PostmanBody(mode="raw", raw=raw_json, language="json")
            else:
                body = PostmanBody(mode="raw", raw=str(body_sample), language="json")
        else:
            body = PostmanBody(mode="raw", raw="{}", language="json")

        # Ensure Content-Type header if not already present
        if not any(h.key.lower() == "content-type" for h in headers):
            headers.append(PostmanHeader(key="Content-Type", value="application/json"))

    # Auth configuration
    auth: Optional[Dict[str, Any]] = None
    auth_type = getattr(endpoint, "auth_type", None)
    if auth_type:
        auth_lower = auth_type.lower()
        if auth_lower == "bearer":
            auth = {
                "type": "bearer",
                "bearer": [
                    {"key": "token", "value": "{{bearerToken}}", "type": "string"}
                ],
            }
        elif auth_lower == "apikey":
            header_name = getattr(endpoint, "auth_header_or_param", "X-API-Key") or "X-API-Key"
            auth = {
                "type": "apikey",
                "apikey": [
                    {"key": "key", "value": header_name, "type": "string"},
                    {"key": "value", "value": "{{apiKey}}", "type": "string"},
                    {"key": "in", "value": "header", "type": "string"},
                ],
            }
        elif auth_lower == "basic":
            auth = {
                "type": "basic",
                "basic": [
                    {"key": "username", "value": "{{username}}", "type": "string"},
                    {"key": "password", "value": "{{password}}", "type": "string"},
                ],
            }

    summary = getattr(endpoint, "summary", None)
    item_name = summary or f"{method} {path}"
    desc = getattr(endpoint, "description", None)

    request = PostmanRequest(
        method=method,
        url=url,
        header=headers,
        body=body,
        auth=auth,
        description=desc,
    )

    return PostmanItem(
        name=item_name,
        request=request,
        description=desc,
    )


# ==============================================================================
# 6. Exporter Engine & Convenience API
# ==============================================================================

class PostmanCollectionExporter:
    """
    Coordinates the conversion and export of ScanResult and endpoint collections
    into Postman Collection v2.1.0 JSON format.
    """

    def __init__(self, flatten_prefixes: bool = True) -> None:
        self.flatten_prefixes = flatten_prefixes

    def export_collection(
        self,
        scan_result: Any,
        collection_name: Optional[str] = None,
        base_url: Optional[str] = None,
        description: Optional[str] = None,
    ) -> PostmanCollection:
        """Builds a PostmanCollection from a ScanResult or dict."""
        if isinstance(scan_result, dict):
            target_url = scan_result.get("target_url", "")
            base_urls = scan_result.get("base_urls", [])
            endpoints = scan_result.get("endpoints", [])
            graphql_ops = scan_result.get("graphql_operations", [])
        else:
            target_url = getattr(scan_result, "target_url", "")
            base_urls = getattr(scan_result, "base_urls", [])
            endpoints = getattr(scan_result, "endpoints", [])
            graphql_ops = getattr(scan_result, "graphql_operations", [])

        # Compute collection name
        if not collection_name:
            if target_url:
                parsed = urllib.parse.urlsplit(target_url)
                collection_name = f"{parsed.netloc or target_url} API Collection"
            else:
                collection_name = "Discovered API Collection"

        # Compute base URL variable value
        resolved_base_url = "http://localhost:3000"
        if base_url:
            resolved_base_url = base_url
        elif base_urls and base_urls[0]:
            resolved_base_url = base_urls[0]
        elif target_url:
            parsed = urllib.parse.urlsplit(target_url)
            resolved_base_url = f"{parsed.scheme or 'http'}://{parsed.netloc}" if parsed.netloc else target_url

        return self.export_from_endpoints(
            endpoints=endpoints,
            collection_name=collection_name,
            base_url=resolved_base_url,
            graphql_operations=graphql_ops,
            description=description or f"Exported collection for {target_url or collection_name}",
        )

    def export_from_endpoints(
        self,
        endpoints: List[Any],
        collection_name: Optional[str] = None,
        base_url: Optional[str] = None,
        graphql_operations: Optional[List[Any]] = None,
        description: Optional[str] = None,
    ) -> PostmanCollection:
        """Builds a PostmanCollection from explicit lists of endpoints and GraphQL operations."""
        tree = FolderTree(flatten_prefixes=self.flatten_prefixes)

        # 1. Organize endpoints into Trie / Radix folder tree
        for ep in endpoints:
            tree.add_endpoint(ep)

        items = tree.build()

        # 2. Add dedicated GraphQL folder if operations provided
        if graphql_operations:
            gql_folder = build_graphql_folder(graphql_operations)
            items.append(gql_folder)

        # 3. Collection variables
        resolved_base_url = base_url or "http://localhost:3000"
        variables = [
            PostmanVariable(
                key="baseUrl",
                value=resolved_base_url,
                type="string",
                description="Base target server URL",
            ),
        ]

        return PostmanCollection(
            name=collection_name or "Discovered API",
            description=description,
            schema=POSTMAN_V21_SCHEMA,
            variables=variables,
            items=items,
        )


# Alias PostmanExporter to PostmanCollectionExporter for unified module interface
PostmanExporter = PostmanCollectionExporter


def generate_postman_collection(
    scan_result: Optional[Any] = None,
    endpoints: Optional[List[Any]] = None,
    graphql_operations: Optional[List[Any]] = None,
    collection_name: Optional[str] = None,
    base_url: Optional[str] = None,
    description: Optional[str] = None,
    flatten_prefixes: bool = True,
) -> PostmanCollection:
    """
    High-level generator function for Postman Collections.
    Accepts either a ScanResult object or explicit endpoint/graphql lists.
    """
    exporter = PostmanCollectionExporter(flatten_prefixes=flatten_prefixes)
    if scan_result is not None:
        return exporter.export_collection(
            scan_result=scan_result,
            collection_name=collection_name,
            base_url=base_url,
            description=description,
        )
    return exporter.export_from_endpoints(
        endpoints=endpoints or [],
        collection_name=collection_name,
        base_url=base_url,
        graphql_operations=graphql_operations,
        description=description,
    )


def export_postman_collection(
    scan_result: Optional[Any] = None,
    output_path: Union[str, Path] = "collection.json",
    endpoints: Optional[List[Any]] = None,
    graphql_operations: Optional[List[Any]] = None,
    collection_name: Optional[str] = None,
    base_url: Optional[str] = None,
    description: Optional[str] = None,
    flatten_prefixes: bool = True,
) -> str:
    """Generates and writes a Postman Collection v2.1.0 file to the specified path."""
    collection = generate_postman_collection(
        scan_result=scan_result,
        endpoints=endpoints,
        graphql_operations=graphql_operations,
        collection_name=collection_name,
        base_url=base_url,
        description=description,
        flatten_prefixes=flatten_prefixes,
    )
    return collection.export_file(output_path)
