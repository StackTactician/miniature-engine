"""
Tree-sitter AST Extractor engine for JavaScript bundles.
High-throughput (>20 MB/s, <25 MB RAM), error-tolerant AST parsing using tree-sitter.

Extracts:
1. Dynamic template literals normalized to OpenAPI format (`/api/v1/{resource}/{id}`)
   with DiscoveredParameter path and query parameter extraction.
2. Next.js Server Action references (createServerReference) with 40-hex action IDs
   into DiscoveredEndpoint(method="POST", headers={"Next-Action": action_id}).
3. HTTP client configurations (Axios baseURL, Ky prefixUrl, timeout) from call expressions
   and default property assignments.
"""

from __future__ import annotations

import re
import urllib.parse
from typing import Any, Dict, List, Optional, Set, Tuple

import tree_sitter
import tree_sitter_javascript

from api_tool.models import DiscoveredEndpoint, DiscoveredParameter


# ==============================================================================
# FALSE-POSITIVE ELIMINATION PATTERNS
# ==============================================================================

FP_SVG_PATH = re.compile(r"^[MmLlHhVvCcSsQqTtAaZz0-9\s,.\-]{6,}$")
FP_SVG_XMLNS = re.compile(
    r"^https?://(?:www\.)?(?:w3\.org/(?:2000/svg|1999/xlink|1999/xhtml)|schema\.org)",
    re.IGNORECASE,
)
FP_TAILWIND_FRACTION = re.compile(
    r"^(?:-?(?:w|h|max-w|min-w|top|bottom|left|right|inset(?:-[xy])?|translate-[xy]|scale-[xy]|rotate|skew-[xy]|basis|col-span|row-span|grid-cols|grid-rows|aspect)-\d+/\d+)$",
    re.IGNORECASE,
)
FP_TAILWIND_OPACITY = re.compile(
    r"^(?:bg|text|border|ring|divide|fill|stroke|from|to|via|placeholder|accent|shadow)-[a-z0-9]+(?:-[a-z0-9]+)?/\d+$",
    re.IGNORECASE,
)
FP_MIME_TYPE = re.compile(
    r"^/?(?:application|audio|font|example|image|message|model|multipart|text|video)/[a-zA-Z0-9\.\+\-_]+$",
    re.IGNORECASE,
)
FP_UUID = re.compile(
    r"^/?(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$"
)
FP_DATE_FORMAT = re.compile(
    r"^/?(?:(?:\d{4}[/-](?:0[1-9]|1[0-2])[/-](?:0[1-9]|[12]\d|3[01]))|(?:(?:YYYY|MM|DD)[/-](?:YYYY|MM|DD)[/-](?:YYYY|MM|DD)))(?:[T\s][0-2]\d:[0-5]\d(?::[0-5]\d(?:\.\d+)?)?(?:Z|[+-][0-2]\d:?[0-5]\d)?)?$",
    re.IGNORECASE,
)
FP_AST_TOKEN = re.compile(
    r"^/?(?:Identifier|Literal|MemberExpression|CallExpression|BinaryExpression|UnaryExpression|BlockStatement|FunctionDeclaration|ReturnStatement)/[A-Za-z]+$"
)
FP_CSS_MODULE_OR_BEM = re.compile(
    r"^(?:styles\.)?[a-zA-Z0-9_-]+__[a-zA-Z0-9_-]+|^_?[a-zA-Z0-9]+_[a-zA-Z0-9]{5,}_[a-zA-Z0-9]+$"
)
FP_STATIC_ASSET = re.compile(
    r"(?<=[a-zA-Z0-9_])\.(?:png|jpe?g|gif|svg|ico|webp|avif|woff2?|ttf|eot|mp4|webm|mp3|wav|ogg|css|map|wasm)$",
    re.IGNORECASE,
)
FP_PURE_FRACTION_OR_NUMBER = re.compile(r"^/?(?:\d+/\d+|\d+)$")
FP_BASE64_DATA = re.compile(r"^/?(?:[A-Za-z0-9+/]{30,}={0,2})$")

# Hex validation for 40-character Server Action IDs
HEX_40_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")


# ==============================================================================
# TREE-SITTER C S-EXPRESSION DEFINITIONS
# ==============================================================================

# 1. Template strings query
TEMPLATE_QUERY_S_EXPR = "(template_string) @template"

# 2. Next.js Server Action references query
SERVER_ACTION_QUERY_S_EXPR = """
(call_expression
  function: [
    (identifier) @fn
    (#eq? @fn "createServerReference")
    (member_expression
      property: (property_identifier) @prop
      (#eq? @prop "createServerReference"))
    (parenthesized_expression
      (sequence_expression
        (member_expression
          property: (property_identifier) @prop
          (#eq? @prop "createServerReference"))))
  ]
  arguments: (arguments (string) @action_id))
"""

# 3. HTTP client configuration calls query
HTTP_CLIENT_CALL_S_EXPR = """
(call_expression
  function: [
    (member_expression
      property: (property_identifier) @method)
    (identifier) @method
  ]
  arguments: (arguments (object) @config_obj))
"""

# 4. Property assignment query (e.g. axios.defaults.baseURL = "...")
PROPERTY_ASSIGNMENT_S_EXPR = """
(assignment_expression
  left: (member_expression
    property: (property_identifier) @prop)
  right: [(string) (number)] @val)
"""


class JSASTExtractor:
    """
    Compulsory Tree-sitter AST extraction engine for JavaScript bundles.
    High throughput (>20 MB/s, < 25MB RAM), zero catastrophic backtracking, error-tolerant.
    """

    def __init__(self) -> None:
        self._language = tree_sitter.Language(tree_sitter_javascript.language())
        self._parser = tree_sitter.Parser(self._language)

        # Precompile C S-expressions
        self._template_query = tree_sitter.Query(self._language, TEMPLATE_QUERY_S_EXPR)
        self._server_action_query = tree_sitter.Query(self._language, SERVER_ACTION_QUERY_S_EXPR)
        self._http_client_query = tree_sitter.Query(self._language, HTTP_CLIENT_CALL_S_EXPR)
        self._assignment_query = tree_sitter.Query(self._language, PROPERTY_ASSIGNMENT_S_EXPR)

    def is_false_positive(self, candidate: str) -> bool:
        """
        Multi-stage false-positive filter.
        Rejects SVG paths, XML namespaces, Tailwind fractions/opacity, CSS modules,
        UUIDs, dates, MIME types, AST tokens, static media, and base64 noise.
        """
        c = candidate.strip()
        if not c or c in ("/", "//", "///", "http://", "https://"):
            return True

        # Discard consecutive slashes not part of scheme
        if "//" in c and not c.startswith(("http://", "https://")):
            return True

        if FP_SVG_XMLNS.search(c):
            return True
        if FP_SVG_PATH.match(c):
            return True
        if FP_TAILWIND_FRACTION.match(c):
            return True
        if FP_TAILWIND_OPACITY.match(c):
            return True
        if FP_PURE_FRACTION_OR_NUMBER.match(c):
            return True
        if FP_MIME_TYPE.match(c):
            return True
        if FP_UUID.match(c):
            return True
        if FP_DATE_FORMAT.match(c):
            return True
        if FP_AST_TOKEN.match(c):
            return True
        if FP_CSS_MODULE_OR_BEM.match(c):
            return True

        if c.startswith("data:"):
            return True
        if c.startswith(("/9j/", "9j/", "iVBORw0KGgo", "/iVBORw0KGgo", "PHN2Zy", "/PHN2Zy", "R0lGOD", "UklGR")):
            return True
        if FP_BASE64_DATA.match(c) and len(c) >= 32:
            return True

        path_without_query = c.split("?")[0].split("#")[0]
        if FP_STATIC_ASSET.search(path_without_query):
            return True

        return False

    def _extract_param_name(self, sub_node: tree_sitter.Node) -> str:
        """
        Extracts clean parameter name from an AST template_substitution node.
        Handles identifiers, member expressions (e.g. user.profile.id -> id),
        and calls (e.g. encodeURIComponent(id) -> id).
        """
        for ch in sub_node.named_children:
            if ch.type == "identifier":
                return ch.text.decode("utf-8")
            if ch.type == "member_expression":
                prop = ch.child_by_field_name("property")
                if prop:
                    return prop.text.decode("utf-8")
            if ch.type == "call_expression":
                args = ch.child_by_field_name("arguments")
                if args:
                    for arg in args.named_children:
                        if arg.type == "identifier":
                            return arg.text.decode("utf-8")
                        if arg.type == "member_expression":
                            prop = arg.child_by_field_name("property")
                            if prop:
                                return prop.text.decode("utf-8")

        raw = sub_node.text.decode("utf-8")
        cleaned = re.sub(r"[^a-zA-Z0-9_]", "", raw.split(".")[-1])
        return cleaned or "param"

    def _reconstruct_template(
        self, node: tree_sitter.Node
    ) -> Tuple[str, List[Tuple[str, int]]]:
        """
        Reconstructs a dynamic template_string AST node into OpenAPI format:
        `/api/v1/${resource}/${id}` -> `/api/v1/{resource}/{id}`
        Returns (reconstructed_string, list_of_(param_name, start_idx)).
        """
        raw_pieces: List[str] = []
        sub_params: List[Tuple[str, int]] = []
        curr_len = 0

        for ch in node.children:
            if ch.type in ("string_fragment", "escape_sequence"):
                txt = ch.text.decode("utf-8")
                raw_pieces.append(txt)
                curr_len += len(txt)
            elif ch.type == "template_substitution":
                p_name = self._extract_param_name(ch)
                placeholder = f"{{{p_name}}}"
                raw_pieces.append(placeholder)
                sub_params.append((p_name, curr_len))
                curr_len += len(placeholder)

        reconstructed = "".join(raw_pieces)

        # Normalize leading base URL substitutions, e.g. `${baseUrl}/api/v1/...` -> `/api/v1/...`
        reconstructed = re.sub(
            r"^\{?(?:baseUrl|baseURL|base_url|api_url|apiUrl|host|origin|domain|endpoint)\}?(/.*)$",
            r"\1",
            reconstructed,
            flags=re.IGNORECASE,
        )

        return reconstructed, sub_params

    def _detect_http_method_ast(self, node: tree_sitter.Node) -> str:
        """
        Traverses enclosing AST nodes to detect the HTTP method (GET, POST, PUT, DELETE, PATCH, etc.).
        Inspects:
        - Parent call expression: client.post(url), axios.delete(url), ky.get(url)
        - Request options object: fetch(url, { method: 'POST' })
        - Chained call expression: wretch(url).post(...)
        """
        curr = node.parent
        while curr and curr.type not in ("call_expression", "program", "function_declaration", "arrow_function"):
            curr = curr.parent

        if not curr or curr.type != "call_expression":
            return "GET"

        # 1. Direct method call: axios.post(...), ky.delete(...)
        fn = curr.child_by_field_name("function")
        if fn and fn.type == "member_expression":
            prop = fn.child_by_field_name("property")
            if prop:
                prop_name = prop.text.decode("utf-8").upper()
                if prop_name in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
                    return prop_name

        # 2. Options object: fetch(url, { method: 'POST' })
        args = curr.child_by_field_name("arguments")
        if args:
            for arg in args.named_children:
                if arg.type == "object":
                    for pair in arg.named_children:
                        if pair.type == "pair":
                            k = pair.child_by_field_name("key")
                            v = pair.child_by_field_name("value")
                            if k and k.text.decode("utf-8").strip("\"'") == "method" and v:
                                val_str = v.text.decode("utf-8").strip("\"'").upper()
                                if val_str in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
                                    return val_str

        # 3. Chained call expression: wretch(url).post(...)
        parent = curr.parent
        if parent and parent.type == "member_expression":
            prop = parent.child_by_field_name("property")
            if prop:
                prop_name = prop.text.decode("utf-8").upper()
                if prop_name in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
                    return prop_name

        return "GET"

    def _is_endpoint_candidate(self, path_str: str, has_http_caller: bool) -> bool:
        """
        Validates if reconstructed path string qualifies as an API endpoint candidate.
        """
        if not path_str or len(path_str) > 2048:
            return False

        # Reject strings with newlines, spaces, or CSS/HTML characters
        if "\n" in path_str or "\r" in path_str or "<" in path_str or ">" in path_str or ";" in path_str:
            return False

        # If inside an explicit HTTP caller (axios.get, fetch, etc.), candidate threshold is low
        if has_http_caller:
            return True

        # Starts with URL scheme or path prefix
        if path_str.startswith(("http://", "https://", "/", "./", "../", "api/", "v1/", "v2/", "v3/", "v4/", "graphql")):
            # Must contain at least one alphanumeric segment
            if re.search(r"[a-zA-Z0-9]", path_str):
                return True

        return False

    def extract_endpoints(self, js_code: str, base_url: str = "") -> List[DiscoveredEndpoint]:
        """
        Parses JavaScript code using Tree-sitter and extracts dynamic REST endpoints
        reconstructed into OpenAPI format with path and query parameters.
        """
        if not js_code:
            return []

        code_bytes = js_code.encode("utf-8", errors="replace") if isinstance(js_code, str) else js_code
        tree = self._parser.parse(code_bytes)

        cursor = tree_sitter.QueryCursor(self._template_query)
        matches = cursor.matches(tree.root_node)

        endpoints: List[DiscoveredEndpoint] = []
        seen_endpoints: Set[Tuple[str, str, str]] = set()

        for _, captures in matches:
            nodes = captures.get("template", [])
            for tmpl_node in nodes:
                reconstructed, sub_params = self._reconstruct_template(tmpl_node)
                if not reconstructed:
                    continue

                if self.is_false_positive(reconstructed):
                    continue

                http_method = self._detect_http_method_ast(tmpl_node)
                has_http_caller = http_method != "GET" or (tmpl_node.parent and tmpl_node.parent.type == "arguments")

                if not self._is_endpoint_candidate(reconstructed, has_http_caller):
                    continue

                # Separate query string
                if "?" in reconstructed:
                    path_part, query_part = reconstructed.split("?", 1)
                    q_idx = len(path_part)
                else:
                    path_part, query_part = reconstructed, ""
                    q_idx = len(reconstructed)

                # Extract base URL if scheme present
                extracted_base = ""
                if path_part.startswith(("http://", "https://")):
                    parsed = urllib.parse.urlsplit(path_part)
                    extracted_base = f"{parsed.scheme}://{parsed.netloc}"
                    path_part = parsed.path or "/"

                # Normalize relative path
                if path_part.startswith("./"):
                    path_part = path_part[1:]
                elif path_part.startswith("../"):
                    path_part = "/" + path_part.lstrip("./")
                elif not path_part.startswith("/"):
                    path_part = "/" + path_part

                # Normalize path parameters in path_part
                # Express route params: :id -> {id}
                norm_path = re.sub(r"(?<=/):([a-zA-Z_][a-zA-Z0-9_]*)", r"{\1}", path_part)
                # Next.js dynamic routes: [id] -> {id}, [...slug] -> {slug*}
                norm_path = re.sub(
                    r"\[+([a-zA-Z0-9_\-\.]+)\]+",
                    lambda m: f"{{{m.group(1)[3:]}*}}" if m.group(1).startswith("...") else f"{{{m.group(1)}}}",
                    norm_path,
                )

                # Extract parameters
                parameters: List[DiscoveredParameter] = []
                seen_params: Set[Tuple[str, str]] = set()

                # 1. Path parameters from curly braces in norm_path
                for m in re.finditer(r"\{([a-zA-Z0-9_]+)(?:\*)?\}", norm_path):
                    p_name = m.group(1)
                    if ("path", p_name) not in seen_params:
                        seen_params.add(("path", p_name))
                        parameters.append(
                            DiscoveredParameter(
                                name=p_name,
                                location="path",
                                required=True,
                                param_type="string",
                                description=f"Path parameter: {p_name}",
                            )
                        )

                # 2. Query parameters from query string
                if query_part:
                    for q_item in query_part.split("&"):
                        if not q_item:
                            continue
                        if "=" in q_item:
                            q_name, q_val = q_item.split("=", 1)
                        else:
                            q_name, q_val = q_item, None
                        q_name = q_name.strip()
                        # Clean curly braces if key itself is a placeholder
                        clean_q_name = re.sub(r"[{}]", "", q_name)
                        if clean_q_name and ("query", clean_q_name) not in seen_params:
                            seen_params.add(("query", clean_q_name))
                            parameters.append(
                                DiscoveredParameter(
                                    name=clean_q_name,
                                    location="query",
                                    required=False,
                                    example=q_val,
                                    param_type="string",
                                    description=f"Query parameter: {clean_q_name}",
                                )
                            )

                final_path = f"{norm_path}?{query_part}" if query_part else norm_path
                resolved_base = extracted_base or base_url.rstrip("/")

                endpoint_key = (norm_path, http_method, resolved_base)
                if endpoint_key in seen_endpoints:
                    continue
                seen_endpoints.add(endpoint_key)

                endpoints.append(
                    DiscoveredEndpoint(
                        path=norm_path,
                        method=http_method,
                        base_url=resolved_base,
                        source="static_ast",
                        tags=["tree_sitter_ast", "openapi_normalized"],
                        parameters=parameters,
                        summary=f"Discovered OpenAPI endpoint: {norm_path}",
                    )
                )

        return endpoints

    def extract_server_actions(
        self, js_code: str, page_route: str = ""
    ) -> List[DiscoveredEndpoint]:
        """
        Extracts Next.js Server Action references (createServerReference)
        with 40-character hex action IDs and emits:
        DiscoveredEndpoint(path=page_route, method="POST", headers={"Next-Action": action_id})
        """
        if not js_code:
            return []

        code_bytes = js_code.encode("utf-8", errors="replace") if isinstance(js_code, str) else js_code
        tree = self._parser.parse(code_bytes)

        cursor = tree_sitter.QueryCursor(self._server_action_query)
        matches = cursor.matches(tree.root_node)

        server_actions: List[DiscoveredEndpoint] = []
        seen_action_ids: Set[str] = set()

        for _, captures in matches:
            action_nodes = captures.get("action_id", [])
            for node in action_nodes:
                raw_id = node.text.decode("utf-8").strip("\"'")
                if not HEX_40_PATTERN.fullmatch(raw_id):
                    continue

                if raw_id in seen_action_ids:
                    continue
                seen_action_ids.add(raw_id)

                server_actions.append(
                    DiscoveredEndpoint(
                        path=page_route,
                        method="POST",
                        source="static_ast",
                        tags=["server_action", "nextjs"],
                        headers={"Next-Action": raw_id},
                        summary=f"Next.js Server Action: {raw_id}",
                        description=f"Server Action invoked via Next-Action header on route '{page_route}'",
                    )
                )

        return server_actions

    def extract_client_configs(self, js_code: str) -> Dict[str, Any]:
        """
        Extracts HTTP client configurations:
        - Axios baseURL, defaults.baseURL, Ky prefixUrl, timeout (Axios/Ky)
        Returns dictionary with base_urls, axios, prefixUrl, timeout, timeouts.
        """
        if not js_code:
            return {
                "base_urls": [],
                "axios": [],
                "prefixUrl": [],
                "ky": [],
                "timeout": [],
                "timeouts": [],
                "configs": [],
            }

        code_bytes = js_code.encode("utf-8", errors="replace") if isinstance(js_code, str) else js_code
        tree = self._parser.parse(code_bytes)

        base_urls: List[str] = []
        axios_urls: List[str] = []
        prefix_urls: List[str] = []
        ky_urls: List[str] = []
        timeouts: List[Any] = []
        configs_list: List[Dict[str, Any]] = []

        def _clean_str(val_node: tree_sitter.Node) -> str:
            txt = val_node.text.decode("utf-8")
            return txt.strip("\"'`")

        def _clean_num(val_node: tree_sitter.Node) -> Any:
            txt = val_node.text.decode("utf-8")
            try:
                return float(txt) if ("." in txt or "e" in txt.lower()) else int(txt)
            except Exception:
                return txt

        # 1. Match HTTP client call expressions: axios.create({...}), ky.create({...}), etc.
        cursor_calls = tree_sitter.QueryCursor(self._http_client_query)
        matches_calls = cursor_calls.matches(tree.root_node)

        for _, captures in matches_calls:
            objs = captures.get("config_obj", [])
            for obj in objs:
                config_record: Dict[str, Any] = {}
                for ch in obj.named_children:
                    if ch.type == "pair":
                        k_node = ch.child_by_field_name("key")
                        v_node = ch.child_by_field_name("value")
                        if not k_node or not v_node:
                            continue

                        k = k_node.text.decode("utf-8").strip("\"'")
                        if k in ("baseURL", "baseUrl"):
                            val = _clean_str(v_node)
                            if val and not self.is_false_positive(val):
                                config_record["baseURL"] = val
                                if val not in axios_urls:
                                    axios_urls.append(val)
                                if val not in base_urls:
                                    base_urls.append(val)
                        elif k in ("prefixUrl", "prefix"):
                            val = _clean_str(v_node)
                            if val and not self.is_false_positive(val):
                                config_record["prefixUrl"] = val
                                if val not in prefix_urls:
                                    prefix_urls.append(val)
                                if val not in ky_urls:
                                    ky_urls.append(val)
                                if val not in base_urls:
                                    base_urls.append(val)
                        elif k == "timeout":
                            val = _clean_num(v_node)
                            config_record["timeout"] = val
                            if val not in timeouts:
                                timeouts.append(val)
                        elif k == "url":
                            val = _clean_str(v_node)
                            if val and not self.is_false_positive(val):
                                config_record["url"] = val
                                if val not in base_urls:
                                    base_urls.append(val)

                if config_record:
                    configs_list.append(config_record)

        # 2. Match property assignments: axios.defaults.baseURL = "...", client.defaults.timeout = 5000
        cursor_assign = tree_sitter.QueryCursor(self._assignment_query)
        matches_assign = cursor_assign.matches(tree.root_node)

        for _, captures in matches_assign:
            prop_nodes = captures.get("prop", [])
            val_nodes = captures.get("val", [])
            if not prop_nodes or not val_nodes:
                continue

            prop = prop_nodes[0].text.decode("utf-8")
            v_node = val_nodes[0]

            if prop in ("baseURL", "baseUrl"):
                val = _clean_str(v_node)
                if val and not self.is_false_positive(val):
                    if val not in axios_urls:
                        axios_urls.append(val)
                    if val not in base_urls:
                        base_urls.append(val)
            elif prop in ("prefixUrl", "prefix"):
                val = _clean_str(v_node)
                if val and not self.is_false_positive(val):
                    if val not in prefix_urls:
                        prefix_urls.append(val)
                    if val not in ky_urls:
                        ky_urls.append(val)
                    if val not in base_urls:
                        base_urls.append(val)
            elif prop == "timeout":
                val = _clean_num(v_node)
                if val not in timeouts:
                    timeouts.append(val)

        return {
            "base_urls": base_urls,
            "axios": axios_urls,
            "prefixUrl": prefix_urls,
            "ky": ky_urls,
            "timeout": timeouts,
            "timeouts": timeouts,
            "configs": configs_list,
        }

    def extract_all(self, js_code: str, base_url: str = "") -> Dict[str, Any]:
        """
        Unified extraction pipeline:
        1. Reconstructs dynamic template literals into OpenAPI format with DiscoveredParameters.
        2. Extracts Next.js Server Action IDs (40-hex) -> DiscoveredEndpoint(method="POST", header Next-Action).
        3. Extracts client configs (Axios baseURL, Ky prefixUrl, timeout).
        """
        template_endpoints = self.extract_endpoints(js_code, base_url=base_url)
        server_actions = self.extract_server_actions(js_code, page_route="")
        client_configs = self.extract_client_configs(js_code)

        # Merge endpoints
        all_endpoints: List[DiscoveredEndpoint] = []
        seen: Set[Tuple[str, str, str]] = set()

        for ep in template_endpoints:
            k = (ep.path, ep.method, ep.base_url)
            if k not in seen:
                seen.add(k)
                all_endpoints.append(ep)

        for sa in server_actions:
            k = (sa.path, sa.method, sa.headers.get("Next-Action", ""))
            if k not in seen:
                seen.add(k)
                all_endpoints.append(sa)

        all_parameters: List[DiscoveredParameter] = []
        for ep in template_endpoints:
            all_parameters.extend(ep.parameters)

        return {
            "endpoints": all_endpoints,
            "template_endpoints": template_endpoints,
            "server_actions": server_actions,
            "parameters": all_parameters,
            "client_configs": client_configs,
            "base_urls": client_configs.get("base_urls", []),
            "axios": client_configs.get("axios", []),
            "prefixUrl": client_configs.get("prefixUrl", []),
            "timeout": client_configs.get("timeout", []),
        }
