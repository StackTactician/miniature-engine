"""
Static Regex & HTTP Client Harvester module for JavaScript bundles.
Analyzes client code, extracts REST API endpoints, parameter metadata,
client configurations (Axios, Ky, ofetch, Wretch, tRPC), and Next.js Server Actions.

Guarantees linear O(N) regex evaluation (strictly ReDoS-safe) with atomic non-overlapping tokenization.
Termux-compatible, pure Python 3 / standard library / httpx.
"""

from typing import List, Dict, Any, Tuple, Optional, Set
import re
import math
import urllib.parse

from api_tool.models import DiscoveredEndpoint, DiscoveredParameter


def shannon_entropy(data: str) -> float:
    """
    Computes Shannon entropy of a string to differentiate between structured paths
    and high-entropy random hashes or base64 chunks.
    """
    if not data:
        return 0.0
    freq: Dict[str, int] = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1
    total_len = len(data)
    return -sum((count / total_len) * math.log2(count / total_len) for count in freq.values())


# ==============================================================================
# STRICTLY LINEAR O(N) REGEX DEFINITIONS (NO CATASTROPHIC BACKTRACKING / REDOS)
# ==============================================================================

# Quoted string candidate matching:
# Three disjoint branches for single quote, double quote, and backtick delimiters.
# Each inner character class explicitly forbids the closing quote, ensuring deterministic,
# non-backtracking linear tokenization across any input length.
ENDPOINT_CANDIDATE_PATTERN = re.compile(
    r"""(?x)
    (?:
        '(?P<sq>(?:https?://[a-zA-Z0-9\.\-_]+(?::\d+)?|/|\./|\.\./|api/|v\d+/)[a-zA-Z0-9_\-\.~%!$&*+,;=:@/?#${}\[\]]{0,2048}+)'
        |
        "(?P<dq>(?:https?://[a-zA-Z0-9\.\-_]+(?::\d+)?|/|\./|\.\./|api/|v\d+/)[a-zA-Z0-9_\-\.~%!$'*+,;=:@/?#${}\[\]]{0,2048}+)"
        |
        `(?P<bt>(?:https?://[a-zA-Z0-9\.\-_]+(?::\d+)?|/|\./|\.\./|api/|v\d+/)[a-zA-Z0-9_\-\.~%!$'"*+,;=:@/?#${}\[\]]{0,2048}+)`
    )
    """
)

# False-Positive Elimination Patterns (Disjoint, atomic, O(N))
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

# Next.js Server Action references
# Matches createServerReference("40_hex_id") or (0, r.createServerReference)('40_hex_id')
NEXT_SERVER_ACTION_PATTERN = re.compile(
    r"""(?:\bcreateServerReference|\.createServerReference)\)?\s*\(\s*["']([a-fA-F0-9]{40})["']"""
)

# HTTP Client Config Patterns
# Axios
AXIOS_CREATE_PATTERN = re.compile(
    r"""(?:\baxios\s*\(\s*\{[^}{]{0,300}?["']?baseURL["']?|\b[a-zA-Z_$][a-zA-Z0-9_$]*\.create\s*\(\s*\{[^}{]{0,300}?["']?baseURL["']?)\s*:\s*["'`](https?://[^"'`\s\\]++|/[^"'`\s\\]*+)["'`]""",
    re.IGNORECASE,
)
AXIOS_DEFAULTS_PATTERN = re.compile(
    r"""\b[a-zA-Z_$][a-zA-Z0-9_$]*\.defaults\.baseURL\s*=\s*["'`](https?://[^"'`\s\\]++|/[^"'`\s\\]*+)["'`]""",
    re.IGNORECASE,
)

# Ky
KY_CREATE_PATTERN = re.compile(
    r"""(?:\bky\.create\s*\(\s*\{[^}{]{0,300}?["']?(?:prefixUrl|prefix|baseUrl|baseURL)["']?|\bprefixUrl)\s*:\s*["'`](https?://[^"'`\s\\]++|/[^"'`\s\\]*+)["'`]""",
    re.IGNORECASE,
)

# ofetch ($fetch / ofetch)
OFETCH_CREATE_PATTERN = re.compile(
    r"""(?:\$fetch|ofetch)\.create\s*\(\s*\{[^}{]{0,300}?["']?baseURL["']?\s*:\s*["'`](https?://[^"'`\s\\]++|/[^"'`\s\\]*+)["'`]""",
    re.IGNORECASE,
)

# Wretch
WRETCH_PATTERN = re.compile(
    r"""\bwretch(?:\s*\(\s*\)|\.url)?\s*\(\s*["'`](https?://[^"'`\s\\]++|/[^"'`\s\\]*+)["'`]""",
    re.IGNORECASE,
)

# tRPC
TRPC_LINK_PATTERN = re.compile(
    r"""\b(?:httpBatchLink|httpLink)\s*\(\s*\{[^}{]{0,300}?["']?url["']?\s*:\s*["'`](https?://[^"'`\s\\]++|/[^"'`\s\\]*+)["'`]""",
    re.IGNORECASE,
)

# Inline Environment Variables
INLINE_ENV_PATTERN = re.compile(
    r"""\b(?:process\.env\.|import\.meta\.env\.)?((?:NEXT_PUBLIC_|VITE_|REACT_APP_)[A-Z0-9_]+)\s*[:=]\s*["'`](https?://[^"'`\s\\]++|/[^"'`\s\\]*+)["'`]""",
    re.IGNORECASE,
)
INLINE_ENV_BRACKET_PATTERN = re.compile(
    r"""(?:process\.env|import\.meta\.env)\[["']((?:NEXT_PUBLIC_|VITE_|REACT_APP_)[A-Z0-9_]+)["']\]\s*=\s*["'`](https?://[^"'`\s\\]++|/[^"'`\s\\]*+)["'`]""",
    re.IGNORECASE,
)


class JSRegexExtractor:
    """
    Static Regex & HTTP Client Harvester.
    Extracts REST API endpoints, client configurations, and Server Actions from JavaScript bundles.
    """

    def __init__(self) -> None:
        pass

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

        # XML / SVG namespaces
        if FP_SVG_XMLNS.search(c):
            return True

        # SVG path command sequences (e.g. M10 20L30 40Z)
        if FP_SVG_PATH.match(c):
            return True

        # Tailwind CSS fractions & opacity
        if FP_TAILWIND_FRACTION.match(c):
            return True
        if FP_TAILWIND_OPACITY.match(c):
            return True
        if FP_PURE_FRACTION_OR_NUMBER.match(c):
            return True

        # MIME types
        if FP_MIME_TYPE.match(c):
            return True

        # UUIDs / GUIDs
        if FP_UUID.match(c):
            return True

        # Dates & Date format strings
        if FP_DATE_FORMAT.match(c):
            return True

        # Compiler / AST node names
        if FP_AST_TOKEN.match(c):
            return True

        # CSS module / BEM class names
        if FP_CSS_MODULE_OR_BEM.match(c):
            return True

        # Base64 data & high-entropy noise
        if c.startswith("data:"):
            return True
        if c.startswith(("/9j/", "9j/", "iVBORw0KGgo", "/iVBORw0KGgo", "PHN2Zy", "/PHN2Zy", "R0lGOD", "UklGR")):
            return True
        if FP_BASE64_DATA.match(c) and (len(c) >= 36 or shannon_entropy(c) > 4.0):
            return True

        # Static assets (images, fonts, stylesheets, source maps)
        path_without_query = c.split("?")[0].split("#")[0]
        if FP_STATIC_ASSET.search(path_without_query):
            return True

        return False

    def _normalize_and_extract_params(
        self, raw_candidate: str
    ) -> Tuple[str, str, List[DiscoveredParameter]]:
        """
        Parses endpoint candidate into (base_url, normalized_path, parameters).
        Normalizes:
        - Express parameters: :id -> {id}
        - Template literals: ${id} -> {id}
        - Next.js dynamic routes: [id] -> {id}, [...slug] -> {slug*}
        - Query string parameters into DiscoveredParameter(location='query')
        """
        # Separate query string
        if "?" in raw_candidate:
            path_part, query_part = raw_candidate.split("?", 1)
        else:
            path_part, query_part = raw_candidate, ""

        # Parse full URL if present
        base_url = ""
        if path_part.startswith(("http://", "https://")):
            parsed = urllib.parse.urlsplit(path_part)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            path_part = parsed.path or "/"

        # Normalize relative path to start with /
        if path_part.startswith("./"):
            path_part = path_part[1:]
        elif path_part.startswith("../"):
            path_part = "/" + path_part.lstrip("./")
        elif not path_part.startswith("/"):
            path_part = "/" + path_part

        parameters: List[DiscoveredParameter] = []
        seen_params: Set[Tuple[str, str]] = set()

        # 1. Express route params: :paramName -> {paramName}
        def replace_express(m: re.Match) -> str:
            name = m.group(1)
            if ("path", name) not in seen_params:
                seen_params.add(("path", name))
                parameters.append(
                    DiscoveredParameter(
                        name=name,
                        location="path",
                        required=True,
                        param_type="string",
                        description="Express path parameter",
                    )
                )
            return f"{{{name}}}"

        norm_path = re.sub(r"(?<=/):([a-zA-Z_][a-zA-Z0-9_]*)", replace_express, path_part)

        # 2. Template literals: ${paramName} or ${user.id} -> {paramName}
        def replace_template(m: re.Match) -> str:
            raw_expr = m.group(1).strip()
            name = raw_expr.split(".")[-1]
            name = re.sub(r"[^a-zA-Z0-9_]", "", name) or "param"
            if ("path", name) not in seen_params:
                seen_params.add(("path", name))
                parameters.append(
                    DiscoveredParameter(
                        name=name,
                        location="path",
                        required=True,
                        param_type="string",
                        description="Template literal path parameter",
                    )
                )
            return f"{{{name}}}"

        norm_path = re.sub(r"\$\{\s*([a-zA-Z0-9_$.]+)\s*\}", replace_template, norm_path)

        # 3. Next.js dynamic routes: [id] or [...slug] -> {id} or {slug*}
        def replace_next(m: re.Match) -> str:
            name = m.group(1)
            is_catch = name.startswith("...")
            clean_name = name[3:] if is_catch else name
            if ("path", clean_name) not in seen_params:
                seen_params.add(("path", clean_name))
                parameters.append(
                    DiscoveredParameter(
                        name=clean_name,
                        location="path",
                        required=not is_catch,
                        param_type="array" if is_catch else "string",
                        description="Next.js dynamic route parameter",
                    )
                )
            return f"{{{clean_name}*}}" if is_catch else f"{{{clean_name}}}"

        norm_path = re.sub(r"\[+([a-zA-Z0-9_\-\.]+)\]+", replace_next, norm_path)

        # 4. OpenAPI / Swagger curly brackets: {id}
        for m in re.finditer(r"\{([a-zA-Z0-9_]+)\}", norm_path):
            name = m.group(1)
            if ("path", name) not in seen_params:
                seen_params.add(("path", name))
                parameters.append(
                    DiscoveredParameter(
                        name=name,
                        location="path",
                        required=True,
                        param_type="string",
                        description="Path parameter",
                    )
                )

        # 5. Query string parameters
        if query_part:
            for q_item in query_part.split("&"):
                if not q_item:
                    continue
                if "=" in q_item:
                    q_name, q_val = q_item.split("=", 1)
                else:
                    q_name, q_val = q_item, None
                q_name = q_name.strip()
                if q_name and ("query", q_name) not in seen_params:
                    seen_params.add(("query", q_name))
                    parameters.append(
                        DiscoveredParameter(
                            name=q_name,
                            location="query",
                            required=False,
                            example=q_val,
                            param_type="string",
                            description="Query string parameter",
                        )
                    )

        final_path = f"{norm_path}?{query_part}" if query_part else norm_path
        return base_url, final_path, parameters

    def _detect_http_method(self, js_code: str, match_start: int, match_end: int) -> str:
        """
        Infers HTTP method (GET, POST, PUT, DELETE, PATCH, etc.) from caller context.
        Inspects pre-match call syntax (e.g. axios.post() or ky.get()) and post-match options.
        """
        pre_window = js_code[max(0, match_start - 80):match_start]
        post_window = js_code[match_end:min(len(js_code), match_end + 100)]

        # Pre-match method call: .post(, .get(, ky.post(, etc.
        m_pre = re.search(r"\.(get|post|put|delete|patch|head|options)\s*\(\s*$", pre_window, re.IGNORECASE)
        if m_pre:
            return m_pre.group(1).upper()

        # Post-match method chaining: wretch(...).post(
        m_post_chain = re.search(r"^\s*\)\s*\.\s*(get|post|put|delete|patch|head|options)\s*\(", post_window, re.IGNORECASE)
        if m_post_chain:
            return m_post_chain.group(1).upper()

        # Post-match options object: fetch('/api', { method: 'POST' })
        m_post_opt = re.search(r"^[^);]{0,100}?method\s*:\s*['\"](GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)['\"]", post_window, re.IGNORECASE)
        if m_post_opt:
            return m_post_opt.group(1).upper()

        return "GET"

    def extract_endpoints(self, js_code: str, base_url: str = "") -> List[DiscoveredEndpoint]:
        """
        Scans JavaScript code for REST endpoint candidates:
        - Scans for /api/..., /v1/..., relative paths, full http/https URLs.
        - Normalizes path parameters (:id -> {id}, ${id} -> {id}, [id] -> {id}).
        - Extracts query parameters into DiscoveredParameter(location='query').
        - Filters false positives (SVG paths, Tailwind classes, MIME types, dates, UUIDs, base64 noise).
        - Infers HTTP method from surrounding context.
        """
        if not js_code:
            return []

        endpoints: List[DiscoveredEndpoint] = []
        seen_endpoints: Set[Tuple[str, str, str]] = set()

        for match in ENDPOINT_CANDIDATE_PATTERN.finditer(js_code):
            raw_endpoint = match.group("sq") or match.group("dq") or match.group("bt")
            if not raw_endpoint:
                continue

            # Run multi-stage false-positive filter
            if self.is_false_positive(raw_endpoint):
                continue

            extracted_base, norm_path, params = self._normalize_and_extract_params(raw_endpoint)

            # Determine base URL: full URL extracted takes precedence over provided base_url
            resolved_base = extracted_base or base_url.rstrip("/")

            # Infer HTTP method from calling context
            method = self._detect_http_method(js_code, match.start(), match.end())

            endpoint_key = (norm_path, method, resolved_base)
            if endpoint_key in seen_endpoints:
                continue
            seen_endpoints.add(endpoint_key)

            endpoints.append(
                DiscoveredEndpoint(
                    path=norm_path,
                    method=method,
                    base_url=resolved_base,
                    source="static_js",
                    tags=["static_regex"],
                    parameters=params,
                    summary=f"Extracted REST endpoint: {norm_path}",
                )
            )

        return endpoints

    def extract_client_configs(self, js_code: str) -> Dict[str, Any]:
        """
        Discovers base URLs from Axios, Ky, ofetch, Wretch, tRPC, and inlined env variables.
        Returns a dictionary with base URLs and framework-specific breakdowns.
        """
        if not js_code:
            return {
                "base_urls": [],
                "axios": [],
                "ky": [],
                "ofetch": [],
                "wretch": [],
                "trpc": [],
                "env_vars": {},
            }

        # 1. Axios instances and defaults
        axios_urls: List[str] = []
        for url in AXIOS_CREATE_PATTERN.findall(js_code):
            if url and not self.is_false_positive(url) and url not in axios_urls:
                axios_urls.append(url)
        for url in AXIOS_DEFAULTS_PATTERN.findall(js_code):
            if url and not self.is_false_positive(url) and url not in axios_urls:
                axios_urls.append(url)

        # 2. Ky instances
        ky_urls: List[str] = []
        for url in KY_CREATE_PATTERN.findall(js_code):
            if url and not self.is_false_positive(url) and url not in ky_urls:
                ky_urls.append(url)

        # 3. ofetch instances
        ofetch_urls: List[str] = []
        for url in OFETCH_CREATE_PATTERN.findall(js_code):
            if url and not self.is_false_positive(url) and url not in ofetch_urls:
                ofetch_urls.append(url)

        # 4. Wretch instances
        wretch_urls: List[str] = []
        for url in WRETCH_PATTERN.findall(js_code):
            if url and not self.is_false_positive(url) and url not in wretch_urls:
                wretch_urls.append(url)

        # 5. tRPC link URLs
        trpc_urls: List[str] = []
        for url in TRPC_LINK_PATTERN.findall(js_code):
            if url and not self.is_false_positive(url) and url not in trpc_urls:
                trpc_urls.append(url)

        # 6. Inlined environment variables
        env_vars: Dict[str, str] = {}
        for var_name, var_val in INLINE_ENV_PATTERN.findall(js_code):
            if var_val and not self.is_false_positive(var_val):
                env_vars[var_name] = var_val
        for var_name, var_val in INLINE_ENV_BRACKET_PATTERN.findall(js_code):
            if var_val and not self.is_false_positive(var_val):
                env_vars[var_name] = var_val

        # Aggregate all unique discovered base URLs
        base_urls: List[str] = []
        all_candidates = (
            axios_urls
            + ky_urls
            + ofetch_urls
            + wretch_urls
            + trpc_urls
            + list(env_vars.values())
        )
        for candidate in all_candidates:
            if candidate not in base_urls:
                base_urls.append(candidate)

        return {
            "base_urls": base_urls,
            "axios": axios_urls,
            "ky": ky_urls,
            "ofetch": ofetch_urls,
            "wretch": wretch_urls,
            "trpc": trpc_urls,
            "env_vars": env_vars,
        }

    def extract_server_actions(
        self, js_code: str, page_route: str = ""
    ) -> List[DiscoveredEndpoint]:
        """
        Discovers Next.js Server Action references (createServerReference),
        extracts 40-character hex action IDs, and emits:
        DiscoveredEndpoint(path=page_route, method='POST', headers={'Next-Action': action_id})
        """
        if not js_code:
            return []

        server_actions: List[DiscoveredEndpoint] = []
        seen_action_ids: Set[str] = set()

        for match in NEXT_SERVER_ACTION_PATTERN.finditer(js_code):
            action_id = match.group(1)
            if action_id in seen_action_ids:
                continue
            seen_action_ids.add(action_id)

            server_actions.append(
                DiscoveredEndpoint(
                    path=page_route,
                    method="POST",
                    source="static_js",
                    tags=["server_action", "nextjs"],
                    headers={"Next-Action": action_id},
                    summary=f"Next.js Server Action: {action_id}",
                    description=f"Server Action invoked via Next-Action header on route '{page_route}'",
                )
            )

        return server_actions
