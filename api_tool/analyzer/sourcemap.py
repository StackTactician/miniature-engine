"""
Source Map Unpacker and Extractor Module for api-tool.
Handles Source Map V3 specifications, Index Maps (sections format),
bundler-specific source paths, strict path traversal / Zip Slip sanitization,
inline Data URI decoding, candidate map probing for hidden-source-map deployments,
and safe in-memory extraction with low memory footprint (<10MB RAM).
"""

from __future__ import annotations

import base64
import json
import logging
import os
import posixpath
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import unquote, urljoin, urlsplit, urlunsplit

import httpx

from api_tool.models import DiscoveredEndpoint, DiscoveredParameter

logger = logging.getLogger(__name__)

# Windows reserved device names to prevent device collision and Zip Slip
WINDOWS_RESERVED_NAMES: Set[str] = {
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
}

# Regex to detect sourceMappingURL comment in JavaScript
# Supports //# and /*# as well as legacy //@ and /*@
SOURCEMAP_COMMENT_REGEX = re.compile(
    r"""(?://[#@]\s*sourceMappingURL=([^\s\r\n]+)|/\*[#@]\s*sourceMappingURL=([^\s*]+)\s*\*/)"""
)

# Regex for route detection from source paths
NEXT_APP_ROUTE_REGEX = re.compile(
    r"""(?:^|/)(?:src/)?app/(.+)/route\.[jt]sx?$""",
    re.IGNORECASE,
)
NEXT_PAGE_ROUTE_REGEX = re.compile(
    r"""(?:^|/)(?:src/)?pages/(api/.+)\.[jt]sx?$""",
    re.IGNORECASE,
)
NUXT_SERVER_ROUTE_REGEX = re.compile(
    r"""(?:^|/)(?:src/)?server/(api/.+)\.[jt]sx?$""",
    re.IGNORECASE,
)
SVELTE_SERVER_ROUTE_REGEX = re.compile(
    r"""(?:^|/)(?:src/)?routes/(.+)/\+server\.[jt]sx?$""",
    re.IGNORECASE,
)

# HTTP method export detection in route files
HTTP_METHOD_EXPORT_REGEX = re.compile(
    r"""\bexport\s+(?:async\s+)?(?:function|const|let|var)\s+(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\b"""
)


def sanitize_source_path(raw_path: str) -> str:
    """
    Strict path sanitization preventing directory traversal and Zip Slip attacks.
    - Strips bundler virtual prefixes (webpack:///, turbopack:///[project]/, vite://, ng:///, etc.)
    - Removes null bytes and non-printable control characters
    - Performs multi-pass URL decoding to neutralize encoded traversal (%2e%2e%2f)
    - Strips Windows drive letters (C:/, D:/) and backslashes
    - Filters out '..' and '.' traversal segments
    - Neutralizes Windows reserved device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9)
    - Strips loader query parameters and hash anchors (?vue, #anchor)
    - Enforces canonical relative path constraint
    """
    if not raw_path or not isinstance(raw_path, str):
        return ""

    # 1. Multi-pass URL decode (up to 3 times to unwrap double-encoded sequences like %252e%252e or %00)
    cleaned = raw_path
    for _ in range(3):
        unquoted = unquote(cleaned)
        if unquoted == cleaned:
            break
        cleaned = unquoted

    # 2. Strip null bytes & control chars (< 32, == 127) AFTER URL decoding
    cleaned = "".join(c for c in cleaned if ord(c) >= 32 and ord(c) != 127)

    # 3. Strip bundler virtual protocol schemes (e.g. webpack:///, turbopack:///, vite://, ng:///, file:///)
    cleaned = re.sub(
        r"^(?:webpack-internal|webpack|turbopack|vite|rollup|parcel|esbuild|meteor|deno|ng|file|https?|app|project|sourcemap):/+",
        "",
        cleaned,
        flags=re.IGNORECASE,
    )

    # Strip Next.js & Turbopack virtual tokens
    cleaned = re.sub(r"^\[project\][/\\]*", "", cleaned)
    cleaned = re.sub(r"^_N_E[/\\]*", "", cleaned)
    cleaned = re.sub(r"^\(webpack\)[/\\]*", "", cleaned)

    # 4. Strip loader queries and hash anchors (e.g. App.vue?vue&type=script)
    cleaned = cleaned.split("?")[0].split("#")[0]

    # 5. Normalize backslashes to forward slashes
    cleaned = cleaned.replace("\\", "/")

    # 6. Strip Windows drive letters (C:, D:, etc.) and any leading slashes (e.g. /C:/Windows)
    cleaned = cleaned.lstrip("/")
    cleaned = re.sub(r"^[a-zA-Z]:[/]*", "", cleaned)
    cleaned = cleaned.lstrip("/")

    # 7. Tokenize path components and sanitize each segment
    parts = cleaned.split("/")
    safe_parts = []
    for part in parts:
        part = part.strip()
        # Strip trailing dots and spaces (Windows directory bypass trick: 'file.txt.')
        part = part.rstrip(". ")
        if not part or part == "." or part == "..":
            continue
        if all(c == "." for c in part):
            continue

        # Check Windows reserved device names
        stem = part.split(".")[0].upper()
        if stem in WINDOWS_RESERVED_NAMES:
            part = f"_{part}"

        safe_parts.append(part)

    sanitized = "/".join(safe_parts)
    if not sanitized:
        return ""

    # Final canonical verification: posixpath normalized form must not escape
    norm = posixpath.normpath(sanitized)
    if norm.startswith("..") or norm.startswith("/"):
        return ""

    return norm


@dataclass
class SourceMapFile:
    """Represents a single original source file extracted from a Source Map."""
    path: str  # Sanitized, safe relative path
    original_path: str  # Original unsanitized path as listed in source map
    content: Optional[str] = None  # Verbatim source code from sourcesContent
    size: int = 0  # Byte size of content
    extension: str = ""  # File extension (e.g. .ts, .tsx, .js)
    is_node_modules: bool = False  # True if vendor / third-party library
    framework: Optional[str] = None  # Detected framework / bundler
    source_map_url: Optional[str] = None  # Source map URL or origin

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "original_path": self.original_path,
            "content": self.content,
            "size": self.size,
            "extension": self.extension,
            "is_node_modules": self.is_node_modules,
            "framework": self.framework,
            "source_map_url": self.source_map_url,
        }


class SourceMapReference(str):
    """
    Represents a reference found in a JavaScript comment.
    Inherits from str so it can be evaluated directly as a string URL or content,
    while also providing structured attributes and dict/tuple access.
    """
    url: Optional[str]
    inline_json: Optional[str]
    is_inline: bool
    raw_reference: str

    def __new__(
        cls,
        val: str,
        url: Optional[str] = None,
        inline_json: Optional[str] = None,
        is_inline: bool = False,
        raw_reference: str = "",
    ):
        obj = super().__new__(cls, val or "")
        obj.url = url
        obj.inline_json = inline_json
        obj.is_inline = is_inline
        obj.raw_reference = raw_reference
        return obj

    def __getitem__(self, item: Any) -> Any:
        if isinstance(item, str):
            if item == "url":
                return self.url
            if item in ("inline_json", "inline_data", "data"):
                return self.inline_json
            if item == "is_inline":
                return self.is_inline
            if item == "raw_reference":
                return self.raw_reference
            raise KeyError(item)
        return super().__getitem__(item)

    def __iter__(self):
        """Allows unpacking as (url, inline_json) tuple if desired."""
        yield self.url
        yield self.inline_json

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, str):
            return str(self) == other or self.url == other or self.inline_json == other
        return super().__eq__(other)


@dataclass
class SourceMapResult:
    """Represents the complete result of unpacking a Source Map."""
    js_url: Optional[str] = None
    map_url: Optional[str] = None
    discovery_source: str = "unknown"  # "inline", "comment", "probe", "none"
    framework: Optional[str] = None  # "turbopack", "webpack", "vite", "nextjs", etc.
    files: List[SourceMapFile] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    endpoints: List[DiscoveredEndpoint] = field(default_factory=list)
    unresolved_sections: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    raw_metadata: Dict[str, Any] = field(default_factory=dict)

    def get_file(self, path: str) -> Optional[SourceMapFile]:
        """Look up a file by sanitized path or original path."""
        for f in self.files:
            if f.path == path or f.original_path == path:
                return f
        return None

    def get_application_files(self) -> List[SourceMapFile]:
        """Returns only first-party application files (excluding node_modules)."""
        return [f for f in self.files if not f.is_node_modules]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "js_url": self.js_url,
            "map_url": self.map_url,
            "discovery_source": self.discovery_source,
            "framework": self.framework,
            "files_count": len(self.files),
            "sources": self.sources,
            "endpoints": [e.to_dict() for e in self.endpoints],
            "unresolved_sections": self.unresolved_sections,
            "errors": self.errors,
            "raw_metadata": self.raw_metadata,
        }

    def save_to_disk(
        self,
        output_dir: str,
        include_node_modules: bool = False,
        overwrite: bool = True,
    ) -> List[str]:
        """
        Safely extracts original unminified files to disk with strict canonical path checking.
        Prevents Zip Slip / Path Traversal vulnerabilities.
        Returns list of written absolute file paths.
        """
        written_files: List[str] = []
        safe_root = os.path.realpath(os.path.abspath(output_dir))
        os.makedirs(safe_root, exist_ok=True)

        for file_entry in self.files:
            if not include_node_modules and file_entry.is_node_modules:
                continue
            if file_entry.content is None:
                continue
            if not file_entry.path or file_entry.path.strip() in ("", ".", "./", "/"):
                continue

            # Verify canonical destination path
            target_path = os.path.realpath(os.path.join(safe_root, file_entry.path))
            if target_path == safe_root:
                continue

            if os.path.commonpath([safe_root, target_path]) != safe_root:
                raise ValueError(
                    f"Security Exception: Path traversal attempt prevented for '{file_entry.path}' -> '{target_path}'"
                )

            if not overwrite and os.path.exists(target_path):
                continue

            os.makedirs(os.path.dirname(target_path), exist_ok=True)
            with open(target_path, "w", encoding="utf-8", errors="replace") as f:
                f.write(file_entry.content)
            written_files.append(target_path)

        return written_files


class SourceMapUnpacker:
    """
    Source Map Unpacker for Source Map V3 and Index Maps (ECMA-426).
    Designed for memory-constrained environments (Termux / Linux) with low RAM footprint (<10MB).
    """

    def __init__(
        self,
        request_timeout: float = 15.0,
        user_agent: Optional[str] = None,
        max_file_size: int = 50 * 1024 * 1024,
    ) -> None:
        self.request_timeout = request_timeout
        self.user_agent = user_agent or (
            "Mozilla/5.0 (Linux; Android 10; Mobile) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36 api-tool/0.1.0"
        )
        self.max_file_size = max_file_size

    @staticmethod
    def _strip_large_mappings(json_str: str) -> str:
        """
        Memory optimization: strips out the massive 'mappings' string from large JSON source maps
        prior to parsing with json.loads.
        In 10MB+ source maps, 'mappings' accounts for 80-95% of the file size but is not needed
        for unpacking sourcesContent. Stripping it cuts RAM usage to under a few megabytes.
        """
        if len(json_str) < 100_000 or '"mappings"' not in json_str:
            return json_str

        pos = 0
        pieces = []
        last_end = 0
        str_len = len(json_str)

        while pos < str_len:
            m = json_str.find('"mappings"', pos)
            if m == -1:
                break
            colon = json_str.find(":", m + 10)
            if colon == -1:
                break

            # Find opening quote of mappings value
            quote_start = -1
            for i in range(colon + 1, min(colon + 50, str_len)):
                ch = json_str[i]
                if ch == '"':
                    quote_start = i
                    break
                elif not ch.isspace():
                    break

            if quote_start == -1:
                pos = colon + 1
                continue

            # Find closing quote of mappings value
            scan_pos = quote_start + 1
            quote_end = -1
            while scan_pos < str_len:
                candidate = json_str.find('"', scan_pos)
                if candidate == -1:
                    break
                # Check for escaped backslash
                bs_count = 0
                k = candidate - 1
                while k >= quote_start + 1 and json_str[k] == "\\":
                    bs_count += 1
                    k -= 1
                if bs_count % 2 == 0:
                    quote_end = candidate
                    break
                scan_pos = candidate + 1

            if quote_end != -1:
                pieces.append(json_str[last_end:quote_start + 1])
                last_end = quote_end
                pos = quote_end + 1
            else:
                pos = quote_start + 1

        if last_end < str_len:
            pieces.append(json_str[last_end:])

        return "".join(pieces)

    @staticmethod
    def _detect_framework_from_path(path: str) -> Optional[str]:
        """Detects bundler / framework signature from a raw source path."""
        p_lower = path.lower()
        if "turbopack://" in p_lower or "[project]" in p_lower:
            return "turbopack"
        if "webpack://" in p_lower or "webpack-internal://" in p_lower:
            return "webpack"
        if "vite://" in p_lower or "/@fs/" in p_lower or "/@id/" in p_lower:
            return "vite"
        if "ng://" in p_lower or "angular" in p_lower:
            return "angular"
        if "_next/" in p_lower or "_n_e" in p_lower:
            return "nextjs"
        if "_nuxt/" in p_lower or ".nuxt/" in p_lower:
            return "nuxt"
        if ".svelte" in p_lower or "_app/immutable/" in p_lower:
            return "svelte"
        if "esbuild://" in p_lower:
            return "esbuild"
        if "rollup://" in p_lower:
            return "rollup"
        return None

    def _detect_overall_framework(
        self,
        sources: List[str],
        base_url: str = "",
        raw_metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """Determines the primary framework / bundler of a source map."""
        if base_url:
            b_lower = base_url.lower()
            if "_next/" in b_lower:
                return "nextjs"
            if "_nuxt/" in b_lower:
                return "nuxt"
            if "_app/immutable/" in b_lower:
                return "sveltekit"

        for s in sources:
            fw = self._detect_framework_from_path(s)
            if fw:
                return fw

        return None

    def _convert_source_routes_to_endpoints(
        self,
        files: List[SourceMapFile],
        base_url: str = "",
    ) -> List[DiscoveredEndpoint]:
        """
        Discovers API endpoints from route file conventions in unpacked source maps:
        - Next.js App Router: app/api/.../route.ts
        - Next.js Pages Router: pages/api/...ts
        - Nuxt.js Server Routes: server/api/...ts
        - SvelteKit Server Routes: routes/api/.../+server.ts
        """
        endpoints: List[DiscoveredEndpoint] = []
        seen_endpoints: Set[Tuple[str, str]] = set()

        for f in files:
            p = f.path
            route_path = None

            # 1. Next.js App Router: app/api/.../route.ts
            m_app = NEXT_APP_ROUTE_REGEX.search(p)
            if m_app:
                raw_route = m_app.group(1)
                # Strip route groups like (dashboard), (auth)
                segments = [s for s in raw_route.split("/") if not (s.startswith("(") and s.endswith(")"))]
                route_path = "/" + "/".join(segments)

            # 2. Next.js Pages Router: pages/api/...ts
            if not route_path:
                m_page = NEXT_PAGE_ROUTE_REGEX.search(p)
                if m_page:
                    route_path = "/" + m_page.group(1)

            # 3. Nuxt server routes: server/api/...ts
            if not route_path:
                m_nuxt = NUXT_SERVER_ROUTE_REGEX.search(p)
                if m_nuxt:
                    route_path = "/" + m_nuxt.group(1)

            # 4. SvelteKit server routes: routes/api/.../+server.ts
            if not route_path:
                m_svelte = SVELTE_SERVER_ROUTE_REGEX.search(p)
                if m_svelte:
                    route_path = "/" + m_svelte.group(1)

            if not route_path:
                continue

            # Convert dynamic params [param] -> {param} and extract parameter objects
            parameters: List[DiscoveredParameter] = []

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
                        description="Route parameter extracted from source map",
                    )
                )
                if is_catch_all:
                    return f"{{{param_name}*}}"
                return f"{{{param_name}}}"

            normalized_path = re.sub(r"\[+([a-zA-Z0-9_\-\.]+)\]+", replace_param, route_path)

            # Detect HTTP methods from file exports
            detected_methods = []
            if f.content:
                detected_methods = HTTP_METHOD_EXPORT_REGEX.findall(f.content)

            if not detected_methods:
                detected_methods = ["GET"]
            else:
                detected_methods = sorted(list(set(detected_methods)))

            for method in detected_methods:
                key = (normalized_path, method)
                if key in seen_endpoints:
                    continue
                seen_endpoints.add(key)

                endpoints.append(
                    DiscoveredEndpoint(
                        path=normalized_path,
                        method=method,
                        base_url=base_url,
                        source="sourcemap",
                        tags=[f.framework or "sourcemap"],
                        parameters=parameters,
                        summary=f"Discovered from source map file: {f.path}",
                    )
                )

        return endpoints

    def extract_from_json(
        self,
        map_json_str_or_dict: Union[str, bytes, Dict[str, Any]],
        base_source_url: str = "",
    ) -> SourceMapResult:
        """
        Parses a Source Map V3 or Index Map JSON document and extracts all original files.
        Accepts dict, str, or bytes. Applies memory optimization and strict path sanitization.
        """
        result = SourceMapResult(map_url=base_source_url or None)

        # Parse JSON input
        data: Dict[str, Any] = {}
        if isinstance(map_json_str_or_dict, bytes):
            map_json_str_or_dict = map_json_str_or_dict.decode("utf-8", errors="replace")

        if isinstance(map_json_str_or_dict, str):
            # Apply memory-safe mappings stripping for large files
            stripped_json = self._strip_large_mappings(map_json_str_or_dict)
            try:
                data = json.loads(stripped_json)
            except Exception as e:
                result.errors.append(f"Failed to parse source map JSON: {e}")
                return result
        elif isinstance(map_json_str_or_dict, dict):
            data = map_json_str_or_dict
        else:
            result.errors.append(f"Unsupported map data type: {type(map_json_str_or_dict).__name__}")
            return result

        if not isinstance(data, dict):
            result.errors.append(f"Invalid source map format: expected JSON object root, got {type(data).__name__}")
            return result

        result.raw_metadata = {
            "version": data.get("version"),
            "file": data.get("file"),
            "sourceRoot": data.get("sourceRoot"),
        }

        # 1. Handle Index Maps (sections format)
        sections = data.get("sections")
        if isinstance(sections, list):
            for sec in sections:
                if not isinstance(sec, dict):
                    continue

                # A. Inline section map
                if "map" in sec and isinstance(sec["map"], dict):
                    child_result = self.extract_from_json(sec["map"], base_source_url=base_source_url)
                    # Merge files and sources
                    existing_paths = {f.path for f in result.files}
                    for f in child_result.files:
                        if f.path not in existing_paths:
                            result.files.append(f)
                            existing_paths.add(f.path)
                        else:
                            existing = result.get_file(f.path)
                            if existing and existing.content is None and f.content is not None:
                                existing.content = f.content
                                existing.size = f.size

                    for s in child_result.sources:
                        if s not in result.sources:
                            result.sources.append(s)

                    result.unresolved_sections.extend(child_result.unresolved_sections)
                    result.errors.extend(child_result.errors)

                # B. External section map URL
                elif "url" in sec and isinstance(sec["url"], str):
                    sec_url = sec["url"]
                    if base_source_url:
                        sec_url = urljoin(base_source_url, sec_url)
                    result.unresolved_sections.append(sec_url)

        # 2. Handle standard Source Map V3
        sources = data.get("sources")
        if isinstance(sources, list):
            sources_content = data.get("sourcesContent")
            source_root = data.get("sourceRoot") or ""

            # Detect framework
            raw_sources_list = [s for s in sources if isinstance(s, str)]
            result.framework = self._detect_overall_framework(
                raw_sources_list,
                base_url=base_source_url,
                raw_metadata=result.raw_metadata,
            )

            files_by_path: Dict[str, SourceMapFile] = {}

            for i, raw_src in enumerate(sources):
                if not isinstance(raw_src, str):
                    continue

                # Prepend sourceRoot if non-empty and raw_src is relative
                full_src = raw_src
                if source_root and not raw_src.startswith(("/", "http://", "https://", "webpack://", "turbopack://")):
                    if source_root.endswith("/"):
                        full_src = f"{source_root}{raw_src}"
                    else:
                        full_src = f"{source_root}/{raw_src}"

                # Strict path sanitization preventing Zip Slip / path traversal
                clean_path = sanitize_source_path(full_src)
                if not clean_path:
                    continue

                content = None
                if isinstance(sources_content, list) and i < len(sources_content):
                    raw_content = sources_content[i]
                    if isinstance(raw_content, str):
                        content = raw_content

                fw = self._detect_framework_from_path(raw_src) or result.framework
                is_vendor = (
                    "node_modules/" in clean_path
                    or clean_path.startswith("node_modules")
                    or "/vendor/" in clean_path
                )

                file_entry = SourceMapFile(
                    path=clean_path,
                    original_path=raw_src,
                    content=content,
                    size=len(content.encode("utf-8")) if content is not None else 0,
                    extension=posixpath.splitext(clean_path)[1].lower(),
                    is_node_modules=is_vendor,
                    framework=fw,
                    source_map_url=base_source_url or None,
                )

                if clean_path not in files_by_path:
                    files_by_path[clean_path] = file_entry
                else:
                    # Update content if existing entry had no content
                    if files_by_path[clean_path].content is None and content is not None:
                        files_by_path[clean_path].content = content
                        files_by_path[clean_path].size = file_entry.size

            result.files = list(files_by_path.values())
            result.sources = [f.path for f in result.files]

        # Extract API endpoints from discovered source route files
        result.endpoints = self._convert_source_routes_to_endpoints(
            result.files,
            base_url=base_source_url,
        )

        return result

    def extract_from_js(
        self,
        js_code: str,
        base_url: str = "",
    ) -> Optional[SourceMapReference]:
        """
        Detects source map references in JavaScript code:
        - Detects //# sourceMappingURL= or /*# sourceMappingURL=*/
        - Base64-decodes inline Data URIs (data:application/json;base64,...)
        - Resolves relative or absolute URLs against base_url
        Returns a SourceMapReference or None.
        """
        if not js_code or not isinstance(js_code, str):
            return None

        matches = list(SOURCEMAP_COMMENT_REGEX.finditer(js_code))
        if not matches:
            return None

        # Take the last match in the file (standard bundler output convention)
        last_match = matches[-1]
        raw_ref = (last_match.group(1) or last_match.group(2) or "").strip()
        if not raw_ref:
            return None

        # Case 1: Inline Data URI
        if raw_ref.startswith("data:"):
            header, sep, payload = raw_ref.partition(",")
            if not sep:
                return None

            try:
                if ";base64" in header.lower():
                    decoded_bytes = base64.b64decode(payload.strip())
                    decoded_str = decoded_bytes.decode("utf-8", errors="replace")
                else:
                    decoded_str = unquote(payload.strip())

                return SourceMapReference(
                    val=decoded_str,
                    url=None,
                    inline_json=decoded_str,
                    is_inline=True,
                    raw_reference=raw_ref,
                )
            except Exception as e:
                logger.debug("Failed decoding inline data URI: %s", e)
                return None

        # Case 2: URL reference
        if base_url:
            resolved_url = urljoin(base_url, raw_ref)
        else:
            resolved_url = raw_ref

        return SourceMapReference(
            val=resolved_url,
            url=resolved_url,
            inline_json=None,
            is_inline=False,
            raw_reference=raw_ref,
        )

    def probe_map_urls(self, js_url: str) -> List[str]:
        """
        Generates candidate map URLs for 'hidden-source-map' deployments
        (where maps exist on the server but reference comments were stripped).
        Supports Webpack 5, Vite 5/6, Next.js 14/15 chunk conventions, and standard layouts.
        """
        if not js_url or not isinstance(js_url, str):
            return []

        parsed = urlsplit(js_url)
        clean_path = parsed.path
        clean_url = urlunsplit((parsed.scheme, parsed.netloc, clean_path, "", ""))
        candidates: List[str] = []

        # 1. Direct .map appended
        candidates.append(f"{clean_url}.map")

        # 2. Replace .js extension with .map
        if clean_path.endswith(".js"):
            candidates.append(f"{clean_url[:-3]}.map")
            if clean_path.endswith(".min.js"):
                candidates.append(f"{clean_url[:-7]}.js.map")
                candidates.append(f"{clean_url[:-7]}.map")

        # 3. Next.js / bundler hash stripping
        filename = posixpath.basename(clean_path)
        parent_dir = posixpath.dirname(clean_path)
        parent_url = urlunsplit((parsed.scheme, parsed.netloc, parent_dir, "", ""))

        # Next.js chunks: e.g. dashboard-c0ffee1234abcd.js -> dashboard.js.map
        hash_match = re.search(r"^(.*?)[.-][a-f0-9]{8,64}(\.min)?\.js$", filename, re.IGNORECASE)
        if hash_match:
            stem = hash_match.group(1)
            candidates.append(f"{parent_url}/{stem}.js.map")
            candidates.append(f"{parent_url}/{stem}.map")

        # 4. Sibling directory conventions
        candidates.append(f"{parent_url}/maps/{filename}.map")
        candidates.append(f"{parent_url}/sourcemaps/{filename}.map")

        # 5. Root directory conventions
        candidates.append(f"{parsed.scheme}://{parsed.netloc}/maps/{filename}.map")
        candidates.append(f"{parsed.scheme}://{parsed.netloc}/sourcemaps/{filename}.map")

        # 6. Include original query string as secondary fallback
        if parsed.query:
            candidates.append(f"{clean_url}.map?{parsed.query}")

        # Deduplicate preserving order
        seen: Set[str] = set()
        deduped: List[str] = []
        for c in candidates:
            if c not in seen and c != js_url:
                seen.add(c)
                deduped.append(c)

        return deduped

    @staticmethod
    def _is_html_response(resp: httpx.Response) -> bool:
        """Checks if HTTP response is an HTML page (e.g. 404/SPA fallback)."""
        ct = resp.headers.get("content-type", "").lower()
        if "text/html" in ct or "application/xhtml+xml" in ct:
            return True
        snippet = resp.text[:200].lstrip().lower()
        return snippet.startswith("<!doctype html") or snippet.startswith("<html")

    @staticmethod
    def _is_plausible_source_map(text: str) -> bool:
        """Validates that a string has JSON structure and source map indicators."""
        snippet = text.lstrip()[:400]
        if not snippet.startswith("{"):
            return False
        return any(k in snippet for k in ('"version"', '"sources"', '"sections"', '"mappings"'))

    async def _resolve_child_sections(
        self,
        result: SourceMapResult,
        client: httpx.AsyncClient,
        max_sections: int = 15,
    ) -> None:
        """Recursively resolves external section URLs in Index Maps."""
        if not result.unresolved_sections:
            return

        to_resolve = list(result.unresolved_sections[:max_sections])
        for sec_url in to_resolve:
            try:
                resp = await client.get(sec_url)
                if resp.status_code == 200 and not self._is_html_response(resp):
                    child_res = self.extract_from_json(resp.text, base_source_url=sec_url)
                    existing_paths = {f.path for f in result.files}
                    for f in child_res.files:
                        if f.path not in existing_paths:
                            result.files.append(f)
                            existing_paths.add(f.path)
                        else:
                            existing = result.get_file(f.path)
                            if existing and existing.content is None and f.content is not None:
                                existing.content = f.content
                                existing.size = f.size

                    for s in child_res.sources:
                        if s not in result.sources:
                            result.sources.append(s)

                    result.endpoints.extend(child_res.endpoints)
                    if sec_url in result.unresolved_sections:
                        result.unresolved_sections.remove(sec_url)
            except Exception as e:
                result.errors.append(f"Failed to fetch section map from {sec_url}: {e}")

    async def fetch_and_unpack(
        self,
        js_url: str,
        js_content: Optional[str] = None,
        client: Optional[httpx.AsyncClient] = None,
    ) -> SourceMapResult:
        """
        Fetches the JS bundle or uses provided content.
        1. Checks for inline Data URI source maps.
        2. Checks for sourceMappingURL comment URL and fetches it.
        3. Probes candidate map URLs for hidden-source-map deployments.
        Decodes and extracts all original unminified files in-memory without mandatory disk writes.
        """
        close_client = False
        c = client
        if c is None:
            c = httpx.AsyncClient(
                timeout=httpx.Timeout(self.request_timeout),
                follow_redirects=True,
                verify=False,
                headers={
                    "User-Agent": self.user_agent,
                    "Accept": "*/*",
                },
            )
            close_client = True

        errors: List[str] = []

        try:
            # 1. Fetch JS content if not provided
            if js_content is None:
                try:
                    resp = await c.get(js_url)
                    if resp.status_code != 200:
                        return SourceMapResult(
                            js_url=js_url,
                            errors=[f"Failed to fetch JavaScript bundle: HTTP {resp.status_code}"],
                        )
                    js_content = resp.text
                except Exception as e:
                    return SourceMapResult(
                        js_url=js_url,
                        errors=[f"Exception fetching JavaScript bundle from {js_url}: {e}"],
                    )

            # 2. Detect source map reference in JS
            ref = self.extract_from_js(js_content, base_url=js_url)

            # 3. Handle inline Data URI
            if ref and ref.is_inline and ref.inline_json:
                result = self.extract_from_json(ref.inline_json, base_source_url=js_url)
                result.js_url = js_url
                result.map_url = "inline"
                result.discovery_source = "inline"
                if result.unresolved_sections:
                    await self._resolve_child_sections(result, c)
                return result

            # 4. Handle comment URL
            if ref and ref.url:
                try:
                    map_resp = await c.get(ref.url)
                    if map_resp.status_code == 200 and not self._is_html_response(map_resp):
                        if self._is_plausible_source_map(map_resp.text):
                            result = self.extract_from_json(map_resp.text, base_source_url=ref.url)
                            result.js_url = js_url
                            result.map_url = ref.url
                            result.discovery_source = "comment"
                            if result.unresolved_sections:
                                await self._resolve_child_sections(result, c)
                            return result
                        else:
                            errors.append(f"Content from {ref.url} is not a valid source map JSON")
                    else:
                        errors.append(f"Comment URL {ref.url} returned HTTP {map_resp.status_code}")
                except Exception as e:
                    errors.append(f"Failed to fetch comment source map from {ref.url}: {e}")

            # 5. Probe candidate map URLs for hidden-source-map deployments
            candidate_urls = self.probe_map_urls(js_url)
            for cand_url in candidate_urls:
                if ref and cand_url == ref.url:
                    continue  # Already attempted
                try:
                    probe_resp = await c.get(cand_url)
                    if probe_resp.status_code == 200 and not self._is_html_response(probe_resp):
                        if self._is_plausible_source_map(probe_resp.text):
                            result = self.extract_from_json(probe_resp.text, base_source_url=cand_url)
                            result.js_url = js_url
                            result.map_url = cand_url
                            result.discovery_source = "probe"
                            if result.unresolved_sections:
                                await self._resolve_child_sections(result, c)
                            return result
                except Exception as e:
                    logger.debug("Probe failed for %s: %s", cand_url, e)

            return SourceMapResult(
                js_url=js_url,
                discovery_source="none",
                errors=errors or ["No accessible source map found via inline comment, remote reference, or probing."],
            )

        finally:
            if close_client:
                await c.aclose()
