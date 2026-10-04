"""
DOM Extractor for deep HTML link, script, asset, and HTMX discovery.
Built with pure Python and BeautifulSoup4 for 100% Termux / Linux portability.
"""

from __future__ import annotations

import logging
import posixpath
import re
from typing import Any, Dict, List, NamedTuple, Optional, Set, Tuple, Union
from urllib.parse import urljoin, urlsplit, urlunsplit

from bs4 import BeautifulSoup, Comment

logger = logging.getLogger(__name__)

# Known static asset extensions
STATIC_ASSET_EXTENSIONS: Set[str] = {
    "png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "bmp", "avif",
    "woff", "woff2", "ttf", "eot", "otf",
    "mp4", "webm", "ogg", "mp3", "wav", "flac",
    "pdf", "zip", "tar", "gz", "rar", "7z", "iso",
    "css", "map",
}

# HTMX attribute to HTTP method mapping
HTMX_ATTRIBUTE_MAP: Dict[str, str] = {
    "hx-get": "GET",
    "data-hx-get": "GET",
    "hx-post": "POST",
    "data-hx-post": "POST",
    "hx-put": "PUT",
    "data-hx-put": "PUT",
    "hx-delete": "DELETE",
    "data-hx-delete": "DELETE",
    "hx-patch": "PATCH",
    "data-hx-patch": "PATCH",
}

# Regexes for inline event handlers navigating or opening URLs
INLINE_EVENT_PATTERNS: List[re.Pattern] = [
    re.compile(
        r"""(?:window\.)?location(?:\.href|\.assign|\.replace)?\s*(?:=|\()\s*['"]([^'"]+)['"]""",
        re.IGNORECASE,
    ),
    re.compile(
        r"""(?:window\.)?open\s*\(\s*['"]([^'"]+)['"]""",
        re.IGNORECASE,
    ),
]

# Regexes for HTML comments scanning
COMMENT_URL_REGEX = re.compile(r"""https?://[^\s"'<>\\]+""")
COMMENT_PATH_REGEX = re.compile(
    r"""/(?:api|v[0-9]+|rest|graphql|admin|users|auth|login|dashboard|settings|docs|assets)[a-zA-Z0-9_\-\./]*"""
)
COMMENT_GENERAL_PATH_REGEX = re.compile(
    r"""/(?:[a-zA-Z0-9_\-\.]+)/[a-zA-Z0-9_\-\./]*"""
)


class HTMXEndpoint(tuple):
    """
    Represents an endpoint discovered from HTMX attributes.
    Inherits from tuple (url, method) to allow index unpacking,
    flexible equality matching regardless of pair order,
    and named property access (.url, .method, .path, .verb).
    """

    def __new__(cls, url: str, method: str):
        return super().__new__(cls, (url, method.upper()))

    @property
    def url(self) -> str:
        return self[0]

    @property
    def path(self) -> str:
        return self[0]

    @property
    def method(self) -> str:
        return self[1]

    @property
    def verb(self) -> str:
        return self[1]

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, (tuple, list)) and len(other) == 2:
            return (self[0] == other[0] and self[1] == other[1]) or (
                self[0] == other[1] and self[1] == other[0]
            )
        return super().__eq__(other)

    def __hash__(self) -> int:
        return hash((self[0], self[1]))

    def __repr__(self) -> str:
        return f"HTMXEndpoint(url={self.url!r}, method={self.method!r})"


class DOMExtractor:
    """
    Extracts navigation links, scripts, assets, and HTMX endpoints from parsed HTML.
    Supports <base href>, HTML5 data attributes, event handlers, frames, and comments.
    """

    @classmethod
    def extract(
        cls, soup: Union[BeautifulSoup, str], page_url: str
    ) -> Tuple[List[str], List[str], List[str], List[Tuple[str, str]]]:
        """
        Parses DOM structure and returns:
        (nav_links, script_urls, asset_urls, htmx_endpoints)
        """
        if isinstance(soup, str):
            soup = BeautifulSoup(soup, "html.parser")

        nav_links: List[str] = []
        script_urls: List[str] = []
        asset_urls: List[str] = []
        htmx_endpoints: List[Tuple[str, str]] = []

        # 1. Resolve effective base URL from <base href="...">
        effective_base = cls._get_effective_base(soup, page_url)

        # 2. Extract <script src="...">
        for script in soup.find_all("script"):
            src = script.get("src")
            resolved = cls._resolve_url(src, effective_base)
            if resolved:
                script_urls.append(resolved)

        # 3. Extract <link rel="...">
        for link in soup.find_all("link"):
            href = link.get("href")
            resolved = cls._resolve_url(href, effective_base)
            if not resolved:
                continue

            rel_attr = link.get("rel", [])
            rel_list = [
                r.lower()
                for r in (rel_attr if isinstance(rel_attr, list) else [rel_attr])
            ]
            as_type = str(link.get("as", "")).lower()

            if any(r in rel_list for r in ("preload", "prefetch", "modulepreload")):
                if as_type == "script" or resolved.endswith((".js", ".mjs")) or "/js/" in resolved:
                    script_urls.append(resolved)
                else:
                    asset_urls.append(resolved)
            elif any(r in rel_list for r in ("stylesheet", "icon", "shortcut icon", "apple-touch-icon", "manifest")):
                asset_urls.append(resolved)
            elif any(r in rel_list for r in ("canonical", "alternate", "next", "prev")):
                nav_links.append(resolved)
            else:
                if resolved.endswith((".js", ".mjs")):
                    script_urls.append(resolved)
                elif cls._is_static_asset(resolved):
                    asset_urls.append(resolved)
                else:
                    nav_links.append(resolved)

        # 4. Extract <a> and <area> tags
        for tag in soup.find_all(["a", "area"]):
            href = tag.get("href")
            resolved = cls._resolve_url(href, effective_base)
            if resolved:
                if cls._is_static_asset(resolved):
                    asset_urls.append(resolved)
                else:
                    nav_links.append(resolved)

        # 5. Extract Frames: <iframe>, <frame>, <embed>, <object>
        for frame in soup.find_all(["iframe", "frame", "embed"]):
            src = frame.get("src")
            resolved = cls._resolve_url(src, effective_base)
            if resolved:
                asset_urls.append(resolved)

        for obj in soup.find_all("object"):
            data = obj.get("data")
            resolved = cls._resolve_url(data, effective_base)
            if resolved:
                asset_urls.append(resolved)

        # 6. Extract Multimedia: <video>, <audio>, <source>, <track>, <img>
        for media in soup.find_all(["video", "audio", "track"]):
            src = media.get("src")
            resolved = cls._resolve_url(src, effective_base)
            if resolved:
                asset_urls.append(resolved)
            if media.name == "video" and media.get("poster"):
                poster_res = cls._resolve_url(media.get("poster"), effective_base)
                if poster_res:
                    asset_urls.append(poster_res)

        for source in soup.find_all("source"):
            src = source.get("src")
            resolved = cls._resolve_url(src, effective_base)
            if resolved:
                asset_urls.append(resolved)
            srcset = source.get("srcset")
            if srcset:
                for item in srcset.split(","):
                    cand = item.strip().split()[0] if item.strip() else ""
                    cand_res = cls._resolve_url(cand, effective_base)
                    if cand_res:
                        asset_urls.append(cand_res)

        for img in soup.find_all("img"):
            src = img.get("src")
            resolved = cls._resolve_url(src, effective_base)
            if resolved:
                asset_urls.append(resolved)
            srcset = img.get("srcset")
            if srcset:
                for item in srcset.split(","):
                    cand = item.strip().split()[0] if item.strip() else ""
                    cand_res = cls._resolve_url(cand, effective_base)
                    if cand_res:
                        asset_urls.append(cand_res)

        # 7. Extract <meta http-equiv="refresh" content="N;url=...">
        for meta in soup.find_all("meta"):
            http_equiv = meta.get("http-equiv", "").lower()
            if http_equiv == "refresh":
                content = meta.get("content", "")
                m = re.search(r"""(?:^|;)\s*url\s*=\s*['"]?([^\'";\s]+)""", content, re.IGNORECASE)
                if m:
                    resolved = cls._resolve_url(m.group(1), effective_base)
                    if resolved:
                        nav_links.append(resolved)

        # 8. Extract HTMX attributes: hx-get, hx-post, hx-put, hx-delete, hx-patch
        for el in soup.find_all(True):
            for attr_name, verb in HTMX_ATTRIBUTE_MAP.items():
                if el.has_attr(attr_name):
                    val = el.get(attr_name)
                    resolved = cls._resolve_url(val, effective_base)
                    if resolved:
                        htmx_endpoints.append(HTMXEndpoint(url=resolved, method=verb))

        # 9. Extract Data attributes: data-url, data-href, data-target, data-endpoint, data-api, data-action, data-src
        for el in soup.find_all(True):
            # data-src
            if el.has_attr("data-src"):
                d_src = el.get("data-src")
                resolved = cls._resolve_url(d_src, effective_base)
                if resolved:
                    if resolved.endswith((".js", ".mjs")):
                        script_urls.append(resolved)
                    elif cls._is_static_asset(resolved):
                        asset_urls.append(resolved)
                    else:
                        nav_links.append(resolved)

            # Navigation / API data attributes
            for attr in ("data-url", "data-href", "data-endpoint", "data-api", "data-action"):
                if el.has_attr(attr):
                    val = el.get(attr)
                    resolved = cls._resolve_url(val, effective_base)
                    if resolved:
                        if resolved.endswith((".js", ".mjs")):
                            script_urls.append(resolved)
                        elif cls._is_static_asset(resolved):
                            asset_urls.append(resolved)
                        else:
                            nav_links.append(resolved)

            # data-target: filter out CSS selectors like #modal or .tab
            if el.has_attr("data-target"):
                val = str(el.get("data-target", "")).strip()
                if val and not val.startswith(("#", ".")) and " " not in val:
                    if "/" in val or val.startswith(("http://", "https://")):
                        resolved = cls._resolve_url(val, effective_base)
                        if resolved:
                            nav_links.append(resolved)

        # 10. Extract Inline event handlers (onclick, onsubmit, onmouseover, etc.)
        event_names = ("onclick", "onsubmit", "onmouseover", "onmousedown", "onmouseup", "onload", "onchange", "ondblclick")
        for el in soup.find_all(True):
            for evt in event_names:
                if el.has_attr(evt):
                    handler = el.get(evt)
                    if isinstance(handler, str) and handler.strip():
                        for pat in INLINE_EVENT_PATTERNS:
                            for match in pat.finditer(handler):
                                candidate = match.group(1).strip()
                                resolved = cls._resolve_url(candidate, effective_base)
                                if resolved:
                                    nav_links.append(resolved)

        # 11. Extract URLs and candidate endpoints from HTML Comments (<!-- ... -->)
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        for comment in comments:
            comment_text = str(comment).strip()
            if not comment_text:
                continue

            # Absolute URLs in comments
            for match in COMMENT_URL_REGEX.finditer(comment_text):
                raw_cand = cls._strip_trailing_punct(match.group(0))
                resolved = cls._resolve_url(raw_cand, effective_base)
                if resolved:
                    cls._categorize_comment_url(resolved, nav_links, script_urls, asset_urls)

            # Root-relative API candidate endpoints in comments
            for match in COMMENT_PATH_REGEX.finditer(comment_text):
                raw_cand = cls._strip_trailing_punct(match.group(0))
                resolved = cls._resolve_url(raw_cand, effective_base)
                if resolved:
                    cls._categorize_comment_url(resolved, nav_links, script_urls, asset_urls)

            # General relative path references in comments
            for match in COMMENT_GENERAL_PATH_REGEX.finditer(comment_text):
                raw_cand = cls._strip_trailing_punct(match.group(0))
                resolved = cls._resolve_url(raw_cand, effective_base)
                if resolved:
                    cls._categorize_comment_url(resolved, nav_links, script_urls, asset_urls)

        # 12. Deduplicate while preserving discovery order
        return (
            list(dict.fromkeys(nav_links)),
            list(dict.fromkeys(script_urls)),
            list(dict.fromkeys(asset_urls)),
            list(dict.fromkeys(htmx_endpoints)),
        )

    @classmethod
    def _get_effective_base(cls, soup: BeautifulSoup, page_url: str) -> str:
        base_tag = soup.find("base")
        if base_tag and base_tag.get("href"):
            raw_base = str(base_tag.get("href")).strip()
            if raw_base:
                return urljoin(page_url, raw_base)
        return page_url

    @classmethod
    def _clean_url(cls, raw_url: Optional[str]) -> str:
        if not raw_url:
            return ""
        val = str(raw_url).strip()
        if not val:
            return ""
        # Ignore pseudo-protocols and pure hash fragments
        lower_val = val.lower()
        if lower_val.startswith(("#", "javascript:", "mailto:", "tel:", "data:", "about:blank")):
            return ""
        # Strip trailing hash fragment
        val = val.split("#", 1)[0].strip()
        return val

    @classmethod
    def _resolve_url(cls, raw_url: Optional[str], base_url: str) -> Optional[str]:
        cleaned = cls._clean_url(raw_url)
        if not cleaned:
            return None
        joined = urljoin(base_url, cleaned)
        # Verify valid scheme
        parsed = urlsplit(joined)
        if parsed.scheme not in ("http", "https"):
            return None
        return joined

    @classmethod
    def _is_static_asset(cls, url: str) -> bool:
        parsed = urlsplit(url)
        path = parsed.path.lower()
        ext = posixpath.splitext(path)[1].lstrip(".")
        return ext in STATIC_ASSET_EXTENSIONS

    @classmethod
    def _strip_trailing_punct(cls, s: str) -> str:
        return re.sub(r"""[\.,;:\)\]>"']+$""", "", s)

    @classmethod
    def _categorize_comment_url(
        cls,
        resolved: str,
        nav_links: List[str],
        script_urls: List[str],
        asset_urls: List[str],
    ) -> None:
        if resolved.endswith((".js", ".mjs")):
            script_urls.append(resolved)
        elif cls._is_static_asset(resolved):
            asset_urls.append(resolved)
        else:
            nav_links.append(resolved)
