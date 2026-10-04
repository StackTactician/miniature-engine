"""
Webpack 5, Webpack 4, Vite, and Next.js Chunk Map Cracker.

Reverse-engineers runtime chunk filename computation functions, dynamic import maps,
and build manifests to extract 100% of lazy-loaded and split JavaScript chunks.

Strictly adheres to Wave Engineering principles:
- Zero external dependencies (pure Python 3 standard library)
- Linear-time O(N) regex evaluation (immune to catastrophic ReDoS)
- Intermediate Representation (IR) contract via DiscoveredChunkManifest
"""

from typing import List, Dict, Any, Optional, Set
import re
import json
import urllib.parse
from api_tool.models import DiscoveredChunkManifest


class ChunkMapCracker:
    """
    Decodes Webpack 4/5, Vite, and Next.js dynamic chunk maps and manifests.
    """

    def __init__(self, base_asset_url: str = ""):
        self.base_asset_url = base_asset_url.strip()

    # Descriptor to support both ChunkMapCracker.crack(...) and cracker.crack(...)
    class _CrackDispatcher:
        def __get__(self, instance, owner):
            if instance is None:
                def _class_crack(content: str, base_asset_url: str = "", source_script: str = "") -> DiscoveredChunkManifest:
                    cracker = owner(base_asset_url=base_asset_url)
                    return cracker.crack_manifest(content, base_asset_url=base_asset_url, source_script=source_script)
                return _class_crack

            def _inst_crack(content: str, base_asset_url: Optional[str] = None, source_script: str = "") -> DiscoveredChunkManifest:
                effective_url = base_asset_url if base_asset_url is not None else instance.base_asset_url
                return instance.crack_manifest(content, base_asset_url=effective_url, source_script=source_script)
            return _inst_crack

    crack = _CrackDispatcher()

    # Descriptor for crack_all as well
    class _CrackAllDispatcher:
        def __get__(self, instance, owner):
            if instance is None:
                def _class_crack_all(content: str, base_asset_url: str = "", source_script: str = "") -> List[DiscoveredChunkManifest]:
                    cracker = owner(base_asset_url=base_asset_url)
                    return cracker.crack_all_manifests(content, base_asset_url=base_asset_url, source_script=source_script)
                return _class_crack_all

            def _inst_crack_all(content: str, base_asset_url: Optional[str] = None, source_script: str = "") -> List[DiscoveredChunkManifest]:
                effective_url = base_asset_url if base_asset_url is not None else instance.base_asset_url
                return instance.crack_all_manifests(content, base_asset_url=effective_url, source_script=source_script)
            return _inst_crack_all

    crack_all = _CrackAllDispatcher()

    def crack_manifest(
        self,
        content: str,
        base_asset_url: Optional[str] = None,
        source_script: str = "",
    ) -> DiscoveredChunkManifest:
        """
        Cracks the primary chunk manifest found in the given JavaScript content.
        Returns DiscoveredChunkManifest with framework='unknown' if none found.
        """
        all_manifests = self.crack_all_manifests(
            content=content,
            base_asset_url=base_asset_url,
            source_script=source_script,
        )
        if all_manifests:
            return all_manifests[0]

        effective_base = base_asset_url if base_asset_url is not None else self.base_asset_url
        return DiscoveredChunkManifest(
            framework="unknown",
            source_script=source_script,
            base_url=effective_base,
            chunk_urls=[],
            chunk_map={},
            template=None,
            metadata={},
        )

    def crack_all_manifests(
        self,
        content: str,
        base_asset_url: Optional[str] = None,
        source_script: str = "",
    ) -> List[DiscoveredChunkManifest]:
        """
        Detects and cracks all manifests (Next.js, Webpack, Vite) present in content.
        """
        if not content or not isinstance(content, str):
            return []

        effective_base = base_asset_url if base_asset_url is not None else self.base_asset_url
        results: List[DiscoveredChunkManifest] = []

        # 1. Next.js Manifest Check
        nextjs_manifest = self.decode_nextjs(content, base_asset_url=effective_base, source_script=source_script)
        if nextjs_manifest:
            results.append(nextjs_manifest)

        # 2. Webpack 4/5 Check
        webpack_manifest = self.decode_webpack(content, base_asset_url=effective_base, source_script=source_script)
        if webpack_manifest:
            results.append(webpack_manifest)

        # 3. Vite Check
        vite_manifest = self.decode_vite(content, base_asset_url=effective_base, source_script=source_script)
        if vite_manifest:
            results.append(vite_manifest)

        return results

    # -------------------------------------------------------------------------
    # Webpack 4 / 5 Runtime Cracker
    # -------------------------------------------------------------------------

    def decode_webpack(
        self,
        content: str,
        base_asset_url: Optional[str] = None,
        source_script: str = "",
    ) -> Optional[DiscoveredChunkManifest]:
        """
        Decodes Webpack 4 and 5 chunk computation functions (__webpack_require__.u / jsonpScriptSrc).
        """
        if not content:
            return None

        effective_base = base_asset_url if base_asset_url is not None else self.base_asset_url

        # Detect Webpack publicPath (__webpack_require__.p or <var>.p = "...")
        public_path = self._extract_webpack_public_path(content)

        # 1. Check for Webpack 5: <var>.u = function(arg) { ... } or <var>.u = arg => ...
        webpack5_manifest = self._crack_webpack5_u(content, public_path, effective_base, source_script)
        if webpack5_manifest:
            return webpack5_manifest

        # 2. Check for Webpack 4: function jsonpScriptSrc(chunkId) { ... }
        webpack4_manifest = self._crack_webpack4_jsonp(content, public_path, effective_base, source_script)
        if webpack4_manifest:
            return webpack4_manifest

        # 3. Check for standalone Webpack chunk loading function (__webpack_require__.e / installedChunks)
        webpack_e_manifest = self._crack_webpack_e(content, public_path, effective_base, source_script)
        if webpack_e_manifest:
            return webpack_e_manifest

        return None

    def _extract_webpack_public_path(self, content: str) -> str:
        """Extracts __webpack_require__.p public path if present."""
        match = re.search(r'''(?:[a-zA-Z0-9_$]+\.p|publicPath)\s*=\s*["']([^"'\r\n]*)["']''', content)
        if match:
            return match.group(1)
        return ""

    def _crack_webpack5_u(
        self,
        content: str,
        public_path: str,
        base_asset_url: str,
        source_script: str,
    ) -> Optional[DiscoveredChunkManifest]:
        """Cracks Webpack 5 __webpack_require__.u runtime function."""
        u_pattern = re.compile(
            r'''(?:\b[a-zA-Z0-9_$]+\.u\s*=\s*(?:function\s*\(\s*([a-zA-Z0-9_$]+)\s*\)\s*\{|(?:\(\s*([a-zA-Z0-9_$]+)\s*\)|([a-zA-Z0-9_$]+))\s*=>\s*(\{?)))''',
            re.MULTILINE,
        )

        for match in u_pattern.finditer(content):
            arg_name = match.group(1) or match.group(2) or match.group(3)
            has_outer_brace = bool(match.group(1)) or (match.group(4) == '{')
            func_start = match.end()

            body_text = self._extract_function_body(content, func_start, has_outer_brace)
            if not body_text:
                continue

            manifest = self._parse_webpack_function_body(
                body_text=body_text,
                arg_name=arg_name,
                framework="webpack5",
                public_path=public_path,
                base_asset_url=base_asset_url,
                source_script=source_script,
            )
            if manifest and (manifest.chunk_urls or manifest.chunk_map):
                return manifest

        return None

    def _crack_webpack4_jsonp(
        self,
        content: str,
        public_path: str,
        base_asset_url: str,
        source_script: str,
    ) -> Optional[DiscoveredChunkManifest]:
        """Cracks Webpack 4 jsonpScriptSrc(chunkId) runtime function."""
        pattern = re.compile(
            r'''\bfunction\s+jsonpScriptSrc\s*\(\s*([a-zA-Z0-9_$]+)\s*\)\s*\{''',
            re.MULTILINE,
        )
        match = pattern.search(content)
        if not match:
            return None

        arg_name = match.group(1)
        func_start = match.end()
        body_text = self._extract_function_body(content, func_start, has_outer_brace=True)
        if not body_text:
            return None

        manifest = self._parse_webpack_function_body(
            body_text=body_text,
            arg_name=arg_name,
            framework="webpack4",
            public_path=public_path,
            base_asset_url=base_asset_url,
            source_script=source_script,
        )
        return manifest

    def _crack_webpack_e(
        self,
        content: str,
        public_path: str,
        base_asset_url: str,
        source_script: str,
    ) -> Optional[DiscoveredChunkManifest]:
        """Fallback check for installedChunks or __webpack_require__.e chunk references."""
        pattern = re.compile(
            r'''(?:installedChunks|installedCssChunks)\s*=\s*\{([^}]+)\}'''
        )
        match = pattern.search(content)
        if not match:
            return None

        obj_content = "{" + match.group(1) + "}"
        chunks_dict = self._parse_js_object(obj_content)
        if not chunks_dict:
            return None

        chunk_map: Dict[str, str] = {}
        chunk_urls: List[str] = []

        framework = "webpack5" if "webpackChunk" in content else "webpack4"

        for chunk_id in chunks_dict.keys():
            rel_path = f"{chunk_id}.js"
            full_url = self._resolve_url(rel_path, base_asset_url, public_path)
            chunk_map[chunk_id] = rel_path
            chunk_urls.append(full_url)

        return DiscoveredChunkManifest(
            framework=framework,
            source_script=source_script,
            base_url=base_asset_url,
            chunk_urls=chunk_urls,
            chunk_map=chunk_map,
            template=f"{public_path}{{id}}.js" if public_path else "{id}.js",
            metadata={"public_path": public_path, "extraction_method": "installedChunks"},
        )

    def _extract_function_body(
        self,
        content: str,
        start_pos: int,
        has_outer_brace: bool,
        max_len: int = 8192,
    ) -> str:
        """
        Safely extracts the function body starting from start_pos.
        Balanced brace/bracket/quote matching in O(N) linear time.
        """
        brace_depth = 1 if has_outer_brace else 0
        paren_depth = 0
        bracket_depth = 0
        in_quote = None
        escaped = False

        end = len(content)
        limit = min(len(content), start_pos + max_len)

        for i in range(start_pos, limit):
            c = content[i]
            if escaped:
                escaped = False
                continue
            if c == '\\':
                escaped = True
                continue
            if in_quote:
                if c == in_quote:
                    in_quote = None
                continue
            if c in ('"', "'", '`'):
                in_quote = c
                continue

            if c == '{':
                brace_depth += 1
            elif c == '}':
                brace_depth -= 1
                if has_outer_brace and brace_depth == 0:
                    end = i
                    break
            elif c == '(':
                paren_depth += 1
            elif c == ')':
                paren_depth -= 1
            elif c == '[':
                bracket_depth += 1
            elif c == ']':
                bracket_depth -= 1
            elif c == ';' and not has_outer_brace and brace_depth == 0 and paren_depth == 0 and bracket_depth == 0:
                end = i
                break

        return content[start_pos:end]

    def _extract_return_expr(self, body_text: str) -> str:
        """Extracts the exact return expression respecting nested braces and quotes."""
        ret_match = re.search(r'\breturn\b', body_text)
        if not ret_match:
            return body_text.strip().rstrip(';').strip()

        start = ret_match.end()
        brace_depth = 0
        bracket_depth = 0
        paren_depth = 0
        in_quote = None
        escaped = False

        end = len(body_text)
        for i in range(start, len(body_text)):
            c = body_text[i]
            if escaped:
                escaped = False
                continue
            if c == '\\':
                escaped = True
                continue
            if in_quote:
                if c == in_quote:
                    in_quote = None
                continue
            if c in ('"', "'", '`'):
                in_quote = c
                continue

            if c == '{':
                brace_depth += 1
            elif c == '}':
                if brace_depth > 0:
                    brace_depth -= 1
                else:
                    end = i
                    break
            elif c == '[':
                bracket_depth += 1
            elif c == ']':
                bracket_depth -= 1
            elif c == '(':
                paren_depth += 1
            elif c == ')':
                paren_depth -= 1
            elif c == ';' and brace_depth == 0 and bracket_depth == 0 and paren_depth == 0:
                end = i
                break

        return body_text[start:end].strip()

    def _normalize_template_literals(self, text: str) -> str:
        """Converts ES6 template literals `prefix${e}suffix` into standard concatenation 'prefix' + (e) + 'suffix'."""
        if '`' not in text:
            return text

        def repl(m):
            content = m.group(1)
            res = []
            i = 0
            depth = 0
            in_expr = False
            expr_start = 0
            current_lit = []
            while i < len(content):
                if not in_expr:
                    if content[i:i+2] == '${':
                        res.append('"' + ''.join(current_lit) + '" + (')
                        current_lit = []
                        in_expr = True
                        depth = 1
                        i += 2
                        expr_start = i
                        continue
                    else:
                        current_lit.append(content[i])
                        i += 1
                else:
                    if content[i] == '{':
                        depth += 1
                    elif content[i] == '}':
                        depth -= 1
                        if depth == 0:
                            res.append(content[expr_start:i] + ') + ')
                            in_expr = False
                            i += 1
                            continue
                    i += 1
            res.append('"' + ''.join(current_lit) + '"')
            return ''.join(res)

        return re.sub(r'`([^`]*)`', repl, text)

    def _parse_webpack_function_body(
        self,
        body_text: str,
        arg_name: str,
        framework: str,
        public_path: str,
        base_asset_url: str,
        source_script: str,
    ) -> Optional[DiscoveredChunkManifest]:
        """
        Parses the return expression of a Webpack chunk filename function.
        Handles object mapping concatenations, ternary expressions, and templates.
        """
        expr = self._extract_return_expr(body_text)
        if not expr:
            return None
        expr = self._normalize_template_literals(expr)

        chunk_map: Dict[str, str] = {}
        all_chunk_ids: Set[str] = set()

        # 1. Parse ternary branches:
        # e.g.: 10 === e ? "vendor.123.js" : 20 === e ? "app.456.js" : fallback
        ternary_re = re.compile(
            r'''(?:([a-zA-Z0-9_$"\']+)\s*={2,3}\s*([a-zA-Z0-9_$"\']+))\s*\?\s*["']([^"'\r\n]+)["']\s*:\s*'''
        )
        rest = expr
        while True:
            t_match = ternary_re.search(rest)
            if not t_match:
                break
            v1, v2, target = t_match.groups()
            chunk_id = v1 if v2 == arg_name else v2
            chunk_id_clean = chunk_id.strip("\"'")
            chunk_map[chunk_id_clean] = self._normalize_chunk_filename(target, public_path)
            all_chunk_ids.add(chunk_id_clean)
            rest = rest[t_match.end():]

        # 2. Extract object literals mapped by [arg_name] in the fallback expression
        dict_maps = self._extract_arg_subscript_objects(rest, arg_name)

        name_map: Dict[str, str] = {}
        hash_map: Dict[str, str] = {}

        if len(dict_maps) >= 2:
            name_map = dict_maps[0]
            hash_map = dict_maps[1]
        elif len(dict_maps) == 1:
            hash_map = dict_maps[0]

        all_chunk_ids.update(hash_map.keys())
        all_chunk_ids.update(name_map.keys())

        # 3. Reconstruct template string from fallback expression
        cleaned = re.sub(r'\b[a-zA-Z0-9_$]+\.p\s*\+\s*', '', rest)
        # Replace ({...}[arg] || arg) with {name}
        tmpl = re.sub(
            r'\(\s*\{[^}]*\}\s*\[\s*' + re.escape(arg_name) + r'\s*\]\s*\|\|\s*' + re.escape(arg_name) + r'\s*\)',
            '{name}',
            cleaned,
        )
        # Replace {...}[arg] with {hash}
        tmpl = re.sub(
            r'\{[^}]*\}\s*\[\s*' + re.escape(arg_name) + r'\s*\]',
            '{hash}',
            tmpl,
        )
        # Replace isolated arg_name with {id}
        tmpl = re.sub(
            r'(?<![a-zA-Z0-9_$"\'])' + re.escape(arg_name) + r'(?![a-zA-Z0-9_$"\'])',
            '{id}',
            tmpl,
        )

        # Assemble template tokens
        token_pattern = re.compile(r'''(["'](?:[^"'\\]|\\.)*["']|{[a-z]+})''')
        parts = []
        for tm in token_pattern.finditer(tmpl):
            tok = tm.group(1)
            if tok.startswith('"') or tok.startswith("'"):
                parts.append(tok[1:-1])
            else:
                parts.append(tok)
        template_str = ''.join(parts) if parts else "{id}.js"

        # 4. Generate chunk filenames for each chunkId
        for chunk_id in sorted(all_chunk_ids, key=lambda x: (len(x), x)):
            if chunk_id in chunk_map:
                continue

            chunk_name = name_map.get(chunk_id, chunk_id)
            chunk_hash = hash_map.get(chunk_id, "")
            rendered = template_str.replace("{name}", chunk_name).replace("{hash}", chunk_hash).replace("{id}", chunk_id)
            if not chunk_hash:
                rendered = rendered.replace("..", ".").replace(".chunk.js", ".js")
            chunk_map[chunk_id] = self._normalize_chunk_filename(rendered, public_path)

        if not chunk_map:
            return None

        # 5. Resolve relative paths to absolute URLs
        chunk_urls: List[str] = []
        seen_urls: Set[str] = set()
        for cid, rel_path in chunk_map.items():
            full_url = self._resolve_url(rel_path, base_asset_url, public_path)
            if full_url and full_url not in seen_urls:
                seen_urls.add(full_url)
                chunk_urls.append(full_url)

        return DiscoveredChunkManifest(
            framework=framework,
            source_script=source_script,
            base_url=base_asset_url,
            chunk_urls=chunk_urls,
            chunk_map=chunk_map,
            template=template_str,
            metadata={
                "public_path": public_path,
                "total_chunks": len(chunk_map),
                "has_name_map": bool(name_map),
                "has_hash_map": bool(hash_map),
            },
        )

    def _extract_arg_subscript_objects(self, expr: str, arg_name: str) -> List[Dict[str, str]]:
        """
        Extracts JS object literals that are indexed with [arg_name] in expr.
        Matches: { ... }[arg_name]
        """
        results: List[Dict[str, str]] = []
        target_token = f"[{arg_name}]"
        search_idx = 0

        while True:
            idx = expr.find(target_token, search_idx)
            if idx == -1:
                break

            brace_end = idx
            brace_start = -1
            brace_count = 0

            for i in range(brace_end - 1, -1, -1):
                c = expr[i]
                if c == '}':
                    brace_count += 1
                elif c == '{':
                    brace_count -= 1
                    if brace_count == 0:
                        brace_start = i
                        break

            if brace_start != -1:
                obj_text = expr[brace_start:brace_end]
                parsed = self._parse_js_object(obj_text)
                if parsed:
                    results.append(parsed)

            search_idx = idx + len(target_token)

        return results

    def _parse_js_object(self, obj_str: str) -> Dict[str, str]:
        """
        Parses a JavaScript object literal into a Python dict.
        Linear-time regex matching key-value pairs without ReDoS.
        """
        result: Dict[str, str] = {}
        if not obj_str:
            return result

        pair_pattern = re.compile(
            r'''(?:["']([^"'\\]*(?:\\.[^"'\\]*)*)["']|([a-zA-Z0-9_$-]+))\s*:\s*(?:["']([^"'\\]*(?:\\.[^"'\\]*)*)["']|([a-zA-Z0-9_$-]+))'''
        )

        for match in pair_pattern.finditer(obj_str):
            key = match.group(1) or match.group(2)
            val = match.group(3) or match.group(4)
            if key is not None and val is not None:
                result[key.strip()] = val.strip()

        return result

    def _normalize_chunk_filename(self, filename: str, public_path: str) -> str:
        """Normalizes chunk filename and ensures clean pathing."""
        cleaned = filename.strip("'\"").strip()
        if public_path:
            pub_clean = public_path.strip().lstrip("/")
            if pub_clean and cleaned.startswith(pub_clean):
                cleaned = cleaned[len(pub_clean):]
        return cleaned.lstrip("/")

    # -------------------------------------------------------------------------
    # Vite Preload & MapDeps Cracker
    # -------------------------------------------------------------------------

    def decode_vite(
        self,
        content: str,
        base_asset_url: Optional[str] = None,
        source_script: str = "",
    ) -> Optional[DiscoveredChunkManifest]:
        """
        Decodes Vite dynamic import maps (__vite__mapDeps) and preload manifests.
        """
        if not content:
            return None

        effective_base = base_asset_url if base_asset_url is not None else self.base_asset_url

        # Check if content is a Vite manifest.json
        if content.strip().startswith("{") and "file" in content:
            manifest_json = self._parse_vite_json_manifest(content, effective_base, source_script)
            if manifest_json:
                return manifest_json

        # 1. Match __vite__mapDeps array or preload function
        deps_list: List[str] = []

        mapdeps_pattern = re.compile(
            r'''(?:__vite__mapDeps\s*=\s*(?:(?:\([^)]*\)|[a-zA-Z0-9_$]+)\s*=>\s*[^;]*?)?\[|__vitePreload\s*\([^,]+,\s*(?:true\s*\?\s*)?\[)(?P<deps>[^\]]+)\]'''
        )
        for match in mapdeps_pattern.finditer(content):
            raw_deps = match.group("deps")
            extracted = self._extract_quoted_strings(raw_deps)
            deps_list.extend(extracted)

        # Fallback: search for standalone __vite__mapDeps reference or arrays containing .js
        if not deps_list and "__vite" in content:
            simple_vite_pattern = re.compile(
                r'''\[(?P<deps>[^\]]*?assets/[^\]]+?\.(?:js|mjs|css)[^\]]*?)\]'''
            )
            for m in simple_vite_pattern.finditer(content):
                deps_list.extend(self._extract_quoted_strings(m.group("deps")))

        if not deps_list:
            return None

        # Build chunk map and resolved URLs
        chunk_map: Dict[str, str] = {}
        chunk_urls: List[str] = []
        seen_urls: Set[str] = set()

        for dep in deps_list:
            clean_dep = dep.strip("'\"").lstrip("/")
            if not clean_dep:
                continue
            base_name = clean_dep.split("/")[-1]
            chunk_map[base_name] = clean_dep
            if clean_dep not in chunk_map:
                chunk_map[clean_dep] = clean_dep

            full_url = self._resolve_url(clean_dep, effective_base)
            if full_url and full_url not in seen_urls:
                seen_urls.add(full_url)
                chunk_urls.append(full_url)

        return DiscoveredChunkManifest(
            framework="vite",
            source_script=source_script,
            base_url=effective_base,
            chunk_urls=chunk_urls,
            chunk_map=chunk_map,
            template="assets/{name}.js",
            metadata={"total_chunks": len(chunk_urls), "source": "__vite__mapDeps"},
        )

    def _parse_vite_json_manifest(
        self,
        content: str,
        base_asset_url: str,
        source_script: str,
    ) -> Optional[DiscoveredChunkManifest]:
        """Parses Vite manifest.json / .vite/manifest.json format."""
        try:
            data = json.loads(content)
        except Exception:
            return None

        if not isinstance(data, dict):
            return None

        chunk_map: Dict[str, str] = {}
        chunk_urls: List[str] = []

        for key, entry in data.items():
            if isinstance(entry, dict) and "file" in entry:
                file_path = entry["file"]
                chunk_map[key] = file_path
                full_url = self._resolve_url(file_path, base_asset_url)
                if full_url and full_url not in chunk_urls:
                    chunk_urls.append(full_url)

                # Dynamic imports
                for d_import in entry.get("dynamicImports", []):
                    if d_import in data and "file" in data[d_import]:
                        df = data[d_import]["file"]
                        chunk_map[d_import] = df
                        du = self._resolve_url(df, base_asset_url)
                        if du and du not in chunk_urls:
                            chunk_urls.append(du)

        if not chunk_urls:
            return None

        return DiscoveredChunkManifest(
            framework="vite",
            source_script=source_script,
            base_url=base_asset_url,
            chunk_urls=chunk_urls,
            chunk_map=chunk_map,
            template="assets/{name}.js",
            metadata={"total_chunks": len(chunk_urls), "manifest_type": "json_manifest"},
        )

    # -------------------------------------------------------------------------
    # Next.js BuildManifest Cracker
    # -------------------------------------------------------------------------

    def decode_nextjs(
        self,
        content: str,
        base_asset_url: Optional[str] = None,
        source_script: str = "",
    ) -> Optional[DiscoveredChunkManifest]:
        """
        Decodes Next.js _buildManifest.js static chunk paths and route mappings.
        Supports both direct object literals and IIFE parameter wrappers.
        """
        if not content:
            return None

        effective_base = base_asset_url if base_asset_url is not None else self.base_asset_url

        if "__BUILD_MANIFEST" not in content and "_ssgManifest" not in content:
            return None

        chunk_map: Dict[str, str] = {}
        chunk_urls: List[str] = []
        routes_map: Dict[str, List[str]] = {}

        # 1. Check for Next.js IIFE wrapper pattern:
        iife_pattern = re.compile(
            r'''__BUILD_MANIFEST\s*=\s*\(?\s*function\s*\((?P<params>[^)]*)\)\s*\{(?P<body>.*?)\}\s*\)\s*\((?P<args>[^)]*)\)''',
            re.DOTALL,
        )
        iife_match = iife_pattern.search(content)

        if iife_match:
            params_raw = iife_match.group("params")
            body_raw = iife_match.group("body")
            args_raw = iife_match.group("args")

            param_names = [p.strip() for p in params_raw.split(",") if p.strip()]
            arg_values = self._extract_quoted_strings(args_raw)

            param_map = dict(zip(param_names, arg_values))

            route_pattern = re.compile(r'''["'](/[^"']*)["']\s*:\s*\[(?P<items>[^\]]*)\]''')
            for r_match in route_pattern.finditer(body_raw):
                route = r_match.group(1)
                items_str = r_match.group("items")
                route_chunks: List[str] = []

                for token in re.split(r'[,\s]+', items_str.strip()):
                    token = token.strip()
                    if not token:
                        continue
                    if token in param_map:
                        route_chunks.append(param_map[token])
                    else:
                        clean_str = token.strip("'\"")
                        if clean_str.endswith(".js"):
                            route_chunks.append(clean_str)

                routes_map[route] = route_chunks
                if route_chunks:
                    chunk_map[route] = route_chunks[-1]
                    for rc in route_chunks:
                        resolved = self._resolve_url(rc, effective_base)
                        if resolved and resolved not in chunk_urls:
                            chunk_urls.append(resolved)

            for arg_val in arg_values:
                resolved = self._resolve_url(arg_val, effective_base)
                if resolved and resolved not in chunk_urls:
                    chunk_urls.append(resolved)

        else:
            # 2. Direct object literal format:
            route_pattern = re.compile(r'''["'](/[^"']*)["']\s*:\s*\[(?P<items>[^\]]*)\]''')
            for r_match in route_pattern.finditer(content):
                route = r_match.group(1)
                items_str = r_match.group("items")
                chunks = self._extract_quoted_strings(items_str)
                if chunks:
                    routes_map[route] = chunks
                    chunk_map[route] = chunks[-1]
                    for c in chunks:
                        resolved = self._resolve_url(c, effective_base)
                        if resolved and resolved not in chunk_urls:
                            chunk_urls.append(resolved)

        # Fallback: scan for all static/chunks/ paths
        all_static_chunks = re.findall(r'''["'](static/chunks/[^"'\r\n]+\.js)["']''', content)
        for sc in all_static_chunks:
            resolved = self._resolve_url(sc, effective_base)
            if resolved and resolved not in chunk_urls:
                chunk_urls.append(resolved)

        if not chunk_urls:
            return None

        return DiscoveredChunkManifest(
            framework="nextjs",
            source_script=source_script,
            base_url=effective_base,
            chunk_urls=chunk_urls,
            chunk_map=chunk_map,
            template="static/chunks/{name}.js",
            metadata={
                "routes": routes_map,
                "total_routes": len(routes_map),
                "total_chunks": len(chunk_urls),
            },
        )

    # -------------------------------------------------------------------------
    # Utility Methods
    # -------------------------------------------------------------------------

    def _extract_quoted_strings(self, text: str) -> List[str]:
        """Extracts single- or double-quoted strings in linear time."""
        if not text:
            return []
        pattern = re.compile(r'''["']([^"'\\]*(?:\\.[^"'\\]*)*)["']''')
        return [m.group(1) for m in pattern.finditer(text)]

    def _resolve_url(self, chunk_path: str, base_asset_url: str, public_path: str = "") -> str:
        """
        Resolves a relative chunk path against base_asset_url into an absolute URL.
        Preserves existing absolute URLs (http:// or https://) and handles publicPath.
        """
        clean_path = chunk_path.strip()
        if not clean_path:
            return ""

        # Already an absolute HTTP/HTTPS URL
        if clean_path.startswith("http://") or clean_path.startswith("https://"):
            return clean_path

        # If public_path is provided, combine with chunk_path if not already prefixed
        if public_path:
            pub_clean = public_path.strip().lstrip("/")
            if not clean_path.startswith("/") and not (pub_clean and clean_path.startswith(pub_clean)):
                combined = f"{public_path.rstrip('/')}/{clean_path.lstrip('/')}"
            else:
                combined = clean_path
        else:
            combined = clean_path

        if not base_asset_url:
            return combined

        return urllib.parse.urljoin(base_asset_url, combined)
