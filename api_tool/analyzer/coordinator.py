"""
Unified StaticAnalyzer Coordinator Module for api-tool.
Coordinates JS regex extraction, client configurations, Server Actions,
GraphQL operations, and source map unpacking into a unified StaticAnalysisResult.

Pure Python 3 / httpx, 100% portable on Termux/Linux, low memory (<10MB RAM),
ReDoS-safe O(N) evaluation, zero Chromium dependency.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlsplit, urlunsplit

import httpx

from api_tool.models import DiscoveredEndpoint, GraphQLOperation, DiscoveredChunkManifest
from api_tool.analyzer.sourcemap import SourceMapResult, SourceMapUnpacker
from api_tool.analyzer.js_regex import JSRegexExtractor
from api_tool.analyzer.graphql_parser import GraphQLQueryExtractor
from api_tool.analyzer.ast_parser import JSASTExtractor
from api_tool.analyzer.chunk_cracker import ChunkMapCracker

logger = logging.getLogger(__name__)


@dataclass
class StaticAnalysisResult:
    """Unified static analysis result container."""
    endpoints: List[DiscoveredEndpoint] = field(default_factory=list)
    graphql_operations: List[GraphQLOperation] = field(default_factory=list)
    base_urls: List[str] = field(default_factory=list)
    source_map_results: List[SourceMapResult] = field(default_factory=list)
    client_configs: Dict[str, Any] = field(default_factory=dict)
    chunk_manifests: List[DiscoveredChunkManifest] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "endpoints": [e.to_dict() for e in self.endpoints],
            "graphql_operations": [g.to_dict() for g in self.graphql_operations],
            "base_urls": list(self.base_urls),
            "source_map_results": [s.to_dict() for s in self.source_map_results],
            "client_configs": dict(self.client_configs),
            "chunk_manifests": [c.to_dict() for c in self.chunk_manifests],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


class StaticAnalyzer:
    """
    Unified static analysis coordinator.
    Orchestrates JS regex extraction, client configuration harvesting,
    Server Actions discovery, GraphQL query harvesting, and source map unpacking.
    """

    def __init__(
        self,
        request_timeout: float = 15.0,
        concurrency: int = 5,
    ) -> None:
        self.request_timeout = request_timeout
        self.concurrency = concurrency
        self.js_extractor = JSRegexExtractor()
        self.graphql_extractor = GraphQLQueryExtractor()
        self.sourcemap_unpacker = SourceMapUnpacker(request_timeout=request_timeout)
        self.ast_extractor = JSASTExtractor()
        self.chunk_cracker = ChunkMapCracker()

    @staticmethod
    def _merge_client_configs(c1: Dict[str, Any], c2: Dict[str, Any]) -> Dict[str, Any]:
        """Merges two client configuration dictionaries deduplicating lists and updating dicts."""
        merged: Dict[str, Any] = {
            "base_urls": [],
            "axios": [],
            "ky": [],
            "ofetch": [],
            "wretch": [],
            "trpc": [],
            "env_vars": {},
        }

        # Seed from c1
        for k, v in c1.items():
            if isinstance(v, list):
                merged[k] = list(v)
            elif isinstance(v, dict):
                merged[k] = dict(v)
            else:
                merged[k] = v

        # Merge from c2
        for k, v in c2.items():
            if k in merged and isinstance(merged[k], list) and isinstance(v, list):
                for item in v:
                    if item not in merged[k]:
                        merged[k].append(item)
            elif k in merged and isinstance(merged[k], dict) and isinstance(v, dict):
                merged[k].update(v)
            elif k not in merged:
                if isinstance(v, list):
                    merged[k] = list(v)
                elif isinstance(v, dict):
                    merged[k] = dict(v)
                else:
                    merged[k] = v

        return merged

    @staticmethod
    def _deduplicate_endpoints(endpoints: List[DiscoveredEndpoint]) -> List[DiscoveredEndpoint]:
        """Deduplicates endpoints by (method, full_url, headers) and merges metadata."""
        seen: Dict[Tuple[str, str, Tuple[Tuple[str, str], ...]], DiscoveredEndpoint] = {}

        for ep in endpoints:
            method = (ep.method or "GET").upper()
            full_url = ep.full_url
            # Normalize trailing slash if not root or query
            if "?" not in full_url and len(full_url) > 1 and full_url.endswith("/"):
                full_url_norm = full_url.rstrip("/")
            else:
                full_url_norm = full_url

            headers_tuple = tuple(sorted(ep.headers.items()))
            key = (method, full_url_norm, headers_tuple)

            if key not in seen:
                seen[key] = ep
            else:
                existing = seen[key]
                # Merge tags
                for tag in ep.tags:
                    if tag not in existing.tags:
                        existing.tags.append(tag)

                # Merge parameters
                existing_params = {(p.location, p.name) for p in existing.parameters}
                for p in ep.parameters:
                    if (p.location, p.name) not in existing_params:
                        existing.parameters.append(p)
                        existing_params.add((p.location, p.name))

                # Merge descriptions / summaries
                if not existing.description and ep.description:
                    existing.description = ep.description
                if (
                    not existing.summary
                    or existing.summary.startswith("Extracted REST endpoint")
                ) and ep.summary:
                    existing.summary = ep.summary

                # Prefer sourcemap source over static_js
                if existing.source == "static_js" and ep.source != "static_js":
                    existing.source = ep.source

                if not existing.base_url and ep.base_url:
                    existing.base_url = ep.base_url

        return list(seen.values())

    @staticmethod
    def _deduplicate_graphql(operations: List[GraphQLOperation]) -> List[GraphQLOperation]:
        """Deduplicates GraphQL operations by operation type, name, query string, and endpoint."""
        seen: Dict[Tuple[str, str, str, str], GraphQLOperation] = {}

        for op in operations:
            clean_query = " ".join((op.query_string or "").split())
            key = (
                (op.operation_type or "query").lower(),
                (op.operation_name or "").strip(),
                clean_query,
                (op.endpoint or "/graphql").strip(),
            )
            if key not in seen:
                seen[key] = op
            else:
                existing = seen[key]
                if not existing.variables_sample and op.variables_sample:
                    existing.variables_sample = op.variables_sample

        return list(seen.values())

    @staticmethod
    def _deduplicate_sourcemaps(sm_results: List[SourceMapResult]) -> List[SourceMapResult]:
        """Deduplicates SourceMapResult instances by js_url, map_url, and discovery_source."""
        seen: Set[Tuple[Optional[str], Optional[str], str]] = set()
        deduped: List[SourceMapResult] = []
        for sm in sm_results:
            key = (sm.js_url, sm.map_url, sm.discovery_source)
            if key not in seen:
                seen.add(key)
                deduped.append(sm)
        return deduped

    def _finalize_result(
        self,
        endpoints: List[DiscoveredEndpoint],
        graphql_ops: List[GraphQLOperation],
        client_configs: Dict[str, Any],
        source_map_results: List[SourceMapResult],
        base_url: str = "",
        chunk_manifests: Optional[List[DiscoveredChunkManifest]] = None,
    ) -> StaticAnalysisResult:
        """
        Resolves relative endpoints against discovered base URLs if base_url is present,
        assembles all discovered base URLs, and deduplicates all findings.
        """
        clean_base = base_url.rstrip("/") if base_url else ""
        resolved_base_urls: List[str] = []

        if clean_base:
            resolved_base_urls.append(clean_base)

        # 1. Resolve client configs base URLs against base_url if relative
        for b in client_configs.get("base_urls", []):
            if not b:
                continue
            if b.startswith("/") and clean_base:
                resolved_b = f"{clean_base}/{b.lstrip('/')}".rstrip("/")
            else:
                resolved_b = b.rstrip("/")
            if resolved_b and resolved_b not in resolved_base_urls:
                resolved_base_urls.append(resolved_b)

        # 2. Add any endpoint base URLs that are absolute
        for ep in endpoints:
            if ep.base_url:
                ep_base = ep.base_url.rstrip("/")
                if ep_base.startswith(("http://", "https://")) and ep_base not in resolved_base_urls:
                    resolved_base_urls.append(ep_base)

        # 3. Resolve relative endpoints if base_url is present
        if clean_base:
            for ep in endpoints:
                if not ep.base_url:
                    ep.base_url = clean_base
                elif ep.base_url.startswith("/"):
                    ep.base_url = f"{clean_base}/{ep.base_url.lstrip('/')}".rstrip("/")

        # 4. Deduplicate findings
        deduped_endpoints = self._deduplicate_endpoints(endpoints)
        deduped_graphql = self._deduplicate_graphql(graphql_ops)
        deduped_sourcemaps = self._deduplicate_sourcemaps(source_map_results)

        # Deduplicate chunk manifests
        deduped_manifests: List[DiscoveredChunkManifest] = []
        seen_manifests: Set[Tuple[str, str, int]] = set()
        if chunk_manifests:
            for m in chunk_manifests:
                key = (m.framework, m.source_script, len(m.chunk_urls))
                if key not in seen_manifests:
                    seen_manifests.add(key)
                    deduped_manifests.append(m)

        return StaticAnalysisResult(
            endpoints=deduped_endpoints,
            graphql_operations=deduped_graphql,
            base_urls=resolved_base_urls,
            source_map_results=deduped_sourcemaps,
            client_configs=client_configs,
            chunk_manifests=deduped_manifests,
        )

    def analyze_code(
        self,
        js_code: str,
        base_url: str = "",
        script_url: str = "",
    ) -> StaticAnalysisResult:
        """
        Synchronously analyzes JavaScript code:
        1. Extracts endpoints using JSRegexExtractor and compulsory Tree-sitter JSASTExtractor.
        2. Extracts client configs using JSRegexExtractor and JSASTExtractor.
        3. Extracts Server Actions using JSRegexExtractor and JSASTExtractor.
        4. Extracts GraphQL operations using GraphQLQueryExtractor.
        5. Cracks dynamic chunk manifests using ChunkMapCracker.
        6. Checks for inline source map using SourceMapUnpacker.
           If inline map present, unpacks original files and analyzes them too.
        7. Resolves relative endpoints against discovered base URLs if base_url is present.
        8. Deduplicates endpoints and GraphQL operations.
        """
        if not js_code or not isinstance(js_code, str):
            return StaticAnalysisResult()

        endpoints: List[DiscoveredEndpoint] = []
        graphql_ops: List[GraphQLOperation] = []
        source_map_results: List[SourceMapResult] = []
        chunk_manifests: List[DiscoveredChunkManifest] = []

        # 1. Extract regex endpoints and configs
        endpoints.extend(self.js_extractor.extract_endpoints(js_code, base_url))
        client_configs = self.js_extractor.extract_client_configs(js_code)
        endpoints.extend(self.js_extractor.extract_server_actions(js_code))
        graphql_ops.extend(self.graphql_extractor.extract_from_code(js_code))

        # 2. Extract AST endpoints, server actions, and configs (compulsory Tree-sitter)
        try:
            ast_data = self.ast_extractor.extract_all(js_code, base_url=base_url)
            if ast_data.get("endpoints"):
                endpoints.extend(ast_data["endpoints"])
            if ast_data.get("client_configs"):
                client_configs = self._merge_client_configs(client_configs, ast_data["client_configs"])
        except Exception as e:
            logger.warning("Error running AST extractor on code: %s", e)

        # 3. Crack dynamic chunks (Webpack/Vite/Next.js)
        try:
            manifests = self.chunk_cracker.crack_all_manifests(
                content=js_code,
                base_asset_url=script_url or base_url,
                source_script=script_url,
            )
            if manifests:
                chunk_manifests.extend(manifests)
        except Exception as e:
            logger.warning("Error cracking chunk maps: %s", e)

        # 4. Check for inline source map
        ref = self.sourcemap_unpacker.extract_from_js(js_code, script_url or base_url)
        if ref and ref.is_inline and ref.inline_json:
            sm_result = self.sourcemap_unpacker.extract_from_json(
                ref.inline_json,
                base_source_url=script_url or base_url,
            )
            sm_result.js_url = script_url or None
            sm_result.map_url = "inline"
            sm_result.discovery_source = "inline"
            source_map_results.append(sm_result)

            if sm_result.endpoints:
                endpoints.extend(sm_result.endpoints)

            # Unpack original files and analyze them too
            for file_entry in sm_result.files:
                if file_entry.content:
                    sub_endpoints = self.js_extractor.extract_endpoints(file_entry.content, base_url)
                    sub_configs = self.js_extractor.extract_client_configs(file_entry.content)
                    sub_actions = self.js_extractor.extract_server_actions(file_entry.content)
                    sub_gql = self.graphql_extractor.extract_from_code(file_entry.content)

                    endpoints.extend(sub_endpoints)
                    endpoints.extend(sub_actions)
                    graphql_ops.extend(sub_gql)
                    client_configs = self._merge_client_configs(client_configs, sub_configs)

                    try:
                        sub_ast = self.ast_extractor.extract_all(file_entry.content, base_url=base_url)
                        if sub_ast.get("endpoints"):
                            endpoints.extend(sub_ast["endpoints"])
                        if sub_ast.get("client_configs"):
                            client_configs = self._merge_client_configs(client_configs, sub_ast["client_configs"])
                    except Exception as e:
                        logger.debug("Error running AST extractor on sourcemap file %s: %s", file_entry.path, e)

        # 5. Resolve relative endpoints and deduplicate
        return self._finalize_result(
            endpoints=endpoints,
            graphql_ops=graphql_ops,
            client_configs=client_configs,
            source_map_results=source_map_results,
            base_url=base_url,
            chunk_manifests=chunk_manifests,
        )

    async def analyze_script(
        self,
        script_url: str,
        base_url: str = "",
        client: Optional[httpx.AsyncClient] = None,
    ) -> StaticAnalysisResult:
        """
        Asynchronously fetches script_url:
        - Proactively checks/unpacks source maps via SourceMapUnpacker.fetch_and_unpack.
        - Analyzes both the JS bundle and all unpacked original sourcesContent files.
        - Cracks Webpack/Vite/Next.js chunk manifests.
        """
        if not script_url or not isinstance(script_url, str):
            return StaticAnalysisResult()

        close_client = False
        c = client
        if c is None:
            c = httpx.AsyncClient(
                timeout=httpx.Timeout(self.request_timeout),
                follow_redirects=True,
                verify=False,
            )
            close_client = True

        try:
            try:
                resp = await c.get(script_url)
                if resp.status_code != 200:
                    logger.warning("Failed to fetch script %s (status %d)", script_url, resp.status_code)
                    return StaticAnalysisResult()
                js_content = resp.text
            except Exception as e:
                logger.warning("Exception fetching script %s: %s", script_url, e)
                return StaticAnalysisResult()

            # Proactively check/unpack source maps (handles inline, comment URLs, and probing)
            sm_result = await self.sourcemap_unpacker.fetch_and_unpack(
                script_url,
                js_content=js_content,
                client=c,
            )

            endpoints: List[DiscoveredEndpoint] = []
            graphql_ops: List[GraphQLOperation] = []
            source_map_results: List[SourceMapResult] = []
            chunk_manifests: List[DiscoveredChunkManifest] = []

            # 1. Analyze JS bundle with regex
            endpoints.extend(self.js_extractor.extract_endpoints(js_content, base_url))
            client_configs = self.js_extractor.extract_client_configs(js_content)
            endpoints.extend(self.js_extractor.extract_server_actions(js_content))
            graphql_ops.extend(self.graphql_extractor.extract_from_code(js_content))

            # 2. Analyze JS bundle with AST extractor
            try:
                ast_data = self.ast_extractor.extract_all(js_content, base_url=base_url)
                if ast_data.get("endpoints"):
                    endpoints.extend(ast_data["endpoints"])
                if ast_data.get("client_configs"):
                    client_configs = self._merge_client_configs(client_configs, ast_data["client_configs"])
            except Exception as e:
                logger.warning("Error running AST extractor on %s: %s", script_url, e)

            # 3. Crack dynamic chunks
            try:
                manifests = self.chunk_cracker.crack_all_manifests(
                    content=js_content,
                    base_asset_url=script_url or base_url,
                    source_script=script_url,
                )
                if manifests:
                    chunk_manifests.extend(manifests)
            except Exception as e:
                logger.warning("Error cracking chunk maps from %s: %s", script_url, e)

            # 4. Check source map result
            if sm_result and (sm_result.discovery_source != "none" or sm_result.files):
                source_map_results.append(sm_result)
                if sm_result.endpoints:
                    endpoints.extend(sm_result.endpoints)

                # Analyze all unpacked original sourcesContent files
                for file_entry in sm_result.files:
                    if file_entry.content:
                        sub_endpoints = self.js_extractor.extract_endpoints(file_entry.content, base_url)
                        sub_configs = self.js_extractor.extract_client_configs(file_entry.content)
                        sub_actions = self.js_extractor.extract_server_actions(file_entry.content)
                        sub_gql = self.graphql_extractor.extract_from_code(file_entry.content)

                        endpoints.extend(sub_endpoints)
                        endpoints.extend(sub_actions)
                        graphql_ops.extend(sub_gql)
                        client_configs = self._merge_client_configs(client_configs, sub_configs)

                        try:
                            sub_ast = self.ast_extractor.extract_all(file_entry.content, base_url=base_url)
                            if sub_ast.get("endpoints"):
                                endpoints.extend(sub_ast["endpoints"])
                            if sub_ast.get("client_configs"):
                                client_configs = self._merge_client_configs(client_configs, sub_ast["client_configs"])
                        except Exception as e:
                            logger.debug("Error running AST extractor on sourcemap file %s: %s", file_entry.path, e)

            return self._finalize_result(
                endpoints=endpoints,
                graphql_ops=graphql_ops,
                client_configs=client_configs,
                source_map_results=source_map_results,
                base_url=base_url,
                chunk_manifests=chunk_manifests,
            )
        finally:
            if close_client:
                await c.aclose()

    async def analyze_scripts(
        self,
        script_urls: List[str],
        base_url: str = "",
        concurrency: int = 5,
        client: Optional[httpx.AsyncClient] = None,
    ) -> StaticAnalysisResult:
        """
        Analyzes multiple script URLs concurrently with semaphore bounding.
        Aggregates and deduplicates all endpoints, GraphQL operations, base URLs, and chunk manifests.
        """
        if not script_urls:
            return StaticAnalysisResult()

        conc = concurrency if concurrency > 0 else self.concurrency
        sem = asyncio.Semaphore(conc)

        all_endpoints: List[DiscoveredEndpoint] = []
        all_graphql: List[GraphQLOperation] = []
        all_source_maps: List[SourceMapResult] = []
        all_client_configs: Dict[str, Any] = {}
        all_chunk_manifests: List[DiscoveredChunkManifest] = []

        close_client = False
        c = client
        if c is None:
            c = httpx.AsyncClient(
                timeout=httpx.Timeout(self.request_timeout),
                follow_redirects=True,
                verify=False,
            )
            close_client = True

        try:
            async def _worker(url: str) -> Optional[StaticAnalysisResult]:
                async with sem:
                    try:
                        return await self.analyze_script(url, base_url=base_url, client=c)
                    except Exception as e:
                        logger.warning("Error analyzing script %s: %s", url, e)
                        return None

            tasks = [_worker(u) for u in script_urls]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for res in results:
                if isinstance(res, StaticAnalysisResult):
                    all_endpoints.extend(res.endpoints)
                    all_graphql.extend(res.graphql_operations)
                    all_source_maps.extend(res.source_map_results)
                    all_client_configs = self._merge_client_configs(all_client_configs, res.client_configs)
                    all_chunk_manifests.extend(res.chunk_manifests)

            return self._finalize_result(
                endpoints=all_endpoints,
                graphql_ops=all_graphql,
                client_configs=all_client_configs,
                source_map_results=all_source_maps,
                base_url=base_url,
                chunk_manifests=all_chunk_manifests,
            )
        finally:
            if close_client:
                await c.aclose()
