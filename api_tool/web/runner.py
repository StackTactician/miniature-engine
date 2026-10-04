"""
Asynchronous Scan Orchestrator for api-tool Web Interface.
Coordinates crawler, manifest extractor, static analyzer, passive OSINT, and probers
while capturing and streaming all events and logs in real-time.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import logging
import time
import traceback
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlsplit

from api_tool.models import (
    DiscoveredEndpoint,
    DiscoveredChunkManifest,
    GraphQLOperation,
    ScanResult,
)
from api_tool.network.client import StealthAsyncClient, BrowserProfile
from api_tool.network.challenge import WAFDetector, RedditPoWSolver
from api_tool.runtime.dom_engine import HappyDOMEngine
from api_tool.spider.scope_resolver import CDNScopeResolver
from api_tool.spider.crawler import AsyncSpider, URLNormalizer
from api_tool.spider.manifest import ManifestExtractor, ManifestResult
from api_tool.spider.passive import PassiveHarvester, PassiveHarvestResult
from api_tool.analyzer.coordinator import StaticAnalyzer, StaticAnalysisResult
from api_tool.prober.coordinator import APIProber, ProberResult

logger = logging.getLogger(__name__)


class RunnerLogHandler(logging.Handler):
    """Logging handler that pipes logs into the ScanRunner's in-memory log buffer."""

    def __init__(self, runner: "ScanRunner") -> None:
        super().__init__()
        self.runner = runner
        self.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s", datefmt="%H:%M:%S")
        )

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = record.getMessage()
            self.runner.add_log(
                level=record.levelname,
                message=msg,
                logger_name=record.name,
            )
        except Exception:
            pass


class ScanRunner:
    """Manages active scan execution, state transitions, log interception, and result aggregation."""

    def __init__(self) -> None:
        self.target_url: str = ""
        self.base_url: str = ""
        self.status: str = "idle"  # idle, running, completed, error, stopped
        self.stage: str = "idle"
        self.start_time: float = 0.0
        self.end_time: float = 0.0
        self.logs: List[Dict[str, Any]] = []
        self.log_lock = asyncio.Lock()
        self.active_task: Optional[asyncio.Task] = None
        self._log_handler: Optional[RunnerLogHandler] = None

        # Data collections
        self.endpoints: List[DiscoveredEndpoint] = []
        self.scripts: Set[str] = set()
        self.assets: Set[str] = set()
        self.specs: List[Dict[str, Any]] = []
        self.graphql_results: List[Dict[str, Any]] = []
        self.graphql_operations: List[GraphQLOperation] = []
        self.client_configs: Dict[str, Any] = {}
        self.sourcemap_results: List[Dict[str, Any]] = []
        self.chunk_manifests: List[Dict[str, Any]] = []
        self.forms: List[Dict[str, Any]] = []
        self.hydration_endpoints: List[Dict[str, Any]] = []
        self.passive_seeds: List[str] = []
        self.summary: Dict[str, Any] = {}
        self.error_message: Optional[str] = None

    def add_log(self, level: str, message: str, logger_name: str = "api_tool") -> None:
        """Appends a log record with timestamp to the buffer."""
        now = datetime.now(timezone.utc).strftime("%H:%M:%S")
        entry = {
            "index": len(self.logs),
            "time": now,
            "level": level.upper(),
            "logger": logger_name,
            "message": message,
            "stage": self.stage,
        }
        self.logs.append(entry)

    def get_status(self) -> Dict[str, Any]:
        """Returns the current execution state and statistics."""
        elapsed = 0.0
        if self.start_time > 0:
            if self.end_time > 0:
                elapsed = round(self.end_time - self.start_time, 2)
            else:
                elapsed = round(time.time() - self.start_time, 2)

        return {
            "target_url": self.target_url,
            "base_url": self.base_url,
            "status": self.status,
            "stage": self.stage,
            "elapsed_seconds": elapsed,
            "counts": {
                "endpoints": len(self.endpoints),
                "specs": len(self.specs),
                "graphql": len(self.graphql_results),
                "graphql_operations": len(self.graphql_operations),
                "scripts": len(self.scripts),
                "assets": len(self.assets),
                "chunk_manifests": len(self.chunk_manifests),
                "forms": len(self.forms),
                "hydration_endpoints": len(self.hydration_endpoints),
                "passive_seeds": len(self.passive_seeds),
                "logs": len(self.logs),
            },
            "summary": self.summary,
            "error": self.error_message,
        }

    def get_logs(self, offset: int = 0) -> List[Dict[str, Any]]:
        """Returns logs starting from index offset."""
        if offset < 0:
            offset = 0
        if offset >= len(self.logs):
            return []
        return self.logs[offset:]

    def get_results(self) -> Dict[str, Any]:
        """Serializes current scan findings to dictionary."""
        chunk_manifest_objs = [
            DiscoveredChunkManifest.from_dict(cm) if isinstance(cm, dict) else cm
            for cm in self.chunk_manifests
        ]
        scan_res = ScanResult(
            target_url=self.target_url,
            base_urls=[self.base_url] if self.base_url else [],
            endpoints=self.endpoints,
            graphql_operations=self.graphql_operations,
            discovered_specs=[s.get("url", "") for s in self.specs if s.get("url")],
            discovered_assets=sorted(list(self.assets)),
            chunk_manifests=chunk_manifest_objs,
            metadata={
                "summary": self.summary,
                "client_configs": self.client_configs,
                "elapsed_seconds": round(self.end_time - self.start_time, 2) if self.end_time else 0.0,
                "counts": {
                    "endpoints": len(self.endpoints),
                    "forms": len(self.forms),
                    "hydration": len(self.hydration_endpoints),
                    "passive_seeds": len(self.passive_seeds),
                },
            },
        )
        data = scan_res.to_dict()
        # Include detailed specs, graphql, scripts, sourcemaps, forms, and hydration for UI
        data["specs_detailed"] = self.specs
        data["graphql_detailed"] = self.graphql_results
        data["scripts_detailed"] = sorted(list(self.scripts))
        data["sourcemaps_detailed"] = self.sourcemap_results
        data["chunk_manifests_detailed"] = self.chunk_manifests
        data["forms_detailed"] = self.forms
        data["hydration_detailed"] = self.hydration_endpoints
        data["passive_seeds_detailed"] = self.passive_seeds
        return data

    def stop_scan(self) -> bool:
        """Cancels active running scan task."""
        if self.active_task and not self.active_task.done():
            self.active_task.cancel()
            self.add_log("WARNING", "Abort requested by user. Terminating active tasks...", "runner")
            self.status = "stopped"
            self.stage = "stopped"
            self.end_time = time.time()
            return True
        return False

    def clear(self) -> None:
        """Resets all data and logs."""
        if self.status == "running":
            self.stop_scan()
        self.target_url = ""
        self.base_url = ""
        self.status = "idle"
        self.stage = "idle"
        self.start_time = 0.0
        self.end_time = 0.0
        self.logs.clear()
        self.endpoints.clear()
        self.scripts.clear()
        self.assets.clear()
        self.specs.clear()
        self.graphql_results.clear()
        self.graphql_operations.clear()
        self.client_configs.clear()
        self.sourcemap_results.clear()
        self.chunk_manifests.clear()
        self.forms.clear()
        self.hydration_endpoints.clear()
        self.passive_seeds.clear()
        self.summary.clear()
        self.error_message = None

    def load_from_scan_result(self, scan_result: ScanResult) -> None:
        """Populates ScanRunner state from an imported ScanResult (e.g. from HARImporter)."""
        self.clear()
        self.target_url = scan_result.target_url
        if scan_result.base_urls:
            self.base_url = scan_result.base_urls[0]
        self.status = "completed"
        self.stage = "imported"
        self.endpoints = list(scan_result.endpoints)
        self.graphql_operations = list(scan_result.graphql_operations)
        for s in scan_result.discovered_specs:
            self.specs.append({"url": s, "type": "openapi"})
        for op in scan_result.graphql_operations:
            self.graphql_results.append(op.to_dict())
        for a in scan_result.discovered_assets:
            self.assets.add(a)
        if scan_result.chunk_manifests:
            self.chunk_manifests = [cm.to_dict() for cm in scan_result.chunk_manifests]
        if "forms" in scan_result.metadata:
            self.forms = list(scan_result.metadata["forms"])
        if "hydration_endpoints" in scan_result.metadata:
            self.hydration_endpoints = list(scan_result.metadata["hydration_endpoints"])
        if "passive_seeds" in scan_result.metadata:
            self.passive_seeds = list(scan_result.metadata["passive_seeds"])
        self.summary = dict(scan_result.metadata.get("summary", scan_result.metadata))
        self.add_log(
            "INFO",
            f"Loaded {len(self.endpoints)} endpoints and {len(self.graphql_operations)} GraphQL ops from import",
            "importer",
        )

    async def run(self, target_url: str, options: Optional[Dict[str, Any]] = None) -> None:
        """Main entry point to execute the complete API tool discovery workflow."""
        options = options or {}
        self.clear()
        self.target_url = target_url.strip()
        self.status = "running"
        self.start_time = time.time()
        self.end_time = 0.0

        # Hook log interception
        root_logger = logging.getLogger()
        self._log_handler = RunnerLogHandler(self)
        root_logger.addHandler(self._log_handler)

        try:
            await self._execute_pipeline(options)
            if self.status != "stopped":
                self.status = "completed"
                self.stage = "finished"
        except asyncio.CancelledError:
            self.status = "stopped"
            self.stage = "stopped"
            self.add_log("WARNING", "Scan cancelled by user.", "runner")
        except Exception as exc:
            self.status = "error"
            self.stage = "error"
            self.error_message = str(exc)
            tb = traceback.format_exc()
            self.add_log("ERROR", f"Pipeline fatal error: {exc}\n{tb}", "runner")
        finally:
            self.end_time = time.time()
            if self._log_handler:
                root_logger.removeHandler(self._log_handler)
                self._log_handler = None
            elapsed = round(self.end_time - self.start_time, 2)
            self.add_log("INFO", f"Scan finished with status '{self.status}' in {elapsed}s.", "runner")

    async def _execute_pipeline(self, opts: Dict[str, Any]) -> None:
        # 1. URL Validation & Base Setup
        url = self.target_url
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"
            self.target_url = url

        normalizer = URLNormalizer()
        norm_url = normalizer.normalize(url)
        if not norm_url:
            raise ValueError(f"Invalid target URL: '{self.target_url}'")

        parsed = urlsplit(norm_url)
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        target_domain = parsed.netloc.split(":")[0]

        # Extract options
        opt_crawl = opts.get("crawl", True)
        opt_depth = int(opts.get("max_depth", 2))
        opt_pages = int(opts.get("max_pages", 30))
        opt_manifest = opts.get("manifest", True)
        opt_static = opts.get("static_analysis", True)
        opt_probe = opts.get("probe", True)
        opt_specs = opts.get("probe_specs", True)
        opt_graphql = opts.get("probe_graphql", True)
        opt_http = opts.get("probe_http", True)
        opt_intro = opts.get("run_introspection", True)
        opt_passive = opts.get("passive_osint", False)
        opt_allow_private = opts.get("allow_private_ips", False)
        opt_concurrency = int(opts.get("concurrency", 5))
        opt_rate_limit = float(opts.get("rate_limit", 10.0))

        opt_crawl_forms = opts.get("crawl_forms", True)
        opt_crawl_hydration = opts.get("crawl_hydration", True)
        opt_passive_seeds = opts.get("passive_seeds", False)
        opt_block_dangerous = opts.get("block_dangerous_actions", True)
        opt_block_rabbit = opts.get("block_rabbit_holes", True)
        opt_include_regex = opts.get("include_regex")
        opt_exclude_regex = opts.get("exclude_regex")

        self.add_log("INFO", f"Target configured: {norm_url} (Domain: {target_domain}, Base: {self.base_url})", "runner")
        self.add_log(
            "INFO",
            f"Config: crawl={opt_crawl}(d={opt_depth},p={opt_pages},forms={opt_crawl_forms},hydration={opt_crawl_hydration},seeds={opt_passive_seeds}), "
            f"manifest={opt_manifest}, static={opt_static}, probe={opt_probe}(specs={opt_specs},gql={opt_graphql},http={opt_http}), "
            f"passive={opt_passive}, private_ips={opt_allow_private}",
            "runner",
        )

        collected_endpoints: List[DiscoveredEndpoint] = []
        collected_scripts: Set[str] = set()
        collected_assets: Set[str] = set()

        # Instantiate CDNScopeResolver
        scope_resolver = CDNScopeResolver(target_domains=[target_domain])

        # Configure StealthAsyncClient with Chrome 120 profile and mock transport detection
        mock_transport = opts.get("transport") or opts.get("mock_transport")
        mock_client = opts.get("client") or opts.get("mock_client")

        client_kwargs: Dict[str, Any] = {
            "timeout": 15.0,
            "follow_redirects": True,
            "verify": False,
        }
        if mock_client is not None:
            client_kwargs["mock_client"] = mock_client
        elif mock_transport is not None:
            client_kwargs["mock_transport"] = mock_transport
        else:
            client_kwargs["impersonate"] = "chrome120"

        async with StealthAsyncClient(**client_kwargs) as client:
            # Step 0: Initial fetch for CSP, WAF detection, and SPA dynamic evaluation
            initial_html = ""
            waf_detector = WAFDetector()
            try:
                init_resp = await client.get(norm_url)
                initial_html = init_resp.text
                if "content-security-policy" in init_resp.headers:
                    scope_resolver.update_from_csp(init_resp.headers["content-security-policy"])
                if "content-security-policy-report-only" in init_resp.headers:
                    scope_resolver.update_from_csp(init_resp.headers["content-security-policy-report-only"])

                waf_res = waf_detector.detect(init_resp)
                if waf_res.detected:
                    self.add_log("WARNING", f"WAF / Challenge detected: {waf_res.waf_name} ({waf_res.challenge_type})", "security")
                    if waf_res.waf_name == "reddit_pow":
                        if waf_res.challenge_type == "js_challenge":
                            js_chal = waf_res.details
                            self.add_log("INFO", f"Solving Reddit inline JS challenge (seed={js_chal.get('seed')})...", "security")
                            from urllib.parse import urljoin
                            chal_url = urljoin(self.base_url, js_chal.get("action", "/"))
                            chal_resp = await client.get(chal_url, params=js_chal.get("inputs", {}))
                            if chal_resp.status_code == 200 and len(chal_resp.text) > len(initial_html):
                                self.add_log("INFO", f"Reddit challenge solved successfully! (Received full HTML: {len(chal_resp.text)} bytes)", "security")
                                initial_html = chal_resp.text
                                if "content-security-policy" in chal_resp.headers:
                                    scope_resolver.update_from_csp(chal_resp.headers["content-security-policy"])
                        else:
                            self.add_log("INFO", "Solving Reddit PoW challenge...", "security")
                            pow_solver = RedditPoWSolver()
                            chal = pow_solver.extract_challenge(init_resp)
                            if chal and chal.get("nonce"):
                                sol = pow_solver.solve(chal["nonce"], chal.get("difficulty", 4))
                                self.add_log("INFO", f"Solved Reddit PoW challenge in {sol.elapsed_ms:.2f}ms", "security")

                # If dynamic SPA markers or challenge detected, evaluate dynamic DOM with HappyDOMEngine
                spa_markers = ("<div id=\"root\"", "<div id=\"app\"", "<div id=\"__next\"", "challenge", "turnstile", "shreddit")
                if any(m in initial_html.lower() for m in spa_markers) or waf_res.detected:
                    try:
                        self.add_log("INFO", "Evaluating dynamic JavaScript SPA with HappyDOMEngine...", "runtime")
                        dom_data = await HappyDOMEngine.evaluate(norm_url, initial_html, timeout=10.0)
                        if dom_data.get("dynamic_endpoints"):
                            self.add_log("INFO", f"Happy-DOM intercepted {len(dom_data['dynamic_endpoints'])} dynamic API calls", "runtime")
                            for dep in dom_data["dynamic_endpoints"]:
                                d_url = dep.get("url", "")
                                p_url = urlsplit(d_url)
                                dep_base = f"{p_url.scheme}://{p_url.netloc}" if p_url.netloc else self.base_url
                                ep = DiscoveredEndpoint(
                                    path=p_url.path or "/",
                                    method=dep.get("method", "GET"),
                                    base_url=dep_base,
                                    source="happy_dom",
                                    tags=["happy_dom", "dynamic_spa"],
                                    summary=f"Dynamic API call: {d_url}",
                                )
                                collected_endpoints.append(ep)
                        if dom_data.get("discovered_links"):
                            for link in dom_data["discovered_links"]:
                                if link.endswith(".js") and scope_resolver.is_asset_in_scope(link):
                                    collected_scripts.add(link)
                    except Exception as dom_exc:
                        self.add_log("WARNING", f"HappyDOMEngine evaluation skipped: {dom_exc}", "runtime")
            except Exception as init_exc:
                self.add_log("WARNING", f"Initial probe encountered an error: {init_exc}", "runner")

            # -------------------------------------------------------------
            # Stage 1: Framework Manifest Discovery
            # -------------------------------------------------------------
            if opt_manifest:
                self.stage = "manifest"
                self.add_log("INFO", f"[1/5] Extracting framework manifests (Next.js, Nuxt, Webpack) from {norm_url}...", "manifest")
                try:
                    extractor = ManifestExtractor(request_timeout=10.0)
                    manifest_res = await extractor.fetch_and_extract(
                        self.base_url,
                        html=initial_html if initial_html else None,
                        client=client,
                    )
                    if manifest_res.framework:
                        self.add_log(
                            "INFO",
                            f"Framework detected: '{manifest_res.framework}', buildId='{manifest_res.build_id or 'none'}', "
                            f"{len(manifest_res.routes)} routes, {len(manifest_res.chunk_scripts)} chunks",
                            "manifest",
                        )
                    else:
                        self.add_log("INFO", "No framework manifest signatures identified in initial response.", "manifest")

                    for ep in manifest_res.endpoints:
                        collected_endpoints.append(ep)
                    for chunk in manifest_res.chunk_scripts:
                        collected_scripts.add(chunk)

                    self.endpoints = list(collected_endpoints)
                    self.scripts = set(collected_scripts)
                except Exception as exc:
                    self.add_log("WARNING", f"Manifest extraction encountered an error: {exc}", "manifest")

            # -------------------------------------------------------------
            # Stage 2: Web Crawler / Spider
            # -------------------------------------------------------------
            if opt_crawl:
                self.stage = "crawler"
                self.add_log(
                    "INFO",
                    f"[2/5] Launching async crawler on {norm_url} (depth={opt_depth}, max_pages={opt_pages}, concurrency={opt_concurrency})...",
                    "crawler",
                )
                try:
                    spider = AsyncSpider(
                        allowed_domains=[target_domain],
                        scope_resolver=scope_resolver,
                        max_depth=opt_depth,
                        max_pages=opt_pages,
                        concurrency=opt_concurrency,
                        client=client,
                        crawl_forms=opt_crawl_forms,
                        crawl_hydration=opt_crawl_hydration,
                        passive_seeds=opt_passive_seeds,
                        allow_private_ips=opt_allow_private,
                        block_dangerous_actions=opt_block_dangerous,
                        block_rabbit_holes=opt_block_rabbit,
                        include_regex=opt_include_regex,
                        exclude_regex=opt_exclude_regex,
                    )
                    crawl_res = await spider.crawl(norm_url)
                    self.add_log(
                        "INFO",
                        f"Crawler completed: {len(crawl_res.visited_urls)} pages visited, "
                        f"{len(crawl_res.endpoints)} endpoints ({len(crawl_res.forms)} forms, {len(crawl_res.hydration_endpoints)} hydration), "
                        f"{len(crawl_res.scripts)} scripts, {len(crawl_res.assets)} assets.",
                        "crawler",
                    )
                    for ep in crawl_res.endpoints:
                        collected_endpoints.append(ep)
                    for sc in crawl_res.scripts:
                        collected_scripts.add(sc)
                    for asst in crawl_res.assets:
                        collected_assets.add(asst)

                    self.forms = [f.to_dict() if hasattr(f, "to_dict") else f for f in crawl_res.forms]
                    self.hydration_endpoints = [
                        h.to_dict() if hasattr(h, "to_dict") else h for h in crawl_res.hydration_endpoints
                    ]
                    self.passive_seeds = list(
                        dict.fromkeys(crawl_res.passive_seeds + crawl_res.disallowed_seeds)
                    )

                    if crawl_res.failed_urls:
                        self.add_log("WARNING", f"{len(crawl_res.failed_urls)} URLs failed during crawl.", "crawler")

                    self.endpoints = list(collected_endpoints)
                    self.scripts = set(collected_scripts)
                    self.assets = set(collected_assets)
                except Exception as exc:
                    self.add_log("ERROR", f"Crawler failed: {exc}", "crawler")

            # -------------------------------------------------------------
            # Stage 3: Passive OSINT Harvesting (Optional)
            # -------------------------------------------------------------
            if opt_passive:
                self.stage = "passive_osint"
                self.add_log("INFO", f"[3/5] Querying Wayback Machine and AlienVault OTX for '{target_domain}'...", "passive")
                try:
                    harvester = PassiveHarvester(client=client)
                    harvest_res = await harvester.harvest_all(target_domain)
                    self.add_log(
                        "INFO",
                        f"Passive OSINT harvested {harvest_res.total_urls} historical URLs, "
                        f"{len(harvest_res.endpoints)} candidate endpoints, {len(harvest_res.scripts)} scripts.",
                        "passive",
                    )
                    for ep in harvest_res.endpoints:
                        collected_endpoints.append(ep)
                    for sc in harvest_res.scripts:
                        collected_scripts.add(sc)
                    if harvest_res.errors:
                        for src, err in harvest_res.errors.items():
                            self.add_log("WARNING", f"Passive OSINT source '{src}' error: {err}", "passive")

                    self.endpoints = list(collected_endpoints)
                    self.scripts = set(collected_scripts)
                except Exception as exc:
                    self.add_log("WARNING", f"Passive OSINT encountered an error: {exc}", "passive")

            # -------------------------------------------------------------
            # Stage 4: Static JS & Source Map Analysis
            # -------------------------------------------------------------
            if opt_static and collected_scripts:
                self.stage = "static_analysis"
                script_list = sorted(list(collected_scripts))
                self.add_log(
                    "INFO",
                    f"[4/5] Analyzing {len(script_list)} JavaScript bundles & source maps with StaticAnalyzer...",
                    "analyzer",
                )
                try:
                    analyzer = StaticAnalyzer(concurrency=opt_concurrency, request_timeout=15.0)
                    static_res: StaticAnalysisResult = await analyzer.analyze_scripts(
                        script_list,
                        base_url=self.base_url,
                        concurrency=opt_concurrency,
                        client=client,
                    )
                    self.add_log(
                        "INFO",
                        f"Static analysis Pass 1 finished: {len(static_res.endpoints)} endpoints, "
                        f"{len(static_res.graphql_operations)} GraphQL queries, "
                        f"{len(static_res.source_map_results)} source maps, "
                        f"{len(static_res.chunk_manifests)} chunk manifests processed.",
                        "analyzer",
                    )
                    for ep in static_res.endpoints:
                        collected_endpoints.append(ep)
                    for gop in static_res.graphql_operations:
                        self.graphql_operations.append(gop)

                    self.client_configs = static_res.client_configs
                    self.sourcemap_results = [sm.to_dict() for sm in static_res.source_map_results]

                    # Iterative Chunk Cracking Pass 2
                    all_chunk_urls: Set[str] = set()
                    for cm in static_res.chunk_manifests:
                        self.chunk_manifests.append(cm.to_dict())
                        for cu in cm.chunk_urls:
                            if cu not in collected_scripts and scope_resolver.is_asset_in_scope(cu):
                                all_chunk_urls.add(cu)

                    if all_chunk_urls:
                        new_chunks = sorted(list(all_chunk_urls))
                        self.add_log(
                            "INFO",
                            f"Discovered {len(new_chunks)} cracked chunk scripts! Fetching and analyzing in Pass 2...",
                            "analyzer",
                        )
                        for cu in new_chunks:
                            collected_scripts.add(cu)

                        pass2_res = await analyzer.analyze_scripts(
                            new_chunks,
                            base_url=self.base_url,
                            concurrency=opt_concurrency,
                            client=client,
                        )
                        self.add_log(
                            "INFO",
                            f"Static analysis Pass 2 finished: +{len(pass2_res.endpoints)} endpoints, "
                            f"+{len(pass2_res.graphql_operations)} GraphQL queries.",
                            "analyzer",
                        )
                        for ep in pass2_res.endpoints:
                            collected_endpoints.append(ep)
                        for gop in pass2_res.graphql_operations:
                            self.graphql_operations.append(gop)
                        for cm in pass2_res.chunk_manifests:
                            self.chunk_manifests.append(cm.to_dict())
                        for sm in pass2_res.source_map_results:
                            self.sourcemap_results.append(sm.to_dict())
                        self.client_configs = StaticAnalyzer._merge_client_configs(
                            self.client_configs, pass2_res.client_configs
                        )

                    self.endpoints = list(collected_endpoints)
                    self.scripts = set(collected_scripts)
                except Exception as exc:
                    self.add_log("ERROR", f"Static analysis failed: {exc}", "analyzer")

            # -------------------------------------------------------------
            # Stage 5: Active API Prober (Specs, GraphQL, Safe HTTP)
            # -------------------------------------------------------------
            if opt_probe:
                self.stage = "prober"
                self.add_log(
                    "INFO",
                    f"[5/5] Running API Prober (Specs: {opt_specs}, GraphQL: {opt_graphql}, HTTP: {opt_http}, "
                    f"Introspection: {opt_intro}, AllowPrivate: {opt_allow_private})...",
                    "prober",
                )
                try:
                    prober = APIProber(
                        rate_limit=opt_rate_limit,
                        concurrency=opt_concurrency,
                        allow_private_ips=opt_allow_private,
                    )
                    prober_res: ProberResult = await prober.probe(
                        base_url=self.base_url,
                        endpoints=collected_endpoints,
                        probe_specs=opt_specs,
                        probe_graphql=opt_graphql,
                        probe_http=opt_http,
                        run_introspection=opt_intro,
                        client=client,
                    )

                    self.endpoints = prober_res.probed_endpoints
                    self.specs = [s.to_dict() for s in prober_res.discovered_specs]
                    self.graphql_results = [g.to_dict() for g in prober_res.graphql_results]
                    self.summary = prober_res.summary

                    self.add_log(
                        "INFO",
                        f"Prober finished: {len(self.endpoints)} unique endpoints, {len(self.specs)} specs found, "
                        f"{len(self.graphql_results)} active GraphQL services.",
                        "prober",
                    )
                    if self.summary:
                        self.add_log("INFO", f"Summary stats: {json.dumps(self.summary)}", "prober")
                except Exception as exc:
                    self.add_log("ERROR", f"Probing encountered an error: {exc}", "prober")
            else:
                # Deduplicate without probing
                self.endpoints = APIProber._deduplicate_endpoints(collected_endpoints, self.base_url)

        self.summary["forms"] = len(self.forms)
        self.summary["hydration_endpoints"] = len(self.hydration_endpoints)
        self.summary["passive_seeds"] = len(self.passive_seeds)
        self.stage = "completed"
        self.add_log(
            "INFO",
            f"Pipeline complete! Total endpoints: {len(self.endpoints)}, Specs: {len(self.specs)}, "
            f"GraphQL: {len(self.graphql_results)}, Scripts: {len(self.scripts)}",
            "runner",
        )
