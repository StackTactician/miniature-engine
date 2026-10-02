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

import httpx

from api_tool.models import (
    DiscoveredEndpoint,
    GraphQLOperation,
    ScanResult,
)
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
        scan_res = ScanResult(
            target_url=self.target_url,
            base_urls=[self.base_url] if self.base_url else [],
            endpoints=self.endpoints,
            graphql_operations=self.graphql_operations,
            discovered_specs=[s.get("url", "") for s in self.specs if s.get("url")],
            discovered_assets=sorted(list(self.assets)),
            metadata={
                "summary": self.summary,
                "client_configs": self.client_configs,
                "elapsed_seconds": round(self.end_time - self.start_time, 2) if self.end_time else 0.0,
            },
        )
        data = scan_res.to_dict()
        # Include detailed specs, graphql, scripts, and sourcemap lists for UI
        data["specs_detailed"] = self.specs
        data["graphql_detailed"] = self.graphql_results
        data["scripts_detailed"] = sorted(list(self.scripts))
        data["sourcemaps_detailed"] = self.sourcemap_results
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
        self.summary.clear()
        self.error_message = None

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

        self.add_log("INFO", f"Target configured: {norm_url} (Domain: {target_domain}, Base: {self.base_url})", "runner")
        self.add_log(
            "INFO",
            f"Config: crawl={opt_crawl}(d={opt_depth},p={opt_pages}), manifest={opt_manifest}, "
            f"static={opt_static}, probe={opt_probe}(specs={opt_specs},gql={opt_graphql},http={opt_http}), "
            f"passive={opt_passive}, private_ips={opt_allow_private}",
            "runner",
        )

        collected_endpoints: List[DiscoveredEndpoint] = []
        collected_scripts: Set[str] = set()
        collected_assets: Set[str] = set()

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(12.0),
            follow_redirects=True,
            verify=False,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Linux; Android 10; Mobile) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36 api-tool/0.1.0"
                )
            },
        ) as client:
            # -------------------------------------------------------------
            # Stage 1: Framework Manifest Discovery
            # -------------------------------------------------------------
            if opt_manifest:
                self.stage = "manifest"
                self.add_log("INFO", f"[1/5] Extracting framework manifests (Next.js, Nuxt, Webpack) from {norm_url}...", "manifest")
                try:
                    extractor = ManifestExtractor(request_timeout=10.0)
                    manifest_res = await extractor.fetch_and_extract(self.base_url, client=client)
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
                        max_depth=opt_depth,
                        max_pages=opt_pages,
                        concurrency=opt_concurrency,
                        client=client,
                    )
                    crawl_res = await spider.crawl(norm_url)
                    self.add_log(
                        "INFO",
                        f"Crawler completed: {len(crawl_res.visited_urls)} pages visited, "
                        f"{len(crawl_res.endpoints)} endpoints, {len(crawl_res.scripts)} scripts, {len(crawl_res.assets)} assets.",
                        "crawler",
                    )
                    for ep in crawl_res.endpoints:
                        collected_endpoints.append(ep)
                    for sc in crawl_res.scripts:
                        collected_scripts.add(sc)
                    for asst in crawl_res.assets:
                        collected_assets.add(asst)

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
                        f"Static analysis finished: {len(static_res.endpoints)} endpoints, "
                        f"{len(static_res.graphql_operations)} GraphQL queries, "
                        f"{len(static_res.source_map_results)} source maps processed.",
                        "analyzer",
                    )
                    for ep in static_res.endpoints:
                        collected_endpoints.append(ep)
                    for gop in static_res.graphql_operations:
                        self.graphql_operations.append(gop)

                    self.client_configs = static_res.client_configs
                    self.sourcemap_results = [sm.to_dict() for sm in static_res.source_map_results]
                    self.endpoints = list(collected_endpoints)
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

        self.stage = "completed"
        self.add_log(
            "INFO",
            f"Pipeline complete! Total endpoints: {len(self.endpoints)}, Specs: {len(self.specs)}, "
            f"GraphQL: {len(self.graphql_results)}, Scripts: {len(self.scripts)}",
            "runner",
        )
