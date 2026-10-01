"""
Unified API Prober Coordinator module for api-tool.

Orchestrates:
1. OpenAPI / Swagger / documentation discovery via SpecFinder.
2. GraphQL service probing and introspection via GraphQLProber.
3. Safe rate-limited HTTP probing and CORS reflection verification via SafeHTTPProber.
4. Intelligent merging and deduplication of discovered endpoints by (path, method).
5. Comprehensive diagnostic summary statistics generation.

Pure Python 3 / httpx / aiolimiter / graphql-core, 100% portable on Termux/Linux.
"""

from __future__ import annotations

import asyncio
import copy
from dataclasses import asdict, dataclass, field
import json
import logging
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlsplit

import httpx

from api_tool.models import (
    DiscoveredEndpoint,
    DiscoveredParameter,
    DiscoveredResponse,
)
from api_tool.prober.spec_finder import DiscoveredSpec, SpecFinder
from api_tool.prober.http_prober import SafeHTTPProber, ProbeResult, is_safe_target
from api_tool.prober.graphql_prober import GraphQLProber, GraphQLProbeResult

logger = logging.getLogger(__name__)


@dataclass
class ProberResult:
    """
    Unified result container for the API Prober coordinator.
    Aggregates probed endpoints, discovered specifications, GraphQL services,
    HTTP probe outcomes, and diagnostic summary metrics.
    """

    probed_endpoints: List[DiscoveredEndpoint] = field(default_factory=list)
    discovered_specs: List[DiscoveredSpec] = field(default_factory=list)
    graphql_results: List[GraphQLProbeResult] = field(default_factory=list)
    http_probe_results: List[ProbeResult] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the probe outcome and all nested models into a JSON-serializable dictionary."""
        return {
            "probed_endpoints": [
                e.to_dict() if hasattr(e, "to_dict") else asdict(e)
                for e in self.probed_endpoints
            ],
            "discovered_specs": [
                s.to_dict() if hasattr(s, "to_dict") else asdict(s)
                for s in self.discovered_specs
            ],
            "graphql_results": [
                g.to_dict() if hasattr(g, "to_dict") else asdict(g)
                for g in self.graphql_results
            ],
            "http_probe_results": [
                h.to_dict() if hasattr(h, "to_dict") else asdict(h)
                for h in self.http_probe_results
            ],
            "summary": dict(self.summary),
        }

    def to_json(self, indent: int = 2) -> str:
        """Serializes the probe outcome into a formatted JSON string."""
        return json.dumps(self.to_dict(), indent=indent)


class APIProber:
    """
    Unified API Prober Coordinator.
    Coordinates specification discovery, GraphQL probing, and safe active HTTP route verification.
    """

    def __init__(
        self,
        rate_limit: float = 10.0,
        concurrency: int = 5,
        request_timeout: float = 10.0,
        allow_private_ips: bool = False,
        user_agent: Optional[str] = None,
    ) -> None:
        self.rate_limit = rate_limit
        self.concurrency = concurrency
        self.request_timeout = request_timeout
        self.allow_private_ips = allow_private_ips
        self.user_agent = user_agent or "api-tool/1.0 (Safe API Prober)"

        # Initialize underlying engines with matching parameters
        self.spec_finder = SpecFinder()
        self.http_prober = SafeHTTPProber(
            rate_limit=self.rate_limit,
            concurrency=self.concurrency,
            request_timeout=self.request_timeout,
            user_agent=self.user_agent,
            allow_private_ips=self.allow_private_ips,
        )
        self.graphql_prober = GraphQLProber(
            timeout=self.request_timeout,
            headers={"User-Agent": self.user_agent},
        )

    @staticmethod
    def _normalize_endpoint(ep: DiscoveredEndpoint, default_base_url: str) -> DiscoveredEndpoint:
        """
        Normalizes an endpoint's path, base_url, and method.
        Handles full URLs in ep.path, leading slashes, and default base URLs.
        """
        raw_path = ep.path or "/"

        # If path is an absolute URL, parse it into base_url and path
        if raw_path.startswith("http://") or raw_path.startswith("https://"):
            parsed = urlsplit(raw_path)
            base = f"{parsed.scheme}://{parsed.netloc}"
            ep.base_url = ep.base_url or base
            ep.path = parsed.path or "/"
        else:
            ep.path = raw_path

        if not ep.base_url and default_base_url:
            ep.base_url = default_base_url

        # Ensure normalized leading slash for relative paths
        if not ep.path.startswith("/") and not (
            ep.path.startswith("http://") or ep.path.startswith("https://")
        ):
            ep.path = f"/{ep.path}"

        # Strip trailing slash if path is longer than 1 character
        if len(ep.path) > 1 and ep.path.endswith("/"):
            ep.path = ep.path.rstrip("/")

        # Normalize HTTP method to uppercase
        ep.method = (ep.method or "GET").upper()
        return ep

    @staticmethod
    def _merge_endpoints(
        existing: DiscoveredEndpoint,
        incoming: DiscoveredEndpoint,
    ) -> DiscoveredEndpoint:
        """
        Merges metadata from incoming endpoint into existing endpoint in-place.
        Prioritizes high-fidelity spec sources over static/crawler sources.
        """
        # Prefer spec source over static/crawler
        if incoming.source == "spec" and existing.source != "spec":
            existing.source = "spec"

        # Merge tags without duplicates
        for tag in incoming.tags:
            if tag not in existing.tags:
                existing.tags.append(tag)

        # Merge parameters by (location, name)
        existing_params = {(p.location, p.name): p for p in existing.parameters}
        for p in incoming.parameters:
            key = (p.location, p.name)
            if key not in existing_params:
                existing.parameters.append(p)
                existing_params[key] = p
            else:
                curr = existing_params[key]
                if not curr.description and p.description:
                    curr.description = p.description
                if curr.example is None and p.example is not None:
                    curr.example = p.example
                if (curr.param_type == "string" or not curr.param_type) and p.param_type != "string":
                    curr.param_type = p.param_type
                if not curr.required and p.required:
                    curr.required = p.required

        # Merge request body sample & schema
        if not existing.request_body_sample and incoming.request_body_sample is not None:
            existing.request_body_sample = incoming.request_body_sample
        if not existing.request_body_schema and incoming.request_body_schema:
            existing.request_body_schema = incoming.request_body_schema

        # Merge responses by status_code
        existing_resps = {r.status_code: r for r in existing.responses}
        for r in incoming.responses:
            if r.status_code not in existing_resps:
                existing.responses.append(r)
                existing_resps[r.status_code] = r
            else:
                curr_r = existing_resps[r.status_code]
                if not curr_r.inferred_schema and r.inferred_schema:
                    curr_r.inferred_schema = r.inferred_schema
                if curr_r.sample_body is None and r.sample_body is not None:
                    curr_r.sample_body = r.sample_body

        # Merge auth info
        if not existing.auth_type and incoming.auth_type:
            existing.auth_type = incoming.auth_type
        if not existing.auth_header_or_param and incoming.auth_header_or_param:
            existing.auth_header_or_param = incoming.auth_header_or_param

        # Merge summary and description
        if not existing.summary and incoming.summary:
            existing.summary = incoming.summary
        elif (
            existing.summary
            and existing.summary.startswith("Extracted REST endpoint")
            and incoming.summary
        ):
            existing.summary = incoming.summary

        if not existing.description and incoming.description:
            existing.description = incoming.description

        # Merge active status if incoming has active status
        if existing.active_status is None and incoming.active_status is not None:
            existing.active_status = incoming.active_status

        # Merge headers
        for hk, hv in incoming.headers.items():
            if hk not in existing.headers:
                existing.headers[hk] = hv

        # Merge base_url
        if not existing.base_url and incoming.base_url:
            existing.base_url = incoming.base_url

        return existing

    @classmethod
    def _deduplicate_endpoints(
        cls,
        endpoints: List[DiscoveredEndpoint],
        default_base_url: str = "",
    ) -> List[DiscoveredEndpoint]:
        """
        Deduplicates endpoints by (path, method) and merges their metadata.
        """
        seen: Dict[Tuple[str, str], DiscoveredEndpoint] = {}
        for ep in endpoints:
            cls._normalize_endpoint(ep, default_base_url)
            key = (ep.path, ep.method)
            if key not in seen:
                seen[key] = ep
            else:
                cls._merge_endpoints(seen[key], ep)
        return list(seen.values())

    async def probe(
        self,
        base_url: str,
        endpoints: Optional[List[DiscoveredEndpoint]] = None,
        probe_specs: bool = True,
        probe_graphql: bool = True,
        probe_http: bool = True,
        run_introspection: bool = True,
        client: Optional[httpx.AsyncClient] = None,
    ) -> ProberResult:
        """
        Runs the unified probing pipeline:
        1. Probes base_url for OpenAPI/Swagger specs and converts findings into DiscoveredEndpoint models.
        2. Probes base_url and candidate paths for active GraphQL services and introspects SDL schema.
        3. Probes all discovered endpoints via SafeHTTPProber to determine live HTTP status, allowed verbs, and CORS.
        4. Merges and deduplicates all results by (path, method).
        5. Computes diagnostic summary statistics.
        """
        clean_base = (base_url or "").strip()
        if not clean_base:
            return ProberResult()

        if not (clean_base.startswith("http://") or clean_base.startswith("https://")):
            clean_base = f"https://{clean_base}"

        clean_base = clean_base.rstrip("/")

        # Check target SSRF safety unless private IPs are explicitly allowed
        if not self.allow_private_ips:
            safe, reason = is_safe_target(clean_base)
            if not safe:
                logger.warning("SSRF blocked probe for base target %s: %s", clean_base, reason)
                return ProberResult(
                    probed_endpoints=[],
                    discovered_specs=[],
                    graphql_results=[],
                    http_probe_results=[],
                    summary={
                        "total_probed": 0,
                        "live_endpoints": 0,
                        "specs_found": 0,
                        "graphql_services_detected": 0,
                        "graphql_services": 0,
                        "cors_reflections": 0,
                        "error": f"SSRF protection blocked target: {reason}",
                    },
                )

        if client is not None:
            return await self._probe_pipeline(
                clean_base=clean_base,
                endpoints=endpoints,
                probe_specs=probe_specs,
                probe_graphql=probe_graphql,
                probe_http=probe_http,
                run_introspection=run_introspection,
                client=client,
            )

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(self.request_timeout),
            headers={"User-Agent": self.user_agent},
            follow_redirects=True,
            verify=False,
        ) as managed_client:
            return await self._probe_pipeline(
                clean_base=clean_base,
                endpoints=endpoints,
                probe_specs=probe_specs,
                probe_graphql=probe_graphql,
                probe_http=probe_http,
                run_introspection=run_introspection,
                client=managed_client,
            )

    async def _probe_pipeline(
        self,
        clean_base: str,
        endpoints: Optional[List[DiscoveredEndpoint]],
        probe_specs: bool,
        probe_graphql: bool,
        probe_http: bool,
        run_introspection: bool,
        client: httpx.AsyncClient,
    ) -> ProberResult:
        # Collect candidate endpoints initialized from input
        collected_endpoints: List[DiscoveredEndpoint] = []
        if endpoints:
            for ep in endpoints:
                # Copy endpoint object to avoid unwanted side-effects on original
                ep_copy = copy.copy(ep)
                self._normalize_endpoint(ep_copy, clean_base)
                collected_endpoints.append(ep_copy)

        discovered_specs: List[DiscoveredSpec] = []
        graphql_results: List[GraphQLProbeResult] = []
        http_probe_results: List[ProbeResult] = []

        # -------------------------------------------------------------
        # Step 1: Probe OpenAPI / Swagger Specifications
        # -------------------------------------------------------------
        if probe_specs:
            try:
                discovered_specs = await self.spec_finder.probe_spec_urls(
                    base_url=clean_base,
                    client=client,
                    concurrency=self.concurrency,
                )
                for spec in discovered_specs:
                    for spec_ep in spec.endpoints:
                        ep_copy = copy.copy(spec_ep)
                        self._normalize_endpoint(ep_copy, clean_base)
                        collected_endpoints.append(ep_copy)
            except Exception as exc:
                logger.warning("Spec discovery failed for %s: %s", clean_base, exc)

        # -------------------------------------------------------------
        # Step 2: Probe GraphQL Services & Schema Introspection
        # -------------------------------------------------------------
        if probe_graphql:
            # Extract candidate GraphQL paths from endpoints
            candidate_graphql_paths: List[str] = []
            for ep in collected_endpoints:
                p_lower = ep.path.lower()
                tag_lower = [t.lower() for t in ep.tags]
                if (
                    "graphql" in p_lower
                    or "gql" in p_lower
                    or p_lower.endswith("/query")
                    or "graphql" in tag_lower
                ):
                    if ep.path not in candidate_graphql_paths:
                        candidate_graphql_paths.append(ep.path)

            try:
                if run_introspection:
                    graphql_results = await self.graphql_prober.discover_and_probe(
                        base_url=clean_base,
                        candidate_endpoints=candidate_graphql_paths,
                        client=client,
                        active_only=True,
                    )
                else:
                    # Probe endpoints for active status without full introspection dump
                    all_gql_paths = list(candidate_graphql_paths)
                    for cp in self.graphql_prober.CANDIDATE_PATHS:
                        if cp not in all_gql_paths:
                            all_gql_paths.append(cp)

                    target_gql_urls: List[str] = []
                    for p in all_gql_paths:
                        p_str = p.strip()
                        if p_str.startswith("http://") or p_str.startswith("https://"):
                            u = p_str
                        else:
                            u = f"{clean_base}/{p_str.lstrip('/')}"
                        if u not in target_gql_urls:
                            target_gql_urls.append(u)

                    gql_sem = asyncio.Semaphore(self.concurrency)

                    async def _probe_single_gql(url_target: str) -> GraphQLProbeResult:
                        async with gql_sem:
                            return await self.graphql_prober.probe_endpoint(
                                url_target, client=client
                            )

                    probed_gql = await asyncio.gather(
                        *(_probe_single_gql(u) for u in target_gql_urls)
                    )
                    graphql_results = [r for r in probed_gql if r.is_active]

                # Convert active GraphQL endpoints to DiscoveredEndpoint models
                for g_res in graphql_results:
                    if g_res.is_active:
                        gql_ep = g_res.to_discovered_endpoint()
                        self._normalize_endpoint(gql_ep, clean_base)
                        collected_endpoints.append(gql_ep)

            except Exception as exc:
                logger.warning("GraphQL probing failed for %s: %s", clean_base, exc)

        # -------------------------------------------------------------
        # Step 3 & 4: Deduplicate and Probe Live HTTP Endpoints
        # -------------------------------------------------------------
        # Deduplicate endpoints by (path, method) prior to active HTTP probing
        endpoints_to_probe = self._deduplicate_endpoints(collected_endpoints, clean_base)

        if probe_http and endpoints_to_probe:
            try:
                http_probe_results = await self.http_prober.probe_endpoints(
                    endpoints=endpoints_to_probe,
                    client=client,
                    concurrency=self.concurrency,
                )
            except Exception as exc:
                logger.warning("Safe HTTP probing failed for %s: %s", clean_base, exc)

        # Final deduplication and synchronization
        final_endpoints = self._deduplicate_endpoints(endpoints_to_probe, clean_base)

        # -------------------------------------------------------------
        # Step 5: Diagnostic Summary Statistics
        # -------------------------------------------------------------
        total_probed = len(http_probe_results) if probe_http else len(final_endpoints)
        live_endpoints = sum(
            1
            for ep in final_endpoints
            if ep.active_status is not None and ep.active_status not in (404, 0)
        )
        specs_found = len(discovered_specs)
        active_graphql_count = len([g for g in graphql_results if g.is_active])
        cors_reflections = sum(1 for r in http_probe_results if r.cors_reflected)

        status_codes_dist: Dict[int, int] = {}
        for r in http_probe_results:
            if r.status_code is not None:
                status_codes_dist[r.status_code] = (
                    status_codes_dist.get(r.status_code, 0) + 1
                )

        summary = {
            "total_probed": total_probed,
            "live_endpoints": live_endpoints,
            "specs_found": specs_found,
            "graphql_services_detected": active_graphql_count,
            "graphql_services": active_graphql_count,
            "cors_reflections": cors_reflections,
            "status_codes": status_codes_dist,
        }

        return ProberResult(
            probed_endpoints=final_endpoints,
            discovered_specs=discovered_specs,
            graphql_results=graphql_results,
            http_probe_results=http_probe_results,
            summary=summary,
        )


# Alias for compatibility
ProberCoordinator = APIProber
