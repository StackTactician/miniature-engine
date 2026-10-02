"""
Core domain models and intermediate representation (IR) for api-tool.
Built with pure Python 3 standard library dataclasses for 100% portability on Termux/Linux.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
import json


@dataclass
class DiscoveredParameter:
    name: str
    location: str = "query"  # "query", "path", "header", "body"
    required: bool = False
    param_type: str = "string"  # "string", "integer", "boolean", "object", "array"
    example: Optional[Any] = None
    description: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class DiscoveredResponse:
    status_code: int
    content_type: str = "application/json"
    headers: Dict[str, str] = field(default_factory=dict)
    sample_body: Optional[Any] = None
    inferred_schema: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class DiscoveredEndpoint:
    path: str
    method: str = "GET"
    base_url: str = ""
    source: str = "static"  # "static_js", "sourcemap", "manifest", "crawler", "passive_osint", "spec"
    tags: List[str] = field(default_factory=list)
    parameters: List[DiscoveredParameter] = field(default_factory=list)
    request_body_sample: Optional[Any] = None
    request_body_schema: Optional[Dict[str, Any]] = None
    responses: List[DiscoveredResponse] = field(default_factory=list)
    auth_type: Optional[str] = None  # "bearer", "apikey", "basic", "none"
    auth_header_or_param: Optional[str] = None
    summary: Optional[str] = None
    description: Optional[str] = None
    active_status: Optional[int] = None  # e.g., 200, 401, 403, 405 if probed
    headers: Dict[str, str] = field(default_factory=dict)

    @property
    def full_url(self) -> str:
        if self.base_url:
            return f"{self.base_url.rstrip('/')}/{self.path.lstrip('/')}"
        return self.path

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["full_url"] = self.full_url
        return {k: v for k, v in data.items() if v is not None}


@dataclass
class GraphQLOperation:
    operation_type: str  # "query", "mutation", "subscription"
    operation_name: str
    query_string: str
    endpoint: str = "/graphql"
    variables_sample: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class ScanResult:
    target_url: str
    base_urls: List[str] = field(default_factory=list)
    endpoints: List[DiscoveredEndpoint] = field(default_factory=list)
    graphql_operations: List[GraphQLOperation] = field(default_factory=list)
    discovered_specs: List[str] = field(default_factory=list)
    discovered_assets: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_url": self.target_url,
            "base_urls": self.base_urls,
            "endpoints": [e.to_dict() for e in self.endpoints],
            "graphql_operations": [g.to_dict() for g in self.graphql_operations],
            "discovered_specs": self.discovered_specs,
            "discovered_assets": self.discovered_assets,
            "metadata": self.metadata,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


def __getattr__(name: str) -> Any:
    if name == "SourceMapFile":
        from api_tool.analyzer.sourcemap import SourceMapFile
        return SourceMapFile
    if name == "SourceMapResult":
        from api_tool.analyzer.sourcemap import SourceMapResult
        return SourceMapResult
    if name == "GraphQLProbeResult":
        from api_tool.prober.graphql_prober import GraphQLProbeResult
        return GraphQLProbeResult
    if name == "GraphQLProber":
        from api_tool.prober.graphql_prober import GraphQLProber
        return GraphQLProber
    if name == "DiscoveredSpec":
        from api_tool.prober.spec_finder import DiscoveredSpec
        return DiscoveredSpec
    if name == "SpecFinder":
        from api_tool.prober.spec_finder import SpecFinder
        return SpecFinder
    if name in ("APIProber", "ProberCoordinator"):
        from api_tool.prober.coordinator import APIProber
        return APIProber
    if name == "ProberResult":
        from api_tool.prober.coordinator import ProberResult
        return ProberResult
    if name == "ExportCoordinator":
        from api_tool.exporter.coordinator import ExportCoordinator
        return ExportCoordinator
    if name == "ExportResult":
        from api_tool.exporter.coordinator import ExportResult
        return ExportResult
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

