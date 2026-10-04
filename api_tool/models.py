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

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DiscoveredParameter":
        return cls(
            name=data.get("name", ""),
            location=data.get("location", "query"),
            required=bool(data.get("required", False)),
            param_type=data.get("param_type", "string"),
            example=data.get("example"),
            description=data.get("description"),
        )


@dataclass
class DiscoveredResponse:
    status_code: int
    content_type: str = "application/json"
    headers: Dict[str, str] = field(default_factory=dict)
    sample_body: Optional[Any] = None
    inferred_schema: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DiscoveredResponse":
        return cls(
            status_code=int(data.get("status_code", 200)),
            content_type=data.get("content_type", "application/json"),
            headers=dict(data.get("headers") or {}),
            sample_body=data.get("sample_body"),
            inferred_schema=data.get("inferred_schema"),
        )


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

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DiscoveredEndpoint":
        raw_params = data.get("parameters") or []
        params = [
            DiscoveredParameter.from_dict(p) if isinstance(p, dict) else p
            for p in raw_params
        ]
        raw_resps = data.get("responses") or []
        resps = [
            DiscoveredResponse.from_dict(r) if isinstance(r, dict) else r
            for r in raw_resps
        ]
        return cls(
            path=data.get("path", ""),
            method=data.get("method", "GET"),
            base_url=data.get("base_url", ""),
            source=data.get("source", "static"),
            tags=list(data.get("tags") or []),
            parameters=params,
            request_body_sample=data.get("request_body_sample"),
            request_body_schema=data.get("request_body_schema"),
            responses=resps,
            auth_type=data.get("auth_type"),
            auth_header_or_param=data.get("auth_header_or_param"),
            summary=data.get("summary"),
            description=data.get("description"),
            active_status=data.get("active_status"),
            headers=dict(data.get("headers") or {}),
        )


@dataclass
class GraphQLOperation:
    operation_type: str  # "query", "mutation", "subscription"
    operation_name: str
    query_string: str
    endpoint: str = "/graphql"
    variables_sample: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GraphQLOperation":
        return cls(
            operation_type=data.get("operation_type", "query"),
            operation_name=data.get("operation_name", ""),
            query_string=data.get("query_string", ""),
            endpoint=data.get("endpoint", "/graphql"),
            variables_sample=data.get("variables_sample"),
        )


@dataclass
class PersistedQueryRecord:
    sha256_hash: str
    operation_name: Optional[str] = None
    query_string: Optional[str] = None
    source: str = "apq_manifest"  # "apq_manifest", "network_har", "bundle_ast"

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PersistedQueryRecord":
        return cls(
            sha256_hash=data.get("sha256_hash") or data.get("sha256Hash") or data.get("id") or data.get("hash") or "",
            operation_name=data.get("operation_name") or data.get("operationName") or data.get("name"),
            query_string=data.get("query_string") or data.get("queryString") or data.get("text") or data.get("query") or data.get("body"),
            source=data.get("source", "apq_manifest"),
        )


@dataclass
class DiscoveredChunkManifest:
    framework: str  # "webpack5", "webpack4", "vite", "nextjs", "unknown"
    source_script: str = ""
    base_url: str = ""
    chunk_urls: List[str] = field(default_factory=list)
    chunk_map: Dict[str, str] = field(default_factory=dict)
    template: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        return {k: v for k, v in data.items() if v is not None}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DiscoveredChunkManifest":
        return cls(
            framework=data.get("framework", "unknown"),
            source_script=data.get("source_script", ""),
            base_url=data.get("base_url", ""),
            chunk_urls=list(data.get("chunk_urls", [])),
            chunk_map=dict(data.get("chunk_map", {})),
            template=data.get("template"),
            metadata=dict(data.get("metadata", {})),
        )


@dataclass
class ScanResult:
    target_url: str
    base_urls: List[str] = field(default_factory=list)
    endpoints: List[DiscoveredEndpoint] = field(default_factory=list)
    graphql_operations: List[GraphQLOperation] = field(default_factory=list)
    discovered_specs: List[str] = field(default_factory=list)
    discovered_assets: List[str] = field(default_factory=list)
    chunk_manifests: List[DiscoveredChunkManifest] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_url": self.target_url,
            "base_urls": self.base_urls,
            "endpoints": [e.to_dict() for e in self.endpoints],
            "graphql_operations": [g.to_dict() for g in self.graphql_operations],
            "discovered_specs": self.discovered_specs,
            "discovered_assets": self.discovered_assets,
            "chunk_manifests": [c.to_dict() for c in self.chunk_manifests],
            "metadata": self.metadata,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanResult":
        raw_eps = data.get("endpoints") or []
        endpoints = [
            DiscoveredEndpoint.from_dict(e) if isinstance(e, dict) else e
            for e in raw_eps
        ]
        raw_gql = data.get("graphql_operations") or []
        graphql_operations = [
            GraphQLOperation.from_dict(g) if isinstance(g, dict) else g
            for g in raw_gql
        ]
        raw_chunks = data.get("chunk_manifests") or []
        chunk_manifests = [
            DiscoveredChunkManifest.from_dict(c) if isinstance(c, dict) else c
            for c in raw_chunks
        ]
        return cls(
            target_url=data.get("target_url", ""),
            base_urls=list(data.get("base_urls") or []),
            endpoints=endpoints,
            graphql_operations=graphql_operations,
            discovered_specs=list(data.get("discovered_specs") or []),
            discovered_assets=list(data.get("discovered_assets") or []),
            chunk_manifests=chunk_manifests,
            metadata=dict(data.get("metadata") or {}),
        )

    @classmethod
    def from_json(cls, json_str: str) -> "ScanResult":
        return cls.from_dict(json.loads(json_str))


def __getattr__(name: str) -> Any:
    if name == "HARImporter":
        from api_tool.importer.har_importer import HARImporter
        return HARImporter
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
    if name == "ChunkMapCracker":
        from api_tool.analyzer.chunk_cracker import ChunkMapCracker
        return ChunkMapCracker
    if name == "APQOperationExtractor":
        from api_tool.analyzer.apq_extractor import APQOperationExtractor
        return APQOperationExtractor
    if name == "HappyDOMEngine":
        from api_tool.runtime.dom_engine import HappyDOMEngine
        return HappyDOMEngine
    if name == "JSASTExtractor":
        from api_tool.analyzer.ast_parser import JSASTExtractor
        return JSASTExtractor
    if name == "ExportResult":
        from api_tool.exporter.coordinator import ExportResult
        return ExportResult
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


