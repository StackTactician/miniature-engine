"""
Unified Exporter Coordinator Module for api-tool.

Coordinates generation and multi-format export of discovered APIs:
1. OpenAPI 3.1.0 (JSON and YAML via PureYamlDumper).
2. Postman Collection v2.1.0 (JSON via PostmanExporter).
3. GraphQL SDL (Standalone schema.graphql via AST parsing & schema synthesis).
4. export_all: Batch export into unified target directory with diagnostic metrics.

Pure Python 3.10+ standard library implementation, 100% portable on Termux/Linux.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, Union

try:
    from graphql import (
        FieldNode,
        OperationDefinitionNode,
        OperationType,
        parse,
        print_ast,
    )
    HAS_GRAPHQL_CORE = True
except ImportError:
    HAS_GRAPHQL_CORE = False

from api_tool.models import (
    DiscoveredEndpoint,
    DiscoveredParameter,
    DiscoveredResponse,
    GraphQLOperation,
    ScanResult,
)
from api_tool.exporter.openapi_gen import OpenAPIGenerator, PureYamlDumper
from api_tool.exporter.schema_inference import OpenAPISchemaInferrer, ParameterInferrer
from api_tool.exporter.postman_gen import (
    PostmanCollection,
    PostmanExporter,
    PostmanItem,
    PostmanCollectionExporter,
)

logger = logging.getLogger(__name__)


# ==============================================================================
# 1. Export Result Container
# ==============================================================================

@dataclass
class ExportResult:
    """
    Unified result container for exported artifacts and diagnostic metrics.
    """
    openapi_json_path: Optional[str] = None
    openapi_yaml_path: Optional[str] = None
    postman_json_path: Optional[str] = None
    graphql_sdl_path: Optional[str] = None
    total_endpoints: int = 0
    total_graphql_ops: int = 0
    summary: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the export result into a dictionary."""
        return {
            "openapi_json_path": self.openapi_json_path,
            "openapi_yaml_path": self.openapi_yaml_path,
            "postman_json_path": self.postman_json_path,
            "graphql_sdl_path": self.graphql_sdl_path,
            "total_endpoints": self.total_endpoints,
            "total_graphql_ops": self.total_graphql_ops,
            "summary": dict(self.summary),
        }

    def to_json(self, indent: int = 2) -> str:
        """Serializes the export result into formatted JSON."""
        return json.dumps(self.to_dict(), indent=indent)


# ==============================================================================
# 2. GraphQL SDL Synthesizer Helper
# ==============================================================================

def synthesize_graphql_sdl_from_operations(
    operations: List[GraphQLOperation],
    title: str = "Discovered GraphQL API",
) -> str:
    """
    Synthesizes a clean, valid GraphQL Schema Definition Language (SDL) string
    from harvested GraphQL operations.
    Parses operations with graphql-core if available, falling back to regex extraction.
    """
    if not operations:
        return (
            f"# {title} - Schema Definition Language (SDL)\n"
            "# Generated automatically by Miniature Engine\n\n"
            "schema {\n"
            "  query: Query\n"
            "}\n\n"
            "type Query {\n"
            "  _empty: String\n"
            "}\n"
        )

    query_fields: Dict[str, str] = {}
    mutation_fields: Dict[str, str] = {}
    subscription_fields: Dict[str, str] = {}
    input_types: Set[str] = set()

    for op in operations:
        op_type = (op.operation_type or "query").lower().strip()
        query_str = (op.query_string or "").strip()
        op_name = op.operation_name or "AnonymousOperation"

        parsed_via_ast = False
        if HAS_GRAPHQL_CORE and query_str:
            try:
                doc = parse(query_str)
                for defn in doc.definitions:
                    if isinstance(defn, OperationDefinitionNode):
                        actual_op_type = defn.operation.value.lower()
                        # Extract variable types for arg mapping
                        vdefs: Dict[str, str] = {}
                        if defn.variable_definitions:
                            for vd in defn.variable_definitions:
                                vname = vd.variable.name.value
                                vtype = print_ast(vd.type)
                                vdefs[vname] = vtype
                                # Note potential input types
                                clean_t = re.sub(r"[!\[\]]", "", vtype)
                                if clean_t not in ("String", "Int", "Float", "Boolean", "ID", "JSON"):
                                    input_types.add(clean_t)

                        # Extract selections
                        if defn.selection_set and defn.selection_set.selections:
                            for sel in defn.selection_set.selections:
                                if isinstance(sel, FieldNode):
                                    fname = sel.name.value
                                    args: List[str] = []
                                    if sel.arguments:
                                        for arg in sel.arguments:
                                            aname = arg.name.value
                                            val_str = print_ast(arg.value)
                                            if val_str.startswith("$"):
                                                var_key = val_str[1:]
                                                arg_type = vdefs.get(var_key, "JSON")
                                            else:
                                                arg_type = "JSON"
                                            args.append(f"{aname}: {arg_type}")

                                    args_joined = ", ".join(args)
                                    args_str = f"({args_joined})" if args else ""
                                    field_sig = f"{fname}{args_str}: JSON"

                                    if actual_op_type == "mutation":
                                        mutation_fields[fname] = field_sig
                                    elif actual_op_type == "subscription":
                                        subscription_fields[fname] = field_sig
                                    else:
                                        query_fields[fname] = field_sig
                                    parsed_via_ast = True
            except Exception:
                parsed_via_ast = False

        if not parsed_via_ast:
            # Fallback regex extraction
            clean_name = re.sub(r"[^a-zA-Z0-9_]", "", op_name) or "operation"
            if clean_name and clean_name[0].isupper():
                field_name = clean_name[0].lower() + clean_name[1:]
            else:
                field_name = clean_name or "operation"

            args_str = "(input: JSON)" if op.variables_sample else ""
            field_sig = f"{field_name}{args_str}: JSON"

            if op_type == "mutation":
                mutation_fields[field_name] = field_sig
            elif op_type == "subscription":
                subscription_fields[field_name] = field_sig
            else:
                query_fields[field_name] = field_sig

    # Assemble SDL document
    lines: List[str] = [
        f"# {title} - Schema Definition Language (SDL)",
        "# Generated automatically by Miniature Engine",
        "",
        "scalar JSON",
        "",
    ]

    # Schema definition
    lines.append("schema {")
    if query_fields:
        lines.append("  query: Query")
    else:
        lines.append("  query: Query")
    if mutation_fields:
        lines.append("  mutation: Mutation")
    if subscription_fields:
        lines.append("  subscription: Subscription")
    lines.append("}")
    lines.append("")

    # Query Type
    lines.append("type Query {")
    if query_fields:
        for fname in sorted(query_fields.keys()):
            lines.append(f"  {query_fields[fname]}")
    else:
        lines.append("  _empty: String")
    lines.append("}")
    lines.append("")

    # Mutation Type
    if mutation_fields:
        lines.append("type Mutation {")
        for fname in sorted(mutation_fields.keys()):
            lines.append(f"  {mutation_fields[fname]}")
        lines.append("}")
        lines.append("")

    # Subscription Type
    if subscription_fields:
        lines.append("type Subscription {")
        for fname in sorted(subscription_fields.keys()):
            lines.append(f"  {subscription_fields[fname]}")
        lines.append("}")
        lines.append("")

    # Stub custom input types if any were detected
    for it in sorted(input_types):
        lines.append(f"input {it} {{")
        lines.append("  _placeholder: JSON")
        lines.append("}")
        lines.append("")

    return "\n".join(lines).strip() + "\n"


# ==============================================================================
# 3. Export Coordinator
# ==============================================================================

class ExportCoordinator:
    """
    Unified Exporter Coordinator for Miniature Engine.
    Orchestrates ingestion of DiscoveredEndpoint and GraphQLOperation models,
    and coordinates simultaneous export into OpenAPI 3.1.0 (JSON & YAML),
    Postman Collection v2.1.0, and GraphQL SDL schema.
    """

    def __init__(
        self,
        target_url: str = "",
        title: str = "Miniature Engine Discovered API",
        version: str = "1.0.0",
        description: str = "",
        endpoints: Optional[List[DiscoveredEndpoint]] = None,
        graphql_operations: Optional[List[GraphQLOperation]] = None,
        scan_result: Optional[ScanResult] = None,
    ) -> None:
        self.target_url = target_url or ""
        self.title = title or "Miniature Engine Discovered API"
        self.version = version or "1.0.0"
        self.description = description or ""
        self.endpoints: List[DiscoveredEndpoint] = []
        self.graphql_operations: List[GraphQLOperation] = []

        if scan_result is not None:
            self.add_scan_result(scan_result)

        if endpoints:
            self.add_endpoints(endpoints)

        if graphql_operations:
            self.add_graphql_operations(graphql_operations)

    def add_endpoint(self, endpoint: DiscoveredEndpoint) -> None:
        """Adds a single DiscoveredEndpoint model."""
        if endpoint is not None:
            self.endpoints.append(endpoint)
            if not self.target_url and getattr(endpoint, "base_url", None):
                self.target_url = endpoint.base_url

    def add_endpoints(self, endpoints: Union[List[DiscoveredEndpoint], Iterable[DiscoveredEndpoint], Any]) -> None:
        """
        Adds a list or iterable of DiscoveredEndpoint models.
        Also gracefully accepts a ScanResult object.
        """
        if endpoints is None:
            return

        if isinstance(endpoints, DiscoveredEndpoint):
            self.add_endpoint(endpoints)
            return

        # Check for ScanResult or similar container
        if hasattr(endpoints, "endpoints"):
            self.add_scan_result(endpoints)
            return

        if isinstance(endpoints, (list, tuple, set)):
            for ep in endpoints:
                if isinstance(ep, DiscoveredEndpoint):
                    self.add_endpoint(ep)
                elif hasattr(ep, "path") and hasattr(ep, "method"):
                    self.endpoints.append(ep)  # type: ignore

    def add_graphql_operation(self, operation: GraphQLOperation) -> None:
        """Adds a single GraphQLOperation model."""
        if operation is not None:
            self.graphql_operations.append(operation)

    def add_graphql_operations(self, operations: Union[List[GraphQLOperation], Iterable[GraphQLOperation], Any]) -> None:
        """Adds a list or iterable of GraphQLOperation models."""
        if operations is None:
            return

        if isinstance(operations, GraphQLOperation):
            self.add_graphql_operation(operations)
            return

        if hasattr(operations, "graphql_operations"):
            for op in operations.graphql_operations:
                self.add_graphql_operation(op)
            return

        if isinstance(operations, (list, tuple, set)):
            for op in operations:
                if isinstance(op, GraphQLOperation):
                    self.add_graphql_operation(op)
                elif hasattr(op, "query_string"):
                    self.graphql_operations.append(op)  # type: ignore

    def add_scan_result(self, scan_result: Any) -> None:
        """Ingests target_url, endpoints, and graphql_operations from a ScanResult."""
        if not self.target_url:
            t_url = getattr(scan_result, "target_url", "")
            if t_url:
                self.target_url = t_url
            else:
                base_urls = getattr(scan_result, "base_urls", [])
                if base_urls and base_urls[0]:
                    self.target_url = base_urls[0]

        eps = getattr(scan_result, "endpoints", [])
        if eps:
            for ep in eps:
                self.add_endpoint(ep)

        gops = getattr(scan_result, "graphql_operations", [])
        if gops:
            for gop in gops:
                self.add_graphql_operation(gop)

    def export_openapi(self, output_path: str, format: str = "json") -> str:
        """
        Exports OpenAPI 3.1.0 specification in JSON or YAML format.
        Creates parent directories if necessary and writes the file.
        Returns the resolved file path.
        """
        out_p = Path(output_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)

        servers = [self.target_url] if self.target_url else None
        gen = OpenAPIGenerator(
            endpoints=self.endpoints,
            title=self.title,
            version=self.version,
            description=self.description or f"OpenAPI 3.1.0 specification for {self.title}",
            servers=servers,
        )

        fmt = (format or "json").lower().strip()
        if fmt in ("yaml", "yml"):
            content = gen.to_yaml()
        else:
            content = gen.to_json(indent=2)

        out_p.write_text(content, encoding="utf-8")
        return str(out_p.resolve())

    def export_postman(self, output_path: str, collection_name: Optional[str] = None) -> str:
        """
        Exports Postman Collection v2.1.0 specification in JSON format.
        Creates parent directories if necessary and writes the file.
        Returns the resolved file path.
        """
        out_p = Path(output_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)

        col_name = collection_name or self.title or "Discovered API"
        exporter = PostmanExporter()
        base_url = self.target_url or "http://localhost:3000"

        collection = exporter.export_from_endpoints(
            endpoints=self.endpoints,
            collection_name=col_name,
            base_url=base_url,
            graphql_operations=self.graphql_operations,
            description=self.description or f"Exported Postman collection for {self.title}",
        )

        collection.export_file(out_p)
        return str(out_p.resolve())

    def export_graphql_sdl(self, output_path: str, sdl_content: Optional[str] = None) -> str:
        """
        Exports standalone schema.graphql SDL schema.
        If sdl_content is provided, writes it directly.
        Otherwise synthesizes SDL from registered GraphQLOperation models.
        Returns the resolved file path.
        """
        out_p = Path(output_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)

        if sdl_content is not None:
            content = sdl_content
        else:
            content = self._generate_graphql_sdl()

        out_p.write_text(content, encoding="utf-8")
        return str(out_p.resolve())

    def _generate_graphql_sdl(self) -> str:
        """Helper to generate SDL string from registered GraphQL operations."""
        return synthesize_graphql_sdl_from_operations(
            self.graphql_operations,
            title=self.title,
        )

    def export_all(self, output_dir: str, base_name: str = "miniature_engine") -> ExportResult:
        """
        Exports all formats into output_dir in a single call:
        - {base_name}.openapi.json
        - {base_name}.openapi.yaml
        - {base_name}.postman.json
        - {base_name}.schema.graphql (if GraphQL operations exist)

        Returns ExportResult with resolved file paths and comprehensive metrics.
        """
        out_dir = Path(output_dir).resolve()
        out_dir.mkdir(parents=True, exist_ok=True)

        # Sanitize base_name strictly against directory traversal
        raw_base = os.path.basename(str(base_name).strip())
        clean_base = re.sub(r"[^\w\-.]", "_", raw_base).lstrip("._") or "miniature_engine"

        # 1. OpenAPI JSON
        openapi_json_file = out_dir / f"{clean_base}.openapi.json"
        openapi_json_path = self.export_openapi(str(openapi_json_file), format="json")

        # 2. OpenAPI YAML
        openapi_yaml_file = out_dir / f"{clean_base}.openapi.yaml"
        openapi_yaml_path = self.export_openapi(str(openapi_yaml_file), format="yaml")

        # 3. Postman JSON
        postman_file = out_dir / f"{clean_base}.postman.json"
        postman_json_path = self.export_postman(str(postman_file))

        # 4. GraphQL SDL (if GraphQL exists)
        graphql_sdl_path: Optional[str] = None
        if self.graphql_operations:
            sdl_file = out_dir / f"{clean_base}.schema.graphql"
            graphql_sdl_path = self.export_graphql_sdl(str(sdl_file))

        # Calculate counts and breakdown metrics
        total_endpoints = len(self.endpoints)
        total_graphql_ops = len(self.graphql_operations)

        method_breakdown: Dict[str, int] = {}
        for ep in self.endpoints:
            m = (getattr(ep, "method", "GET") or "GET").upper()
            method_breakdown[m] = method_breakdown.get(m, 0) + 1

        tag_set: Set[str] = set()
        for ep in self.endpoints:
            for t in getattr(ep, "tags", []) or []:
                tag_set.add(t)

        summary: Dict[str, Any] = {
            "title": self.title,
            "version": self.version,
            "target_url": self.target_url,
            "total_endpoints": total_endpoints,
            "total_graphql_ops": total_graphql_ops,
            "methods_breakdown": method_breakdown,
            "tags_count": len(tag_set),
            "has_graphql": bool(self.graphql_operations),
            "files": {
                "openapi_json": openapi_json_path,
                "openapi_yaml": openapi_yaml_path,
                "postman_json": postman_json_path,
                "graphql_sdl": graphql_sdl_path,
            },
        }

        return ExportResult(
            openapi_json_path=openapi_json_path,
            openapi_yaml_path=openapi_yaml_path,
            postman_json_path=postman_json_path,
            graphql_sdl_path=graphql_sdl_path,
            total_endpoints=total_endpoints,
            total_graphql_ops=total_graphql_ops,
            summary=summary,
        )
