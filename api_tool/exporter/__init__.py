"""
Exporter package for api-tool (Miniature Engine).

Provides unified exporters for:
- OpenAPI 3.1.0 (JSON and YAML via PureYamlDumper)
- Postman Collection v2.1.0 (JSON via PostmanExporter)
- GraphQL SDL (schema.graphql via ExportCoordinator)
- Unified ExportCoordinator orchestration
"""

from api_tool.exporter.coordinator import (
    ExportCoordinator,
    ExportResult,
    synthesize_graphql_sdl_from_operations,
)
from api_tool.exporter.openapi_gen import (
    OpenAPIGenerator,
    PureYamlDumper,
)
from api_tool.exporter.schema_inference import (
    OpenAPISchemaInferrer,
    ParameterInferrer,
)
from api_tool.exporter.postman_gen import (
    PostmanExporter,
    PostmanCollectionExporter,
    PostmanCollection,
    PostmanItem,
    PostmanRequest,
    PostmanUrl,
    PostmanHeader,
    PostmanVariable,
    PostmanQueryParam,
    PostmanPathVariable,
    PostmanBody,
    FolderTree,
    generate_postman_collection,
    export_postman_collection,
)

__all__ = [
    "ExportCoordinator",
    "ExportResult",
    "OpenAPIGenerator",
    "PureYamlDumper",
    "OpenAPISchemaInferrer",
    "ParameterInferrer",
    "PostmanExporter",
    "PostmanCollectionExporter",
    "PostmanCollection",
    "PostmanItem",
    "PostmanRequest",
    "PostmanUrl",
    "PostmanHeader",
    "PostmanVariable",
    "PostmanQueryParam",
    "PostmanPathVariable",
    "PostmanBody",
    "FolderTree",
    "generate_postman_collection",
    "export_postman_collection",
    "synthesize_graphql_sdl_from_operations",
]
