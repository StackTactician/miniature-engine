from __future__ import annotations

from app.analysis import infer_models, infer_relationships
from app.models import GraphEdge, GraphNode, GraphPayload, TrafficRecord
from app.processing import summarize_endpoints

_IGNORED_PATH_SEGMENTS = {"api", "rest", "graphql", "v1", "v2", "v3", "internal"}


def _resource_variants(value: str) -> set[str]:
    cleaned = value.strip().lower()
    if not cleaned or cleaned == "{id}":
        return set()
    variants = {cleaned}
    if cleaned.endswith("s") and len(cleaned) > 1:
        variants.add(cleaned[:-1])
    else:
        variants.add(f"{cleaned}s")
    return variants


def _endpoint_resource_candidates(normalized_path: str) -> list[str]:
    segments = [segment for segment in normalized_path.strip("/").split("/") if segment]
    candidates: list[str] = []
    for segment in segments:
        lowered = segment.lower()
        if lowered in _IGNORED_PATH_SEGMENTS or lowered == "{id}":
            continue
        candidates.append(lowered)
    return candidates


def build_graph(records: list[TrafficRecord]) -> GraphPayload:
    endpoints = summarize_endpoints(records)
    models = infer_models(records)
    model_relationships = infer_relationships(models)

    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []

    for endpoint in endpoints:
        endpoint_id = f"endpoint:{endpoint.method}:{endpoint.normalized_path}"
        nodes.append(
            GraphNode(
                id=endpoint_id,
                label=f"{endpoint.method} {endpoint.normalized_path}",
                type="endpoint",
                metadata={
                    "operation": endpoint.operation,
                    "has_pagination": endpoint.has_pagination,
                    "is_authenticated": endpoint.is_authenticated,
                    "is_idor_candidate": endpoint.is_idor_candidate,
                },
            )
        )

    for model in models:
        model_id = f"model:{model.name}"
        has_pii = any(field.is_pii for field in model.fields)
        nodes.append(
            GraphNode(
                id=model_id,
                label=model.name,
                type="model",
                metadata={
                    "fields": [field.model_dump() for field in model.fields],
                    "has_pii": has_pii,
                },
            )
        )

    model_names = {model.name for model in models}
    model_lookup: dict[str, str] = {}
    for model_name in model_names:
        for variant in _resource_variants(model_name):
            model_lookup.setdefault(variant, model_name)

    for endpoint in endpoints:
        guessed_model: str | None = None
        candidates = _endpoint_resource_candidates(endpoint.normalized_path)

        if candidates:
            for candidate in candidates:
                for variant in _resource_variants(candidate):
                    if variant in model_lookup:
                        guessed_model = model_lookup[variant]
                        break
                if guessed_model:
                    break

        if guessed_model:
            edges.append(
                GraphEdge(
                    source=f"endpoint:{endpoint.method}:{endpoint.normalized_path}",
                    target=f"model:{guessed_model}",
                    relation="returns",
                    metadata={"confidence": "high"},
                )
            )

    for source, target in model_relationships:
        edges.append(
            GraphEdge(
                source=f"model:{source}",
                target=f"model:{target}",
                relation="references",
                metadata={"confidence": "medium"},
            )
        )

    return GraphPayload(nodes=nodes, edges=edges)
