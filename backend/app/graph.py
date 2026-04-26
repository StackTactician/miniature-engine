from __future__ import annotations

from app.analysis import infer_models, infer_relationships
from app.models import GraphEdge, GraphNode, GraphPayload, TrafficRecord
from app.processing import summarize_endpoints


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
                },
            )
        )

    for model in models:
        model_id = f"model:{model.name}"
        nodes.append(
            GraphNode(
                id=model_id,
                label=model.name,
                type="model",
                metadata={"fields": [field.model_dump() for field in model.fields]},
            )
        )

    model_names = {model.name for model in models}
    for endpoint in endpoints:
        guessed = endpoint.normalized_path.strip("/").split("/")[0]
        if guessed in model_names:
            edges.append(
                GraphEdge(
                    source=f"endpoint:{endpoint.method}:{endpoint.normalized_path}",
                    target=f"model:{guessed}",
                    relation="returns",
                )
            )

    for source, target in model_relationships:
        edges.append(
            GraphEdge(
                source=f"model:{source}",
                target=f"model:{target}",
                relation="references",
            )
        )

    return GraphPayload(nodes=nodes, edges=edges)
