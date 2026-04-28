from __future__ import annotations

from app.models import GraphDiffNodeChange, GraphDiffPayload, GraphEdge, GraphNode, GraphPayload


def diff_graphs(baseline: GraphPayload, candidate: GraphPayload) -> GraphDiffPayload:
    baseline_nodes = {node.id: node for node in baseline.nodes}
    candidate_nodes = {node.id: node for node in candidate.nodes}

    added_node_ids = sorted(candidate_nodes.keys() - baseline_nodes.keys())
    removed_node_ids = sorted(baseline_nodes.keys() - candidate_nodes.keys())
    common_node_ids = sorted(baseline_nodes.keys() & candidate_nodes.keys())

    changed_nodes: list[GraphDiffNodeChange] = []
    for node_id in common_node_ids:
        before = baseline_nodes[node_id]
        after = candidate_nodes[node_id]
        if (
            before.label != after.label
            or before.type != after.type
            or before.metadata != after.metadata
        ):
            changed_nodes.append(GraphDiffNodeChange(id=node_id, before=before, after=after))

    baseline_edges = {(edge.source, edge.target, edge.relation): edge for edge in baseline.edges}
    candidate_edges = {(edge.source, edge.target, edge.relation): edge for edge in candidate.edges}

    added_edge_keys = sorted(candidate_edges.keys() - baseline_edges.keys())
    removed_edge_keys = sorted(baseline_edges.keys() - candidate_edges.keys())

    added_nodes = [candidate_nodes[node_id] for node_id in added_node_ids]
    removed_nodes = [baseline_nodes[node_id] for node_id in removed_node_ids]
    added_edges = [candidate_edges[key] for key in added_edge_keys]
    removed_edges = [baseline_edges[key] for key in removed_edge_keys]

    summary = {
        "added_nodes": len(added_nodes),
        "removed_nodes": len(removed_nodes),
        "changed_nodes": len(changed_nodes),
        "added_edges": len(added_edges),
        "removed_edges": len(removed_edges),
    }

    return GraphDiffPayload(
        added_nodes=added_nodes,
        removed_nodes=removed_nodes,
        changed_nodes=changed_nodes,
        added_edges=added_edges,
        removed_edges=removed_edges,
        summary=summary,
    )
