from app.graph import build_graph
from app.models import TrafficRecord


def test_build_graph_nodes_and_edges() -> None:
    records = [
        TrafficRecord(
            method="GET",
            url="https://x.test/users/1",
            response_status=200,
            response_body={"id": 1, "team_id": 7},
        ),
        TrafficRecord(
            method="GET",
            url="https://x.test/team/7",
            response_status=200,
            response_body={"id": 7, "name": "core"},
        ),
    ]

    graph = build_graph(records)

    assert any(n.id.startswith("endpoint:") for n in graph.nodes)
    assert any(n.id == "model:users" for n in graph.nodes)
    assert any(n.id == "model:team" for n in graph.nodes)
    assert any(e.relation == "references" and e.source == "model:users" and e.target == "model:team" for e in graph.edges)


def test_model_inference_uses_resource_name_not_id_segment() -> None:
    records = [
        TrafficRecord(
            method="GET",
            url="https://x.test/projects/6f9619ff-8b86-d011-b42d-00cf4fc964ff",
            response_status=200,
            response_body={"id": "6f9619ff-8b86-d011-b42d-00cf4fc964ff", "name": "Apollo"},
        ),
    ]

    graph = build_graph(records)

    assert any(n.id == "model:projects" for n in graph.nodes)


def test_endpoint_return_edges_handle_api_prefix_and_pluralization() -> None:
    records = [
        TrafficRecord(
            method="GET",
            url="https://x.test/api/v1/user/1",
            response_status=200,
            response_body={"id": 1, "name": "Ada"},
        ),
    ]

    graph = build_graph(records)

    assert any(n.id == "model:user" for n in graph.nodes)
    assert any(
        e.relation == "returns"
        and e.source == "endpoint:GET:/api/v1/user/{id}"
        and e.target == "model:user"
        and e.metadata.get("confidence") == "high"
        for e in graph.edges
    )
