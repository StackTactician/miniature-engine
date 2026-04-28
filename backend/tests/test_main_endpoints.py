from app.main import build_graph_endpoint, diff_graph_endpoint, health
from app.models import BuildGraphRequest, GraphDiffRequest, TrafficRecord


def test_health_endpoint() -> None:
    assert health() == {"status": "ok"}


def test_build_graph_endpoint_includes_confidence_metadata() -> None:
    payload = BuildGraphRequest(
        records=[
            TrafficRecord(
                method="GET",
                url="https://x.test/api/v1/user/1",
                response_status=200,
                response_body={"id": 1, "teamId": 9},
            ),
            TrafficRecord(
                method="GET",
                url="https://x.test/teams/9",
                response_status=200,
                response_body={"id": 9, "name": "Core"},
            ),
        ]
    )

    graph = build_graph_endpoint(payload)

    assert any(edge.relation == "returns" and edge.metadata.get("confidence") == "high" for edge in graph.edges)
    assert any(
        edge.relation == "references"
        and edge.source == "model:user"
        and edge.target == "model:teams"
        and edge.metadata.get("confidence") == "medium"
        for edge in graph.edges
    )


def test_diff_graph_endpoint_returns_changed_nodes_summary() -> None:
    payload = GraphDiffRequest(
        baseline_records=[
            TrafficRecord(
                method="GET",
                url="https://x.test/users/1",
                response_status=200,
                response_body={"id": 1, "name": "Ada"},
            )
        ],
        candidate_records=[
            TrafficRecord(
                method="GET",
                url="https://x.test/users/1",
                response_status=200,
                response_body={"id": 1, "name": "Ada", "email": "a@x.test"},
            )
        ],
    )

    diff_payload = diff_graph_endpoint(payload)

    assert diff_payload.summary["changed_nodes"] >= 1
