from app.diff import diff_graphs
from app.graph import build_graph
from app.models import TrafficRecord


def test_diff_graphs_added_removed_and_changed() -> None:
    baseline_records = [
        TrafficRecord(
            method="GET",
            url="https://x.test/users/1",
            response_status=200,
            response_body={"id": 1, "name": "Alice"},
        ),
    ]
    candidate_records = [
        TrafficRecord(
            method="GET",
            url="https://x.test/users/1",
            response_status=200,
            response_body={"id": 1, "name": "Alice", "email": "alice@x.test"},
        ),
        TrafficRecord(
            method="GET",
            url="https://x.test/teams/7",
            response_status=200,
            response_body={"id": 7, "name": "Core"},
        ),
    ]

    baseline = build_graph(baseline_records)
    candidate = build_graph(candidate_records)
    diff = diff_graphs(baseline, candidate)

    assert diff.summary["added_nodes"] == 2
    assert diff.summary["changed_nodes"] == 1
    assert diff.summary["removed_nodes"] == 0
    assert any(node.id == "model:teams" for node in diff.added_nodes)
    assert any(change.id == "model:users" for change in diff.changed_nodes)
