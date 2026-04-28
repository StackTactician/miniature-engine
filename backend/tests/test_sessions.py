from app.models import GraphEdge, GraphNode, GraphPayload
from app.sessions import clear_sessions, create_session, get_session, list_sessions


def test_create_list_and_get_session() -> None:
    clear_sessions()
    graph = GraphPayload(
        nodes=[GraphNode(id="model:users", label="users", type="model", metadata={})],
        edges=[GraphEdge(source="endpoint:GET:/users", target="model:users", relation="returns")],
    )

    created = create_session("Baseline", graph)
    assert created.name == "Baseline"
    assert created.graph.nodes[0].id == "model:users"

    summaries = list_sessions()
    assert len(summaries) == 1
    assert summaries[0].node_count == 1
    assert summaries[0].edge_count == 1

    fetched = get_session(created.id)
    assert fetched is not None
    assert fetched.id == created.id


def test_get_session_missing() -> None:
    clear_sessions()
    assert get_session("does-not-exist") is None
