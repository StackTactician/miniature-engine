from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from app.models import GraphPayload, SessionRecord, SessionSummary

_SESSIONS: dict[str, SessionRecord] = {}


def create_session(name: str, graph: GraphPayload) -> SessionRecord:
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    session_id = uuid4().hex
    session = SessionRecord(id=session_id, name=name.strip(), created_at=now, graph=graph)
    _SESSIONS[session_id] = session
    return session


def list_sessions() -> list[SessionSummary]:
    ordered = sorted(_SESSIONS.values(), key=lambda item: item.created_at, reverse=True)
    return [
        SessionSummary(
            id=item.id,
            name=item.name,
            created_at=item.created_at,
            node_count=len(item.graph.nodes),
            edge_count=len(item.graph.edges),
        )
        for item in ordered
    ]


def get_session(session_id: str) -> SessionRecord | None:
    return _SESSIONS.get(session_id)


def clear_sessions() -> None:
    _SESSIONS.clear()
