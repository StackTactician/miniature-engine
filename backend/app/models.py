from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class TrafficRecord(BaseModel):
    method: str
    url: str
    request_headers: dict[str, str] = Field(default_factory=dict)
    request_body: Any = None
    response_status: int
    response_headers: dict[str, str] = Field(default_factory=dict)
    response_body: Any = None


class EndpointSummary(BaseModel):
    method: str
    raw_path: str
    normalized_path: str
    operation: Literal["create", "read", "update", "delete", "other"]
    has_pagination: bool = False
    is_authenticated: bool = True
    is_idor_candidate: bool = False


class ModelField(BaseModel):
    name: str
    type: str
    is_pii: bool = False


class DataModel(BaseModel):
    name: str
    fields: list[ModelField] = Field(default_factory=list)


class GraphNode(BaseModel):
    id: str
    label: str
    type: Literal["endpoint", "model"]
    metadata: dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    source: str
    target: str
    relation: Literal["returns", "references"]


class GraphPayload(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]


class BuildGraphRequest(BaseModel):
    records: list[TrafficRecord]


class CaptureRequest(BaseModel):
    url: str


class GraphDiffNodeChange(BaseModel):
    id: str
    before: GraphNode
    after: GraphNode


class GraphDiffRequest(BaseModel):
    baseline_records: list[TrafficRecord]
    candidate_records: list[TrafficRecord]


class GraphDiffPayload(BaseModel):
    added_nodes: list[GraphNode]
    removed_nodes: list[GraphNode]
    changed_nodes: list[GraphDiffNodeChange]
    added_edges: list[GraphEdge]
    removed_edges: list[GraphEdge]
    summary: dict[str, int]


class CreateSessionRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    graph: GraphPayload


class SessionSummary(BaseModel):
    id: str
    name: str
    created_at: str
    node_count: int
    edge_count: int


class SessionRecord(BaseModel):
    id: str
    name: str
    created_at: str
    graph: GraphPayload
