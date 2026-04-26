from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.graph import build_graph
from app.models import BuildGraphRequest, GraphPayload

app = FastAPI(title="API Graph Mapper", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/graph/build", response_model=GraphPayload)
def build_graph_endpoint(payload: BuildGraphRequest) -> GraphPayload:
    return build_graph(payload.records)
