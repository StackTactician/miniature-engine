from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.capture_playwright import capture as playwright_capture
from app.graph import build_graph
from app.models import BuildGraphRequest, CaptureRequest, GraphPayload

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


@app.post("/capture", response_model=GraphPayload)
def capture_endpoint(req: CaptureRequest) -> GraphPayload:
    records = playwright_capture(req.url)
    if not records:
        raise HTTPException(
            status_code=422,
            detail=(
                "No JSON API responses were captured. "
                "The site may not make XHR/fetch requests on load, "
                "or all responses use a non-JSON content type."
            ),
        )
    return build_graph(records)
