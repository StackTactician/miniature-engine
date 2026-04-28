from __future__ import annotations

from urllib.parse import parse_qs, urlparse
import asyncio

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from app.capture_playwright import capture as playwright_capture
from app.diff import diff_graphs
from app.graph import build_graph
from app.models import (
    BuildGraphRequest,
    CaptureRequest,
    CreateSessionRequest,
    GraphDiffPayload,
    GraphDiffRequest,
    GraphPayload,
    SessionRecord,
    SessionSummary,
)
from app.sessions import create_session, get_session, list_sessions

app = FastAPI(title="Miniature Engine", version="0.1.0")

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


@app.post("/graph/diff", response_model=GraphDiffPayload)
def diff_graph_endpoint(payload: GraphDiffRequest) -> GraphDiffPayload:
    baseline_graph = build_graph(payload.baseline_records)
    candidate_graph = build_graph(payload.candidate_records)
    return diff_graphs(baseline_graph, candidate_graph)


@app.get("/sessions", response_model=list[SessionSummary])
def list_sessions_endpoint() -> list[SessionSummary]:
    return list_sessions()


@app.get("/sessions/{session_id}", response_model=SessionRecord)
def get_session_endpoint(session_id: str) -> SessionRecord:
    session = get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found.")
    return session


@app.post("/sessions", response_model=SessionRecord)
def create_session_endpoint(payload: CreateSessionRequest) -> SessionRecord:
    return create_session(payload.name, payload.graph)


@app.websocket("/capture/stream")
async def capture_stream(websocket: WebSocket) -> None:
    await websocket.accept()
    try:
        raw_url = parse_qs(urlparse(str(websocket.url)).query).get("url", [""])[0].strip()
        if not raw_url.startswith(("http://", "https://")):
            await websocket.send_json({"type": "error", "message": "Missing or invalid url query parameter."})
            await websocket.close(code=1008)
            return

        await websocket.send_json({"type": "progress", "message": "Starting live capture..."})
        queue: asyncio.Queue[str | None] = asyncio.Queue()
        loop = asyncio.get_running_loop()
        records: list = []
        capture_error: Exception | None = None

        def on_progress(message: str) -> None:
            loop.call_soon_threadsafe(queue.put_nowait, message)

        def run_capture() -> None:
            nonlocal records, capture_error
            try:
                records = playwright_capture(raw_url, on_progress=on_progress)
            except Exception as exc:
                capture_error = exc
            finally:
                loop.call_soon_threadsafe(queue.put_nowait, None)

        capture_task = asyncio.create_task(asyncio.to_thread(run_capture))

        while True:
            message = await queue.get()
            if message is None:
                break
            await websocket.send_json({"type": "progress", "message": message})

        await capture_task
        if capture_error:
            await websocket.send_json({"type": "error", "message": f"Live capture failed: {capture_error}"})
            await websocket.close(code=1011)
            return

        if not records:
            await websocket.send_json(
                {
                    "type": "error",
                    "message": (
                        "No JSON API responses were captured. "
                        "The site may not make XHR/fetch requests on load, "
                        "or all responses use a non-JSON content type."
                    ),
                }
            )
            await websocket.close(code=1000)
            return

        payload = build_graph(records)
        await websocket.send_json({"type": "result", "graph": payload.model_dump()})
        await websocket.close(code=1000)
    except WebSocketDisconnect:
        return
