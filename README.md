# Miniature Engine

Miniature Engine is a developer/security analysis platform that captures website API traffic and turns it into an interactive graph of endpoints, models, and relationships. It now supports **live browser capture**, **real-time capture progress streaming**, and **graph diffing** for change detection across releases.

---

## Why Miniature Engine

Miniature Engine helps teams answer:

- What API surface area actually exists in production behavior?
- Which data models and relationships can be inferred from observed traffic?
- What changed between two captures (added/removed/changed endpoints/models/edges)?
- Which areas may carry elevated risk (unauthenticated ID-style paths, sensitive fields, etc.)?

---

## Core capabilities

- **Traffic ingestion**
  - JSON record ingestion (`POST /graph/build`)
  - HAR upload/parsing (frontend)
  - Live Playwright capture (`POST /capture`)
  - WebSocket live-capture progress stream (`/capture/stream`)
- **Graph construction**
  - Endpoint normalization and deduplication
  - CRUD classification
  - Pagination signal detection
  - Model inference + relationship inference
- **Graph diffing**
  - Compare two captures via `POST /graph/diff`
  - Detect added/removed/changed nodes and edges
  - Return machine-friendly summary counts
- **Session management**
  - Save named graph snapshots
  - List and reload prior sessions
- **Visualization**
  - Interactive React Flow canvas
  - Endpoint and model custom node renderers
  - Detail panel and live stats bar

---

## System architecture at a glance

1. **Capture** traffic from JSON/HAR/live browser.
2. **Process** traffic into normalized endpoint summaries.
3. **Analyze** response bodies into inferred models + relationships.
4. **Build** a graph payload (nodes + edges).
5. **Diff** two graphs to identify structural drift.
6. **Visualize** graph and details in the frontend.

For deeper architecture notes, see:

- `docs/architecture.md`
- `docs/features.md`
- `docs/api.md`
- `docs/development.md`

---

## Repository layout

```text
backend/                        FastAPI backend
  app/
    main.py                     API + WebSocket routes
    models.py                   Shared Pydantic models
    capture.py                  Capture adapter interface
    capture_playwright.py       Playwright-based live capture
    processing.py               Endpoint normalization + summaries
    analysis.py                 Model/schema/relationship inference
    graph.py                    Graph construction
    diff.py                     Graph diff engine
  tests/                        Unit tests

frontend/                       React + Vite frontend
  src/
    App.jsx                     App shell and orchestration
    api.js                      Backend API client helpers
    harParser.js                HAR -> TrafficRecord conversion
    layout.js                   Graph payload -> React Flow layout
    components/                 Input/canvas/detail/stats UI

docs/                           Product/architecture/API/development docs
```

---

## Quickstart

### 1) Start backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate   # Windows PowerShell: .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Backend runs at:

- API: `http://localhost:8000`
- OpenAPI docs: `http://localhost:8000/docs`

### 2) Start frontend

```bash
cd frontend
npm install
npm run dev
```

Frontend runs at:

- `http://localhost:5173`

---

## Usage flows

### A. Build graph from JSON records

1. Open Miniature Engine at `http://localhost:5173`.
2. Select **JSON** tab.
3. Paste `TrafficRecord[]`.
4. Click **Build Graph**.

### B. Build graph from HAR

1. Select **HAR File** tab.
2. Drop/select a `.har` file.
3. Click **Build Graph**.

### C. Live capture with progress stream

1. Select **Live Capture** tab.
2. Enter a full URL (`http://` or `https://`).
3. Click **Build Graph**.
4. Watch real-time progress messages while capture runs.

---

## API reference (summary)

### `GET /health`

Returns backend liveness status.

### `POST /graph/build`

Input:

```json
{
  "records": [/* TrafficRecord[] */]
}
```

Output:

```json
{
  "nodes": [/* GraphNode[] */],
  "edges": [/* GraphEdge[] */]
}
```

### `POST /capture`

Input:

```json
{ "url": "https://example.com" }
```

Output: `GraphPayload`.

### `POST /graph/diff`

Input:

```json
{
  "baseline_records": [/* TrafficRecord[] */],
  "candidate_records": [/* TrafficRecord[] */]
}
```

### Session APIs

- `GET /sessions`
- `GET /sessions/{id}`
- `POST /sessions` with `{ "name": "...", "graph": GraphPayload }`

Output:

```json
{
  "added_nodes": [],
  "removed_nodes": [],
  "changed_nodes": [],
  "added_edges": [],
  "removed_edges": [],
  "summary": {
    "added_nodes": 0,
    "removed_nodes": 0,
    "changed_nodes": 0,
    "added_edges": 0,
    "removed_edges": 0
  }
}
```

### `WS /capture/stream?url=<encoded-url>`

Message types:

- `{"type":"progress","message":"..."}`
- `{"type":"result","graph":{...GraphPayload...}}`
- `{"type":"error","message":"..."}`

---

## Testing and quality checks

Backend:

```bash
cd backend
pytest -q
```

Frontend build:

```bash
cd frontend
node ./node_modules/vite/bin/vite.js build
```

---

## Troubleshooting

- **No live-capture results**:
  - Target may not use XHR/fetch on initial page load.
  - Responses may be non-JSON and intentionally ignored.
- **Empty HAR parse**:
  - Ensure HAR includes network responses and API calls.
  - Prefer capturing an API-heavy interaction path.
- **WebSocket errors**:
  - Confirm backend is reachable at `localhost:8000`.
  - Ensure URL includes protocol and is accessible from environment.

---

## Roadmap focus

Current focus areas:

1. Rich graph diff UX in frontend (side-by-side and filtered changes).
2. Incremental node/edge streaming during live capture.
3. Session baseline management and diff UX enhancements.
4. Advanced protocol support (GraphQL/WebSocket/gRPC).
