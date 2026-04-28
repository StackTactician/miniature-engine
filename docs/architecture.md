# Miniature Engine Architecture

This document describes the technical architecture of Miniature Engine across capture, processing, analysis, graphing, diffing, and visualization.

---

## 1. Design goals

Miniature Engine is built around four primary goals:

1. **Fast API reconnaissance** from observed traffic.
2. **Explainable structure inference** for endpoints/models/relationships.
3. **Change detection** between captures via graph diff.
4. **Operator-friendly UX** with interactive graph exploration and live capture feedback.

---

## 2. End-to-end pipeline

### 2.1 Capture

Traffic enters through one of three paths:

- JSON `TrafficRecord[]` (direct API/textarea)
- HAR ingestion (frontend parser)
- Playwright live capture (`POST /capture` or `/capture/stream`)

Live capture intercepts browser `xhr/fetch` responses and filters to JSON content types.

### 2.2 Processing

Raw records are normalized into endpoint summaries:

- path normalization (`/users/123` → `/users/{id}`)
- operation classification by HTTP verb
- pagination signal detection from query params and response keys
- auth footprint and simple IDOR candidate markers

### 2.3 Analysis

Response JSON bodies are inspected to infer data models:

- field names and inferred scalar/container types
- union types when fields vary across records
- model relationship hints from `*_id` fields
- resource-segment model naming (ID-like URL segments skipped)

### 2.4 Graph assembly

Graph payload construction:

- endpoint nodes
- model nodes
- endpoint `returns` model edges
- model `references` model edges

### 2.5 Graph diffing

Two graph payloads are compared for:

- added nodes
- removed nodes
- changed nodes (`before/after`)
- added edges
- removed edges
- summary counts for dashboard/CI use

### 2.6 Visualization

Frontend renders graph with React Flow + Dagre:

- endpoint/model custom nodes
- interactive pan/zoom/minimap
- detail panel and relationship context
- live capture progress messaging

---

## 3. Backend components

### `app/main.py`

Routing/orchestration layer:

- `GET /health`
- `POST /graph/build`
- `POST /capture`
- `POST /graph/diff`
- `WS /capture/stream`

### `app/capture.py`

Adapter contract (`TrafficCaptureAdapter`) for pluggable capture mechanisms.

### `app/capture_playwright.py`

Playwright implementation for live browser capture:

- headless Chromium session
- response interception and JSON filtering
- `on_progress` callback hooks for stream consumers

### `app/processing.py`

Endpoint normalization and summary generation.

### `app/analysis.py`

Model/schema inference and relationship inference.

### `app/graph.py`

Graph assembly from processed endpoints + inferred models.

### `app/diff.py`

Deterministic graph diff computation.

### `app/models.py`

Shared Pydantic contracts for API and internal payload shapes.

---

## 4. Frontend components

### `src/App.jsx`

Main orchestrator:

- input flow handling (JSON/HAR/live)
- loading and error state management
- graph conversion and selection state

### `src/api.js`

Backend communication helpers:

- graph build
- graph diff
- standard capture
- WebSocket capture stream

### `src/harParser.js`

Transforms HAR network entries into `TrafficRecord[]`.

### `src/layout.js`

Transforms backend graph payload into positioned React Flow graph with Dagre.

### `src/components/*`

- `InputPanel`: input modes and validation
- `GraphCanvas`: React Flow rendering
- `DetailPanel`: selected node details
- `StatsBar`: aggregate counts

---

## 5. Data contracts

Core objects:

- `TrafficRecord`
- `EndpointSummary`
- `DataModel` / `ModelField`
- `GraphNode` / `GraphEdge` / `GraphPayload`
- `GraphDiffRequest` / `GraphDiffPayload`

These contracts are centralized in `backend/app/models.py`.

---

## 6. Runtime behavior details

### Live capture stream behavior

`WS /capture/stream` sends message envelopes:

- `progress`: operational status updates
- `result`: final built `GraphPayload`
- `error`: recoverable/fatal capture issues

Capture execution runs on a background thread and forwards progress messages into an async queue to avoid blocking WebSocket response flow.

### Diff behavior

Node identity key: `node.id`  
Edge identity key: `(source, target, relation)`

Changed nodes are detected when one or more of:

- `label`
- `type`
- `metadata`

are different across baseline and candidate graphs.

---

## 7. Scalability and extension points

1. **Capture adapters**
   - add mitmproxy, browser extension, replay driver adapters
2. **Analysis**
   - nested object/array schema depth
   - enum/timestamp heuristics
   - richer auth/security findings
3. **Storage**
   - move from in-memory only to persisted sessions/baselines
4. **Collaboration**
   - shareable sessions and team workflows
5. **CI/CD integration**
   - graph-diff policy checks on pull requests

---

## 8. Current constraints

- JSON REST traffic is the primary optimized path.
- Live capture discovers what runtime behavior executes; hidden/rare flows may require deeper crawl scripts.
- Diff output is backend-first today; richer frontend diff UX is the next step.

