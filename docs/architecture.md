# Architecture

## High-level flow

1. User submits a URL/session.
2. Capture adapters collect HTTP traffic records.
3. Processing layer normalizes endpoints and identifies behavior patterns.
4. Analysis layer infers schemas and model relationships.
5. Graph engine creates endpoint/model nodes + edges.
6. Backend API returns graph payload for frontend visualization.

## Components

### Capture Layer

- `TrafficCaptureAdapter` interface for pluggable collectors.
- Future adapters:
  - mitmproxy (deep interception)
  - Playwright network events (browser-driven flows)

### Processing Engine

- Path parameter normalization
- Endpoint deduplication by method + normalized path
- Lightweight pattern detection:
  - CRUD classification from HTTP methods
  - Pagination flag from query params / response keys

### Analysis Engine

- JSON schema inference from response payloads
- Model relationship detection using identifier references (`*_id`, `id`)

### Graph Engine

- Endpoint nodes
- Model nodes
- Edges:
  - Endpoint -> Model (`returns`)
  - Model -> Model (`references`)

### API Layer

- FastAPI endpoint accepts records and returns graph JSON for UI clients.

## MVP boundaries

In scope:

- Ingest traffic records (already captured externally)
- Endpoint normalization
- Basic JSON schema/model extraction
- Graph response API

Out of scope:

- Full browser automation UI
- Persistent storage
- GraphQL support
- Fuzzing/vulnerability scans
