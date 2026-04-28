# Miniature Engine API Guide

This guide documents request/response contracts and message semantics for backend integrations.

Base URL (local): `http://localhost:8000`

---

## 1) Health

### `GET /health`

Response:

```json
{ "status": "ok" }
```

---

## 2) Build graph from records

### `POST /graph/build`

Request:

```json
{
  "records": [
    {
      "method": "GET",
      "url": "https://api.example.com/users/1",
      "request_headers": {},
      "request_body": null,
      "response_status": 200,
      "response_headers": { "content-type": "application/json" },
      "response_body": { "id": 1, "name": "Alice" }
    }
  ]
}
```

Response:

```json
{
  "nodes": [],
  "edges": []
}
```

---

## 3) Live capture (HTTP)

### `POST /capture`

Request:

```json
{ "url": "https://example.com" }
```

Response:

```json
{
  "nodes": [],
  "edges": []
}
```

Error behavior:

- `422` when no JSON API responses are captured.

---

## 4) Graph diff

### `POST /graph/diff`

Request:

```json
{
  "baseline_records": [],
  "candidate_records": []
}
```

Response:

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

`changed_nodes` element shape:

```json
{
  "id": "model:users",
  "before": { "id": "model:users", "label": "users", "type": "model", "metadata": {} },
  "after": { "id": "model:users", "label": "users", "type": "model", "metadata": {} }
}
```

---

## 5) Live capture stream (WebSocket)

### `WS /capture/stream?url=<encoded-url>`

The server sends one of:

```json
{ "type": "progress", "message": "Launching headless Chromium..." }
```

```json
{ "type": "result", "graph": { "nodes": [], "edges": [] } }
```

```json
{ "type": "error", "message": "No JSON API responses were captured..." }
```

Notes:

- URL query parameter is required and must include `http://` or `https://`.
- Errors can represent invalid input, capture failures, or no-results captures.

---

## 6) Session APIs

### `POST /sessions`

Request:

```json
{
  "name": "Release 2026.04.28",
  "graph": { "nodes": [], "edges": [] }
}
```

Response:

```json
{
  "id": "session-id",
  "name": "Release 2026.04.28",
  "created_at": "2026-04-28T00:00:00+00:00",
  "graph": { "nodes": [], "edges": [] }
}
```

### `GET /sessions`

Response:

```json
[
  {
    "id": "session-id",
    "name": "Release 2026.04.28",
    "created_at": "2026-04-28T00:00:00+00:00",
    "node_count": 12,
    "edge_count": 20
  }
]
```

### `GET /sessions/{session_id}`

Returns full `SessionRecord` with embedded graph payload.

---

## 7) Practical integration patterns

### CI graph drift check

1. Capture baseline and candidate records from two builds.
2. Call `POST /graph/diff`.
3. Gate on `summary` values and/or specific node/edge deltas.

### Frontend progressive capture UX

1. Open `WS /capture/stream`.
2. Render `progress` in UI.
3. On `result`, render graph payload.
4. On `error`, show actionable message.

### Session baseline workflow

1. Save a known-good graph snapshot via `POST /sessions`.
2. Load it later with `GET /sessions/{id}`.
3. Diff a current capture against the baseline with `POST /graph/diff`.
