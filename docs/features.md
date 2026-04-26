# Feature Registry

Comprehensive record of all implemented, in-progress, and planned features for API Graph Mapper.
Status key: `[x]` done · `[ ]` planned · `[-]` partial / stub

---

## 1. Capture Layer

Responsible for collecting raw HTTP traffic records.

| Status | Feature | Notes |
|--------|---------|-------|
| `[x]` | `TrafficCaptureAdapter` abstract interface | Pluggable adapter contract in `capture.py` |
| `[x]` | `StaticCaptureAdapter` | Development adapter — wraps a pre-collected list |
| `[x]` | JSON records via API | `POST /graph/build` accepts `TrafficRecord[]` directly |
| `[x]` | HAR file parsing (frontend) | Converts Chrome/Firefox `.har` exports to `TrafficRecord[]`; filters to JSON responses only |
| `[ ]` | Playwright live capture | Headless browser visits a URL, intercepts all XHR/fetch traffic, returns graph automatically |
| `[ ]` | mitmproxy adapter | Runs as a proxy; all traffic through it gets captured in real time |
| `[ ]` | Browser extension | Captures traffic from an active browsing session without a proxy |
| `[ ]` | Curl replay adapter | Accepts a list of curl commands, replays them, captures responses |
| `[ ]` | OpenAPI / Swagger import | Ingest an existing API spec as synthetic traffic records |

---

## 2. Processing Engine

Normalizes and deduplicates raw records before analysis.

| Status | Feature | Notes |
|--------|---------|-------|
| `[x]` | Path normalization | Replaces numeric and UUID-like segments with `{id}` |
| `[x]` | Endpoint deduplication | Keyed on `(method, normalized_path)` — one entry per unique operation |
| `[x]` | CRUD classification | Maps HTTP methods to `create / read / update / delete / other` |
| `[x]` | Pagination detection | Checks query params (`page`, `limit`, `cursor`, etc.) and response keys (`next`, `previous`, `total`) |
| `[ ]` | Smarter model name extraction | Walk back past numeric/UUID segments to find the resource name (`/users/123` → `users`, not `123`) |
| `[ ]` | Schema merging across responses | Union fields across multiple responses for the same normalized endpoint instead of one record per URL |
| `[ ]` | Request body normalization | Parse and schema-infer request bodies, not just responses |
| `[ ]` | Query parameter extraction | Capture and catalogue query params per endpoint as part of the endpoint summary |
| `[ ]` | Content-type filtering | Ignore non-API traffic (HTML pages, images, fonts, analytics) during processing |

---

## 3. Analysis Engine

Infers schemas and relationships from processed records.

| Status | Feature | Notes |
|--------|---------|-------|
| `[x]` | JSON schema inference | Infers field types from response body values (`string`, `integer`, `boolean`, `array`, `object`, `null`) |
| `[x]` | Model relationship detection | Detects `model_a → model_b` via `*_id` field naming convention |
| `[x]` | Union types | When the same field appears with different types across responses, types are joined with `\|` |
| `[ ]` | Nested object schema inference | Recurse into object-valued fields to infer sub-schemas |
| `[ ]` | Array item schema inference | Infer the schema of array items, not just flag the field as `array` |
| `[ ]` | Auth detection | Flag endpoints that were called without an `Authorization` / `Cookie` header |
| `[ ]` | PII field detection | Flag model fields named `email`, `phone`, `ssn`, `dob`, `address`, `password`, etc. |
| `[ ]` | IDOR candidate detection | Endpoints with `{id}` path params that appear unauthenticated |
| `[ ]` | Response code analysis | Track observed status codes per endpoint (200, 201, 400, 401, 403, 404, 422, 500) |
| `[ ]` | Rate-limit signal detection | Detect 429 responses and flag the endpoint |
| `[ ]` | Enum detection | When a string field has a small set of repeated values, infer it as an enum |
| `[ ]` | Timestamp field detection | Recognise ISO-8601 strings / Unix timestamps and tag them as `datetime` |

---

## 4. Graph Engine

Assembles the final graph payload from processed endpoints and inferred models.

| Status | Feature | Notes |
|--------|---------|-------|
| `[x]` | Endpoint nodes | One node per `(method, normalized_path)` |
| `[x]` | Model nodes | One node per inferred data model |
| `[x]` | `returns` edges | Endpoint → Model when the first path segment matches a model name |
| `[x]` | `references` edges | Model → Model when a `*_id` field points to another known model |
| `[ ]` | `accepts` edges | Endpoint → Model when request body matches a known model's schema |
| `[ ]` | Graph diff | Compare two graph payloads and surface added/removed/changed nodes and edges |
| `[ ]` | Subgraph extraction | Return only the subgraph reachable from a given node |

---

## 5. Backend API

| Status | Feature | Notes |
|--------|---------|-------|
| `[x]` | `GET /health` | Liveness check |
| `[x]` | `POST /graph/build` | Accepts `TrafficRecord[]`, returns `GraphPayload` |
| `[x]` | CORS for `localhost:5173` | Allows the Vite dev server to call the API |
| `[ ]` | `POST /capture` | Accepts a URL, runs Playwright capture, returns graph |
| `[ ]` | `POST /ingest/har` | Server-side HAR parsing (alternative to frontend parsing) |
| `[ ]` | `GET /sessions` | List saved graph sessions |
| `[ ]` | `GET /sessions/{id}` | Retrieve a saved session |
| `[ ]` | `POST /sessions` | Save a named session |
| `[ ]` | WebSocket streaming | Stream nodes/edges as they are discovered during live capture |

---

## 6. Frontend — Input

| Status | Feature | Notes |
|--------|---------|-------|
| `[x]` | JSON paste input | Textarea for raw `TrafficRecord[]` JSON |
| `[x]` | Sample data loader | Realistic 8-endpoint, 3-model fixture loaded with one click |
| `[x]` | HAR file drag-and-drop | Drop zone accepting `.har` files; converts to `TrafficRecord[]` in-browser |
| `[x]` | HAR file browser picker | Fallback file input for users who prefer click-to-browse |
| `[x]` | Input validation | Parse errors shown inline before submission |
| `[x]` | Empty HAR guard | Friendly error when no JSON API responses are found in the HAR |
| `[ ]` | URL input (live capture) | Text field + "Capture" button — triggers `POST /capture` on the backend |
| `[ ]` | Multi-file HAR merge | Accept multiple `.har` files and merge all records before building |
| `[ ]` | OpenAPI import | Accept a `swagger.json` / `openapi.yaml` as input |

---

## 7. Frontend — Graph Canvas

| Status | Feature | Notes |
|--------|---------|-------|
| `[x]` | Interactive React Flow canvas | Zoom, pan, drag nodes |
| `[x]` | Dagre LR layout | Endpoints left, models right — deterministic, structured |
| `[x]` | Custom EndpointNode | Method badge color-coded by HTTP verb, path label, pagination badge |
| `[x]` | Custom ModelNode | Purple accent, model name, field count badge, type label |
| `[x]` | Animated `returns` edges | Animated dashed line for endpoint → model edges |
| `[x]` | Styled `references` edges | Purple line for model → model edges |
| `[x]` | Edge relation labels | `returns` / `references` labels on edges |
| `[x]` | MiniMap | Color-coded by node type/method; pannable and zoomable |
| `[x]` | Controls | Zoom in/out, fit view |
| `[x]` | Dot-grid background | Subtle visual texture |
| `[x]` | Empty state | Instructional placeholder when no graph is loaded |
| `[x]` | Loading state | Spinner overlay while API call is in flight |
| `[ ]` | Node search / highlight | Type to filter/highlight matching nodes |
| `[ ]` | Filter by HTTP method | Toggle visibility of GET / POST / DELETE etc. |
| `[ ]` | Filter by auth status | Show only unauthenticated endpoints |
| `[ ]` | Filter by PII | Show only models containing PII fields |
| `[ ]` | Security badge overlay | Visual risk indicators on nodes (unauthenticated, PII, IDOR candidate) |
| `[ ]` | Fit-to-selection | Zoom to a selected subset of nodes |
| `[ ]` | Node grouping | Visually group endpoints by resource prefix (`/users/*`) |
| `[ ]` | Export as PNG/SVG | Download the current graph view as an image |
| `[ ]` | Export as JSON | Download the raw graph payload for re-import |
| `[ ]` | Live capture progress | Show nodes appearing in real time during Playwright capture via WebSocket |

---

## 8. Frontend — Detail Panel

| Status | Feature | Notes |
|--------|---------|-------|
| `[x]` | Slide-in animation | Panel animates in on node click |
| `[x]` | Escape to close | Keyboard-accessible dismiss |
| `[x]` | Endpoint detail | Method, path, operation type chip, pagination flag |
| `[x]` | Endpoint → Model links | "Returns" section listing connected model nodes |
| `[x]` | Model field table | Field name + inferred type, type color-coded |
| `[x]` | Model → Endpoint links | "Referenced by" section listing endpoints pointing to this model |
| `[ ]` | Observed status codes | List of HTTP status codes seen for this endpoint |
| `[ ]` | Auth status indicator | Whether the endpoint was ever called without credentials |
| `[ ]` | PII field highlighting | Flag fields that match PII naming patterns |
| `[ ]` | Query parameters list | All observed query params for an endpoint |
| `[ ]` | Request body schema | Inferred schema of the request body |
| `[ ]` | Raw request/response viewer | Expandable section showing an example request and response |

---

## 9. Frontend — General UI

| Status | Feature | Notes |
|--------|---------|-------|
| `[x]` | Stats bar | Live count of endpoints, models, and relationships |
| `[x]` | Error banner | API and parse errors surfaced above the canvas |
| `[x]` | Dark theme design system | CSS custom properties, glass surfaces, method color tokens |
| `[x]` | Inter + JetBrains Mono fonts | Professional typography for UI and code elements |
| `[x]` | Responsive layout | Three-column shell (sidebar · canvas · detail) |
| `[ ]` | Keyboard shortcuts | `Escape` to deselect, `/` to open search, `F` to fit view |
| `[ ]` | Session history sidebar | List of previously built graphs for the session |
| `[ ]` | Dark/light mode toggle | |
| `[ ]` | Toast notifications | Non-blocking success/warning messages |

---

## 10. Persistence (Phase 2)

| Status | Feature | Notes |
|--------|---------|-------|
| `[-]` | In-memory store | Current default — lost on server restart |
| `[ ]` | SQLite persistence | Lightweight local persistence, no infra required |
| `[ ]` | PostgreSQL backend | Production-grade relational store |
| `[ ]` | Neo4j backend | Native graph database — natural fit for the data model |
| `[ ]` | Named sessions | Save and reload named graph snapshots |
| `[ ]` | Session diff | Compare two saved sessions side by side |

---

## 11. Advanced / Phase 3

| Status | Feature | Notes |
|--------|---------|-------|
| `[ ]` | GraphQL support | Parse GraphQL queries/responses into the graph model |
| `[ ]` | WebSocket traffic capture | Capture and visualise WebSocket message schemas |
| `[ ]` | gRPC support | Parse protobuf-encoded traffic |
| `[ ]` | OpenAPI spec export | Reverse-engineer captured traffic into a Swagger/OpenAPI 3.0 document |
| `[ ]` | Postman collection export | Export captured endpoints as a Postman collection |
| `[ ]` | CI/CD integration | Run as a CLI tool on PRs; diff API surface and comment on changes |
| `[ ]` | Fuzzing hooks | Pass discovered endpoints to a fuzzer (e.g. ffuf, Burp) |
| `[ ]` | Team collaboration | Shareable graph URLs; multi-user session viewing |
| `[ ]` | CLI entrypoint | `agm capture https://example.com` — run from the terminal without the UI |
| `[ ]` | Docker Compose setup | Single `docker compose up` to run frontend + backend together |
