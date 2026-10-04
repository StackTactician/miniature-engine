# Miniature Engine

An automated API discovery, reverse engineering, and contract synthesis engine. Miniature Engine inspects modern web applications, client-side JavaScript bundles, and network captures to reconstruct API surfaces, route parameters, schemas, and specifications.

---

## Capabilities

* **Tree-sitter AST Extraction**: High-throughput C AST queries via `tree-sitter` and `tree-sitter-javascript` to recover parameterized route templates (e.g. `/api/v1/{resource}/{id}`), query parameters, and Next.js Server Actions (`Next-Action` hashes).
* **Chunk Map Cracking (Pass 2 Discovery)**: Decodes Webpack 4/5 runtime chunk templates (`__webpack_require__.u`), Vite dynamic import maps (`__vite__mapDeps`), and Next.js `_buildManifest.js` to iteratively discover code-split bundles.
* **Stealth Networking & Challenge Solver**: `curl_cffi`-powered Chrome TLS impersonation, automated Reddit Proof-of-Work (PoW SHA-256) solver, and WAF challenge detection (Cloudflare Turnstile, Akamai, AWS WAF), with automatic fallback to standard `httpx`.
* **Headless DOM Runtime**: Lightweight Node.js sidecar using `happy-dom` that intercepts runtime `window.fetch` and `XMLHttpRequest` calls in dynamic SPAs without requiring Chromium or Puppeteer.
* **Scope & CDN Resolver**: CSP-driven (`script-src`, `connect-src`) dynamic asset host whitelisting, multi-tenant CDN tracking (CloudFront, Fastly, Akamai, unpkg, cdnjs), and analytics filter.
* **HAR 1.2 Ingestion Engine**: Pure Python standard library HAR parser. Extracts authentication credentials (Bearer JWTs, Basic Auth, API keys, session cookies), clusters route calls, and runs structural type inference for request/response bodies.
* **GraphQL & Apollo APQ Synthesizer**: Extracts Apollo Persisted Queries (APQ 64-hex SHA-256 hashes) and Relay queries; synthesizes standalone `schema.graphql` SDL documents without needing `__schema` introspection.
* **Multi-Format Exporters**: Generates OpenAPI 3.1.0 specifications (JSON and YAML), Postman Collection v2.1.0, and GraphQL SDL schemas.
* **Decoupled Testing Web Interface**: Native single-file web dashboard (Python stdlib HTTP server + asyncio) with Server-Sent Events (SSE) live logs, drag-and-drop HAR ingestion, cracked chunk viewer, and direct exports.

---

## Requirements

* **Python 3.10+**
* Core Python dependencies:
  * `httpx`
  * `aiolimiter`
  * `graphql-core`
  * `beautifulsoup4`
  * `tree-sitter` & `tree-sitter-javascript`
* Optional extensions:
  * `curl_cffi` (for Chrome TLS fingerprinting and stealth requests)
  * `node` & `happy-dom` (for headless DOM dynamic script evaluation)

---

## Quickstart

### Start the Testing Web Dashboard

```bash
python3 -m api_tool.web.server --host=127.0.0.1 --port=8000
```
Open `http://127.0.0.1:8000` in your browser.

### Run Test Suite

```bash
python3 -m unittest discover tests/ -v
```
*(411 tests passing across 24 test suites including AST parsing, chunk cracking, stealth client, HAR ingestion, DOM engine, and stress benchmarks).*

---

## License

MIT
