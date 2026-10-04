# Miniature Engine

**Turn modern web apps, JavaScript bundles, and network captures into clean OpenAPI specs and Postman collections.**

Miniature Engine is an automated API reverse engineering and discovery tool. Whether you need to document a legacy system, map an application's full attack surface, or convert browser recordings into runnable API test suites, it reconstructs endpoints, route parameters, and data schemas automatically.

---

## What You Can Do

### 1. Document Undocumented Web Applications & SPAs
Point the engine at a target URL. It crawls the application, follows client-side routing, and extracts endpoints directly from JavaScript code—recovering clean, parameterized route templates (e.g. `/api/v1/users/{userId}/invoices`) and Next.js Server Actions.

### 2. Convert Network Captures (HAR) into OpenAPI Specs
Record a session in Chrome DevTools, Burp Suite, or Charles Proxy, and drop the `.har` file into the dashboard. Miniature Engine filters out static asset noise, extracts authentication credentials (Bearer JWTs, session cookies, API keys), clusters requests, and infers JSON validation schemas for both request bodies and responses.

### 3. Discover Hidden & Shadow Endpoints in Code-Split Bundles
Modern frameworks (Webpack 4/5, Vite, Next.js) split code into dozens of asynchronous chunks that only load on specific user actions. Miniature Engine decodes runtime chunk manifests to discover and inspect 100% of chunk files across the app, uncovering internal APIs and administrative routes that can't be reached by simple crawling.

### 4. Reconstruct GraphQL Schemas (Even Without Introspection)
Production GraphQL servers almost universally disable `__schema` introspection. Miniature Engine extracts queries, mutations, and Apollo Persisted Query (APQ) hashes from client bundles, then synthesizes a valid, standalone `schema.graphql` SDL file without needing introspection.

### 5. Crawl Protected Targets Without Immediate IP Blocks
Engineered with a stealth networking client that impersonates real browser TLS fingerprints and automatically solves proof-of-work nonces and inline challenges, preventing aggressive bot walls from shutting down discovery scans.

---

## Instant Exports

Everything discovered can be exported in standard formats ready for your toolchain:
* **OpenAPI 3.1.0** (`openapi.json` & `openapi.yaml`) – Ready for Swagger UI, Prism mock servers, or SDK generators.
* **Postman Collection v2.1.0** – Pre-configured requests, route parameters, and body templates ready for automated testing.
* **GraphQL SDL** (`schema.graphql`) – Standalone type and field definitions for harvested operations.

---

## Quickstart

### Launch the Web Dashboard

```bash
python3 -m api_tool.web.server --port=8000
```
Open `http://localhost:8000` in your browser to:
* Run automated discovery scans with real-time streaming feedback.
* Drag-and-drop `.har` files for instant reverse engineering.
* Browse cracked chunk manifests, extracted GraphQL queries, and parameter tables.
* Download OpenAPI and Postman files with one click.

### Run Test Suite

```bash
python3 -m unittest discover tests/ -v
```
*(411 tests passing across 24 test suites).*

---

## Requirements

* **Python 3.10+**
* Core dependencies: `httpx`, `aiolimiter`, `graphql-core`, `beautifulsoup4`, `tree-sitter`, `tree-sitter-javascript`
* Optional: `curl_cffi` (stealth TLS fingerprinting), Node.js + `happy-dom` (headless DOM dynamic script execution)

---

## License

MIT
