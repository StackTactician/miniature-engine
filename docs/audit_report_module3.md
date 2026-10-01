# Audit Report — Module 3: HTTP Networking Modules

**Date:** 2026-10-01  
**Reviewer:** Senior Python Software Engineer (Antigravity Code Review)  
**Scope:** `api_tool/prober/` — `http_prober.py`, `spec_finder.py`, `graphql_prober.py`, `coordinator.py`

---

## 1. Target URL Validation Consistency (`is_safe_target`)

### Finding 1.1 — `spec_finder.py`: No SSRF check in `probe_path`
| Field | Value |
|---|---|
| **File** | `api_tool/prober/spec_finder.py` |
| **Location** | `_probe_execution()` → `probe_path()` inner function |
| **Original lines** | 774–793 (pre-patch) |
| **Severity** | 🔴 Critical |

**Description:** `probe_path` issued `client.head()` and `client.get()` requests for every candidate path without first calling `is_safe_target()`. An attacker supplying a crafted `base_url` (e.g., pointing to `http://169.254.169.254/`) could trigger SSRF via the spec discovery pipeline.

**Patch applied:** Added `is_safe_target(target_url)` call at the top of `probe_path`, before acquiring the semaphore and before any HTTP call. Uses a lazy import of `is_safe_target` from `http_prober` to avoid circular import. Returns early with a `debug` log if the URL is blocked.

---

### Finding 1.2 — `spec_finder.py`: No SSRF check in `fetch_secondary`
| Field | Value |
|---|---|
| **File** | `api_tool/prober/spec_finder.py` |
| **Location** | `_probe_execution()` → `fetch_secondary()` inner function |
| **Original lines** | 919–932 (pre-patch) |
| **Severity** | 🔴 Critical |

**Description:** `fetch_secondary` fetched arbitrary URLs extracted from HTML pages (e.g., from `<script>` tags) without SSRF validation. A malicious HTML response could embed `url: 'http://192.168.0.1/admin'` to redirect subsequent fetches to internal addresses.

**Patch applied:** Added `is_safe_target(sec_url)` call at the top of `fetch_secondary`, before the semaphore acquisition and HTTP call. Returns early with a `debug` log if blocked.

---

### Finding 1.3 — `graphql_prober.py`: No SSRF check in `probe_endpoint`
| Field | Value |
|---|---|
| **File** | `api_tool/prober/graphql_prober.py` |
| **Location** | `GraphQLProber.probe_endpoint()` |
| **Original lines** | 172–179 (pre-patch) |
| **Severity** | 🔴 Critical |

**Description:** `probe_endpoint` issued POST and GET requests (`c.post()`, `c.get()`) to the supplied URL without any SSRF validation. This is the primary entry point for GraphQL probing and was entirely unguarded.

**Patch applied:** Added `is_safe_target(url)` call immediately after `url.strip()`, before client creation. Returns a `GraphQLProbeResult` with an error message and logs a warning if blocked.

---

### Finding 1.4 — `graphql_prober.py`: No SSRF check in `run_introspection`
| Field | Value |
|---|---|
| **File** | `api_tool/prober/graphql_prober.py` |
| **Location** | `GraphQLProber.run_introspection()` |
| **Original lines** | 323–330 (pre-patch) |
| **Severity** | 🟠 High |

**Description:** `run_introspection` accepts an optional `probe_result` argument. When pre-supplied, it bypasses the call to `probe_endpoint` (which now has a guard), meaning a caller could supply a `probe_result` for a dangerous internal URL and still trigger POST/GET requests via `_send_intro`.

**Patch applied:** Added defense-in-depth `is_safe_target(url)` guard at the top of `run_introspection`, before client creation. Returns an empty `GraphQLProbeResult` with an error message if blocked.

---

### Finding 1.5 — `graphql_prober.py`: No SSRF check in `discover_and_probe`
| Field | Value |
|---|---|
| **File** | `api_tool/prober/graphql_prober.py` |
| **Location** | `GraphQLProber.discover_and_probe()` |
| **Original lines** | 541 (pre-patch) |
| **Severity** | 🟡 Medium |

**Description:** `discover_and_probe` constructs N candidate URLs from `base_url` and delegates each to `run_introspection` (now guarded). However, the `base_url` itself was not validated before URL construction, and individual `candidate_endpoints` containing full `http://` URLs were passed through unchecked.

**Patch applied:** Added `is_safe_target(clean_base)` guard at the start of `discover_and_probe`. Returns `[]` immediately if the base URL is dangerous. Individual candidate URL checks are handled by the existing guards in `run_introspection` → `probe_endpoint`.

---

### Finding 1.6 — `coordinator.py`: SSRF check already present ✅
| Field | Value |
|---|---|
| **File** | `api_tool/prober/coordinator.py` |
| **Location** | `APIProber.probe()` — lines 283–301 |
| **Severity** | None |

**Description:** `coordinator.py` already imports and calls `is_safe_target(clean_base)` before dispatching to sub-probers. No action required.

---

## 2. Regular Expression Time Complexity

### Finding 2.1 — `spec_finder.py`: ReDoS in SwaggerUI pattern
| Field | Value |
|---|---|
| **File** | `api_tool/prober/spec_finder.py` |
| **Location** | `extract_spec_url_from_html()` — original line 308 |
| **Severity** | 🔴 Critical |

**Vulnerable pattern:**
```python
r"SwaggerUI(?:Bundle)?\s*\(\s*\{[^}]*?url\s*:\s*['\"]([^'\"]+)['\"]"
```

**Analysis:** The lazy `[^}]*?url` suffix causes O(N²) backtracking on inputs where a `SwaggerUI(` opening is present but no matching `}url` sequence follows for thousands of characters. On a 100KB+ HTML page, each character position triggers a `url` probe attempt.

**Patch applied:** Two-step approach — first locate `SwaggerUI(?:Bundle)?\s*\(\s*\{` as an anchor (simple linear scan), then search only a **bounded 2000-character window** after the anchor for `url\s*:\s*['"]([^'"]+)['"]`. This guarantees O(N) overall behavior since each anchor triggers at most one bounded search.

---

### Finding 2.2 — `spec_finder.py`: ReDoS in `createApiReference` pattern
| Field | Value |
|---|---|
| **File** | `api_tool/prober/spec_finder.py` |
| **Location** | `extract_spec_url_from_html()` — original line 324 |
| **Severity** | 🔴 Critical |

**Vulnerable pattern:**
```python
r"createApiReference\s*\([^)]*?url\s*:\s*['\"]([^'\"]+)['\"]"
```

**Analysis:** Same class of vulnerability as Finding 2.1. The lazy `[^)]*?url` causes O(N²) backtracking on inputs where `createApiReference(` is present but no `)url` sequence follows for a large span. With `re.DOTALL`, `[^)]` excludes only `)`, so every character triggers a new `url` match attempt.

**Patch applied:** Two-step approach — locate `createApiReference\s*\(` as anchor, then search a bounded 2000-character window. O(N) total.

---

### Finding 2.3 — All other patterns in `spec_finder.py` ✅
| Pattern | Analysis |
|---|---|
| `url\s*:\s*['"](…\.json…)['"]\b` | Safe — lazy on exclusion class, no nesting |
| `\{\s*url\s*:\s*['"]([^'"]+)['"]` | Safe — simple literal anchor + exclusion class |
| `configUrl\s*:\s*['"]([^'"]+)['"]` | Safe — literal anchor |
| `Redoc\.init\s*\(\s*['"]([^'"]+)['"]` | Safe — literal anchor |
| `(?:spec-url\|…)\s*[:=]\s*['"]([^'"]+)['"]` | Safe — literal anchor |

---

### Finding 2.4 — `graphql_prober.py` `_UI_PATTERNS` ✅
All four compiled patterns use character exclusion classes `[^<]+` and literal string anchors before character groups. No nested quantifiers. All patterns are safe on 100KB+ inputs.

---

## 3. Concurrency Resource Safety

### Finding 3.1 — `spec_finder.py`: Semaphore usage via `async with` ✅
Both `probe_path` and `fetch_secondary` acquire `asyncio.Semaphore` via `async with`, which guarantees release on any exception including `asyncio.CancelledError`.

### Finding 3.2 — `graphql_prober.py`: `httpx.AsyncClient` closure via `finally` ✅
`probe_endpoint`, `run_introspection`, and `discover_and_probe` all use `try/finally: await c.aclose()` when managing a client internally. Correct.

### Finding 3.3 — `http_prober.py`: `aiolimiter.AsyncLimiter` usage ✅
Rate limiter acquired via `async with self.limiter:` in `_send_request` and the streaming fallback. Both release correctly.

### Finding 3.4 — `http_prober.py`: `httpx.AsyncClient` context manager ✅
`probe_endpoint` and `probe_endpoints` both use `async with httpx.AsyncClient(...) as ...:`.

### Finding 3.5 — `coordinator.py`: `httpx.AsyncClient` context manager ✅
`APIProber.probe()` opens a managed client via `async with httpx.AsyncClient(...) as managed_client:`.

**All concurrency patterns are correct. No changes required.**

---

## 4. Memory Safety for Large Inputs

### Finding 4.1 — `spec_finder.py`: No content-length guard in `probe_path`
| Field | Value |
|---|---|
| **File** | `api_tool/prober/spec_finder.py` |
| **Location** | `_probe_execution()` → `probe_path()` |
| **Severity** | 🟠 High |

**Description:** `resp.text` was accessed for 200 responses without checking response body size. A server returning a 100MB+ YAML payload would be fully buffered into memory.

**Patch applied:**
1. Added `_MAX_RESPONSE_BYTES = 20 * 1024 * 1024` module-level constant.
2. Checks `Content-Length` header before `resp.text` — returns early with warning if exceeded.
3. Checks `len(resp.content)` after `resp.text` to catch chunked responses without `Content-Length`.

---

### Finding 4.2 — `spec_finder.py`: No content-length guard in `fetch_secondary`
| Field | Value |
|---|---|
| **File** | `api_tool/prober/spec_finder.py` |
| **Location** | `_probe_execution()` → `fetch_secondary()` |
| **Severity** | 🟠 High |

**Patch applied:** Same dual-check pattern as Finding 4.1.

---

## 5. Exception Handling Completeness

### Finding 5.1 — `spec_finder.py`: `probe_path` exception types incomplete
| Field | Value |
|---|---|
| **File** | `api_tool/prober/spec_finder.py` |
| **Location** | `probe_path()` except clause |
| **Severity** | 🟡 Medium |

**Patch applied:** Added explicit `ssl.SSLError`, `httpx.ConnectError`, and `httpx.TooManyRedirects` to the except clause. Added `import ssl`.

---

### Finding 5.2 — `spec_finder.py`: `fetch_secondary` catches only bare `Exception`
**Patch applied:** Same explicit enumeration as Finding 5.1.

---

### Finding 5.3 — `graphql_prober.py`: HTTP calls wrapped in `except Exception` ✅
Individual HTTP calls in `probe_endpoint` are wrapped in separate `try/except Exception` blocks for POST, GET, and UI fallback. Coverage is complete.

### Finding 5.4 — `graphql_prober.py`: `_send_intro` helper ✅
POST and GET within `_send_intro` are individually wrapped in `except Exception`. No unguarded calls.

### Finding 5.5 — `http_prober.py`: `_send_request` outer caller provides coverage ✅
`_probe_with_client` wraps the entire probe flow in `try/except Exception` (line 570). No unguarded network calls.

---

## Summary Table

| # | File | Finding | Severity | Patched |
|---|---|---|---|---|
| 1.1 | `spec_finder.py` | `probe_path` missing `is_safe_target` SSRF check | 🔴 Critical | ✅ |
| 1.2 | `spec_finder.py` | `fetch_secondary` missing `is_safe_target` SSRF check | 🔴 Critical | ✅ |
| 1.3 | `graphql_prober.py` | `probe_endpoint` missing `is_safe_target` SSRF check | 🔴 Critical | ✅ |
| 1.4 | `graphql_prober.py` | `run_introspection` missing SSRF check (defense-in-depth) | 🟠 High | ✅ |
| 1.5 | `graphql_prober.py` | `discover_and_probe` missing base URL SSRF check | 🟡 Medium | ✅ |
| 1.6 | `coordinator.py` | `is_safe_target` already called | — | N/A |
| 2.1 | `spec_finder.py` | ReDoS: `SwaggerUI…[^}]*?url` — O(N²) on large JS blobs | 🔴 Critical | ✅ |
| 2.2 | `spec_finder.py` | ReDoS: `createApiReference…[^)]*?url` — O(N²) on large JS blobs | 🔴 Critical | ✅ |
| 2.3 | `spec_finder.py` | All other regex patterns — safe O(N) | — | N/A |
| 2.4 | `graphql_prober.py` | All `_UI_PATTERNS` — safe O(N) | — | N/A |
| 3.1–3.5 | all files | Semaphore / AsyncClient / AsyncLimiter — all safe | — | N/A |
| 4.1 | `spec_finder.py` | `probe_path`: No 20MB content-length guard | 🟠 High | ✅ |
| 4.2 | `spec_finder.py` | `fetch_secondary`: No 20MB content-length guard | 🟠 High | ✅ |
| 5.1 | `spec_finder.py` | `probe_path`: Missing explicit exception types | 🟡 Medium | ✅ |
| 5.2 | `spec_finder.py` | `fetch_secondary`: Bare `except Exception` | 🟡 Medium | ✅ |
| 5.3–5.5 | all files | Exception coverage complete or handled by design | — | N/A |

---

## Test Results

```
Ran 160 tests in 32.691s

OK
```

All 160 existing tests pass after patches.
