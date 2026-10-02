# Subagent Prompt Templates & Protocols

High-performing subagents require unambiguous instructions, clearly bounded scopes, absolute file paths, and explicit constraints.

Follow these battle-tested prompt templates when invoking subagents in each wave.

---

## 1. Deep Research Subagent (`typeName: "research"`)

Use during **Phase 1** to research specifications, modern framework behaviors, and security attack surfaces before writing code.

```markdown
Your ONLY job is to conduct comprehensive online research on [TOPIC / SPECIFICATION / VULNERABILITY SURFACE].

Specifically investigate:
1. Modern 2026-era specifications, standards, and nuances:
   - [Spec 1, e.g., OpenAPI 3.1 JSON Schema 2020-12 alignment]
   - [Spec 2, e.g., Postman Collection v2.1 schema requirements]
2. Modern framework behaviors and edge cases:
   - [Framework 1, e.g., Next.js 14/15 Server Actions, Route Handlers]
   - [Framework 2, e.g., FastAPI, Spring Boot 3 documentation exposure paths]
3. Non-destructive probing and security considerations:
   - [Security topic 1, e.g., SSRF validation against private/loopback/cloud metadata]
   - [Security topic 2, e.g., ReDoS linear O(N) regex design]
4. Pure Python & Termux compatibility:
   - Zero-C dependency techniques (pure-Python YAML serialization, lightweight JSON schema inference).

Return a complete, highly structured markdown report with concrete candidate lists, regexes, code snippets, and architectural recommendations.
```

---

## 2. Component Builder Subagent (`typeName: "self"`)

Use during **Phase 2 (Wave 1)**. Apply the **Single-Job Rule**: assign exactly one component per subagent.

```markdown
Your ONLY job is to build [COMPONENT NAME] in:
`[ABSOLUTE PATH TO TARGET FILE]`

Constraints: Pure Python 3.10+, Termux-compatible (Android Bionic libc). Zero compiled C/Rust dependencies (no pydantic-core, no libyaml, no genson). Strict memory ceiling (< 10MB RAM delta).

Before writing code:
1. Inspect the existing data contracts in `[ABSOLUTE PATH TO MODELS FILE]`.
2. Inspect any existing components this module interacts with:
   - `[FILE 1]`
   - `[FILE 2]`

Implementation Requirements:
- Domain Dataclasses:
  - Define `[DataclassName]` with typed fields and `.to_dict() -> Dict[str, Any]`.
- Class `[ClassName]`:
  - `__init__(...)` with sensible timeouts and concurrency limits.
  - `[Method 1]`: [Detailed functional specification].
  - `[Method 2]`: [Detailed functional specification].
- Error Handling & Resilience:
  - Catch network timeouts, connection errors, and malformed inputs gracefully. Never crash the host process.
- Write clean, modular code and verify with a standalone unit test in `[ABSOLUTE PATH TO TEST FILE]`. Run `python3 -m unittest [TEST_FILE] -v` to ensure 100% pass rate.
```

---

## 3. Coordinator Integrator Subagent (`typeName: "self"`)

Use at the end of **Phase 2 (Wave 1)** to integrate isolated components into a unified headless engine.

```markdown
Your ONLY job is to build the unified Coordinator in `[PATH]/coordinator.py` and export the module API in `[PATH]/__init__.py`.

Constraints: Pure Python 3.10+, headless engine design (zero CLI/print dependencies), low memory.

Before writing code:
1. Read the completed component implementations:
   - `[PATH]/component_a.py`
   - `[PATH]/component_b.py`
   - `[PATH]/models.py`

Implementation Requirements:
- Dataclass `[Module]Result`:
  - Strongly typed fields aggregating results from all sub-components.
  - `to_dict() -> Dict[str, Any]` serialization.
- Class `[Module]Coordinator`:
  - `__init__(...)` initializing sub-components.
  - Unified orchestration methods coordinating the pipeline.
- Export all public classes and dataclasses in `[PATH]/__init__.py`.
- Write a comprehensive integration test in `tests/test_[module]_coordinator.py` with mock transports and assert 100% test pass rate.
```

---

## 4. Security & Reliability Auditor Subagent (`typeName: "self"`)

Use during **Phase 3 (Wave 2)**. This agent must be independent from the builders.

```markdown
Your ONLY job is to perform a rigorous Security & Code Quality Audit of [MODULE NAME] in `[ABSOLUTE DIRECTORY PATH]`.

Inspect these files:
- `[FILE 1]`
- `[FILE 2]`
- `[FILE 3]`

Audit for:
1. ReDoS (Regular Expression Denial of Service):
   - Mathematically analyze every `re.compile()` pattern.
   - Eliminate nested quantifiers `(a+)+`, overlapping alternations, and catastrophic backtracking. Verify linear O(N) execution.
2. Path Traversal & Zip Slip:
   - Verify file output, unpacking, or directory resolution.
   - Guard against `../`, absolute paths, null bytes, UNC shares, and verify canonical paths (`os.path.commonpath`).
3. SSRF & Network Safety:
   - Ensure all target URLs resolve IP addresses and block loopback, private RFC 1918, link-local, and cloud metadata (`169.254.169.254`).
4. Recursion Safety:
   - Ensure nested payload traversal, schema inference, and serializers have depth guards (`max_depth=30`) to prevent `RecursionError`.
5. Resource & Connection Leaks:
   - Ensure `asyncio.Semaphore` always releases in `finally:`.
   - Ensure HTTP clients use context managers.

Output:
- Apply necessary patches directly to the source code.
- Write a detailed audit report in `docs/audit_report_[module].md` documenting findings, line numbers, and patch status.
- Run `python3 -m unittest discover tests -v` to ensure zero regressions.
```

---

## 5. Stress & Performance Tester Subagent (`typeName: "self"`)

Use during **Phase 3 (Wave 2)** concurrently with the auditor.

```markdown
Your ONLY job is to build and run Stress Testing and Performance Benchmarking for [MODULE NAME] in `tests/test_[module]_stress.py`.

Requirements:
1. ReDoS Safety Benchmark:
   - Construct adversarial strings (100,000+ characters of repeating quotes, brackets, and escape sequences).
   - Benchmark regex evaluation time; assert evaluation completes in < 50ms.
2. High-Volume Payload & Memory Benchmark:
   - Generate simulated high-volume production datasets (1,000–2,000 items).
   - Measure memory usage via `tracemalloc`. Assert peak RAM delta is strictly under 10MB!
3. Deep Recursion / Cyclic Benchmark:
   - Feed deeply nested payloads (50+ levels of nesting) to schema inference and serializers. Assert safe truncation without `RecursionError`.
4. Concurrency & Rate Limiting Benchmark:
   - Mock a rate-limited endpoint (429 Retry-After) and high concurrent load. Assert proper backoff and zero unhandled exceptions.

Output:
- Run `python3 -m unittest tests/test_[module]_stress.py -v`.
- Document all latency (ms), throughput (ops/sec), and peak RAM delta (MB).
```
