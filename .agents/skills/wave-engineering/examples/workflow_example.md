# Case Study: Building Miniature Engine with Wave Engineering

This case study documents how **Miniature Engine**—a high-performance API reconnaissance and specification generation suite—was built using the Wave Engineering methodology across 4 core modules on Android Termux.

---

## Overview of Miniature Engine

| Module | Purpose | Key Sub-Components | Test Count |
| :--- | :--- | :--- | :--- |
| **Module 1** | Spider & Asset Harvester | `crawler.py`, `manifest.py`, `passive.py` | 54 tests |
| **Module 2** | Static JS & Source Map Analyzer | `sourcemap.py`, `js_regex.py`, `graphql_parser.py`, `coordinator.py` | 68 tests |
| **Module 3** | API Prober & Spec Discovery | `spec_finder.py`, `http_prober.py`, `graphql_prober.py`, `coordinator.py` | 83 tests |
| **Module 4** | Spec Generator & Exporter Engine | `schema_inference.py`, `openapi_gen.py`, `postman_gen.py`, `coordinator.py` | 113 tests |
| **Total** | **Unified Recon & Export Engine** | **15 Core Components** | **289 tests (100% pass)** |

---

## Module 4 Execution Walkthrough

Here is the exact step-by-step execution followed for Module 4 (Spec Generator & Exporter Engine):

### 1. Phase 0: Architecture Blueprint & Data Modeling
- **Goal**: Export discovered endpoints and GraphQL schemas into standard OpenAPI 3.1.0 (JSON & YAML), Postman Collection v2.1.0, and GraphQL SDL (`schema.graphql`).
- **Data Modeling**:
  - `ExportResult` dataclass in `coordinator.py`.
  - Pure Python `OpenAPISchemaInferrer` and `ParameterInferrer`.
  - Trie / Radix `FolderTree` for Postman v2.1 hierarchy.

### 2. Phase 1: Deep Online Research Wave
Two specialized research subagents were dispatched concurrently:
- `OpenAPI 3.1 & Schema Researcher`: Researched JSON Schema 2020-12 alignment (`type: ["string", "null"]` vs deprecated `nullable: true`), zero-C YAML serialization nuances, and status code quoting (`"200":`).
- `Postman & Client Format Researcher`: Researched Postman Collection v2.1.0 schema, Next.js 14/15 Server Actions (`Next-Action` headers), and compatibility with modern API clients (Postman, Bruno, Insomnia, Caido).

### 3. Phase 2: Wave 1 Builders (The Single-Job Rule)
Three builders were launched concurrently:
- `OpenAPI 3.1 Generator Engineer`: Built `schema_inference.py` and `openapi_gen.py` (with a pure-Python `PureYamlDumper` with zero C-dependencies).
- `Postman Exporter Engineer`: Built `postman_gen.py` (with Radix/Trie folder nesting, Next.js Server Action support, and GraphQL body mode).
- `Exporter Coordinator Engineer`: Built `coordinator.py` and package `__init__.py` unifying the pipeline.

### 4. Phase 3: Wave 2 Audit & Stress Benchmarking
Two independent subagents were dispatched:
- `Module 4 Security & Quality Auditor`:
  - Audited `coordinator.py` for directory traversal: added `os.path.basename` and `os.path.commonpath` verification to guarantee exported files cannot escape the target directory.
  - Audited `schema_inference.py` and `PureYamlDumper`: implemented `max_depth=30` recursion guards and object ID cycle detection (`seen: Set[int]`) preventing `RecursionError`.
  - Documented findings in `docs/audit_report_module4.md`.
- `Module 4 Stress & Performance Tester`:
  - Built `tests/test_exporter_stress.py`.
  - Benchmarked 2,000 OpenAPI endpoints: peak RAM delta **8.35MB** (well under 10MB ceiling).
  - Benchmarked 2,000 Postman endpoints: peak RAM delta **3.40MB**.
  - Benchmarked 50-level nested recursion handling: safely truncated without crashing.
  - Benchmarked 1,000 adversarial route templates in `ParameterInferrer.normalize_path`: evaluated in **20ms** (linear $O(N)$).

### 5. Phase 4: Zero-Regression Verification
- Ran full repository discovery:
  ```bash
  python3 -m unittest discover tests -v
  ```
- **Result**: `Ran 289 tests in 65.965s - OK` (100% passing across Modules 1, 2, 3, and 4).
