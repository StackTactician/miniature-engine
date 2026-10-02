---
name: wave-engineering
description: Autonomous multi-agent wave engineering framework for building modular, production-grade decoupled engines. Use this skill whenever building or refactoring complex software systems into decoupled modules using coordinated waves of specialized subagents (researchers, builders, auditors, and stress testers).
---

# Wave Engineering Framework

A disciplined, battle-tested methodology for engineering complex software projects using coordinated waves of specialized subagents.

This framework was born from developing high-performance, resource-constrained engines (such as **Miniature Engine**), achieving 100% test coverage, strict < 10MB RAM footprints, zero C-dependency portability, and rock-solid resilience against SSRF, ReDoS, and directory traversal.

---

## The Core Philosophy: Headless Decoupled Engines

Before dispatching agents or writing code, every project is divided into **independent, decoupled software engines**:

1. **Headless by Default**:
   Every module is an independent software library. It has **zero** dependencies on CLI flags, terminal rendering, `print()` statements, or web frameworks.
2. **Intermediate Representation (IR) Contracts**:
   Modules communicate exclusively through strongly typed `@dataclass` models with `.to_dict()` and `.from_dict()` serialization. No untyped dictionaries as primary API boundaries.
3. **Composable Coordinator Pattern**:
   Each module exposes a unified Coordinator (e.g., `StaticAnalyzer`, `APIProber`, `ExportCoordinator`) that orchestrates low-level components and can be embedded anywhere: CLI, REST API, WebSocket server, or GUI.
4. **Environment-Conscious Portability**:
   Pure Python 3 / zero-C dependencies where required (e.g., Termux Android Bionic libc compatibility, containers, serverless). Peak memory delta strictly enforced (< 10MB).
5. **Linear Time Regexes**:
   All regular expressions are mathematically checked for $O(N)$ execution to prevent catastrophic ReDoS backtracking on minified or adversarial inputs.

---

## The 5-Phase Wave Engineering Lifecycle

For every module or significant system component, execute the following 5 phases in strict sequence:

```
┌─────────────────────────────────────────────────────────────┐
│ Phase 0: Architecture Blueprint & Data Contract Modeling    │
│ (Define module boundary, dataclass IRs, memory constraints) │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ Phase 1: Deep Online Research Wave                          │
│ (Parallel research subagents: modern specs, edge cases)     │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ Phase 2: Wave 1 — Specialized Builders                      │
│ (1 subagent = 1 job; concurrent isolated implementation)    │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ Phase 3: Wave 2 — Security Audit & Stress Benchmark         │
│ (Auditor: SSRF, ReDoS, traversal, recursion | Tester: RAM)  │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ Phase 4: Zero-Regression Full Suite Verification            │
│ (Run full discovery test suite; 100% pass rate required)    │
└─────────────────────────────────────────────────────────────┘
```

---

## Detailed Phase Execution

### Phase 0: Architecture Blueprint & Data Contract Modeling
- Identify the exact inputs and outputs of the module.
- Define pure domain `@dataclass` models in a central models module (e.g., `models.py`).
- Guarantee JSON serializability (`to_dict()`) on all models.
- Set explicit resource bounds: memory ceiling, timeouts, concurrency limits.

### Phase 1: Deep Online Research Wave
- **Subagent Type**: `typeName: "research"`
- **Rule**: Never start building without researching current industry standards, protocol edge cases, and modern framework behaviors.
- Launch 2–4 specialized research subagents concurrently, each targeting a specific technical angle:
  1. *Protocol & Specification Researcher*: Investigates RFCs, OpenAPI 3.1 JSON Schema 2020-12 nuances, Postman v2.1 schema quirks, etc.
  2. *Framework Internals Researcher*: Investigates how modern frameworks (Next.js 14/15, Nuxt, FastAPI, Spring Boot 3) expose routes, server actions, or documentation.
  3. *Security Attack Surface Researcher*: Investigates attack vectors, SSRF validation bypasses, ReDoS vulnerabilities, and bypass techniques.
- Combine findings into an architectural specification before Phase 2.

### Phase 2: Wave 1 — Specialized Builders (The Single-Job Rule)
- **Subagent Type**: `typeName: "self"`
- **The Single-Job Rule**: Every builder subagent is assigned **exactly one component**. Never assign multiple disparate components to a single builder.
- Typical Wave 1 team structure:
  - `Builder A`: Low-level parser / generator / worker #1.
  - `Builder B`: Low-level parser / generator / worker #2.
  - `Builder C`: Low-level networking / prober / engine worker #3.
  - `Coordinator Builder`: Builds the unified module Coordinator and package `__init__.py` export.
- Each builder must write isolated unit tests for their component and verify them before reporting completion.

### Phase 3: Wave 2 — Independent Audit & Stress Benchmarking
- **Subagent Type**: `typeName: "self"`
- **Rule**: Never trust builder tests alone. Always spawn an independent quality auditor and an independent stress tester concurrently:
  1. **Security & Code Quality Auditor**:
     - Audits every line for SSRF, path traversal, Zip Slip, stack recursion overflow, and ReDoS.
     - Patches vulnerabilities directly in the code.
     - Produces a formal audit report (e.g., `docs/audit_report_moduleX.md`).
  2. **Stress & Performance Tester**:
     - Builds dedicated stress suites (e.g., `tests/test_<module>_stress.py`).
     - Benchmarks adversarial inputs (100k+ chars) for ReDoS ($O(N)$ execution < 50ms).
     - Benchmarks high-volume payloads (1,000–2,000 items).
     - Measures memory delta using `tracemalloc` to strictly assert RAM < 10MB.

### Phase 4: Zero-Regression Full Suite Verification
- Run the full test suite across the entire repository:
  ```bash
  python3 -m unittest discover tests -v
  ```
- **Zero Tolerance Policy**: 100% of tests across all modules must pass. Any regression must be resolved before the module is marked complete.

---

## Detailed References & Runbooks

Consult the following reference documents included in this skill:

- [Subagent Prompt Templates](references/subagent_prompts.md): Exact prompt structures for researchers, builders, auditors, and stress testers.
- [Architecture & Platform Rules](references/architecture_rules.md): Headless engine design, IR modeling, and Termux/pure-Python constraints.
- [Security Audit & Stress Checklist](references/audit_checklist.md): Step-by-step checklist for ReDoS, SSRF, traversal, recursion, and memory benchmarks.
- [Case Study & Workflow Example](examples/workflow_example.md): End-to-end walkthrough of how Miniature Engine Modules 1–4 were built.
