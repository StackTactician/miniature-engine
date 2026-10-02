# Architecture & Platform Rules

The Wave Engineering methodology enforces strict engineering standards to guarantee that every developed system is maintainable, decoupled, and capable of running in resource-constrained environments like Android Termux.

---

## 1. The Headless Engine Standard

1. **Zero UI / CLI Coupling**:
   - Never import `argparse`, `click`, `typer`, or write `sys.exit()` inside engine modules.
   - Never call `print()` inside engine code. Use structured loggers (`logging.getLogger(__name__)`) or diagnostic result fields.
   - The engine must be equally usable from a CLI, a FastAPI / Starlette server, an automated pipeline, or a background worker.

2. **Unified Coordinator Facade**:
   - Each module must expose a single high-level Coordinator class (e.g. `StaticAnalyzer`, `APIProber`, `ExportCoordinator`).
   - The Coordinator accepts configuration options in `__init__` (e.g., concurrency, timeouts, rate limits) and provides clean async/sync orchestration methods.

3. **Package API Boundary (`__init__.py`)**:
   - Every module must cleanly export its public classes, functions, and dataclasses in `__init__.py`.
   - Internal helper utilities should be prefixed with `_` or kept in private sub-modules.

---

## 2. Strong Intermediate Representations (IR)

1. **Pure `@dataclass` Models**:
   - All module inputs and outputs must be strongly typed `@dataclass` objects.
   - Use standard library types: `Optional[str]`, `List[T]`, `Dict[str, Any]`, `Set[str]`.
   - Avoid generic, untyped dictionaries as the primary boundary between components.

2. **Bidirectional Serialization**:
   - Every domain dataclass must implement `.to_dict() -> Dict[str, Any]`.
   - Result containers must be JSON serializable via standard `json.dumps(result.to_dict())`.
   - Where state rehydration is needed, implement `@classmethod def from_dict(cls, data: Dict[str, Any]) -> Self`.

---

## 3. Platform & Dependency Constraints (Termux / Pure Python)

1. **Zero Compiled C/Rust Extensions**:
   - In environments like Termux (Android Bionic libc, `aarch64`), compiled packages (`pydantic-core`, `libyaml`, `genson`, `cryptography`) often fail to build or install cleanly.
   - Pure Python standard library or zero-C pure-Python packages (`httpx`, `aiolimiter`, `graphql-core`, `beautifulsoup4`) must be preferred.
   - When YAML serialization is required, implement a zero-dependency `PureYamlDumper`.
   - When JSON Schema inference is required, implement a pure-Python `OpenAPISchemaInferrer`.

2. **Strict < 10MB RAM Ceiling**:
   - Android process memory is constrained. Every module must operate with a memory delta under **10MB**, even when handling large datasets.
   - Never read 100MB+ files entirely into RAM without chunking or stripping.
   - For source maps: strip or discard multi-megabyte `mappings` strings if only `sourcesContent` is required.
   - For HTTP responses: inspect `Content-Length` headers and streaming limits before reading response bodies.
   - Verify RAM deltas in unit tests using Python's `tracemalloc`.

---

## 4. ReDoS Linear $O(N)$ Guarantees

1. **The Anti-Pattern**:
   - Catastrophic backtracking occurs when regular expressions contain nested quantifiers or overlapping alternation branches:
     - Danger: `(a+)+`, `(\s*...)+`, `([^"']*)*`, `(x|x)*`
   - On a minified, single-line JavaScript bundle (1MB+), an engine with backtracking regexes will hang indefinitely.

2. **The Safe Pattern**:
   - Always bound quantifiers or use character exclusion classes:
     - Safe: `"[^"\\]*(\\.[^"\\]*)*"` or `[^"'`\s]{1,500}`.
   - Use atomic group equivalents or positive lookaheads where appropriate.
   - Mandate regex benchmarks on 100,000+ character adversarial strings in tests.
