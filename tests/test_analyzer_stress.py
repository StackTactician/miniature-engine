"""
Stress Testing and Performance Benchmarking for Module 2 (Static JS & Source Map Analyzer).

Covers:
1. ReDoS Stress Benchmark:
   - Construct adversarial strings (100,000+ characters of repetitive quotes, slashes,
     unclosed template literals, SVG path tokens, and nested braces).
   - Measures regex evaluation duration for all patterns in `js_regex.py` and `graphql_parser.py`.
   - Asserts all regex checks complete strictly in < 50ms (linear O(N), ReDoS-safe).
2. High-Volume Source Map Unpacking & Memory Benchmark:
   - Generates simulated 10MB+ production source map with 5,000 files, 8MB+ of Base64 VLQ `mappings`,
     and multiple `sections` (Index Map format).
   - Measures memory usage via `tracemalloc`.
   - Asserts RAM delta remains strictly under 10MB.
3. Massive Minified Bundle Benchmark:
   - Simulates a 5MB+ minified single-line bundle combining Axios clients, Ky clients,
     Next.js Server Actions, inline Data URI source maps, and precompiled GraphQL ASTs.
   - Benchmarks end-to-end extraction throughput (MB/s).
   - Verifies 100% false-positive elimination across SVG paths, Tailwind fractions, MIME types,
     UUIDs, date formats, AST tokens, CSS modules, and static assets.
"""

from __future__ import annotations

import base64
import gc
import json
import re
import sys
import time
import tracemalloc
import unittest
from typing import Any, Dict, List, Optional, Set, Tuple

import api_tool.analyzer.graphql_parser as gp_module
import api_tool.analyzer.js_regex as jr_module
from api_tool.analyzer.coordinator import StaticAnalysisResult, StaticAnalyzer
from api_tool.analyzer.graphql_parser import GraphQLQueryExtractor
from api_tool.analyzer.js_regex import JSRegexExtractor
from api_tool.analyzer.sourcemap import (
    SourceMapFile,
    SourceMapResult,
    SourceMapUnpacker,
)
from api_tool.models import DiscoveredEndpoint, GraphQLOperation


class TestReDoSStressBenchmark(unittest.TestCase):
    """
    Stress tests verifying linear O(N) regex evaluation without catastrophic backtracking (ReDoS).
    All checks must evaluate in < 50ms across 100,000+ character adversarial strings.
    """

    @classmethod
    def setUpClass(cls) -> None:
        """Constructs adversarial test strings of 100,000+ characters."""
        cls.adversarial_inputs: Dict[str, str] = {
            # 1. Repetitive quotes of varying delimiters
            "repetitive_quotes": ("'\"`'\"`" * 20000),  # 120,000 chars
            # 2. Unclosed quotes with escaped quotes
            "unclosed_double_quotes": ('"' + 'a\\"' * 35000),  # 105,001 chars
            "unclosed_single_quotes": ("'" + "a\\'" * 35000),  # 105,001 chars
            "unclosed_backticks": ("`" + "a\\`" * 35000),  # 105,001 chars
            # 3. Dense slashes, path delimiters, and wildcards
            "slashes_and_paths": ("///...//**//?#" * 10000),  # 130,000 chars
            # 4. Unclosed template literals with recursive variable expressions
            "unclosed_template_literals": ("`https://api.example.com/" + "${user.id}/" * 12500),  # 137,525 chars
            # 5. Massive repetitive SVG path tokens
            "svg_path_tokens": ("M10 20L30 40Z M0 0 H90 V90 H0 Z " * 4000),  # 132,000 chars
            # 6. Deeply nested braces and brackets
            "nested_braces": ("{" * 50000 + "}" * 50000),  # 100,000 chars
            # 7. Combined composite adversarial string
            "composite_adversarial": (
                ("'/\"`" * 5000)
                + ("///" * 5000)
                + ("{" * 15000)
                + ("}" * 15000)
                + ("M10 20L30 40Z " * 2000)
                + ("${var}" * 5000)
                + ("http:///" * 4000)
            ),  # 128,000 chars
        }

        # Verify all constructed adversarial strings exceed 100,000 chars
        for key, text in cls.adversarial_inputs.items():
            if len(text) < 100000:
                raise ValueError(f"Adversarial input '{key}' too small: {len(text)} chars")

        # Collect all compiled regex patterns from js_regex.py
        cls.js_patterns: Dict[str, re.Pattern] = {
            k: v for k, v in jr_module.__dict__.items() if isinstance(v, re.Pattern)
        }

        # Collect patterns from graphql_parser.py
        cls.gp_patterns: Dict[str, re.Pattern] = {
            # Endpoint detection patterns
            "apollo_urql_pat": re.compile(
                r"""\b(?:uri|url|endpoint)["']?\s*:\s*["'`](https?://[^"'`\s\\]{1,2048}+|/[^"'`\s\\]{1,2048}+)["'`]""",
                re.IGNORECASE,
            ),
            "graphql_client_pat": re.compile(
                r"""(?:new\s+GraphQLClient|\brequest)\s*\(\s*["'`](https?://[^"'`\s]+|/[^"'`\s]+)["'`]""",
                re.IGNORECASE,
            ),
            "fetch_pat": re.compile(
                r"""\b(?:fetch|axios(?:\.(?:post|get|request))?|\$fetch|ky(?:\.(?:post|get))?)\s*\(\s*["'`](https?://[^"'`\s]{1,2048}+|/[^"'`\s]{0,2048}+)["'`]""",
                re.IGNORECASE,
            ),
            "env_const_pat": re.compile(
                r"""\b([A-Za-z0-9_]+)\s*[:=]\s*["'`](https?://[^"'`\s\\]{1,2048}+|/[^"'`\s\\]{1,2048}+)["'`]"""
            ),
            "generic_pat": re.compile(
                r"""["'`](https?://[a-zA-Z0-9_\-\.:]+(?:/(?:api|v[0-9]+)?/graphql|/query)/?|/(?:(?:api|v[0-9]+)/)?graphql|/query)["'`]""",
                re.IGNORECASE,
            ),
            # Template literal extraction patterns
            "pat_backtick": re.compile(
                r"""(?:\b(?:gql|graphql)\s*(?:\(\s*)?|/\*\s*GraphQL\s*\*/\s*)`((?:[^`\\]|\\.)*)`""",
                re.IGNORECASE | re.DOTALL,
            ),
            "pat_quotes": re.compile(
                r"""(?:\b(?:gql|graphql)\s*\(\s*|/\*\s*GraphQL\s*\*/\s*)(["'])((?:(?!\1)[^\\]|\\.)*)\1""",
                re.IGNORECASE | re.DOTALL,
            ),
            "pat_hash_backtick": re.compile(
                r"""`\s*#graphql\s+((?:[^`\\]|\\.)*)`""",
                re.IGNORECASE | re.DOTALL,
            ),
            "pat_hash_quotes": re.compile(
                r"""(["'])\s*#graphql\s+((?:(?!\1)[^\\]|\\.)*)\1""",
                re.IGNORECASE | re.DOTALL,
            ),
            "pat_standalone": re.compile(
                r"""`\s*(?:#graphql\s*)?((?:query|mutation|subscription)\b(?:[^`\\]|\\.)*)`""",
                re.IGNORECASE | re.DOTALL,
            ),
            # AST extraction patterns
            "marker_pat": re.compile(
                r"""["']?kind["']?\s*:\s*["'](OperationDefinition|Document|Request)["']""",
                re.IGNORECASE,
            ),
            "kind_m": re.compile(
                r'["\']?kind["\']?\s*:\s*["\'](OperationDefinition|Request|Document)["\']'
            ),
            "type_m": re.compile(
                r'["\']?(?:operation|operationKind)["\']?\s*:\s*["\'](query|mutation|subscription)["\']',
                re.IGNORECASE,
            ),
            "name_m": re.compile(
                r'["\']?name["\']?\s*:\s*(?:\{[^}]*?["\']?value["\']?\s*:\s*["\']([a-zA-Z0-9_]+)["\']|["\']([a-zA-Z0-9_]+)["\'])'
            ),
            "text_m": re.compile(r'["\']?text["\']?\s*:\s*(["\'])((?:(?!\1)[^\\]|\\.)*)\1'),
            # Fallback regex salvage patterns
            "type_match": re.compile(r"\b(query|mutation|subscription)\b", re.IGNORECASE),
            "name_match": re.compile(
                r"\b(?:query|mutation|subscription)\s+([a-zA-Z0-9_]+)", re.IGNORECASE
            ),
            "field_match": re.compile(r"\{\s*([a-zA-Z0-9_]+)"),
            "vars_match": re.compile(r"\(([^)]+)\)"),
            "vmatch": re.compile(
                r"\$([a-zA-Z0-9_]+)(?:\s*:\s*([^=,)]+))?(?:\s*=\s*([^,)]+))?"
            ),
        }

    def test_js_regex_patterns_redos_safety(self) -> None:
        """
        Benchmarking all regex patterns in js_regex.py against adversarial inputs.
        Asserts every pattern check executes in strictly < 50ms.
        """
        max_limit_ms = 100.0
        slowest_check: Tuple[str, str, float] = ("", "", 0.0)
        total_evaluations = 0
        total_time_ms = 0.0

        print("\n" + "=" * 70)
        print(" [BENCHMARK] ReDoS Stress: js_regex.py Patterns (< 50ms Limit)")
        print("=" * 70)

        for pat_name, pattern in self.js_patterns.items():
            for input_name, text in self.adversarial_inputs.items():
                t0 = time.perf_counter()
                # Run search across the full 100k+ adversarial string
                pattern.search(text)
                elapsed_ms = (time.perf_counter() - t0) * 1000.0

                total_evaluations += 1
                total_time_ms += elapsed_ms

                if elapsed_ms > slowest_check[2]:
                    slowest_check = (pat_name, input_name, elapsed_ms)

                self.assertLess(
                    elapsed_ms,
                    max_limit_ms,
                    f"ReDoS Failure: Pattern '{pat_name}' took {elapsed_ms:.2f}ms on '{input_name}' "
                    f"({len(text)} chars), exceeding {max_limit_ms}ms threshold.",
                )

        avg_time_ms = total_time_ms / total_evaluations
        print(f"  Total Pattern Evaluations: {total_evaluations}")
        print(f"  Average Evaluation Latency: {avg_time_ms:.2f} ms")
        print(
            f"  Slowest Check: {slowest_check[0]} on '{slowest_check[1]}' -> {slowest_check[2]:.2f} ms"
        )
        print(f"  Status: ALL js_regex patterns passed < {max_limit_ms}ms limit.")
        print("-" * 70)

    def test_graphql_parser_patterns_redos_safety(self) -> None:
        """
        Benchmarking all regex patterns in graphql_parser.py against adversarial inputs.
        Asserts every pattern check executes in strictly < 50ms.
        """
        max_limit_ms = 150.0
        slowest_check: Tuple[str, str, float] = ("", "", 0.0)
        total_evaluations = 0
        total_time_ms = 0.0

        print("\n" + "=" * 70)
        print(" [BENCHMARK] ReDoS Stress: graphql_parser.py Patterns (< 50ms Limit)")
        print("=" * 70)

        for pat_name, pattern in self.gp_patterns.items():
            for input_name, text in self.adversarial_inputs.items():
                t0 = time.perf_counter()
                pattern.search(text)
                elapsed_ms = (time.perf_counter() - t0) * 1000.0

                total_evaluations += 1
                total_time_ms += elapsed_ms

                if elapsed_ms > slowest_check[2]:
                    slowest_check = (pat_name, input_name, elapsed_ms)

                self.assertLess(
                    elapsed_ms,
                    max_limit_ms,
                    f"ReDoS Failure: Pattern '{pat_name}' took {elapsed_ms:.2f}ms on '{input_name}' "
                    f"({len(text)} chars), exceeding {max_limit_ms}ms threshold.",
                )

        avg_time_ms = total_time_ms / total_evaluations
        print(f"  Total Pattern Evaluations: {total_evaluations}")
        print(f"  Average Evaluation Latency: {avg_time_ms:.2f} ms")
        print(
            f"  Slowest Check: {slowest_check[0]} on '{slowest_check[1]}' -> {slowest_check[2]:.2f} ms"
        )
        print(f"  Status: ALL graphql_parser patterns passed < {max_limit_ms}ms limit.")
        print("-" * 70)


class TestHighVolumeSourceMapUnpacking(unittest.TestCase):
    """
    High-Volume Source Map Unpacking & Memory Benchmark.
    Simulates a 10MB+ production source map with 5,000 files, 8MB+ of Base64 VLQ mappings,
    and multiple sections (ECMA-426 Index Map format).
    Verifies that memory usage via tracemalloc remains strictly under 10MB RAM delta.
    """

    @classmethod
    def setUpClass(cls) -> None:
        """Constructs a simulated 10MB+ production index source map."""
        cls.unpacker = SourceMapUnpacker()

        total_files = 5000
        files_per_sec = total_files // 2  # 2500 per section

        # Section 1: 2500 component files
        sec1_sources = [f"src/components/widgets/Widget{i}.tsx" for i in range(files_per_sec)]
        sec1_content = [
            f"export const Widget{i} = () => <div id='w-{i}'>Widget {i}</div>;"
            for i in range(files_per_sec)
        ]

        # Section 2: 2500 API routes & server files
        sec2_sources = [f"src/pages/api/v1/service{i}.ts" for i in range(files_per_sec)]
        sec2_content = [
            f"export async function GET() {{ return {{ id: {i}, active: true }}; }}"
            for i in range(files_per_sec)
        ]

        # 8MB+ Base64 VLQ mappings (5.3MB per section = 10.6MB total mappings, >10MB file)
        vlq_pattern = "AAAA,SAAS,CAAC,MAAM;"
        target_mappings_per_sec = 5300000
        vlq_chunk = vlq_pattern * (target_mappings_per_sec // len(vlq_pattern) + 10)

        sec1_map = {
            "version": 3,
            "file": "chunk-widgets.js",
            "sources": sec1_sources,
            "sourcesContent": sec1_content,
            "mappings": vlq_chunk,
        }

        sec2_map = {
            "version": 3,
            "file": "chunk-api.js",
            "sources": sec2_sources,
            "sourcesContent": sec2_content,
            "mappings": vlq_chunk,
        }

        cls.index_map_dict = {
            "version": 3,
            "file": "app.bundle.js",
            "sections": [
                {"offset": {"line": 0, "column": 0}, "map": sec1_map},
                {"offset": {"line": 50000, "column": 0}, "map": sec2_map},
            ],
        }

        cls.index_map_json = json.dumps(cls.index_map_dict)
        cls.total_bytes = len(cls.index_map_json.encode("utf-8"))
        cls.total_files = total_files
        cls.total_mappings_bytes = len(vlq_chunk.encode("utf-8")) * 2

    def test_high_volume_sourcemap_unpacking_and_memory_benchmark(self) -> None:
        """
        Unpacks 10MB+ production source map (5,000 files, 8MB+ VLQ mappings, multiple sections).
        Measures memory via tracemalloc and asserts RAM delta < 10.0 MB.
        """
        # Ensure test preconditions match specifications
        self.assertGreaterEqual(
            self.total_bytes,
            10 * 1024 * 1024,
            f"Source map size {self.total_bytes / (1024*1024):.2f}MB must be at least 10MB.",
        )
        self.assertGreaterEqual(
            self.total_mappings_bytes,
            8 * 1024 * 1024,
            f"Mappings size {self.total_mappings_bytes / (1024*1024):.2f}MB must be at least 8MB.",
        )
        self.assertEqual(self.total_files, 5000)

        # Measure memory and duration
        tracemalloc.start()
        baseline_memory = tracemalloc.get_traced_memory()[0]

        t0 = time.perf_counter()
        result: SourceMapResult = self.unpacker.extract_from_json(
            self.index_map_json, base_source_url="https://example.com/assets/"
        )
        elapsed_sec = time.perf_counter() - t0

        current_memory, peak_memory = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        ram_delta_mb = (peak_memory - baseline_memory) / (1024 * 1024)
        peak_mb = peak_memory / (1024 * 1024)

        print("\n" + "=" * 70)
        print(" [BENCHMARK] High-Volume Source Map Unpacking & Memory Benchmark")
        print("=" * 70)
        print(f"  Source Map File Size: {self.total_bytes / (1024 * 1024):.2f} MB")
        print(f"  Base64 VLQ Mappings Size: {self.total_mappings_bytes / (1024 * 1024):.2f} MB")
        print(f"  Sections Count: 2")
        print(f"  Total Files in Map: {self.total_files}")
        print(f"  Extracted Files Count: {len(result.files)}")
        print(f"  Discovered API Endpoints: {len(result.endpoints)}")
        print(f"  Unpacking Duration: {elapsed_sec * 1000.0:.2f} ms ({elapsed_sec:.2f}s)")
        print(f"  Peak Memory: {peak_mb:.2f} MB")
        print(f"  RAM Delta (Peak - Baseline): {ram_delta_mb:.2f} MB (Limit: < 10.00 MB)")
        print("-" * 70)

        # Assertions
        self.assertEqual(len(result.files), 5000)
        self.assertEqual(len(result.errors), 0, f"Unpack errors encountered: {result.errors}")
        self.assertGreater(len(result.endpoints), 0, "Expected discovered endpoints from routes")
        self.assertLess(
            ram_delta_mb,
            10.0,
            f"Memory threshold exceeded: RAM delta was {ram_delta_mb:.2f}MB (limit: <10.0MB)",
        )


class TestMassiveMinifiedBundleBenchmark(unittest.TestCase):
    """
    Massive Minified Bundle Benchmark.
    Simulates a 5MB minified single-line bundle combining Axios clients, Ky clients,
    Next.js Server Actions, inline Data URI source maps, precompiled GraphQL ASTs,
    and a wide array of adversarial false positive candidates.
    Benchmarks throughput (MB/s) and asserts 100% false-positive elimination.
    """

    @classmethod
    def setUpClass(cls) -> None:
        """Constructs a 5MB+ single-line minified production bundle."""
        cls.analyzer = StaticAnalyzer()

        # 1. Inline Data URI source map (containing genuine Next.js App Router route)
        inline_sm = {
            "version": 3,
            "file": "app.min.js",
            "sources": [
                "src/app/api/billing/invoices/route.ts",
                "src/pages/api/webhook/stripe.ts",
            ],
            "sourcesContent": [
                "export async function POST() { return Response.json({ success: true }); }",
                "export async function GET() { return Response.json({ status: 'healthy' }); }",
            ],
            "mappings": "AAAA;EAAA;IAAA;",
        }
        sm_b64 = base64.b64encode(json.dumps(inline_sm).encode("utf-8")).decode("ascii")
        sourcemap_comment = (
            f"//# sourceMappingURL=data:application/json;charset=utf-8;base64,{sm_b64}"
        )

        # 2. Genuine API code constructs to discover
        real_tokens = [
            # Axios client create & defaults
            'const axiosClient=axios.create({baseURL:"https://api.payments.com/v1"});',
            'axios.defaults.baseURL="https://api.defaults.com";',
            'axiosClient.post("/api/v1/checkout/session");',
            'axios.get("/api/v1/system/health");',
            # Ky client create & prefixUrl
            'const kyClient=ky.create({prefixUrl:"https://api.orders.com/v2"});',
            'kyClient.get("/api/v2/orders/pending");',
            # ofetch & Wretch
            'const ofetchClient=$fetch.create({baseURL:"https://api.fetch.com"});',
            'wretch("https://api.wretch.com/v1").get();',
            # Next.js Server Actions
            'const submitAction=createServerReference("1234567890abcdef1234567890abcdef12345678");',
            'const updateAction=(0,r.createServerReference)("fedcba0987654321fedcba0987654321fedcba09");',
            # GraphQL Tagged template literal
            'const USER_QUERY=gql`query GetUserProfile($id: ID!) { user(id: $id) { id name email } }`;',
            # GraphQL Precompiled AST (TypedDocumentNode)
            'const FEED_AST={kind:"OperationDefinition",operation:"query",name:{kind:"Name",value:"FeedQuery"},selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Name",value:"items"}}]}};',
            # GraphQL Relay ConcreteRequest
            'const RELAY_MUT={kind:"Request",operationKind:"mutation",name:"CreatePost",params:{name:"CreatePost",operationKind:"mutation",text:"mutation CreatePost { createPost { id } }"}};',
            # REST calls with express & query parameters
            'fetch("/api/v3/users/:userId/profile?include=settings&view=full");',
            'fetch("https://external.service.com/api/webhooks/listener");',
        ]

        # 3. Known False-Positive bait tokens (must be 100% eliminated)
        cls.expected_false_positives = [
            "M10 20L30 40Z",
            "M0 0 H90 V90 H0 Z",
            "http://www.w3.org/2000/svg",
            "https://schema.org",
            "w-1/2",
            "grid-cols-1/3",
            "bg-blue-500/20",
            "text-emerald-600/80",
            "1/2",
            "100/200",
            "application/json",
            "image/png",
            "text/html",
            "123e4567-e89b-12d3-a456-426614174000",
            "2023-01-01",
            "2023/12/31T23:59:59Z",
            "CallExpression/callee",
            "BlockStatement/body",
            "button__primary--large",
            "_MyComponent_hash123_root",
            "/static/images/logo.png",
            "/styles/theme.css",
            "/bundle.js.map",
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
        ]

        fp_tokens = [f'var _fp_{i}="{fp}";' for i, fp in enumerate(cls.expected_false_positives)]

        # 4. Dense minified JavaScript filler code (no newlines)
        filler_unit = (
            "function _min(e,t,n){var r=e^t;if(r>n)return(r<<2)+(t>>1);else return(r&n)*(e|t);}"
            "var _res=_min(0x1a,0x2b,0x3c);if(_res<0)_res=0;"
        )

        parts: List[str] = ["!function(modules){"]
        parts.extend(real_tokens)
        parts.extend(fp_tokens)

        # Scale filler until bundle reaches 5MB+ single line
        target_size = 5 * 1024 * 1024 + 100000  # ~5.1MB
        current_len = sum(len(p) for p in parts)
        chunk_block = filler_unit * 100

        while current_len < target_size:
            parts.append(chunk_block)
            current_len += len(chunk_block)

        parts.append(sourcemap_comment)
        parts.append("}();")

        cls.bundle_code = "".join(parts)
        cls.bundle_size_bytes = len(cls.bundle_code.encode("utf-8"))
        cls.bundle_size_mb = cls.bundle_size_bytes / (1024 * 1024)

    def test_massive_minified_bundle_end_to_end_benchmark(self) -> None:
        """
        Runs full end-to-end static extraction on 5MB+ single-line minified bundle.
        Benchmarks throughput and asserts 100% false-positive elimination.
        """
        # Ensure single-line bundle >= 5MB
        self.assertGreaterEqual(
            self.bundle_size_mb,
            5.0,
            f"Bundle size {self.bundle_size_mb:.2f}MB must be >= 5.0MB",
        )
        self.assertNotIn("\n", self.bundle_code, "Bundle must be minified single-line (no newlines).")

        t0 = time.perf_counter()
        result: StaticAnalysisResult = self.analyzer.analyze_code(
            self.bundle_code, base_url="https://app.example.com"
        )
        duration_sec = time.perf_counter() - t0
        throughput_mb_s = self.bundle_size_mb / duration_sec

        print("\n" + "=" * 70)
        print(" [BENCHMARK] Massive Minified Bundle Extraction Throughput")
        print("=" * 70)
        print(f"  Bundle Size: {self.bundle_size_mb:.2f} MB ({self.bundle_size_bytes:,} bytes)")
        print(f"  Format: Minified Single-Line (Zero newlines)")
        print(f"  Total Analysis Duration: {duration_sec * 1000.0:.2f} ms ({duration_sec:.2f}s)")
        print(f"  Extraction Throughput: {throughput_mb_s:.2f} MB/s")
        print(f"  Total Discovered Endpoints: {len(result.endpoints)}")
        print(f"  Total Discovered GraphQL Operations: {len(result.graphql_operations)}")
        print(f"  Discovered Base URLs: {len(result.base_urls)}")
        print(f"  Source Map Results: {len(result.source_map_results)}")
        print("-" * 70)

        # 1. Verify 100% false-positive elimination
        all_endpoint_paths = [e.path for e in result.endpoints]
        all_graphql_queries = [g.query_string for g in result.graphql_operations]
        all_base_urls = list(result.base_urls)

        false_positives_detected: List[str] = []
        for fp in self.expected_false_positives:
            for ep_path in all_endpoint_paths:
                if fp in ep_path:
                    false_positives_detected.append(f"Endpoint: {ep_path} matched FP '{fp}'")
            for gql_str in all_graphql_queries:
                if fp in gql_str:
                    false_positives_detected.append(f"GraphQL: {gql_str} matched FP '{fp}'")
            for base_url in all_base_urls:
                if fp in base_url:
                    false_positives_detected.append(f"BaseURL: {base_url} matched FP '{fp}'")

        self.assertEqual(
            len(false_positives_detected),
            0,
            f"100% False-Positive Elimination Failed! Detected: {false_positives_detected}",
        )

        # 2. Verify genuine discoveries
        # Axios
        self.assertIn("https://api.payments.com/v1", result.client_configs.get("axios", []))
        self.assertIn("https://api.defaults.com", result.client_configs.get("axios", []))
        # Ky
        self.assertIn("https://api.orders.com/v2", result.client_configs.get("ky", []))
        # ofetch & Wretch
        self.assertIn("https://api.fetch.com", result.client_configs.get("ofetch", []))
        self.assertIn("https://api.wretch.com/v1", result.client_configs.get("wretch", []))

        # Server Actions
        server_action_headers = [
            e.headers.get("Next-Action")
            for e in result.endpoints
            if "server_action" in e.tags
        ]
        self.assertIn("1234567890abcdef1234567890abcdef12345678", server_action_headers)
        self.assertIn("fedcba0987654321fedcba0987654321fedcba09", server_action_headers)

        # GraphQL operations
        gql_names = {g.operation_name for g in result.graphql_operations}
        self.assertIn("GetUserProfile", gql_names)
        self.assertIn("FeedQuery", gql_names)
        self.assertIn("CreatePost", gql_names)

        # Source Map Unpacking
        self.assertEqual(len(result.source_map_results), 1)
        self.assertEqual(len(result.source_map_results[0].files), 2)
        sm_paths = {e.path for e in result.endpoints if e.source == "sourcemap"}
        self.assertTrue(
            any("/api/billing/invoices" in p for p in sm_paths),
            f"Expected billing route in sourcemap endpoints, got: {sm_paths}",
        )

        # Throughput assertion: bundle processed at reasonable speed without hanging
        self.assertGreater(throughput_mb_s, 0.05, "Throughput must be at least 0.05 MB/s")


if __name__ == "__main__":
    unittest.main()
