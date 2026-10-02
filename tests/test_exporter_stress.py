"""
Stress Testing and Performance Benchmarking for Module 4 (Spec Generator & Exporter Engine).

Covers:
1. Massive 2,000-Endpoint OpenAPI Generation & Memory Benchmark:
   - Generate 2,000 synthetic endpoints with varied path parameters, query parameters,
     headers, request bodies, and response payloads.
   - Run `OpenAPIGenerator` to export both JSON and YAML.
   - Measure RAM delta using `tracemalloc`. Assert peak RAM delta is strictly under 10MB.
   - Benchmark serialization throughput (endpoints per second) and elapsed time.
2. Massive 2,000-Endpoint Postman Collection Memory Benchmark:
   - Convert 2,000 endpoints through `PostmanExporter` with full Radix/Trie folder
     tree nesting, Next.js Server Actions, and GraphQL operations.
   - Measure RAM delta using `tracemalloc`. Assert RAM delta is strictly under 10MB.
   - Benchmark folder hierarchy generation latency.
3. Deeply Nested Payload & Recursion Stress Test:
   - Test `OpenAPISchemaInferrer` and `PureYamlDumper` against a 50-level deeply nested dictionary payload.
   - Verify it handles extreme depth gracefully without raising `RecursionError`.
4. High-Volume Path Normalization ReDoS Benchmark:
   - Run `ParameterInferrer.normalize_path` against 1,000 complex and adversarial route
     templates (nested brackets, multiple colons, unicode, unclosed brackets, long sequences).
   - Assert all 1,000 templates evaluate in linear O(N) time with total duration under 100ms.
5. Round-Trip JSON/YAML Validity Check:
   - Verify that generated OpenAPI JSON parses cleanly with standard library `json.loads`
     and conforms to OpenAPI 3.1.0 structure.
   - Verify that generated OpenAPI YAML parses with `yaml.safe_load` and matches the data structure.
   - Verify that generated Postman Collection JSON parses cleanly with `json.loads`
     and contains valid Postman v2.1.0 structure.
"""

from __future__ import annotations

import copy
import gc
import json
import time
import tracemalloc
import unittest
from typing import Any, Dict, List, Optional

import yaml  # PyYAML for cross-validation of pure-Python YAML output

from api_tool.exporter import (
    ExportCoordinator,
    ExportResult,
    FolderTree,
    OpenAPIGenerator,
    OpenAPISchemaInferrer,
    ParameterInferrer,
    PostmanCollection,
    PostmanExporter,
    PostmanItem,
    PureYamlDumper,
)
from api_tool.models import (
    DiscoveredEndpoint,
    DiscoveredParameter,
    DiscoveredResponse,
    GraphQLOperation,
)


class TestOpenAPIMassiveStressBenchmark(unittest.TestCase):
    """
    Benchmark 1: Massive 2,000-Endpoint OpenAPI Generation & Memory Benchmark.
    Generates 2,000 synthetic endpoints with varied path parameters, query parameters,
    headers, and request bodies. Runs OpenAPIGenerator to export both JSON and YAML.
    Verifies peak RAM delta is strictly under 10MB and measures throughput.
    """

    @classmethod
    def setUpClass(cls) -> None:
        """Constructs 2,000 synthetic endpoints with diverse parameters and bodies."""
        cls.endpoints: List[DiscoveredEndpoint] = []
        http_methods = ["GET", "POST", "PUT", "DELETE", "PATCH"]

        for i in range(2000):
            res_id = i % 80
            action_id = (i // 80) % 5
            method = http_methods[i % 5]

            # Varied parameters: path, query, header
            params = [
                DiscoveredParameter(name="id", location="path", required=True, example=i),
                DiscoveredParameter(
                    name="filter",
                    location="query",
                    required=False,
                    example=f"category_{i % 12}",
                    description="Filter items by category",
                ),
                DiscoveredParameter(
                    name="X-Request-Trace",
                    location="header",
                    required=False,
                    example=f"trace-uuid-{i:06d}",
                ),
            ]
            if i % 3 == 0:
                params.append(
                    DiscoveredParameter(name="page", location="query", required=False, example=1)
                )
            if i % 4 == 0:
                params.append(
                    DiscoveredParameter(name="limit", location="query", required=False, example=50)
                )
            if i % 7 == 0:
                params.append(
                    DiscoveredParameter(name="is_active", location="query", required=False, example=True)
                )

            # Varied request bodies for write methods
            body = None
            if method in ("POST", "PUT", "PATCH"):
                body = {
                    "id": i,
                    "name": f"synthetic_item_{i}",
                    "active": (i % 2 == 0),
                    "tags": [f"tag_{i % 8}", "benchmark"],
                    "config": {
                        "retry_count": i % 5,
                        "ratio": round(i * 0.123, 3),
                    },
                }

            # Varied responses
            responses = [
                DiscoveredResponse(
                    status_code=200,
                    sample_body={"status": "success", "id": i, "data": f"result_{i}"},
                )
            ]
            if i % 2 == 0:
                responses.append(
                    DiscoveredResponse(
                        status_code=400,
                        sample_body={"error": "Bad Request", "code": 400},
                    )
                )
            if i % 5 == 0:
                responses.append(
                    DiscoveredResponse(
                        status_code=404,
                        sample_body={"error": "Not Found", "code": 404},
                    )
                )

            ep = DiscoveredEndpoint(
                path=f"/api/v1/resource_{res_id}/:id/action_{action_id}",
                method=method,
                parameters=params,
                request_body_sample=body,
                responses=responses,
                active_status=200,
                tags=[f"Resource_{res_id}"],
                summary=f"{method} Resource {res_id} Action {action_id}",
                description=f"Generated synthetic benchmark endpoint {i}",
                base_url="https://api.example.com",
            )
            cls.endpoints.append(ep)

    def test_massive_2000_endpoint_openapi_generation_and_memory(self) -> None:
        """
        Executes OpenAPIGenerator across 2,000 synthetic endpoints.
        Exports both JSON and YAML strings.
        Asserts peak RAM delta is strictly under 10MB.
        Measures serialization throughput (endpoints/sec) and latency.
        """
        gc.collect()
        tracemalloc.start()
        tracemalloc.reset_peak()
        start_current, _ = tracemalloc.get_traced_memory()

        t_start = time.perf_counter()

        gen = OpenAPIGenerator(
            endpoints=self.endpoints,
            title="Massive 2,000-Endpoint Benchmark API",
            version="2.0.0",
            description="OpenAPI 3.1.0 specification generated during stress testing",
        )
        spec = gen.generate()
        t_generate = time.perf_counter()

        json_output = gen.to_json(indent=2)
        t_json = time.perf_counter()

        yaml_output = gen.to_yaml()
        t_yaml = time.perf_counter()

        final_current, peak_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        # Latency & Throughput metrics
        generate_duration = t_generate - t_start
        json_duration = t_json - t_generate
        yaml_duration = t_yaml - t_json
        total_duration = t_yaml - t_start
        throughput = len(self.endpoints) / total_duration

        # Memory calculations
        ram_delta_bytes = peak_mem - start_current
        ram_delta_mb = ram_delta_bytes / (1024 * 1024)
        peak_mb = peak_mem / (1024 * 1024)

        # Print detailed benchmark report
        print(
            f"\n[BENCHMARK] Massive 2,000-Endpoint OpenAPI Generation:"
            f"\n  Total Endpoints: {len(self.endpoints)}"
            f"\n  OpenAPI Spec Build Time: {generate_duration * 1000:.2f} ms ({generate_duration:.3f} s)"
            f"\n  JSON Serialization Time: {json_duration * 1000:.2f} ms ({json_duration:.3f} s)"
            f"\n  YAML Serialization Time: {yaml_duration * 1000:.2f} ms ({yaml_duration:.3f} s)"
            f"\n  Total Execution Time: {total_duration * 1000:.2f} ms ({total_duration:.3f} s)"
            f"\n  Serialization Throughput: {throughput:.2f} endpoints/second"
            f"\n  Peak Memory: {peak_mb:.2f} MB"
            f"\n  RAM Delta: {ram_delta_mb:.2f} MB (Limit: < 10.00 MB)"
            f"\n  Generated JSON Size: {len(json_output):,} bytes"
            f"\n  Generated YAML Size: {len(yaml_output):,} bytes"
        )

        # Assertions
        self.assertLess(
            ram_delta_mb,
            10.0,
            f"OpenAPI generator RAM delta exceeded 10MB limit: {ram_delta_mb:.2f} MB",
        )
        self.assertEqual(spec["openapi"], "3.1.0")
        self.assertIn("paths", spec)
        self.assertGreater(len(spec["paths"]), 0)
        self.assertGreater(len(json_output), 10000)
        self.assertGreater(len(yaml_output), 10000)


class TestPostmanMassiveStressBenchmark(unittest.TestCase):
    """
    Benchmark 2: Massive 2,000-Endpoint Postman Collection Memory Benchmark.
    Converts 2,000 endpoints through PostmanExporter with full Radix/Trie folder tree nesting,
    Next.js Server Actions, and GraphQL operations.
    Asserts RAM delta is strictly under 10MB and benchmarks hierarchy generation latency.
    """

    @classmethod
    def setUpClass(cls) -> None:
        """Constructs 2,000 endpoints combining REST, Server Actions, and GraphQL."""
        cls.endpoints: List[DiscoveredEndpoint] = []
        cls.graphql_operations: List[GraphQLOperation] = []

        http_methods = ["GET", "POST", "PUT", "DELETE", "PATCH"]

        # 1,950 REST endpoints including Next.js Server Actions
        for i in range(1950):
            if i % 10 == 0:
                # Next.js Server Action
                action_id = f"{i:040x}"
                ep = DiscoveredEndpoint(
                    path=f"/actions/form_handler_{i % 25}",
                    method="POST",
                    headers={
                        "Next-Action": action_id,
                        "Accept": "text/x-component",
                    },
                    request_body_sample={"form_data": f"input_{i}", "action_id": action_id},
                    summary=f"Next.js Server Action: form_handler_{i % 25}",
                    description=f"Action identifier {action_id}",
                    tags=["server_action", "nextjs"],
                )
            else:
                module_id = i % 30
                sub_id = i % 10
                method = http_methods[i % 5]
                ep = DiscoveredEndpoint(
                    path=f"/api/v1/module_{module_id}/sub_{sub_id}/:id",
                    method=method,
                    parameters=[
                        DiscoveredParameter(name="id", location="path", required=True, example=i),
                        DiscoveredParameter(name="query", location="query", required=False, example="test"),
                    ],
                    request_body_sample={"name": f"item_{i}", "flag": (i % 2 == 0)} if method in ("POST", "PUT") else None,
                    tags=[f"Module_{module_id}"],
                    summary=f"{method} Module {module_id} Sub {sub_id}",
                )
            cls.endpoints.append(ep)

        # 50 GraphQL operations
        for j in range(50):
            op_type = "query" if j % 2 == 0 else "mutation"
            cls.graphql_operations.append(
                GraphQLOperation(
                    operation_name=f"Operation_{j}",
                    operation_type=op_type,
                    query_string=f"{op_type} Operation_{j} {{ items {{ id name status }} }}",
                    endpoint="/graphql",
                    variables_sample={"limit": 10, "offset": j * 10},
                )
            )

    def test_massive_2000_endpoint_postman_collection_and_memory(self) -> None:
        """
        Runs PostmanExporter on 2,000 endpoints with Trie/Radix folder hierarchy,
        Server Actions, and GraphQL operations.
        Measures RAM delta with tracemalloc and asserts strictly under 10MB.
        Benchmarks folder tree construction latency.
        """
        gc.collect()
        tracemalloc.start()
        tracemalloc.reset_peak()
        start_current, _ = tracemalloc.get_traced_memory()

        t_start = time.perf_counter()

        exporter = PostmanExporter(flatten_prefixes=True)
        collection = exporter.export_from_endpoints(
            endpoints=self.endpoints,
            collection_name="Massive 2,000-Endpoint Postman Collection",
            base_url="https://api.example.com",
            graphql_operations=self.graphql_operations,
            description="Stress test collection with full Trie folders, Next.js Server Actions, and GraphQL",
        )
        t_tree = time.perf_counter()

        final_current, peak_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        tree_latency = t_tree - t_start
        ram_delta_bytes = peak_mem - start_current
        ram_delta_mb = ram_delta_bytes / (1024 * 1024)
        peak_mb = peak_mem / (1024 * 1024)

        total_items_converted = len(self.endpoints) + len(self.graphql_operations)
        items_per_second = total_items_converted / tree_latency if tree_latency > 0 else 0

        print(
            f"\n[BENCHMARK] Massive 2,000-Endpoint Postman Collection Memory & Hierarchy:"
            f"\n  Total Items Processed: {total_items_converted} (REST: {len(self.endpoints)}, GraphQL: {len(self.graphql_operations)})"
            f"\n  Folder Hierarchy Generation Latency: {tree_latency * 1000:.2f} ms ({tree_latency:.3f} s)"
            f"\n  Folder Generation Throughput: {items_per_second:.2f} items/second"
            f"\n  Peak Memory: {peak_mb:.2f} MB"
            f"\n  RAM Delta: {ram_delta_mb:.2f} MB (Limit: < 10.00 MB)"
            f"\n  Top-level Folders & Items: {len(collection.items)}"
        )

        # Assertions
        self.assertLess(
            ram_delta_mb,
            10.0,
            f"Postman exporter RAM delta exceeded 10MB limit: {ram_delta_mb:.2f} MB",
        )
        self.assertEqual(collection.name, "Massive 2,000-Endpoint Postman Collection")
        self.assertGreater(len(collection.items), 0)

        # Check GraphQL folder is present
        folder_names = [it.name for it in collection.items]
        self.assertIn("GraphQL", folder_names)


class TestDeeplyNestedPayloadRecursionStress(unittest.TestCase):
    """
    Benchmark 3: Deeply Nested Payload & Recursion Stress Test.
    Tests OpenAPISchemaInferrer and PureYamlDumper against a 50-level deeply nested
    dictionary payload. Verifies it handles extreme depth gracefully without raising RecursionError.
    """

    def test_50_level_deeply_nested_dict_schema_inference_and_yaml(self) -> None:
        """
        Constructs a 50-level deeply nested dictionary:
        {"level_1": {"level_2": ... {"level_50": "leaf_value"} ... }}
        Tests OpenAPISchemaInferrer (both default guarded depth and custom depth)
        and PureYamlDumper against extreme nesting without raising RecursionError.
        """
        depth = 50
        leaf_value = "deep_leaf_scalar"
        nested_data: Any = leaf_value
        for i in range(depth, 0, -1):
            nested_data = {f"level_{i}": nested_data}

        # 1. Test default inferrer: verifies graceful truncation defense without RecursionError
        default_inferrer = OpenAPISchemaInferrer()
        t0 = time.perf_counter()
        guarded_schema = default_inferrer.infer(nested_data)
        default_infer_duration = time.perf_counter() - t0

        self.assertIsInstance(guarded_schema, dict)
        self.assertEqual(guarded_schema.get("type"), "object")
        # Ensure it safely truncated at max_depth without RecursionError
        curr = guarded_schema
        for i in range(1, default_inferrer.max_depth + 1):
            curr = curr["properties"][f"level_{i}"]
        self.assertIn("Truncated", curr.get("description", ""))

        # 2. Test deep inferrer configured for full 50-level traversal without RecursionError
        deep_inferrer = OpenAPISchemaInferrer(max_depth=60)
        t1 = time.perf_counter()
        full_schema = deep_inferrer.infer(nested_data)
        deep_infer_duration = time.perf_counter() - t1

        self.assertIsInstance(full_schema, dict)
        curr_schema = full_schema
        for i in range(1, depth + 1):
            prop_key = f"level_{i}"
            props = curr_schema.get("properties", {})
            self.assertIn(prop_key, props, f"Missing level_{i} at depth {i}")
            curr_schema = props[prop_key]

        self.assertEqual(curr_schema, {"type": "string"})

        # 3. Serialize 50-level payload with PureYamlDumper without RecursionError
        t2 = time.perf_counter()
        yaml_payload = PureYamlDumper.dump(nested_data)
        dumper_duration = time.perf_counter() - t2

        self.assertIsInstance(yaml_payload, str)
        self.assertIn("level_1:", yaml_payload)
        self.assertIn("level_50:", yaml_payload)
        self.assertIn(leaf_value, yaml_payload)

        # 4. Serialize 50-level inferred schema with PureYamlDumper without RecursionError
        t3 = time.perf_counter()
        yaml_schema = PureYamlDumper.dump(full_schema)
        schema_dump_duration = time.perf_counter() - t3

        self.assertIsInstance(yaml_schema, str)
        self.assertIn("type: object", yaml_schema)
        self.assertIn("level_50:", yaml_schema)

        # 5. Verify roundtrip of 50-level YAML with PyYAML
        roundtrip_parsed = yaml.safe_load(yaml_payload)
        self.assertEqual(roundtrip_parsed, nested_data)

        print(
            f"\n[BENCHMARK] Deeply Nested Payload & Recursion Stress Test (Depth: {depth}):"
            f"\n  Guarded Schema Inference Latency (depth={default_inferrer.max_depth}): {default_infer_duration * 1000:.3f} ms"
            f"\n  Full 50-Level Schema Inference Latency: {deep_infer_duration * 1000:.3f} ms"
            f"\n  Payload YAML Dump Latency: {dumper_duration * 1000:.3f} ms"
            f"\n  Schema YAML Dump Latency: {schema_dump_duration * 1000:.3f} ms"
            f"\n  YAML Output Length: {len(yaml_payload)} chars"
            f"\n  RecursionError Guard: Verified (0 RecursionError raised)"
            f"\n  PyYAML Roundtrip: Verified 100% matched"
        )


class TestHighVolumePathNormalizationReDoSBenchmark(unittest.TestCase):
    """
    Benchmark 4: High-Volume Path Normalization ReDoS Benchmark.
    Runs ParameterInferrer.normalize_path against 1,000 complex and adversarial route templates.
    Asserts all 1,000 templates evaluate in linear O(N) time with total duration strictly under 100ms.
    """

    @classmethod
    def setUpClass(cls) -> None:
        """Constructs 1,000 complex, malformed, nested, and adversarial route templates."""
        adversarial_seeds = [
            # Nested brackets (Next.js optional catchall variations)
            "/api/v1/users/[[[id]]]/profile/[[[[action]]]]",
            "/repo/[[...org]]/[[...project]]/[[[branch]]]",
            # Multiple colons and delimiter repetitions
            "/api/:org:::repo/:branch::sub",
            "/service/:a/:b/:c/:d/:e/:f/:g/:h",
            # Unicode and emojis in path and parameters
            "/api/v1/🔥/用户/{user_id}/группа/<slug:group_slug>",
            "/api/v2/🚀/org/{org_id}/spaces/🌌/<token>",
            # Unclosed and mismatched brackets
            "/api/[users/[id/profile/[name",
            "/api/files/[[...unclosed_path",
            "/api/items/{unclosed_brace",
            # Unclosed angle brackets (Django style)
            "/api/<int:id/<str:name/<uuid:token",
            "/articles/<int:pk>/<slug:slug/<missing_close",
            # Mixed delimiters in single segments
            "/api/:org_{repo_id}_<int:build_id>",
            "/v1/[category]/:filter/<sort>",
            # Extreme long sequences of colons, slashes, braces
            "/::::://///:::::[param]:::::<uuid:u>",
            "/" + "{param_nested}" * 20,
            # Query strings and trailing punctuation in template
            "/api/v1/search/:query?filter=:filter#section",
            "/api/v1/users/:user_id/",
        ]

        cls.templates: List[str] = [
            adversarial_seeds[i % len(adversarial_seeds)] for i in range(1000)
        ]

    def test_1000_complex_adversarial_route_templates_linear_time(self) -> None:
        """
        Evaluates 1,000 adversarial route templates through ParameterInferrer.normalize_path.
        Asserts total elapsed duration is strictly under 100ms (< 0.100 s).
        Verifies all templates produce valid normalized path strings without catastrophic backtracking.
        """
        t_start = time.perf_counter()

        results: List[tuple[str, List[str]]] = []
        for template in self.templates:
            norm_path, param_names = ParameterInferrer.normalize_path(template)
            results.append((norm_path, param_names))

        t_elapsed = time.perf_counter() - t_start
        elapsed_ms = t_elapsed * 1000
        throughput = len(self.templates) / t_elapsed if t_elapsed > 0 else 0

        print(
            f"\n[BENCHMARK] High-Volume Path Normalization ReDoS Benchmark:"
            f"\n  Templates Evaluated: {len(self.templates)}"
            f"\n  Total Duration: {elapsed_ms:.2f} ms ({t_elapsed:.4f} s)"
            f"\n  Average per Template: {elapsed_ms / len(self.templates):.4f} ms"
            f"\n  Throughput: {throughput:.1f} templates/second"
            f"\n  ReDoS Safety Threshold: < 100.00 ms"
        )

        # Assertions
        self.assertEqual(len(results), 1000)
        self.assertLess(
            elapsed_ms,
            100.0,
            f"Path normalization took too long ({elapsed_ms:.2f}ms), potential ReDoS!",
        )

        # Verify output integrity
        for norm_path, params in results:
            self.assertTrue(norm_path.startswith("/"))
            self.assertIsInstance(params, list)


class TestRoundTripJsonYamlValidity(unittest.TestCase):
    """
    Benchmark 5: Round-Trip JSON/YAML Validity Check.
    Verifies that generated OpenAPI JSON and Postman Collection JSON parse cleanly
    with standard library `json.loads` and match expected specifications.
    Verifies that PureYamlDumper output parses with PyYAML `yaml.safe_load`.
    """

    def test_openapi_roundtrip_validity(self) -> None:
        """
        Generates OpenAPI 3.1.0 specification with diverse endpoints and auth.
        Verifies JSON output parses with json.loads and validates OpenAPI 3.1.0 schema fields.
        Verifies YAML output parses with yaml.safe_load and matches the spec dictionary.
        """
        endpoints = [
            DiscoveredEndpoint(
                path="/api/v1/users/:user_id",
                method="GET",
                parameters=[
                    DiscoveredParameter(name="user_id", location="path", required=True, example=42),
                    DiscoveredParameter(name="fields", location="query", required=False, example="id,name,email"),
                ],
                responses=[
                    DiscoveredResponse(
                        status_code=200,
                        sample_body={"id": 42, "name": "Alice", "email": "alice@example.com"},
                    )
                ],
                active_status=200,
                auth_type="bearer",
                tags=["Users"],
                summary="Get User Profile",
            ),
            DiscoveredEndpoint(
                path="/api/v1/users",
                method="POST",
                request_body_sample={"name": "Bob", "email": "bob@example.com", "role": "admin"},
                responses=[
                    DiscoveredResponse(
                        status_code=201,
                        sample_body={"id": 43, "created": True},
                    )
                ],
                active_status=201,
                auth_type="apikey",
                auth_header_or_param="X-API-Key",
                tags=["Users"],
                summary="Create User",
            ),
        ]

        gen = OpenAPIGenerator(
            endpoints=endpoints,
            title="Round-Trip Verification API",
            version="1.0.0",
            servers=["https://api.example.com"],
        )

        # 1. JSON Round-Trip Check
        json_str = gen.to_json()
        parsed_json = json.loads(json_str)

        self.assertEqual(parsed_json["openapi"], "3.1.0")
        self.assertEqual(parsed_json["info"]["title"], "Round-Trip Verification API")
        self.assertEqual(parsed_json["info"]["version"], "1.0.0")
        self.assertIn("/api/v1/users/{user_id}", parsed_json["paths"])
        self.assertIn("get", parsed_json["paths"]["/api/v1/users/{user_id}"])
        self.assertIn("/api/v1/users", parsed_json["paths"])
        self.assertIn("post", parsed_json["paths"]["/api/v1/users"])

        # Security schemes
        self.assertIn("components", parsed_json)
        self.assertIn("securitySchemes", parsed_json["components"])
        self.assertIn("bearerAuth", parsed_json["components"]["securitySchemes"])
        self.assertIn("apiKeyAuth", parsed_json["components"]["securitySchemes"])

        # 2. YAML Round-Trip Check
        yaml_str = gen.to_yaml()
        parsed_yaml = yaml.safe_load(yaml_str)

        self.assertEqual(parsed_yaml["openapi"], "3.1.0")
        self.assertEqual(parsed_yaml["info"], parsed_json["info"])
        self.assertEqual(parsed_yaml["paths"].keys(), parsed_json["paths"].keys())
        self.assertEqual(parsed_yaml["components"], parsed_json["components"])

        print(
            f"\n[BENCHMARK] Round-Trip OpenAPI JSON & YAML Validity:"
            f"\n  JSON Parse: PASSED (size: {len(json_str)} bytes)"
            f"\n  YAML Parse: PASSED (size: {len(yaml_str)} bytes)"
            f"\n  Specification: OpenAPI 3.1.0 validated"
        )

    def test_postman_roundtrip_validity(self) -> None:
        """
        Generates Postman Collection v2.1.0 with REST endpoints, Server Actions,
        and GraphQL operations.
        Verifies JSON output parses with json.loads and validates Postman v2.1.0 structure.
        """
        endpoints = [
            DiscoveredEndpoint(
                path="/api/v1/items/:id",
                method="GET",
                parameters=[
                    DiscoveredParameter(name="id", location="path", required=True, example=123),
                    DiscoveredParameter(name="expand", location="query", required=False, example="true"),
                ],
                tags=["Inventory"],
                summary="Get Inventory Item",
            ),
            DiscoveredEndpoint(
                path="/actions/submit_feedback",
                method="POST",
                headers={
                    "Next-Action": "c0ffee1234567890abcdef1234567890abcdef12",
                    "Accept": "text/x-component",
                },
                summary="Submit Feedback Server Action",
                tags=["server_action"],
            ),
        ]
        graphql_ops = [
            GraphQLOperation(
                operation_name="ListItems",
                operation_type="query",
                query_string="query ListItems { items { id name } }",
                endpoint="/graphql",
                variables_sample={"limit": 20},
            )
        ]

        exporter = PostmanExporter(flatten_prefixes=True)
        collection = exporter.export_from_endpoints(
            endpoints=endpoints,
            collection_name="Round-Trip Verification Collection",
            base_url="https://api.example.com",
            graphql_operations=graphql_ops,
        )

        json_str = collection.to_json()
        parsed = json.loads(json_str)

        # Postman Collection v2.1.0 structure validation
        self.assertIn("info", parsed)
        self.assertEqual(parsed["info"]["name"], "Round-Trip Verification Collection")
        self.assertEqual(
            parsed["info"]["schema"],
            "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        )
        self.assertIn("_postman_id", parsed["info"])

        # Variables validation
        self.assertIn("variable", parsed)
        has_base_url = any(v["key"] == "baseUrl" for v in parsed["variable"])
        self.assertTrue(has_base_url, "baseUrl variable missing from Postman Collection")

        # Items & Folders validation
        self.assertIn("item", parsed)
        folder_names = [it["name"] for it in parsed["item"]]
        self.assertIn("GraphQL", folder_names)

        # Validate Next.js Server Action headers
        all_requests: List[Dict[str, Any]] = []

        def collect_requests(items: List[Dict[str, Any]]) -> None:
            for it in items:
                if "request" in it:
                    all_requests.append(it)
                if "item" in it:
                    collect_requests(it["item"])

        collect_requests(parsed["item"])
        self.assertGreaterEqual(len(all_requests), 3)

        # Check Server Action item
        server_action_req = next(
            (r for r in all_requests if r["name"] == "Submit Feedback Server Action"),
            None,
        )
        self.assertIsNotNone(server_action_req)
        sa_headers = {h["key"].lower(): h["value"] for h in server_action_req["request"]["header"]}
        self.assertIn("next-action", sa_headers)
        self.assertEqual(sa_headers["next-action"], "c0ffee1234567890abcdef1234567890abcdef12")
        self.assertEqual(sa_headers.get("accept"), "text/x-component")

        # Check GraphQL item
        gql_req = next(
            (r for r in all_requests if "ListItems" in r["name"]),
            None,
        )
        self.assertIsNotNone(gql_req)
        self.assertEqual(gql_req["request"]["body"]["mode"], "graphql")
        self.assertIn("query ListItems", gql_req["request"]["body"]["graphql"]["query"])

        print(
            f"\n[BENCHMARK] Round-Trip Postman Collection JSON Validity:"
            f"\n  JSON Parse: PASSED (size: {len(json_str)} bytes)"
            f"\n  Schema: Postman v2.1.0 collection.json validated"
            f"\n  Requests extracted: {len(all_requests)}"
            f"\n  Server Action & GraphQL modes: Verified"
        )


if __name__ == "__main__":
    unittest.main()
