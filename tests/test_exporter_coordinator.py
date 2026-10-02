"""
Comprehensive unit tests for api_tool.exporter.coordinator (ExportCoordinator and ExportResult).

Covers:
1. Package exports and api_tool.models integration via __getattr__.
2. ExportResult dataclass serialization and formatting.
3. ExportCoordinator initialization, endpoint ingestion, and ScanResult ingestion.
4. export_openapi (OpenAPI 3.1.0 JSON and PureYamlDumper YAML).
5. export_postman (Postman Collection v2.1.0 with Radix folders & Next.js Server Actions).
6. export_graphql_sdl (explicit SDL and synthesized SDL from operations).
7. export_all unified batch export (with and without GraphQL operations).
8. End-to-end integration and edge cases.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict

import yaml

from api_tool.exporter import (
    ExportCoordinator,
    ExportResult,
    OpenAPIGenerator,
    PureYamlDumper,
    OpenAPISchemaInferrer,
    ParameterInferrer,
    PostmanExporter,
    PostmanCollection,
    PostmanItem,
    synthesize_graphql_sdl_from_operations,
)
from api_tool.models import (
    DiscoveredEndpoint,
    DiscoveredParameter,
    DiscoveredResponse,
    GraphQLOperation,
    ScanResult,
)
import api_tool.models as models_module


class TestExporterPackageAndModelExports(unittest.TestCase):
    """Verifies package-level exports and models.py dynamic exports."""

    def test_package_exports(self):
        """Verifies that all required symbols are exported from api_tool.exporter."""
        from api_tool.exporter import (
            ExportCoordinator as EC,
            ExportResult as ER,
            OpenAPIGenerator as OG,
            PureYamlDumper as PYD,
            OpenAPISchemaInferrer as OSI,
            ParameterInferrer as PI,
            PostmanExporter as PE,
            PostmanCollection as PC,
            PostmanItem as PI_item,
        )
        self.assertIs(EC, ExportCoordinator)
        self.assertIs(ER, ExportResult)
        self.assertIs(OG, OpenAPIGenerator)
        self.assertIs(PYD, PureYamlDumper)
        self.assertIs(OSI, OpenAPISchemaInferrer)
        self.assertIs(PI, ParameterInferrer)
        self.assertIs(PE, PostmanExporter)
        self.assertIs(PC, PostmanCollection)
        self.assertIs(PI_item, PostmanItem)

    def test_models_getattr_exports(self):
        """Verifies that ExportCoordinator and ExportResult can be accessed from api_tool.models."""
        ec = getattr(models_module, "ExportCoordinator")
        er = getattr(models_module, "ExportResult")
        self.assertIs(ec, ExportCoordinator)
        self.assertIs(er, ExportResult)

        # Direct import syntax
        from api_tool.models import ExportCoordinator as EC_Direct, ExportResult as ER_Direct
        self.assertIs(EC_Direct, ExportCoordinator)
        self.assertIs(ER_Direct, ExportResult)

    def test_models_invalid_getattr_raises(self):
        """Verifies that unknown attributes still raise AttributeError."""
        with self.assertRaises(AttributeError):
            _ = getattr(models_module, "NonExistentClass12345")


class TestExportResultDataclass(unittest.TestCase):
    """Verifies ExportResult defaults, serialization, and methods."""

    def test_defaults(self):
        res = ExportResult()
        self.assertIsNone(res.openapi_json_path)
        self.assertIsNone(res.openapi_yaml_path)
        self.assertIsNone(res.postman_json_path)
        self.assertIsNone(res.graphql_sdl_path)
        self.assertEqual(res.total_endpoints, 0)
        self.assertEqual(res.total_graphql_ops, 0)
        self.assertEqual(res.summary, {})

    def test_to_dict_and_to_json(self):
        res = ExportResult(
            openapi_json_path="/tmp/out.openapi.json",
            openapi_yaml_path="/tmp/out.openapi.yaml",
            postman_json_path="/tmp/out.postman.json",
            graphql_sdl_path="/tmp/out.schema.graphql",
            total_endpoints=15,
            total_graphql_ops=3,
            summary={"status": "success", "methods": {"GET": 10, "POST": 5}},
        )
        d = res.to_dict()
        self.assertEqual(d["openapi_json_path"], "/tmp/out.openapi.json")
        self.assertEqual(d["openapi_yaml_path"], "/tmp/out.openapi.yaml")
        self.assertEqual(d["postman_json_path"], "/tmp/out.postman.json")
        self.assertEqual(d["graphql_sdl_path"], "/tmp/out.schema.graphql")
        self.assertEqual(d["total_endpoints"], 15)
        self.assertEqual(d["total_graphql_ops"], 3)
        self.assertEqual(d["summary"]["status"], "success")

        json_str = res.to_json()
        parsed = json.loads(json_str)
        self.assertEqual(parsed, d)


class TestExportCoordinatorIngestion(unittest.TestCase):
    """Verifies endpoint and GraphQL operation ingestion on ExportCoordinator."""

    def setUp(self):
        self.coord = ExportCoordinator(
            target_url="https://api.example.com",
            title="Example API",
            version="2.0.0",
            description="Testing ingestion",
        )

    def test_initial_state(self):
        self.assertEqual(self.coord.target_url, "https://api.example.com")
        self.assertEqual(self.coord.title, "Example API")
        self.assertEqual(self.coord.version, "2.0.0")
        self.assertEqual(self.coord.description, "Testing ingestion")
        self.assertEqual(len(self.coord.endpoints), 0)
        self.assertEqual(len(self.coord.graphql_operations), 0)

    def test_add_endpoints_list_and_single(self):
        ep1 = DiscoveredEndpoint(path="/users", method="GET")
        ep2 = DiscoveredEndpoint(path="/users/{id}", method="POST")

        self.coord.add_endpoints([ep1])
        self.assertEqual(len(self.coord.endpoints), 1)

        # Single endpoint via add_endpoints
        self.coord.add_endpoints(ep2)
        self.assertEqual(len(self.coord.endpoints), 2)

        # None/empty handling
        self.coord.add_endpoints([])
        self.coord.add_endpoints(None)
        self.assertEqual(len(self.coord.endpoints), 2)

    def test_add_graphql_operations(self):
        op1 = GraphQLOperation(
            operation_type="query",
            operation_name="GetUser",
            query_string="query GetUser { user { id } }",
        )
        op2 = GraphQLOperation(
            operation_type="mutation",
            operation_name="CreateUser",
            query_string="mutation CreateUser { createUser { id } }",
        )

        self.coord.add_graphql_operations([op1])
        self.assertEqual(len(self.coord.graphql_operations), 1)

        # Single op handling
        self.coord.add_graphql_operations(op2)
        self.assertEqual(len(self.coord.graphql_operations), 2)

        # None/empty handling
        self.coord.add_graphql_operations([])
        self.coord.add_graphql_operations(None)
        self.assertEqual(len(self.coord.graphql_operations), 2)

    def test_add_scan_result(self):
        coord = ExportCoordinator()
        scan = ScanResult(
            target_url="https://service.local",
            endpoints=[
                DiscoveredEndpoint(path="/items", method="GET"),
                DiscoveredEndpoint(path="/items", method="POST"),
            ],
            graphql_operations=[
                GraphQLOperation(
                    operation_type="query",
                    operation_name="ListItems",
                    query_string="query ListItems { items { id } }",
                )
            ],
        )

        coord.add_scan_result(scan)
        self.assertEqual(coord.target_url, "https://service.local")
        self.assertEqual(len(coord.endpoints), 2)
        self.assertEqual(len(coord.graphql_operations), 1)

    def test_init_with_scan_result_and_lists(self):
        scan = ScanResult(
            target_url="https://auto.local",
            endpoints=[DiscoveredEndpoint(path="/auto", method="GET")],
        )
        coord = ExportCoordinator(
            scan_result=scan,
            endpoints=[DiscoveredEndpoint(path="/manual", method="POST")],
            graphql_operations=[
                GraphQLOperation(
                    operation_type="query",
                    operation_name="TestOp",
                    query_string="query { test }",
                )
            ],
        )
        self.assertEqual(coord.target_url, "https://auto.local")
        self.assertEqual(len(coord.endpoints), 2)
        self.assertEqual(len(coord.graphql_operations), 1)


class TestExportCoordinatorOpenAPI(unittest.TestCase):
    """Verifies OpenAPI 3.1.0 JSON and YAML file exports."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="test_openapi_export_")
        self.coord = ExportCoordinator(
            target_url="https://api.example.com/v1",
            title="Customer Service API",
            version="3.1.0",
            description="Generated by Miniature Engine",
        )
        self.coord.add_endpoints([
            DiscoveredEndpoint(
                path="/customers/{id}",
                method="GET",
                summary="Get customer by ID",
                parameters=[
                    DiscoveredParameter(name="id", location="path", required=True),
                    DiscoveredParameter(name="include_details", location="query", required=False),
                ],
                responses=[
                    DiscoveredResponse(
                        status_code=200,
                        sample_body={"id": 101, "name": "John Doe", "email": "john@example.com"},
                    )
                ],
                auth_type="bearer",
            ),
            DiscoveredEndpoint(
                path="/customers",
                method="POST",
                summary="Create new customer",
                request_body_sample={"name": "Jane Doe", "email": "jane@example.com"},
                responses=[
                    DiscoveredResponse(status_code=201, sample_body={"id": 102, "status": "created"})
                ],
                auth_type="apikey",
                auth_header_or_param="X-API-Key",
            ),
        ])

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_export_openapi_json(self):
        out_path = os.path.join(self.temp_dir, "nested", "specs", "openapi.json")
        res_path = self.coord.export_openapi(out_path, format="json")

        self.assertEqual(res_path, str(Path(out_path).resolve()))
        self.assertTrue(os.path.isfile(res_path))

        with open(res_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertEqual(data["openapi"], "3.1.0")
        self.assertEqual(data["info"]["title"], "Customer Service API")
        self.assertEqual(data["info"]["version"], "3.1.0")
        self.assertIn("/customers/{id}", data["paths"])
        self.assertIn("get", data["paths"]["/customers/{id}"])
        self.assertIn("post", data["paths"]["/customers"])

        # Check path parameter requirement
        get_op = data["paths"]["/customers/{id}"]["get"]
        path_param = next(p for p in get_op["parameters"] if p["name"] == "id")
        self.assertTrue(path_param["required"])
        self.assertEqual(path_param["in"], "path")

        # Check security
        self.assertIn("securitySchemes", data["components"])

    def test_export_openapi_yaml(self):
        out_path = os.path.join(self.temp_dir, "nested", "specs", "openapi.yaml")
        res_path = self.coord.export_openapi(out_path, format="yaml")

        self.assertEqual(res_path, str(Path(out_path).resolve()))
        self.assertTrue(os.path.isfile(res_path))

        with open(res_path, "r", encoding="utf-8") as f:
            yaml_content = f.read()

        parsed = yaml.safe_load(yaml_content)
        self.assertEqual(parsed["openapi"], "3.1.0")
        self.assertEqual(parsed["info"]["title"], "Customer Service API")
        self.assertIn("/customers/{id}", parsed["paths"])
        self.assertIn("200", parsed["paths"]["/customers/{id}"]["get"]["responses"])


class TestExportCoordinatorPostman(unittest.TestCase):
    """Verifies Postman Collection v2.1.0 exports."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="test_postman_export_")
        self.coord = ExportCoordinator(
            target_url="https://shop.example.com",
            title="E-Commerce API",
            version="1.0.0",
        )
        self.coord.add_endpoints([
            DiscoveredEndpoint(
                path="/api/v1/orders/{order_id}",
                method="GET",
                tags=["Orders"],
                summary="Fetch Order Details",
                parameters=[
                    DiscoveredParameter(name="order_id", location="path", required=True),
                ],
            ),
            DiscoveredEndpoint(
                path="/api/v1/orders",
                method="POST",
                tags=["Orders"],
                summary="Place Order",
                request_body_sample={"items": [{"item_id": 1, "quantity": 2}]},
            ),
            # Next.js Server Action
            DiscoveredEndpoint(
                path="/dashboard",
                method="POST",
                tags=["server_action", "nextjs"],
                headers={"Next-Action": "c8a49c6ef6e611843b0d11a7a0b38c03e843c0d1"},
                summary="Next.js Server Action: RefreshCart",
            ),
        ])
        self.coord.add_graphql_operations([
            GraphQLOperation(
                operation_type="query",
                operation_name="GetInventory",
                query_string="query GetInventory($sku: String!) { inventory(sku: $sku) { available } }",
            )
        ])

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_export_postman_collection(self):
        out_path = os.path.join(self.temp_dir, "collections", "shop.postman.json")
        res_path = self.coord.export_postman(out_path, collection_name="Shop Test Collection")

        self.assertEqual(res_path, str(Path(out_path).resolve()))
        self.assertTrue(os.path.isfile(res_path))

        with open(res_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertIn("info", data)
        self.assertEqual(data["info"]["schema"], "https://schema.getpostman.com/json/collection/v2.1.0/collection.json")
        self.assertEqual(data["info"]["name"], "Shop Test Collection")

        # Check collection variables
        var_keys = [v["key"] for v in data.get("variable", [])]
        self.assertIn("baseUrl", var_keys)

        # Check GraphQL folder exists
        folder_names = [item["name"] for item in data.get("item", []) if "item" in item]
        self.assertIn("GraphQL", folder_names)


class TestExportCoordinatorGraphQLSDL(unittest.TestCase):
    """Verifies GraphQL SDL schema generation and export."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="test_graphql_export_")
        self.coord = ExportCoordinator(
            target_url="https://graphql.example.com",
            title="Graph API",
        )

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_export_explicit_sdl(self):
        out_path = os.path.join(self.temp_dir, "schema.graphql")
        custom_sdl = (
            "schema {\n"
            "  query: Query\n"
            "}\n"
            "type Query {\n"
            "  viewer: User\n"
            "}\n"
            "type User {\n"
            "  id: ID!\n"
            "  username: String!\n"
            "}\n"
        )
        res_path = self.coord.export_graphql_sdl(out_path, sdl_content=custom_sdl)
        self.assertEqual(res_path, str(Path(out_path).resolve()))
        self.assertTrue(os.path.isfile(res_path))

        with open(res_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertEqual(content, custom_sdl)

    def test_export_synthesized_sdl_from_operations(self):
        self.coord.add_graphql_operations([
            GraphQLOperation(
                operation_type="query",
                operation_name="GetUser",
                query_string="query GetUser($id: ID!) { user(id: $id) { id name } }",
            ),
            GraphQLOperation(
                operation_type="mutation",
                operation_name="UpdateEmail",
                query_string="mutation UpdateEmail($email: String!) { updateEmail(email: $email) { success } }",
            ),
        ])

        out_path = os.path.join(self.temp_dir, "synthesized.schema.graphql")
        res_path = self.coord.export_graphql_sdl(out_path)
        self.assertEqual(res_path, str(Path(out_path).resolve()))
        self.assertTrue(os.path.isfile(res_path))

        with open(res_path, "r", encoding="utf-8") as f:
            sdl = f.read()

        self.assertIn("type Query", sdl)
        self.assertIn("user", sdl)
        self.assertIn("type Mutation", sdl)
        self.assertIn("updateEmail", sdl)

    def test_export_empty_operations_synthesizes_stub(self):
        out_path = os.path.join(self.temp_dir, "empty.schema.graphql")
        res_path = self.coord.export_graphql_sdl(out_path)
        self.assertTrue(os.path.isfile(res_path))
        with open(res_path, "r", encoding="utf-8") as f:
            sdl = f.read()
        self.assertIn("type Query", sdl)
        self.assertIn("_empty: String", sdl)


class TestExportCoordinatorExportAll(unittest.TestCase):
    """Verifies unified export_all functionality across all formats."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="test_export_all_")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_export_all_without_graphql(self):
        coord = ExportCoordinator(
            target_url="https://rest-only.example.com",
            title="REST Only API",
            version="1.5.0",
        )
        coord.add_endpoints([
            DiscoveredEndpoint(path="/health", method="GET", summary="Health check"),
            DiscoveredEndpoint(path="/users", method="GET", summary="List users"),
            DiscoveredEndpoint(path="/users", method="POST", summary="Create user"),
        ])

        result = coord.export_all(self.temp_dir, base_name="rest_api")

        self.assertIsInstance(result, ExportResult)
        self.assertEqual(result.total_endpoints, 3)
        self.assertEqual(result.total_graphql_ops, 0)
        self.assertIsNone(result.graphql_sdl_path)
        self.assertFalse(result.summary["has_graphql"])

        # Check files exist
        self.assertIsNotNone(result.openapi_json_path)
        self.assertTrue(os.path.isfile(result.openapi_json_path))
        self.assertTrue(result.openapi_json_path.endswith("rest_api.openapi.json"))

        self.assertIsNotNone(result.openapi_yaml_path)
        self.assertTrue(os.path.isfile(result.openapi_yaml_path))
        self.assertTrue(result.openapi_yaml_path.endswith("rest_api.openapi.yaml"))

        self.assertIsNotNone(result.postman_json_path)
        self.assertTrue(os.path.isfile(result.postman_json_path))
        self.assertTrue(result.postman_json_path.endswith("rest_api.postman.json"))

        # Check summary breakdown
        self.assertEqual(result.summary["methods_breakdown"]["GET"], 2)
        self.assertEqual(result.summary["methods_breakdown"]["POST"], 1)

    def test_export_all_with_graphql(self):
        coord = ExportCoordinator(
            target_url="https://full-stack.example.com",
            title="Full Stack API",
            version="2.0.0",
        )
        coord.add_endpoints([
            DiscoveredEndpoint(path="/api/status", method="GET", tags=["System"]),
            DiscoveredEndpoint(
                path="/api/messages",
                method="POST",
                tags=["Messages"],
                request_body_sample={"text": "hello"},
            ),
        ])
        coord.add_graphql_operations([
            GraphQLOperation(
                operation_type="query",
                operation_name="ListMessages",
                query_string="query ListMessages { messages { id text } }",
            ),
            GraphQLOperation(
                operation_type="mutation",
                operation_name="SendMessage",
                query_string="mutation SendMessage($text: String!) { sendMessage(text: $text) { id } }",
            ),
        ])

        out_dir = os.path.join(self.temp_dir, "deep", "output")
        result = coord.export_all(out_dir, base_name="full_engine")

        self.assertEqual(result.total_endpoints, 2)
        self.assertEqual(result.total_graphql_ops, 2)
        self.assertTrue(result.summary["has_graphql"])

        # All 4 files must exist
        self.assertTrue(os.path.isfile(result.openapi_json_path))
        self.assertTrue(os.path.isfile(result.openapi_yaml_path))
        self.assertTrue(os.path.isfile(result.postman_json_path))
        self.assertIsNotNone(result.graphql_sdl_path)
        self.assertTrue(os.path.isfile(result.graphql_sdl_path))
        self.assertTrue(result.graphql_sdl_path.endswith("full_engine.schema.graphql"))

        # Verify Postman collection has both REST endpoints and GraphQL folder
        with open(result.postman_json_path, "r", encoding="utf-8") as f:
            p_data = json.load(f)
        folder_names = [i["name"] for i in p_data.get("item", []) if "item" in i]
        self.assertIn("GraphQL", folder_names)

        # Verify GraphQL SDL content
        with open(result.graphql_sdl_path, "r", encoding="utf-8") as f:
            sdl_text = f.read()
        self.assertIn("type Query", sdl_text)
        self.assertIn("messages", sdl_text)
        self.assertIn("type Mutation", sdl_text)
        self.assertIn("sendMessage", sdl_text)


class TestExportCoordinatorStressAndEdgeCases(unittest.TestCase):
    """Stress tests and edge case handling for ExportCoordinator."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="test_stress_coord_")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_stress_fifty_endpoints_multi_methods_and_tags(self):
        coord = ExportCoordinator(
            target_url="https://stress-test.internal",
            title="Stress Test API",
            version="9.9.9",
        )
        endpoints = []
        for i in range(50):
            method = ["GET", "POST", "PUT", "DELETE", "PATCH"][i % 5]
            tag = f"Module_{i % 5}"
            endpoints.append(
                DiscoveredEndpoint(
                    path=f"/api/v1/entities/{i}/action",
                    method=method,
                    tags=[tag],
                    summary=f"Action on entity {i}",
                    parameters=[
                        DiscoveredParameter(name="id", location="path", required=True),
                        DiscoveredParameter(name="filter", location="query", required=False),
                    ],
                    request_body_sample={"field": f"value_{i}"} if method != "GET" else None,
                    responses=[
                        DiscoveredResponse(status_code=200, sample_body={"success": True, "index": i})
                    ],
                )
            )

        coord.add_endpoints(endpoints)
        self.assertEqual(len(coord.endpoints), 50)

        result = coord.export_all(self.temp_dir, base_name="stress")
        self.assertEqual(result.total_endpoints, 50)
        self.assertEqual(len(result.summary["methods_breakdown"]), 5)
        self.assertEqual(result.summary["methods_breakdown"]["GET"], 10)
        self.assertEqual(result.summary["methods_breakdown"]["POST"], 10)

        # Confirm valid OpenAPI JSON
        with open(result.openapi_json_path, "r", encoding="utf-8") as f:
            openapi_spec = json.load(f)
        self.assertEqual(len(openapi_spec["paths"]), 50)

        # Confirm valid OpenAPI YAML
        with open(result.openapi_yaml_path, "r", encoding="utf-8") as f:
            yaml_spec = yaml.safe_load(f)
        self.assertEqual(len(yaml_spec["paths"]), 50)

        # Confirm valid Postman JSON
        with open(result.postman_json_path, "r", encoding="utf-8") as f:
            postman_col = json.load(f)
        self.assertEqual(postman_col["info"]["name"], "Stress Test API")

    def test_reusability_and_sequential_exports(self):
        coord = ExportCoordinator(title="Incremental API")
        ep1 = DiscoveredEndpoint(path="/alpha", method="GET")
        coord.add_endpoints([ep1])

        res1 = coord.export_all(self.temp_dir, base_name="inc1")
        self.assertEqual(res1.total_endpoints, 1)

        # Add more endpoints and re-export
        ep2 = DiscoveredEndpoint(path="/beta", method="POST")
        coord.add_endpoints([ep2])

        res2 = coord.export_all(self.temp_dir, base_name="inc2")
        self.assertEqual(res2.total_endpoints, 2)

    def test_base_name_special_characters_sanitized(self):
        coord = ExportCoordinator(title="Special Chars")
        coord.add_endpoints([DiscoveredEndpoint(path="/ping", method="GET")])

        res = coord.export_all(self.temp_dir, base_name="my api / special @ name")
        self.assertTrue(os.path.isfile(res.openapi_json_path))
        self.assertTrue(os.path.isfile(res.openapi_yaml_path))
        self.assertTrue(os.path.isfile(res.postman_json_path))


if __name__ == "__main__":
    unittest.main()
