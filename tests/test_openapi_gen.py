"""
Comprehensive unit tests for OpenAPISchemaInferrer, ParameterInferrer, PureYamlDumper,
and OpenAPIGenerator (Module 4: Schema Inference & OpenAPI 3.1.0 Generator).
"""

import json
import os
import shutil
import tempfile
import unittest
from typing import Any, Dict

import yaml  # Used for cross-validation of PureYamlDumper output

from api_tool.exporter.schema_inference import OpenAPISchemaInferrer, ParameterInferrer
from api_tool.exporter.openapi_gen import OpenAPIGenerator, PureYamlDumper
from api_tool.models import (
    DiscoveredEndpoint,
    DiscoveredParameter,
    DiscoveredResponse,
    ScanResult,
)


class TestOpenAPISchemaInferrer(unittest.TestCase):
    """Tests for OpenAPISchemaInferrer: types, formats, nullability, widening, anyOf."""

    def setUp(self):
        self.inferrer = OpenAPISchemaInferrer()

    def test_infer_none_null(self):
        schema = self.inferrer.infer(None)
        self.assertEqual(schema, {"type": "null"})

    def test_infer_bool_not_int(self):
        # CRITICAL: In Python, bool subclasses int. isinstance(True, int) is True!
        schema_true = self.inferrer.infer(True)
        self.assertEqual(schema_true, {"type": "boolean"})
        schema_false = self.inferrer.infer(False)
        self.assertEqual(schema_false, {"type": "boolean"})

    def test_infer_integer(self):
        self.assertEqual(self.inferrer.infer(0), {"type": "integer"})
        self.assertEqual(self.inferrer.infer(42), {"type": "integer"})
        self.assertEqual(self.inferrer.infer(-999), {"type": "integer"})

    def test_infer_number_float(self):
        self.assertEqual(self.inferrer.infer(3.14159), {"type": "number"})
        self.assertEqual(self.inferrer.infer(-0.001), {"type": "number"})

    def test_infer_plain_string(self):
        self.assertEqual(self.inferrer.infer("hello world"), {"type": "string"})
        self.assertEqual(self.inferrer.infer("some-random-slug"), {"type": "string"})

    def test_infer_string_format_uuid(self):
        uuid_str = "550e8400-e29b-41d4-a716-446655440000"
        schema = self.inferrer.infer(uuid_str)
        self.assertEqual(schema, {"type": "string", "format": "uuid"})

    def test_infer_string_format_date(self):
        date_str = "2026-10-02"
        schema = self.inferrer.infer(date_str)
        self.assertEqual(schema, {"type": "string", "format": "date"})

    def test_infer_string_format_datetime(self):
        dt1 = "2026-10-02T13:38:37Z"
        dt2 = "2026-10-02T13:38:37+00:00"
        dt3 = "2026-10-02 13:38:37.500"
        self.assertEqual(self.inferrer.infer(dt1), {"type": "string", "format": "date-time"})
        self.assertEqual(self.inferrer.infer(dt2), {"type": "string", "format": "date-time"})
        self.assertEqual(self.inferrer.infer(dt3), {"type": "string", "format": "date-time"})

    def test_infer_string_format_email(self):
        email_str = "alice@example.com"
        self.assertEqual(self.inferrer.infer(email_str), {"type": "string", "format": "email"})
        email_complex = "bob.smith+tag@sub.domain.co.uk"
        self.assertEqual(self.inferrer.infer(email_complex), {"type": "string", "format": "email"})

    def test_infer_string_format_ipv4(self):
        ipv4_str = "192.168.1.1"
        self.assertEqual(self.inferrer.infer(ipv4_str), {"type": "string", "format": "ipv4"})
        self.assertEqual(self.inferrer.infer("10.0.0.1"), {"type": "string", "format": "ipv4"})
        # Invalid IP string should fall back to plain string
        self.assertEqual(self.inferrer.infer("999.999.999.999"), {"type": "string"})

    def test_infer_string_format_uri(self):
        uri_str = "https://api.example.com/v1/users"
        self.assertEqual(self.inferrer.infer(uri_str), {"type": "string", "format": "uri"})
        self.assertEqual(self.inferrer.infer("ftp://files.example.com/data.csv"), {"type": "string", "format": "uri"})

    def test_infer_empty_array(self):
        self.assertEqual(self.inferrer.infer([]), {"type": "array"})

    def test_infer_homogeneous_array(self):
        data = [1, 2, 3, 4]
        schema = self.inferrer.infer(data)
        self.assertEqual(schema, {"type": "array", "items": {"type": "integer"}})

    def test_infer_heterogeneous_array_widening(self):
        # Array with int and float widens to number
        data = [1, 2.5, 3]
        schema = self.inferrer.infer(data)
        self.assertEqual(schema, {"type": "array", "items": {"type": "number"}})

    def test_infer_dict_object(self):
        data = {
            "id": 101,
            "username": "coder",
            "active": True,
            "email": "coder@test.com",
        }
        schema = self.inferrer.infer(data)
        self.assertEqual(schema["type"], "object")
        self.assertEqual(schema["properties"]["id"], {"type": "integer"})
        self.assertEqual(schema["properties"]["username"], {"type": "string"})
        self.assertEqual(schema["properties"]["active"], {"type": "boolean"})
        self.assertEqual(schema["properties"]["email"], {"type": "string", "format": "email"})
        self.assertEqual(schema["required"], ["active", "email", "id", "username"])

    def test_infer_from_samples(self):
        samples = [
            {"id": 1, "name": "A"},
            {"id": 2, "name": "B", "extra": "info"},
        ]
        schema = self.inferrer.infer_from_samples(samples)
        self.assertEqual(schema["type"], "object")
        self.assertIn("id", schema["properties"])
        self.assertIn("name", schema["properties"])
        self.assertIn("extra", schema["properties"])
        # 'extra' is not in sample 1, so required is only id and name
        self.assertEqual(schema["required"], ["id", "name"])

    # ------------------ Merging Tests ------------------

    def test_merge_empty_and_identical(self):
        s1 = {"type": "string"}
        self.assertEqual(self.inferrer.merge({}, s1), s1)
        self.assertEqual(self.inferrer.merge(s1, {}), s1)
        self.assertEqual(self.inferrer.merge(s1, s1), s1)

    def test_merge_nullability_openapi_3_1(self):
        # OpenAPI 3.1 mandates type: ["string", "null"] - NEVER nullable: true!
        s1 = {"type": "string"}
        s2 = {"type": "null"}
        merged = self.inferrer.merge(s1, s2)
        self.assertEqual(merged["type"], ["string", "null"])
        self.assertNotIn("nullable", merged)

    def test_merge_nullability_idempotent(self):
        s1 = {"type": ["string", "null"]}
        s2 = {"type": "string"}
        merged = self.inferrer.merge(s1, s2)
        self.assertEqual(merged["type"], ["string", "null"])
        self.assertNotIn("nullable", merged)

    def test_merge_strips_legacy_nullable(self):
        legacy = {"type": "integer", "nullable": True}
        norm = self.inferrer._normalize_schema(legacy)
        self.assertEqual(norm["type"], ["integer", "null"])
        self.assertNotIn("nullable", norm)

    def test_merge_type_widening_int_and_number(self):
        s_int = {"type": "integer"}
        s_num = {"type": "number"}
        merged = self.inferrer.merge(s_int, s_num)
        self.assertEqual(merged, {"type": "number"})

        # Reverse order
        merged_rev = self.inferrer.merge(s_num, s_int)
        self.assertEqual(merged_rev, {"type": "number"})

    def test_merge_type_widening_with_null(self):
        s_int_null = {"type": ["integer", "null"]}
        s_num = {"type": "number"}
        merged = self.inferrer.merge(s_int_null, s_num)
        self.assertEqual(merged["type"], ["number", "null"])

    def test_merge_objects_union_props_and_intersect_required(self):
        obs1 = {
            "type": "object",
            "properties": {
                "id": {"type": "integer"},
                "name": {"type": "string"},
                "role": {"type": "string"},
            },
            "required": ["id", "name", "role"],
        }
        obs2 = {
            "type": "object",
            "properties": {
                "id": {"type": "integer"},
                "name": {"type": "string"},
                "department": {"type": "string"},
            },
            "required": ["id", "name", "department"],
        }

        merged = self.inferrer.merge(obs1, obs2)
        self.assertEqual(merged["type"], "object")
        # Union of properties: id, name, role, department
        self.assertEqual(set(merged["properties"].keys()), {"id", "name", "role", "department"})
        # Intersect required: id, name
        self.assertEqual(merged["required"], ["id", "name"])

    def test_merge_arrays(self):
        arr1 = {"type": "array", "items": {"type": "integer"}}
        arr2 = {"type": "array", "items": {"type": "number"}}
        merged = self.inferrer.merge(arr1, arr2)
        self.assertEqual(merged, {"type": "array", "items": {"type": "number"}})

    def test_merge_string_formats_lossy(self):
        email_schema = {"type": "string", "format": "email"}
        uuid_schema = {"type": "string", "format": "uuid"}
        # Merging different formats generalizes to plain string
        merged = self.inferrer.merge(email_schema, uuid_schema)
        self.assertEqual(merged, {"type": "string"})
        self.assertNotIn("format", merged)

    def test_merge_polymorphic_fallback_anyof(self):
        str_schema = {"type": "string"}
        obj_schema = {"type": "object", "properties": {"count": {"type": "integer"}}}
        merged = self.inferrer.merge(str_schema, obj_schema)
        self.assertIn("anyOf", merged)
        self.assertEqual(len(merged["anyOf"]), 2)
        self.assertIn(str_schema, merged["anyOf"])
        self.assertIn(obj_schema, merged["anyOf"])


class TestParameterInferrer(unittest.TestCase):
    """Tests for ParameterInferrer: path normalization and parameter heuristics."""

    def test_normalize_express_path(self):
        path = "/users/:id/posts/:postId"
        norm, params = ParameterInferrer.normalize_path(path)
        self.assertEqual(norm, "/users/{id}/posts/{postId}")
        self.assertEqual(params, ["id", "postId"])

    def test_normalize_nextjs_path(self):
        path = "/api/posts/[id]"
        norm, params = ParameterInferrer.normalize_path(path)
        self.assertEqual(norm, "/api/posts/{id}")
        self.assertEqual(params, ["id"])

    def test_normalize_nextjs_catchall(self):
        path = "/api/docs/[...slug]"
        norm, params = ParameterInferrer.normalize_path(path)
        self.assertEqual(norm, "/api/docs/{slug}")
        self.assertEqual(params, ["slug"])

    def test_normalize_nextjs_optional_catchall(self):
        path = "/api/files/[[...filepath]]"
        norm, params = ParameterInferrer.normalize_path(path)
        self.assertEqual(norm, "/api/files/{filepath}")
        self.assertEqual(params, ["filepath"])

    def test_normalize_django_path(self):
        path = "/articles/<int:article_id>/<slug:article_slug>/<uuid:token>/"
        norm, params = ParameterInferrer.normalize_path(path)
        self.assertEqual(norm, "/articles/{article_id}/{article_slug}/{token}/")
        self.assertEqual(params, ["article_id", "article_slug", "token"])

    def test_normalize_django_untyped(self):
        path = "/users/<user_id>/"
        norm, params = ParameterInferrer.normalize_path(path)
        self.assertEqual(norm, "/users/{user_id}/")
        self.assertEqual(params, ["user_id"])

    def test_normalize_openapi_path_unchanged(self):
        path = "/items/{item_id}"
        norm, params = ParameterInferrer.normalize_path(path)
        self.assertEqual(norm, "/items/{item_id}")
        self.assertEqual(params, ["item_id"])

    def test_normalize_mixed_path(self):
        path = "/api/v1/:org/repos/[repo_id]/<int:issue_id>"
        norm, params = ParameterInferrer.normalize_path(path)
        self.assertEqual(norm, "/api/v1/{org}/repos/{repo_id}/{issue_id}")
        self.assertEqual(params, ["org", "repo_id", "issue_id"])

    def test_normalize_empty_path(self):
        norm, params = ParameterInferrer.normalize_path("")
        self.assertEqual(norm, "/")
        self.assertEqual(params, [])

    def test_infer_param_schema_heuristics(self):
        # Heuristics: id, uuid, slug, date, page, limit, is_*, order
        self.assertEqual(ParameterInferrer.infer_param_schema("id", "path"), {"type": "integer"})
        self.assertEqual(ParameterInferrer.infer_param_schema("user_id", "path"), {"type": "integer"})
        self.assertEqual(ParameterInferrer.infer_param_schema("uuid", "path"), {"type": "string", "format": "uuid"})
        self.assertEqual(ParameterInferrer.infer_param_schema("user_uuid", "path"), {"type": "string", "format": "uuid"})
        self.assertEqual(ParameterInferrer.infer_param_schema("slug", "path"), {"type": "string"})
        self.assertEqual(ParameterInferrer.infer_param_schema("date", "query"), {"type": "string", "format": "date"})
        self.assertEqual(ParameterInferrer.infer_param_schema("start_date", "query"), {"type": "string", "format": "date"})
        self.assertEqual(ParameterInferrer.infer_param_schema("created_at", "query"), {"type": "string", "format": "date-time"})
        self.assertEqual(ParameterInferrer.infer_param_schema("timestamp", "query"), {"type": "string", "format": "date-time"})
        self.assertEqual(ParameterInferrer.infer_param_schema("page", "query"), {"type": "integer"})
        self.assertEqual(ParameterInferrer.infer_param_schema("limit", "query"), {"type": "integer"})
        self.assertEqual(ParameterInferrer.infer_param_schema("offset", "query"), {"type": "integer"})
        self.assertEqual(ParameterInferrer.infer_param_schema("per_page", "query"), {"type": "integer"})
        self.assertEqual(ParameterInferrer.infer_param_schema("is_active", "query"), {"type": "boolean"})
        self.assertEqual(ParameterInferrer.infer_param_schema("has_permission", "query"), {"type": "boolean"})
        self.assertEqual(ParameterInferrer.infer_param_schema("order", "query"), {"type": "string"})
        self.assertEqual(ParameterInferrer.infer_param_schema("sort", "query"), {"type": "string"})
        self.assertEqual(ParameterInferrer.infer_param_schema("random_query", "query"), {"type": "string"})

    def test_infer_param_schema_with_sample(self):
        # Sample value overrides or informs heuristic
        self.assertEqual(ParameterInferrer.infer_param_schema("id", "path", sample_val="550e8400-e29b-41d4-a716-446655440000"), {"type": "string", "format": "uuid"})
        self.assertEqual(ParameterInferrer.infer_param_schema("page", "query", sample_val=1), {"type": "integer"})
        self.assertEqual(ParameterInferrer.infer_param_schema("page", "query", sample_val="5"), {"type": "integer"})
        self.assertEqual(ParameterInferrer.infer_param_schema("flag", "query", sample_val="true"), {"type": "boolean"})
        self.assertEqual(ParameterInferrer.infer_param_schema("flag", "query", sample_val=False), {"type": "boolean"})


class TestPureYamlDumper(unittest.TestCase):
    """Tests for PureYamlDumper: zero-dependency YAML dumper and quoting rules."""

    def test_dump_status_code_keys_quoted(self):
        # Status codes ("200":, "404":, "500":) MUST be quoted
        data = {
            "responses": {
                "200": {"description": "OK"},
                "404": {"description": "Not Found"},
                "default": {"description": "Default"},
            }
        }
        yaml_str = PureYamlDumper.dump(data)
        self.assertIn('"200":', yaml_str)
        self.assertIn('"404":', yaml_str)
        # Verify it roundtrips with PyYAML safely
        parsed = yaml.safe_load(yaml_str)
        self.assertEqual(parsed, data)

    def test_dump_path_templates_with_braces_quoted(self):
        # Path templates ("/{id}":, "/users/{user_id}/items":) MUST be quoted
        data = {
            "paths": {
                "/{id}": {"get": {"summary": "Get one"}},
                "/users/{user_id}/items": {"post": {"summary": "Create item"}},
            }
        }
        yaml_str = PureYamlDumper.dump(data)
        self.assertIn('"/{id}":', yaml_str)
        self.assertIn('"/users/{user_id}/items":', yaml_str)
        parsed = yaml.safe_load(yaml_str)
        self.assertEqual(parsed, data)

    def test_dump_string_scalars_quoted(self):
        # String scalars "true", "false", "null" must be quoted to avoid boolean/null type conversion
        data = {
            "test_null_str": "null",
            "test_true_str": "true",
            "test_false_str": "false",
            "test_numeric_str": "200",
            "real_bool_true": True,
            "real_bool_false": False,
            "real_null": None,
        }
        yaml_str = PureYamlDumper.dump(data)
        self.assertIn('"null"', yaml_str)
        self.assertIn('"true"', yaml_str)
        self.assertIn('"false"', yaml_str)
        self.assertIn('"200"', yaml_str)

        parsed = yaml.safe_load(yaml_str)
        # Assert type fidelity in roundtrip
        self.assertIsInstance(parsed["test_null_str"], str)
        self.assertEqual(parsed["test_null_str"], "null")
        self.assertIsInstance(parsed["test_true_str"], str)
        self.assertEqual(parsed["test_true_str"], "true")
        self.assertIsInstance(parsed["test_false_str"], str)
        self.assertEqual(parsed["test_false_str"], "false")
        self.assertIsInstance(parsed["test_numeric_str"], str)
        self.assertEqual(parsed["test_numeric_str"], "200")
        self.assertIs(parsed["real_bool_true"], True)
        self.assertIs(parsed["real_bool_false"], False)
        self.assertIsNone(parsed["real_null"])

    def test_dump_complex_nested_structure(self):
        data = {
            "openapi": "3.1.0",
            "info": {"title": "Sample API", "version": "1.0.0"},
            "servers": [{"url": "https://api.example.com"}],
            "paths": {
                "/users/{id}": {
                    "get": {
                        "parameters": [
                            {"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}},
                            {"name": "fields", "in": "query", "required": False, "schema": {"type": "string"}},
                        ],
                        "responses": {
                            "200": {
                                "description": "OK",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "id": {"type": "integer"},
                                                "name": {"type": "string"},
                                                "deleted_at": {"type": ["string", "null"], "format": "date-time"},
                                            },
                                            "required": ["id", "name"],
                                        }
                                    }
                                },
                            }
                        },
                    }
                }
            },
        }
        yaml_str = PureYamlDumper.dump(data)
        parsed = yaml.safe_load(yaml_str)
        self.assertEqual(parsed, data)


class TestOpenAPIGenerator(unittest.TestCase):
    """Tests for OpenAPIGenerator: OpenAPI 3.1.0 compliance, path params, responses, requestBody, security."""

    def test_openapi_version_is_3_1_0(self):
        gen = OpenAPIGenerator(endpoints=[])
        spec = gen.generate()
        self.assertEqual(spec["openapi"], "3.1.0")
        self.assertIn("info", spec)
        self.assertIn("paths", spec)

    def test_mandate_required_true_for_path_params(self):
        # Path parameter MUST have required: true in OpenAPI 3.1.0 even if DiscoveredParameter had required=False
        ep = DiscoveredEndpoint(
            path="/users/:id",
            method="GET",
            parameters=[
                DiscoveredParameter(name="id", location="path", required=False),
            ],
            active_status=200,
        )
        gen = OpenAPIGenerator(endpoints=[ep])
        spec = gen.generate()
        op = spec["paths"]["/users/{id}"]["get"]
        param = next(p for p in op["parameters"] if p["name"] == "id" and p["in"] == "path")
        self.assertTrue(param["required"])

    def test_extracted_path_params_created_if_missing_from_endpoint(self):
        # If path has {id} but endpoint.parameters is empty, generator synthesizes it with required: True
        ep = DiscoveredEndpoint(
            path="/orders/:order_id/items/:item_id",
            method="GET",
            parameters=[],
            active_status=200,
        )
        gen = OpenAPIGenerator(endpoints=[ep])
        spec = gen.generate()
        op = spec["paths"]["/orders/{order_id}/items/{item_id}"]["get"]
        p_names = [p["name"] for p in op["parameters"]]
        self.assertIn("order_id", p_names)
        self.assertIn("item_id", p_names)
        for p in op["parameters"]:
            if p["in"] == "path":
                self.assertTrue(p["required"])
                self.assertIn("schema", p)

    def test_responses_populated_never_empty(self):
        # Empty responses must at least have default/200 response
        ep = DiscoveredEndpoint(
            path="/ping",
            method="GET",
            responses=[],
            active_status=None,
        )
        gen = OpenAPIGenerator(endpoints=[ep])
        spec = gen.generate()
        op = spec["paths"]["/ping"]["get"]
        self.assertTrue(len(op["responses"]) > 0)
        self.assertIn("200", op["responses"])

    def test_active_status_populates_response(self):
        ep = DiscoveredEndpoint(
            path="/secure/resource",
            method="GET",
            active_status=401,
        )
        gen = OpenAPIGenerator(endpoints=[ep])
        spec = gen.generate()
        op = spec["paths"]["/secure/resource"]["get"]
        self.assertIn("401", op["responses"])

    def test_request_body_generation_post_put_patch_delete(self):
        ep = DiscoveredEndpoint(
            path="/items",
            method="POST",
            request_body_sample={
                "title": "Widget",
                "price": 19.99,
                "in_stock": True,
            },
            responses=[DiscoveredResponse(status_code=201, sample_body={"id": 1, "title": "Widget"})],
        )
        gen = OpenAPIGenerator(endpoints=[ep])
        spec = gen.generate()
        op = spec["paths"]["/items"]["post"]
        self.assertIn("requestBody", op)
        self.assertTrue(op["requestBody"]["required"])
        content = op["requestBody"]["content"]["application/json"]
        schema = content["schema"]
        self.assertEqual(schema["type"], "object")
        self.assertIn("title", schema["properties"])
        self.assertIn("price", schema["properties"])
        self.assertIn("in_stock", schema["properties"])

    def test_security_schemes_bearer(self):
        ep = DiscoveredEndpoint(
            path="/api/profile",
            method="GET",
            auth_type="bearer",
            active_status=200,
        )
        gen = OpenAPIGenerator(endpoints=[ep])
        spec = gen.generate()
        self.assertIn("components", spec)
        self.assertIn("securitySchemes", spec["components"])
        self.assertIn("bearerAuth", spec["components"]["securitySchemes"])
        bearer_scheme = spec["components"]["securitySchemes"]["bearerAuth"]
        self.assertEqual(bearer_scheme["type"], "http")
        self.assertEqual(bearer_scheme["scheme"], "bearer")

        op = spec["paths"]["/api/profile"]["get"]
        self.assertEqual(op["security"], [{"bearerAuth": []}])

    def test_security_schemes_apikey(self):
        ep = DiscoveredEndpoint(
            path="/api/data",
            method="GET",
            auth_type="apikey",
            auth_header_or_param="X-Custom-Token",
            active_status=200,
        )
        gen = OpenAPIGenerator(endpoints=[ep])
        spec = gen.generate()
        self.assertIn("components", spec)
        self.assertIn("securitySchemes", spec["components"])
        self.assertIn("apiKeyAuth", spec["components"]["securitySchemes"])
        api_key_scheme = spec["components"]["securitySchemes"]["apiKeyAuth"]
        self.assertEqual(api_key_scheme["type"], "apiKey")
        self.assertEqual(api_key_scheme["name"], "X-Custom-Token")
        self.assertEqual(api_key_scheme["in"], "header")

        op = spec["paths"]["/api/data"]["get"]
        self.assertEqual(op["security"], [{"apiKeyAuth": []}])

    def test_to_json_and_to_yaml(self):
        ep = DiscoveredEndpoint(
            path="/status",
            method="GET",
            active_status=200,
        )
        gen = OpenAPIGenerator(endpoints=[ep], title="Status API")
        json_str = gen.to_json()
        parsed_json = json.loads(json_str)
        self.assertEqual(parsed_json["openapi"], "3.1.0")
        self.assertEqual(parsed_json["info"]["title"], "Status API")

        yaml_str = gen.to_yaml()
        parsed_yaml = yaml.safe_load(yaml_str)
        self.assertEqual(parsed_yaml["openapi"], "3.1.0")
        self.assertEqual(parsed_yaml["info"]["title"], "Status API")

    def test_export_file(self):
        temp_dir = tempfile.mkdtemp()
        try:
            ep = DiscoveredEndpoint(path="/test", method="GET", active_status=200)
            gen = OpenAPIGenerator(endpoints=[ep])

            json_path = os.path.join(temp_dir, "subdir", "openapi.json")
            yaml_path = os.path.join(temp_dir, "subdir", "openapi.yaml")

            gen.export_file(json_path, format="json")
            gen.export_file(yaml_path, format="yaml")

            self.assertTrue(os.path.exists(json_path))
            self.assertTrue(os.path.exists(yaml_path))

            with open(json_path, "r", encoding="utf-8") as f:
                json_data = json.load(f)
            self.assertEqual(json_data["openapi"], "3.1.0")

            with open(yaml_path, "r", encoding="utf-8") as f:
                yaml_data = yaml.safe_load(f)
            self.assertEqual(yaml_data["openapi"], "3.1.0")
        finally:
            shutil.rmtree(temp_dir)

    def test_scan_result_ingestion(self):
        ep1 = DiscoveredEndpoint(path="/users", method="GET", active_status=200)
        ep2 = DiscoveredEndpoint(path="/users", method="POST", active_status=201)
        sr = ScanResult(
            target_url="https://api.example.com",
            base_urls=["https://api.example.com/v1"],
            endpoints=[ep1, ep2],
        )
        gen = OpenAPIGenerator(endpoints=sr)
        spec = gen.generate()
        self.assertIn("/users", spec["paths"])
        self.assertIn("get", spec["paths"]["/users"])
    def test_security_schemes_basic_and_oauth2(self):
        ep_basic = DiscoveredEndpoint(path="/basic", method="GET", auth_type="basic", active_status=200)
        ep_oauth = DiscoveredEndpoint(path="/oauth", method="POST", auth_type="oauth2", active_status=200)
        gen = OpenAPIGenerator(endpoints=[ep_basic, ep_oauth])
        spec = gen.generate()
        self.assertIn("basicAuth", spec["components"]["securitySchemes"])
        self.assertIn("oauth2", spec["components"]["securitySchemes"])
        self.assertEqual(spec["components"]["securitySchemes"]["basicAuth"]["type"], "http")
        self.assertEqual(spec["components"]["securitySchemes"]["basicAuth"]["scheme"], "basic")
        self.assertEqual(spec["components"]["securitySchemes"]["oauth2"]["type"], "oauth2")

    def test_multiple_methods_on_same_path(self):
        ep_get = DiscoveredEndpoint(path="/api/items/:id", method="GET", active_status=200)
        ep_put = DiscoveredEndpoint(
            path="/api/items/:id",
            method="PUT",
            request_body_sample={"title": "Updated Item"},
            active_status=200,
        )
        ep_del = DiscoveredEndpoint(path="/api/items/:id", method="DELETE", active_status=204)
        gen = OpenAPIGenerator(endpoints=[ep_get, ep_put, ep_del])
        spec = gen.generate()
        self.assertIn("/api/items/{id}", spec["paths"])
        item_path = spec["paths"]["/api/items/{id}"]
        self.assertIn("get", item_path)
        self.assertIn("put", item_path)
        self.assertIn("delete", item_path)
        self.assertIn("requestBody", item_path["put"])
        self.assertIn("204", item_path["delete"]["responses"])

    def test_merge_multiple_endpoint_observations_same_path_method(self):
        ep1 = DiscoveredEndpoint(
            path="/api/v1/users/:id",
            method="GET",
            responses=[
                DiscoveredResponse(
                    status_code=200,
                    sample_body={"id": 1, "username": "alice", "email": "alice@test.com"},
                )
            ],
        )
        ep2 = DiscoveredEndpoint(
            path="/api/v1/users/:id",
            method="GET",
            responses=[
                DiscoveredResponse(
                    status_code=200,
                    sample_body={
                        "id": 2,
                        "username": "bob",
                        "email": "bob@test.com",
                        "avatar_url": "https://example.com/avatar.png",
                    },
                ),
                DiscoveredResponse(
                    status_code=404,
                    sample_body={"error": "Not Found"},
                ),
            ],
        )
        gen = OpenAPIGenerator(endpoints=[ep1, ep2])
        spec = gen.generate()
        op = spec["paths"]["/api/v1/users/{id}"]["get"]
        self.assertIn("200", op["responses"])
        self.assertIn("404", op["responses"])
        resp_200_schema = op["responses"]["200"]["content"]["application/json"]["schema"]
        self.assertEqual(resp_200_schema["type"], "object")
        # avatar_url was in ep2 but not ep1, so required is only id, username, email
        self.assertEqual(resp_200_schema["required"], ["email", "id", "username"])
        self.assertIn("avatar_url", resp_200_schema["properties"])

    def test_request_body_from_body_parameters(self):
        ep = DiscoveredEndpoint(
            path="/api/login",
            method="POST",
            parameters=[
                DiscoveredParameter(name="username", location="body", required=True, example="user1"),
                DiscoveredParameter(name="password", location="body", required=True, example="pass123"),
                DiscoveredParameter(name="remember_me", location="body", required=False, example=True),
            ],
            active_status=200,
        )
        gen = OpenAPIGenerator(endpoints=[ep])
        spec = gen.generate()
        op = spec["paths"]["/api/login"]["post"]
        self.assertIn("requestBody", op)
        schema = op["requestBody"]["content"]["application/json"]["schema"]
        self.assertEqual(schema["type"], "object")
        self.assertEqual(schema["required"], ["password", "username"])
        self.assertEqual(schema["properties"]["remember_me"], {"type": "boolean"})

    def test_yaml_dumper_scalar_edge_cases(self):
        data = {
            "empty_str": "",
            "multiline": "line one\nline two\nline three",
            "escaped_quote": 'He said "Hello"',
            "special_symbols": "foo: bar # not a comment",
            "nested_empty_list": [],
            "nested_empty_dict": {},
        }
        yaml_out = PureYamlDumper.dump(data)
        parsed = yaml.safe_load(yaml_out)
        self.assertEqual(parsed, data)


if __name__ == "__main__":
    unittest.main()

