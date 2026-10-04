"""
Tests for HAR 1.2 Ingestion Engine (HARImporter).
Verifies HAR log parsing, static asset filtering, tracking domain rejection,
authentication extraction, OpenAPI 3.1.0 schema inference, embedded GraphQL detection,
multi-request endpoint merging, and model serialization roundtrips.
"""

import base64
import json
import os
import tempfile
import unittest

from api_tool.importer import HARImporter
from api_tool.models import (
    DiscoveredEndpoint,
    DiscoveredParameter,
    DiscoveredResponse,
    GraphQLOperation,
    ScanResult,
)


class TestHARImporter(unittest.TestCase):
    def setUp(self) -> None:
        self.importer = HARImporter()

    def test_import_json_basic_get_and_post(self) -> None:
        sample_har = {
            "log": {
                "version": "1.2",
                "creator": {"name": "BrowserAgent", "version": "1.0"},
                "pages": [
                    {
                        "id": "page_1",
                        "title": "https://api.example.com/app",
                        "startedDateTime": "2026-10-03T12:00:00.000Z",
                    }
                ],
                "entries": [
                    {
                        "startedDateTime": "2026-10-03T12:00:01.000Z",
                        "request": {
                            "method": "GET",
                            "url": "https://api.example.com/api/v1/users?page=1&limit=20",
                            "headers": [
                                {"name": "Authorization", "value": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-ID"},
                                {"name": "Accept", "value": "application/json"},
                            ],
                            "queryString": [
                                {"name": "page", "value": "1"},
                                {"name": "limit", "value": "20"},
                            ],
                            "cookies": [],
                            "headersSize": -1,
                            "bodySize": 0,
                        },
                        "response": {
                            "status": 200,
                            "statusText": "OK",
                            "headers": [
                                {"name": "Content-Type", "value": "application/json; charset=utf-8"}
                            ],
                            "content": {
                                "mimeType": "application/json",
                                "text": json.dumps({
                                    "data": [
                                        {"id": 1, "username": "alice", "active": True}
                                    ],
                                    "total": 1,
                                }),
                            },
                        },
                    },
                    {
                        "startedDateTime": "2026-10-03T12:00:02.000Z",
                        "request": {
                            "method": "POST",
                            "url": "https://api.example.com/api/v1/users",
                            "headers": [
                                {"name": "Authorization", "value": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-ID"},
                                {"name": "Content-Type", "value": "application/json"},
                            ],
                            "postData": {
                                "mimeType": "application/json",
                                "text": json.dumps({
                                    "username": "bob",
                                    "email": "bob@example.com",
                                    "role": "editor",
                                }),
                            },
                            "queryString": [],
                            "cookies": [],
                        },
                        "response": {
                            "status": 201,
                            "statusText": "Created",
                            "headers": [
                                {"name": "Content-Type", "value": "application/json"}
                            ],
                            "content": {
                                "mimeType": "application/json",
                                "text": json.dumps({
                                    "id": 2,
                                    "username": "bob",
                                    "email": "bob@example.com",
                                    "role": "editor",
                                    "created_at": "2026-10-03T12:00:02Z",
                                }),
                            },
                        },
                    },
                ],
            }
        }

        result = self.importer.import_json(sample_har)
        self.assertIsInstance(result, ScanResult)
        self.assertEqual(result.target_url, "https://api.example.com/app")
        self.assertIn("https://api.example.com", result.base_urls)
        self.assertEqual(len(result.endpoints), 2)

        # Validate GET endpoint
        get_ep = next((e for e in result.endpoints if e.method == "GET"), None)
        self.assertIsNotNone(get_ep)
        self.assertEqual(get_ep.path, "/api/v1/users")
        self.assertEqual(get_ep.auth_type, "bearer")
        self.assertEqual(get_ep.auth_header_or_param, "Authorization")
        param_names = {p.name for p in get_ep.parameters}
        self.assertIn("page", param_names)
        self.assertIn("limit", param_names)
        self.assertEqual(len(get_ep.responses), 1)
        self.assertEqual(get_ep.responses[0].status_code, 200)
        schema = get_ep.responses[0].inferred_schema
        self.assertIsNotNone(schema)
        self.assertEqual(schema.get("type"), "object")
        self.assertIn("data", schema.get("properties", {}))

        # Validate POST endpoint
        post_ep = next((e for e in result.endpoints if e.method == "POST"), None)
        self.assertIsNotNone(post_ep)
        self.assertEqual(post_ep.path, "/api/v1/users")
        self.assertEqual(post_ep.auth_type, "bearer")
        req_schema = post_ep.request_body_schema
        self.assertIsNotNone(req_schema)
        self.assertEqual(req_schema.get("type"), "object")
        self.assertIn("username", req_schema.get("properties", {}))
        self.assertIn("email", req_schema.get("properties", {}))

        resp_schema = post_ep.responses[0].inferred_schema
        self.assertIsNotNone(resp_schema)
        self.assertIn("created_at", resp_schema.get("properties", {}))
        self.assertEqual(resp_schema["properties"]["created_at"].get("format"), "date-time")

    def test_static_asset_filtering(self) -> None:
        har = {
            "log": {
                "version": "1.2",
                "entries": [
                    {
                        "request": {"method": "GET", "url": "https://example.com/static/logo.png"},
                        "response": {"status": 200, "content": {"mimeType": "image/png"}},
                    },
                    {
                        "request": {"method": "GET", "url": "https://example.com/assets/style.css"},
                        "response": {"status": 200, "content": {"mimeType": "text/css"}},
                    },
                    {
                        "request": {"method": "GET", "url": "https://example.com/fonts/inter.woff2"},
                        "response": {"status": 200, "content": {"mimeType": "font/woff2"}},
                    },
                    {
                        "request": {"method": "GET", "url": "https://example.com/static/icon.svg"},
                        "response": {"status": 200, "content": {"mimeType": "image/svg+xml"}},
                    },
                    {
                        "request": {"method": "GET", "url": "https://example.com/bundle.js"},
                        "response": {"status": 200, "content": {"mimeType": "application/javascript"}},
                    },
                    {
                        "request": {"method": "GET", "url": "https://example.com/api/status"},
                        "response": {"status": 200, "content": {"mimeType": "application/json", "text": "{\"ok\": true}"}},
                    },
                ],
            }
        }

        result = self.importer.import_json(har)
        self.assertEqual(len(result.endpoints), 1)
        self.assertEqual(result.endpoints[0].path, "/api/status")
        self.assertEqual(result.metadata.get("filtered_static_entries"), 5)

    def test_tracking_domain_filtering(self) -> None:
        har = {
            "log": {
                "version": "1.2",
                "entries": [
                    {
                        "request": {"method": "POST", "url": "https://www.google-analytics.com/g/collect"},
                        "response": {"status": 204, "content": {}},
                    },
                    {
                        "request": {"method": "POST", "url": "https://o1234.ingest.sentry.io/api/5678/envelope/"},
                        "response": {"status": 200, "content": {}},
                    },
                    {
                        "request": {"method": "POST", "url": "https://browser-http-intake.logs.datadoghq.com/v1/input"},
                        "response": {"status": 200, "content": {}},
                    },
                    {
                        "request": {"method": "GET", "url": "https://api.myservice.com/v1/metrics"},
                        "response": {"status": 200, "content": {"mimeType": "application/json", "text": "{\"cpu\": 20}"}},
                    },
                ],
            }
        }

        result = self.importer.import_json(har)
        self.assertEqual(len(result.endpoints), 1)
        self.assertEqual(result.endpoints[0].base_url, "https://api.myservice.com")
        self.assertEqual(result.metadata.get("filtered_tracker_entries"), 3)

    def test_auth_extraction_all_types(self) -> None:
        # 1. Bearer Auth
        har_bearer = {
            "log": {
                "entries": [
                    {
                        "request": {
                            "method": "GET",
                            "url": "https://example.com/api/bearer-test",
                            "headers": [{"name": "Authorization", "value": "Bearer token123"}],
                        },
                        "response": {"status": 200, "content": {}},
                    }
                ]
            }
        }
        res_bearer = self.importer.import_json(har_bearer)
        self.assertEqual(res_bearer.endpoints[0].auth_type, "bearer")
        self.assertEqual(res_bearer.endpoints[0].auth_header_or_param, "Authorization")

        # 2. Basic Auth
        har_basic = {
            "log": {
                "entries": [
                    {
                        "request": {
                            "method": "GET",
                            "url": "https://example.com/api/basic-test",
                            "headers": [{"name": "Authorization", "value": "Basic dXNlcjpwYXNz"}],
                        },
                        "response": {"status": 200, "content": {}},
                    }
                ]
            }
        }
        res_basic = self.importer.import_json(har_basic)
        self.assertEqual(res_basic.endpoints[0].auth_type, "basic")
        self.assertEqual(res_basic.endpoints[0].auth_header_or_param, "Authorization")

        # 3. API Key Header
        har_apikey = {
            "log": {
                "entries": [
                    {
                        "request": {
                            "method": "GET",
                            "url": "https://example.com/api/key-test",
                            "headers": [{"name": "X-API-Key", "value": "secret-abc-123"}],
                        },
                        "response": {"status": 200, "content": {}},
                    }
                ]
            }
        }
        res_apikey = self.importer.import_json(har_apikey)
        self.assertEqual(res_apikey.endpoints[0].auth_type, "apikey")
        self.assertEqual(res_apikey.endpoints[0].auth_header_or_param, "X-API-Key")

        # 4. Session Cookie
        har_cookie = {
            "log": {
                "entries": [
                    {
                        "request": {
                            "method": "GET",
                            "url": "https://example.com/api/cookie-test",
                            "cookies": [{"name": "session_id", "value": "sess_999888"}],
                        },
                        "response": {"status": 200, "content": {}},
                    }
                ]
            }
        }
        res_cookie = self.importer.import_json(har_cookie)
        self.assertEqual(res_cookie.endpoints[0].auth_type, "cookie")
        self.assertEqual(res_cookie.endpoints[0].auth_header_or_param, "session_id")

    def test_graphql_operation_detection(self) -> None:
        har = {
            "log": {
                "entries": [
                    # Standard POST /graphql
                    {
                        "request": {
                            "method": "POST",
                            "url": "https://api.example.com/graphql",
                            "headers": [{"name": "Content-Type", "value": "application/json"}],
                            "postData": {
                                "mimeType": "application/json",
                                "text": json.dumps({
                                    "operationName": "GetViewer",
                                    "query": "query GetViewer { viewer { id name email } }",
                                    "variables": {"includeEmail": True},
                                }),
                            },
                        },
                        "response": {
                            "status": 200,
                            "content": {
                                "mimeType": "application/json",
                                "text": json.dumps({"data": {"viewer": {"id": "1", "name": "Admin"}}}),
                            },
                        },
                    },
                    # Non-standard path with embedded mutation query
                    {
                        "request": {
                            "method": "POST",
                            "url": "https://api.example.com/api/proxy",
                            "headers": [{"name": "Content-Type", "value": "application/json"}],
                            "postData": {
                                "mimeType": "application/json",
                                "text": json.dumps({
                                    "query": "mutation AddItem($title: String!) { addItem(title: $title) { id } }",
                                    "variables": {"title": "Test Book"},
                                }),
                            },
                        },
                        "response": {
                            "status": 200,
                            "content": {"mimeType": "application/json", "text": "{\"data\": {\"addItem\": {\"id\": 10}}}"},
                        },
                    },
                    # GET request to /graphql with query param
                    {
                        "request": {
                            "method": "GET",
                            "url": "https://api.example.com/graphql?query=%7Bschema%7D",
                            "queryString": [{"name": "query", "value": "{ schema }"}],
                        },
                        "response": {"status": 200, "content": {}},
                    },
                ]
            }
        }

        result = self.importer.import_json(har)
        self.assertGreaterEqual(len(result.graphql_operations), 3)

        op_names = {op.operation_name for op in result.graphql_operations}
        self.assertIn("GetViewer", op_names)
        self.assertIn("AddItem", op_names)

        op_get_viewer = next(op for op in result.graphql_operations if op.operation_name == "GetViewer")
        self.assertEqual(op_get_viewer.operation_type, "query")
        self.assertEqual(op_get_viewer.endpoint, "/graphql")
        self.assertEqual(op_get_viewer.variables_sample, {"includeEmail": True})

        op_add_item = next(op for op in result.graphql_operations if op.operation_name == "AddItem")
        self.assertEqual(op_add_item.operation_type, "mutation")
        self.assertEqual(op_add_item.endpoint, "/api/proxy")

        # Endpoint has graphql tag
        graphql_ep = next((e for e in result.endpoints if e.path == "/graphql"), None)
        self.assertIsNotNone(graphql_ep)
        self.assertIn("graphql", graphql_ep.tags)

    def test_multi_request_endpoint_merging(self) -> None:
        har = {
            "log": {
                "entries": [
                    # Call 1: GET /items with limit=10, returns 200 with items array
                    {
                        "request": {
                            "method": "GET",
                            "url": "https://api.example.com/items?limit=10",
                            "headers": [{"name": "X-Client-Version", "value": "1.0.0"}],
                            "queryString": [{"name": "limit", "value": "10"}],
                        },
                        "response": {
                            "status": 200,
                            "headers": [{"name": "ETag", "value": "w123"}],
                            "content": {
                                "mimeType": "application/json",
                                "text": json.dumps({
                                    "items": [{"id": 1, "name": "Apple"}],
                                }),
                            },
                        },
                    },
                    # Call 2: GET /items with sort=asc, returns 200 with extra price field & total
                    {
                        "request": {
                            "method": "GET",
                            "url": "https://api.example.com/items?sort=asc",
                            "headers": [{"name": "X-Request-Trace", "value": "trace-99"}],
                            "queryString": [{"name": "sort", "value": "asc"}],
                        },
                        "response": {
                            "status": 200,
                            "headers": [{"name": "X-Cache", "value": "HIT"}],
                            "content": {
                                "mimeType": "application/json",
                                "text": json.dumps({
                                    "items": [{"id": 2, "name": "Banana", "price": 1.99}],
                                    "total": 2,
                                }),
                            },
                        },
                    },
                    # Call 3: GET /items with invalid param, returns 400
                    {
                        "request": {
                            "method": "GET",
                            "url": "https://api.example.com/items?limit=-1",
                            "headers": [],
                            "queryString": [{"name": "limit", "value": "-1"}],
                        },
                        "response": {
                            "status": 400,
                            "content": {
                                "mimeType": "application/json",
                                "text": json.dumps({"error": "Invalid limit parameter"}),
                            },
                        },
                    },
                ]
            }
        }

        result = self.importer.import_json(har)
        # All 3 requests should be merged into exactly ONE endpoint
        self.assertEqual(len(result.endpoints), 1)
        ep = result.endpoints[0]
        self.assertEqual(ep.path, "/items")
        self.assertEqual(ep.method, "GET")

        # Parameters should be aggregated (limit, sort)
        param_names = {p.name for p in ep.parameters}
        self.assertEqual(param_names, {"limit", "sort"})

        # Request headers should be aggregated
        self.assertIn("X-Client-Version", ep.headers)
        self.assertIn("X-Request-Trace", ep.headers)

        # Responses should contain both 200 and 400
        status_codes = [r.status_code for r in ep.responses]
        self.assertEqual(status_codes, [200, 400])

        # 200 response should have merged schema combining both observations
        r200 = next(r for r in ep.responses if r.status_code == 200)
        schema_props = r200.inferred_schema.get("properties", {})
        self.assertIn("items", schema_props)
        self.assertIn("total", schema_props)

        item_props = schema_props["items"].get("items", {}).get("properties", {})
        self.assertIn("id", item_props)
        self.assertIn("name", item_props)
        self.assertIn("price", item_props)

        # 400 response schema
        r400 = next(r for r in ep.responses if r.status_code == 400)
        self.assertIn("error", r400.inferred_schema.get("properties", {}))

    def test_base64_encoded_response(self) -> None:
        json_body = json.dumps({"message": "Hello from encoded HAR", "code": 42})
        b64_body = base64.b64encode(json_body.encode("utf-8")).decode("utf-8")

        har = {
            "log": {
                "entries": [
                    {
                        "request": {"method": "GET", "url": "https://api.example.com/b64-test"},
                        "response": {
                            "status": 200,
                            "content": {
                                "mimeType": "application/json",
                                "encoding": "base64",
                                "text": b64_body,
                            },
                        },
                    }
                ]
            }
        }

        result = self.importer.import_json(har)
        self.assertEqual(len(result.endpoints), 1)
        resp = result.endpoints[0].responses[0]
        self.assertEqual(resp.sample_body.get("code"), 42)
        self.assertIn("message", resp.inferred_schema.get("properties", {}))

    def test_import_file_from_disk(self) -> None:
        har_payload = {
            "log": {
                "version": "1.2",
                "entries": [
                    {
                        "request": {"method": "GET", "url": "https://example.com/api/file-test"},
                        "response": {"status": 200, "content": {"mimeType": "application/json", "text": "{\"ok\": true}"}},
                    }
                ]
            }
        }
        with tempfile.NamedTemporaryFile("w", suffix=".har", delete=False) as tf:
            tf.write(json.dumps(har_payload))
            temp_path = tf.name

        try:
            result = self.importer.import_file(temp_path)
            self.assertEqual(len(result.endpoints), 1)
            self.assertEqual(result.endpoints[0].path, "/api/file-test")
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_models_from_dict_and_to_dict_symmetry(self) -> None:
        p = DiscoveredParameter(name="page", location="query", required=True, param_type="integer", example=1)
        p_dict = p.to_dict()
        p_restored = DiscoveredParameter.from_dict(p_dict)
        self.assertEqual(p_restored.name, "page")
        self.assertEqual(p_restored.location, "query")
        self.assertTrue(p_restored.required)
        self.assertEqual(p_restored.example, 1)

        r = DiscoveredResponse(status_code=200, content_type="application/json", headers={"X-A": "1"}, sample_body={"ok": True})
        r_dict = r.to_dict()
        r_restored = DiscoveredResponse.from_dict(r_dict)
        self.assertEqual(r_restored.status_code, 200)
        self.assertEqual(r_restored.headers.get("X-A"), "1")
        self.assertEqual(r_restored.sample_body, {"ok": True})

        ep = DiscoveredEndpoint(
            path="/api/test",
            method="POST",
            base_url="https://api.example.com",
            parameters=[p],
            responses=[r],
            auth_type="bearer",
            auth_header_or_param="Authorization",
        )
        ep_dict = ep.to_dict()
        ep_restored = DiscoveredEndpoint.from_dict(ep_dict)
        self.assertEqual(ep_restored.path, "/api/test")
        self.assertEqual(ep_restored.method, "POST")
        self.assertEqual(len(ep_restored.parameters), 1)
        self.assertEqual(ep_restored.parameters[0].name, "page")
        self.assertEqual(len(ep_restored.responses), 1)
        self.assertEqual(ep_restored.responses[0].status_code, 200)

        gql = GraphQLOperation(
            operation_type="query",
            operation_name="GetUser",
            query_string="query GetUser { user { id } }",
            endpoint="/graphql",
            variables_sample={"id": 1},
        )
        gql_dict = gql.to_dict()
        gql_restored = GraphQLOperation.from_dict(gql_dict)
        self.assertEqual(gql_restored.operation_name, "GetUser")
        self.assertEqual(gql_restored.variables_sample, {"id": 1})

        scan = ScanResult(
            target_url="https://api.example.com",
            base_urls=["https://api.example.com"],
            endpoints=[ep],
            graphql_operations=[gql],
            discovered_specs=["https://api.example.com/openapi.json"],
        )
        scan_dict = scan.to_dict()
        scan_restored = ScanResult.from_dict(scan_dict)
        self.assertEqual(scan_restored.target_url, "https://api.example.com")
        self.assertEqual(len(scan_restored.endpoints), 1)
        self.assertEqual(len(scan_restored.graphql_operations), 1)
        self.assertEqual(scan_restored.endpoints[0].path, "/api/test")

        # Test from_json roundtrip
        json_str = scan.to_json()
        scan_json_restored = ScanResult.from_json(json_str)
        self.assertEqual(scan_json_restored.target_url, "https://api.example.com")
        self.assertEqual(len(scan_json_restored.endpoints), 1)


if __name__ == "__main__":
    unittest.main()
