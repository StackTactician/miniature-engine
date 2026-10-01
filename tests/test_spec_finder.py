"""
Tests for api_tool.prober.spec_finder:
- DiscoveredSpec serialization
- Candidate paths coverage (60+ paths)
- HTML spec URL extraction (Swagger UI, Redoc, Scalar, RapiDoc, Elements, link tags)
- OpenAPI 3.0, 3.1 & Swagger 2.0 JSON/YAML parsing
- Endpoint, parameter, request body, response, and security extraction
- Async candidate probing with MockTransport (simulating specs, HTML docs, SpringDoc configs, 404s, timeouts)
"""

import asyncio
import json
import unittest
from typing import Any, Dict

import httpx

from api_tool.models import (
    DiscoveredEndpoint,
    DiscoveredParameter,
    DiscoveredResponse,
    DiscoveredSpec as ModelDiscoveredSpec,
    SpecFinder as ModelSpecFinder,
)
from api_tool.prober.spec_finder import DiscoveredSpec, SpecFinder


class TestDiscoveredSpecDataclass(unittest.TestCase):
    """Test DiscoveredSpec data structures and serialization."""

    def test_spec_model_imports_and_parity(self):
        self.assertIs(DiscoveredSpec, ModelDiscoveredSpec)
        self.assertIs(SpecFinder, ModelSpecFinder)

    def test_discovered_spec_to_dict(self):
        endpoint = DiscoveredEndpoint(
            path="/users/{id}",
            method="GET",
            base_url="https://api.example.com",
            source="spec",
            summary="Get user",
            parameters=[
                DiscoveredParameter(name="id", location="path", required=True, param_type="integer")
            ],
            responses=[
                DiscoveredResponse(status_code=200, content_type="application/json")
            ],
        )

        spec = DiscoveredSpec(
            url="https://api.example.com/openapi.json",
            spec_type="openapi_3",
            title="User API",
            version="1.0.0",
            raw_spec={"openapi": "3.0.0"},
            endpoints=[endpoint],
        )

        d = spec.to_dict()
        self.assertEqual(d["url"], "https://api.example.com/openapi.json")
        self.assertEqual(d["spec_type"], "openapi_3")
        self.assertEqual(d["title"], "User API")
        self.assertEqual(d["version"], "1.0.0")
        self.assertEqual(len(d["endpoints"]), 1)
        self.assertEqual(d["endpoints"][0]["path"], "/users/{id}")
        self.assertEqual(d["endpoints"][0]["full_url"], "https://api.example.com/users/{id}")
        self.assertEqual(d["endpoints"][0]["method"], "GET")
        self.assertEqual(len(d["endpoints"][0]["parameters"]), 1)
        self.assertEqual(d["endpoints"][0]["parameters"][0]["name"], "id")


class TestCandidatePaths(unittest.TestCase):
    """Verify candidate paths definition and breadth."""

    def test_candidate_paths_count_and_coverage(self):
        paths = SpecFinder.CANDIDATE_PATHS
        self.assertGreaterEqual(len(paths), 60)

        required_examples = [
            "/openapi.json",
            "/openapi.yaml",
            "/v3/api-docs",
            "/v3/api-docs/swagger-config",
            "/swagger.json",
            "/swagger/v1/swagger.json",
            "/api-docs",
            "/api/openapi.json",
            "/docs/openapi.json",
            "/swagger/doc.json",
            "/api/docs/swagger.json",
            "/redoc",
            "/scalar",
            "/docs",
            "/swagger-ui.html",
            "/swagger-ui/index.html",
        ]
        for req in required_examples:
            self.assertIn(req, paths, f"Missing required candidate path: {req}")


class TestHTMLExtraction(unittest.TestCase):
    """Test extracting embedded specification URLs from HTML documentation engines."""

    def setUp(self):
        self.finder = SpecFinder()
        self.base_url = "https://example.com/docs/"

    def test_extract_swagger_ui_bundle_single_url(self):
        html = """
        <html>
        <body>
        <script>
            window.ui = SwaggerUIBundle({
                url: "/api/v1/openapi.json",
                dom_id: '#swagger-ui'
            });
        </script>
        </body>
        </html>
        """
        urls = self.finder.extract_spec_url_from_html(html, self.base_url)
        self.assertIn("https://example.com/api/v1/openapi.json", urls)

    def test_extract_swagger_ui_urls_array(self):
        html = """
        <script>
            SwaggerUIBundle({
                urls: [
                    {url: "/v3/api-docs/public", name: "Public"},
                    {url: "/v3/api-docs/private", name: "Private"}
                ]
            });
        </script>
        """
        urls = self.finder.extract_spec_url_from_html(html, self.base_url)
        self.assertIn("https://example.com/v3/api-docs/public", urls)
        self.assertIn("https://example.com/v3/api-docs/private", urls)

    def test_extract_redoc_tag_and_init(self):
        html_tag = '<redoc spec-url="/redoc/spec.yaml"></redoc>'
        urls = self.finder.extract_spec_url_from_html(html_tag, self.base_url)
        self.assertIn("https://example.com/redoc/spec.yaml", urls)

        html_init = "<script>Redoc.init('/static/openapi.json', {}, document.getElementById('redoc'))</script>"
        urls_init = self.finder.extract_spec_url_from_html(html_init, self.base_url)
        self.assertIn("https://example.com/static/openapi.json", urls_init)

    def test_extract_scalar_configurations(self):
        # 1. Scalar data-configuration attribute
        html_cfg = '<div id="scalar" data-configuration=\'{"spec": {"url": "/scalar/spec.json"}}\'></div>'
        urls_cfg = self.finder.extract_spec_url_from_html(html_cfg, self.base_url)
        self.assertIn("https://example.com/scalar/spec.json", urls_cfg)

        # 2. Scalar script tag with data-url
        html_script = '<script id="api-reference" data-url="/api/scalar.json"></script>'
        urls_script = self.finder.extract_spec_url_from_html(html_script, self.base_url)
        self.assertIn("https://example.com/api/scalar.json", urls_script)

        # 3. Scalar createApiReference in JavaScript
        html_js = """
        <script>
            Scalar.createApiReference(document.getElementById('app'), {
                url: '/docs/spec.yaml'
            });
        </script>
        """
        urls_js = self.finder.extract_spec_url_from_html(html_js, self.base_url)
        self.assertIn("https://example.com/docs/spec.yaml", urls_js)

    def test_extract_rapidoc_and_elements(self):
        html = """
        <rapi-doc spec-url="/rapidoc/swagger.json"></rapi-doc>
        <elements-api apiDescriptionUrl="/elements/openapi.json" router="hash" />
        """
        urls = self.finder.extract_spec_url_from_html(html, self.base_url)
        self.assertIn("https://example.com/rapidoc/swagger.json", urls)
        self.assertIn("https://example.com/elements/openapi.json", urls)

    def test_extract_link_alternate_tags(self):
        html = """
        <head>
            <link rel="alternate" type="application/openapi+json" href="/specs/v1.json">
            <link rel="service-desc" type="application/json" href="/specs/desc.json">
            <link rel="stylesheet" href="/style.css">
        </head>
        """
        urls = self.finder.extract_spec_url_from_html(html, self.base_url)
        self.assertIn("https://example.com/specs/v1.json", urls)
        self.assertIn("https://example.com/specs/desc.json", urls)
        self.assertNotIn("https://example.com/style.css", urls)


class TestSpecParsing(unittest.TestCase):
    """Test OpenAPI 3.x and Swagger 2.0 specification parsing."""

    def setUp(self):
        self.finder = SpecFinder()

    def test_parse_openapi_3_json(self):
        raw = {
            "openapi": "3.0.1",
            "info": {
                "title": "Inventory API",
                "version": "1.2.3",
                "description": "Store inventory management",
            },
            "servers": [{"url": "https://api.store.com/v1"}],
            "components": {
                "securitySchemes": {
                    "BearerToken": {"type": "http", "scheme": "bearer"},
                    "ApiKeyHeader": {"type": "apiKey", "name": "X-API-KEY", "in": "header"},
                }
            },
            "paths": {
                "/items": {
                    "parameters": [
                        {"name": "X-Tenant-ID", "in": "header", "required": True, "schema": {"type": "string"}}
                    ],
                    "get": {
                        "tags": ["items"],
                        "summary": "List items",
                        "security": [{"ApiKeyHeader": []}],
                        "parameters": [
                            {"name": "category", "in": "query", "required": False, "schema": {"type": "string"}, "example": "books"},
                            {"name": "limit", "in": "query", "schema": {"type": "integer"}, "example": 50},
                        ],
                        "responses": {
                            "200": {
                                "description": "Success",
                                "content": {
                                    "application/json": {
                                        "schema": {"type": "array"},
                                        "example": [{"id": 1, "name": "Book A"}],
                                    }
                                },
                            }
                        },
                    },
                    "post": {
                        "tags": ["items"],
                        "summary": "Create item",
                        "security": [{"BearerToken": []}],
                        "requestBody": {
                            "description": "New item payload",
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {"type": "object", "properties": {"name": {"type": "string"}}},
                                    "example": {"name": "New Book"},
                                }
                            },
                        },
                        "responses": {
                            "201": {"description": "Created"},
                            "400": {"description": "Bad Request"},
                        },
                    },
                }
            },
        }

        spec = self.finder.parse_openapi_spec(json.dumps(raw), spec_url="https://api.store.com/openapi.json")
        self.assertEqual(spec.spec_type, "openapi_3")
        self.assertEqual(spec.title, "Inventory API")
        self.assertEqual(spec.version, "1.2.3")
        self.assertEqual(len(spec.endpoints), 2)

        # Validate GET /items
        get_ep = next(e for e in spec.endpoints if e.method == "GET")
        self.assertEqual(get_ep.path, "/items")
        self.assertEqual(get_ep.base_url, "https://api.store.com/v1")
        self.assertEqual(get_ep.full_url, "https://api.store.com/v1/items")
        self.assertEqual(get_ep.auth_type, "apikey")
        self.assertEqual(get_ep.auth_header_or_param, "X-API-KEY")
        self.assertIn("items", get_ep.tags)

        # Check parameters (header + query)
        params_by_name = {p.name: p for p in get_ep.parameters}
        self.assertIn("X-Tenant-ID", params_by_name)
        self.assertEqual(params_by_name["X-Tenant-ID"].location, "header")
        self.assertTrue(params_by_name["X-Tenant-ID"].required)
        self.assertIn("category", params_by_name)
        self.assertEqual(params_by_name["category"].example, "books")

        # Check responses
        self.assertEqual(len(get_ep.responses), 1)
        self.assertEqual(get_ep.responses[0].status_code, 200)
        self.assertEqual(get_ep.responses[0].sample_body, [{"id": 1, "name": "Book A"}])

        # Validate POST /items
        post_ep = next(e for e in spec.endpoints if e.method == "POST")
        self.assertEqual(post_ep.auth_type, "bearer")
        self.assertEqual(post_ep.auth_header_or_param, "Authorization")
        self.assertIsNotNone(post_ep.request_body_schema)
        self.assertEqual(post_ep.request_body_sample, {"name": "New Book"})
        body_param = next(p for p in post_ep.parameters if p.location == "body")
        self.assertTrue(body_param.required)

    def test_parse_swagger_2_json(self):
        raw = {
            "swagger": "2.0",
            "info": {
                "title": "Legacy Petstore",
                "version": "2.0.0",
            },
            "host": "petstore.example.com",
            "basePath": "/v2",
            "schemes": ["https"],
            "securityDefinitions": {
                "basicAuth": {"type": "basic"},
            },
            "paths": {
                "/pet/{petId}": {
                    "get": {
                        "tags": ["pet"],
                        "summary": "Find pet",
                        "security": [{"basicAuth": []}],
                        "parameters": [
                            {
                                "name": "petId",
                                "in": "path",
                                "required": True,
                                "type": "integer",
                                "description": "Pet ID",
                            }
                        ],
                        "responses": {
                            "200": {
                                "description": "OK",
                                "schema": {"type": "object"},
                            }
                        },
                    },
                    "delete": {
                        "tags": ["pet"],
                        "summary": "Delete pet",
                        "parameters": [
                            {"name": "petId", "in": "path", "required": True, "type": "integer"},
                            {"name": "api_key", "in": "header", "required": False, "type": "string"},
                        ],
                        "responses": {"204": {"description": "Deleted"}},
                    },
                }
            },
        }

        spec = self.finder.parse_openapi_spec(raw, spec_url="https://petstore.example.com/v2/swagger.json")
        self.assertEqual(spec.spec_type, "openapi_2")
        self.assertEqual(spec.title, "Legacy Petstore")
        self.assertEqual(spec.version, "2.0.0")
        self.assertEqual(len(spec.endpoints), 2)

        get_ep = next(e for e in spec.endpoints if e.method == "GET")
        self.assertEqual(get_ep.base_url, "https://petstore.example.com/v2")
        self.assertEqual(get_ep.full_url, "https://petstore.example.com/v2/pet/{petId}")
        self.assertEqual(get_ep.auth_type, "basic")
        self.assertEqual(get_ep.parameters[0].name, "petId")
        self.assertEqual(get_ep.parameters[0].location, "path")
        self.assertEqual(get_ep.parameters[0].param_type, "integer")

    def test_parse_openapi_yaml(self):
        yaml_content = """
openapi: 3.0.0
info:
  title: YAML Petstore
  version: 1.0.0
servers:
  - url: https://api.yaml-store.org/api
paths:
  /ping:
    get:
      summary: Health check
      responses:
        '200':
          description: OK
"""
        spec = self.finder.parse_openapi_spec(yaml_content, spec_url="https://api.yaml-store.org/openapi.yaml")
        self.assertEqual(spec.spec_type, "openapi_3")
        self.assertEqual(spec.title, "YAML Petstore")
        self.assertEqual(len(spec.endpoints), 1)
        self.assertEqual(spec.endpoints[0].path, "/ping")
        self.assertEqual(spec.endpoints[0].full_url, "https://api.yaml-store.org/api/ping")

    def test_parse_invalid_or_non_spec_payload(self):
        # Empty string
        empty_spec = self.finder.parse_openapi_spec("", spec_url="https://example.com/empty.json")
        self.assertEqual(empty_spec.spec_type, "unknown")
        self.assertEqual(len(empty_spec.endpoints), 0)

        # Random JSON
        random_spec = self.finder.parse_openapi_spec('{"status": "ok", "error": null}', spec_url="https://example.com/status")
        self.assertEqual(random_spec.spec_type, "unknown")
        self.assertEqual(len(random_spec.endpoints), 0)


class TestProbingAsync(unittest.IsolatedAsyncioTestCase):
    """Test async candidate probing against simulated endpoints using httpx MockTransport."""

    async def test_probe_direct_spec_url(self):
        spec_payload = {
            "openapi": "3.0.0",
            "info": {"title": "FastAPI App", "version": "0.1.0"},
            "servers": [{"url": "https://fastapi.example.com"}],
            "paths": {
                "/health": {
                    "get": {
                        "summary": "Health Check",
                        "responses": {"200": {"description": "Healthy"}},
                    }
                }
            },
        }

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/openapi.json":
                return httpx.Response(
                    200,
                    headers={"Content-Type": "application/json"},
                    json=spec_payload,
                )
            return httpx.Response(404, text="Not Found")

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            specs = await SpecFinder.probe("https://fastapi.example.com", client=client, concurrency=3)

        self.assertEqual(len(specs), 1)
        self.assertEqual(specs[0].spec_type, "openapi_3")
        self.assertEqual(specs[0].title, "FastAPI App")
        self.assertEqual(len(specs[0].endpoints), 1)
        self.assertEqual(specs[0].endpoints[0].path, "/health")

    async def test_probe_html_swagger_ui_with_embedded_spec(self):
        swagger_html = """
        <!DOCTYPE html>
        <html>
        <head><title>Swagger UI</title></head>
        <body>
        <script>
            SwaggerUIBundle({
                url: "/v3/api-docs/custom",
                dom_id: '#swagger-ui'
            });
        </script>
        </body>
        </html>
        """

        spec_json = {
            "openapi": "3.0.0",
            "info": {"title": "SpringDoc API", "version": "1.0"},
            "paths": {
                "/api/data": {
                    "get": {"summary": "Get Data", "responses": {"200": {"description": "Data"}}}
                }
            },
        }

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/swagger-ui.html" or request.url.path == "/docs":
                return httpx.Response(200, headers={"Content-Type": "text/html"}, text=swagger_html)
            elif request.url.path == "/v3/api-docs/custom":
                return httpx.Response(200, headers={"Content-Type": "application/json"}, json=spec_json)
            return httpx.Response(404, text="Not Found")

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            finder = SpecFinder()
            specs = await finder.probe_spec_urls("https://spring.example.com", client=client, concurrency=4)

        self.assertGreaterEqual(len(specs), 1)
        target_spec = next((s for s in specs if s.spec_type == "openapi_3"), None)
        self.assertIsNotNone(target_spec)
        self.assertEqual(target_spec.title, "SpringDoc API")
        self.assertEqual(target_spec.endpoints[0].path, "/api/data")

    async def test_probe_spring_swagger_config_pointer(self):
        # /v3/api-docs/swagger-config returns JSON pointing to /v3/api-docs
        config_payload = {
            "configUrl": "/v3/api-docs/swagger-config",
            "url": "/v3/api-docs",
            "urls": [{"url": "/v3/api-docs", "name": "default"}],
        }

        spec_payload = {
            "openapi": "3.0.2",
            "info": {"title": "Spring Boot Microservice", "version": "3.1.0"},
            "paths": {
                "/actuator/health": {
                    "get": {"summary": "Actuator Health", "responses": {"200": {"description": "UP"}}}
                }
            },
        }

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/v3/api-docs/swagger-config":
                return httpx.Response(200, headers={"Content-Type": "application/json"}, json=config_payload)
            elif request.url.path == "/v3/api-docs":
                return httpx.Response(200, headers={"Content-Type": "application/json"}, json=spec_payload)
            return httpx.Response(404, text="Not Found")

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            specs = await SpecFinder.probe("https://boot.example.com", client=client, concurrency=4)

        target_spec = next((s for s in specs if s.title == "Spring Boot Microservice"), None)
        self.assertIsNotNone(target_spec)
        self.assertEqual(target_spec.spec_type, "openapi_3")
        self.assertEqual(target_spec.endpoints[0].path, "/actuator/health")

    async def test_probe_resilience_to_errors(self):
        # Verify that timeouts, 500s, and connection issues don't crash probe_spec_urls
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/openapi.json":
                raise httpx.ConnectTimeout("Connection timed out", request=request)
            elif request.url.path == "/swagger.json":
                raise httpx.ConnectError("Connection refused", request=request)
            elif request.url.path == "/docs":
                return httpx.Response(500, text="Internal Server Error")
            return httpx.Response(404, text="Not Found")

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            specs = await SpecFinder.probe("https://broken.example.com", client=client, concurrency=2)

        self.assertEqual(specs, [])

    async def test_probe_head_method(self):
        # Testing method='HEAD' probing
        spec_payload = {
            "openapi": "3.0.0",
            "info": {"title": "Head Probe API", "version": "1.0"},
            "paths": {"/status": {"get": {"responses": {"200": {"description": "OK"}}}}},
        }

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/openapi.json":
                if request.method == "HEAD":
                    return httpx.Response(200, headers={"Content-Type": "application/json"})
                elif request.method == "GET":
                    return httpx.Response(200, headers={"Content-Type": "application/json"}, json=spec_payload)
            return httpx.Response(404, text="Not Found")

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            specs = await SpecFinder.probe("https://head.example.com", client=client, method="HEAD")

        self.assertEqual(len(specs), 1)
        self.assertEqual(specs[0].title, "Head Probe API")

    async def test_probe_ui_html_without_spec_link(self):
        # When an HTML page is a Swagger UI or Scalar or Redoc page but has no external spec link
        swagger_html = "<!DOCTYPE html><html><head><title>API Documentation</title></head><body><div id='swagger-ui'></div></body></html>"

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/swagger-ui.html":
                return httpx.Response(200, headers={"Content-Type": "text/html"}, text=swagger_html)
            return httpx.Response(404, text="Not Found")

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            specs = await SpecFinder.probe("https://ui-only.example.com", client=client)

        self.assertEqual(len(specs), 1)
        self.assertEqual(specs[0].spec_type, "swagger_ui")
        self.assertEqual(specs[0].title, "API Documentation")

    async def test_probe_class_level_direct_call(self):
        # Directly calling SpecFinder.probe_spec_urls without instantiating
        spec_payload = {
            "openapi": "3.0.0",
            "info": {"title": "Direct Call API"},
            "paths": {"/ping": {"get": {"responses": {"200": {"description": "pong"}}}}},
        }

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/openapi.json":
                return httpx.Response(200, headers={"Content-Type": "application/json"}, json=spec_payload)
            return httpx.Response(404, text="Not Found")

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            specs = await SpecFinder.probe_spec_urls("https://direct.example.com", client=client)

        self.assertEqual(len(specs), 1)
        self.assertEqual(specs[0].title, "Direct Call API")

    async def test_custom_candidate_paths(self):
        finder = SpecFinder(candidate_paths=["/private/secret-spec.json"])
        self.assertEqual(finder.candidate_paths, ["/private/secret-spec.json"])

        spec_payload = {
            "openapi": "3.0.0",
            "info": {"title": "Secret Spec"},
            "paths": {"/secret": {"get": {"responses": {"200": {"description": "OK"}}}}},
        }

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/private/secret-spec.json":
                return httpx.Response(200, headers={"Content-Type": "application/json"}, json=spec_payload)
            return httpx.Response(404, text="Not Found")

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            specs = await finder.probe_spec_urls("https://custom.example.com", client=client)

        self.assertEqual(len(specs), 1)
        self.assertEqual(specs[0].title, "Secret Spec")


if __name__ == "__main__":
    unittest.main()
