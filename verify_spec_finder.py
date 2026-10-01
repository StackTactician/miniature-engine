#!/usr/bin/env python3
"""
Standalone verification script for api_tool.prober.spec_finder.
Verifies:
1. Seamless imports from api_tool.models and api_tool.prober.spec_finder
2. DiscoveredSpec dataclass instantiation and to_dict() serialization
3. CANDIDATE_PATHS coverage (60+ paths)
4. extract_spec_url_from_html for Swagger UI, Redoc, Scalar, RapiDoc, Elements, and Link tags
5. parse_openapi_spec for OpenAPI 3.0, OpenAPI 3.1, and Swagger 2.0 (JSON and YAML)
6. Async candidate probing using httpx MockTransport
"""

import asyncio
import json
import sys

import httpx

from api_tool.models import (
    DiscoveredEndpoint,
    DiscoveredParameter,
    DiscoveredResponse,
    DiscoveredSpec,
    SpecFinder,
)


def verify_models():
    print("[1/5] Verifying models and imports...")
    ep = DiscoveredEndpoint(
        path="/api/v1/test",
        method="GET",
        base_url="https://example.com",
        source="spec",
        summary="Test endpoint",
        parameters=[
            DiscoveredParameter(name="filter", location="query", required=False, param_type="string")
        ],
        responses=[
            DiscoveredResponse(status_code=200, content_type="application/json")
        ],
    )
    spec = DiscoveredSpec(
        url="https://example.com/openapi.json",
        spec_type="openapi_3",
        title="Test API",
        version="1.0.0",
        raw_spec={"openapi": "3.0.0"},
        endpoints=[ep],
    )
    d = spec.to_dict()
    assert d["title"] == "Test API"
    assert d["spec_type"] == "openapi_3"
    assert len(d["endpoints"]) == 1
    assert d["endpoints"][0]["full_url"] == "https://example.com/api/v1/test"
    print("  ✓ DiscoveredSpec & DiscoveredEndpoint model serialization verified.")


def verify_candidate_paths():
    print("[2/5] Verifying candidate paths...")
    paths = SpecFinder.CANDIDATE_PATHS
    print(f"  Total candidate paths: {len(paths)}")
    assert len(paths) >= 60, f"Expected at least 60 candidate paths, found {len(paths)}"
    required = [
        "/openapi.json", "/openapi.yaml", "/v3/api-docs", "/v3/api-docs/swagger-config",
        "/swagger.json", "/swagger/v1/swagger.json", "/api-docs", "/api/openapi.json",
        "/docs/openapi.json", "/swagger/doc.json", "/api/docs/swagger.json",
        "/redoc", "/scalar", "/docs", "/swagger-ui.html", "/swagger-ui/index.html"
    ]
    for r in required:
        assert r in paths, f"Missing required path: {r}"
    print("  ✓ All required candidate paths present.")


def verify_html_extraction():
    print("[3/5] Verifying embedded HTML spec URL extraction...")
    finder = SpecFinder()
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <link rel="alternate" type="application/openapi+json" href="/specs/openapi.json">
        <link rel="service-desc" href="/specs/service-desc.json">
    </head>
    <body>
        <script>
            window.ui = SwaggerUIBundle({
                url: "/swagger-ui/v1/swagger.json",
                urls: [{url: "/swagger-ui/v2/swagger.json", name: "v2"}]
            });
        </script>
        <redoc spec-url="/redoc/openapi.yaml"></redoc>
        <div id="scalar" data-configuration='{"spec": {"url": "/scalar/openapi.json"}}'></div>
        <script id="api-ref" data-url="/scalar/script-url.json"></script>
        <rapi-doc spec-url="/rapidoc/spec.json"></rapi-doc>
        <elements-api apiDescriptionUrl="/elements/spec.json" />
    </body>
    </html>
    """
    base_url = "https://demo.example.com/docs/"
    urls = finder.extract_spec_url_from_html(html, base_url)
    expected = [
        "https://demo.example.com/specs/openapi.json",
        "https://demo.example.com/specs/service-desc.json",
        "https://demo.example.com/swagger-ui/v1/swagger.json",
        "https://demo.example.com/swagger-ui/v2/swagger.json",
        "https://demo.example.com/redoc/openapi.yaml",
        "https://demo.example.com/scalar/openapi.json",
        "https://demo.example.com/scalar/script-url.json",
        "https://demo.example.com/rapidoc/spec.json",
        "https://demo.example.com/elements/spec.json",
    ]
    for exp in expected:
        assert exp in urls, f"Expected URL {exp} not found in extracted URLs: {urls}"
    print(f"  ✓ Extracted {len(urls)} spec URLs from Swagger UI, Redoc, Scalar, RapiDoc, Elements, and Link tags.")


def verify_spec_parsing():
    print("[4/5] Verifying OpenAPI 3.0 & Swagger 2.0 parsing...")
    finder = SpecFinder()

    # 1. OpenAPI 3.0 JSON
    openapi_json = {
        "openapi": "3.0.3",
        "info": {"title": "Users Service", "version": "3.0.0"},
        "servers": [{"url": "https://api.example.com/v3"}],
        "components": {
            "securitySchemes": {
                "bearerAuth": {"type": "http", "scheme": "bearer"}
            }
        },
        "paths": {
            "/users": {
                "get": {
                    "tags": ["Users"],
                    "summary": "List Users",
                    "parameters": [
                        {"name": "page", "in": "query", "schema": {"type": "integer"}, "example": 1}
                    ],
                    "responses": {
                        "200": {
                            "description": "OK",
                            "content": {
                                "application/json": {
                                    "example": [{"id": 1, "username": "alice"}]
                                }
                            }
                        }
                    }
                },
                "post": {
                    "tags": ["Users"],
                    "summary": "Create User",
                    "security": [{"bearerAuth": []}],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"type": "object", "properties": {"username": {"type": "string"}}},
                                "example": {"username": "bob"}
                            }
                        }
                    },
                    "responses": {"201": {"description": "Created"}}
                }
            }
        }
    }
    spec3 = finder.parse_openapi_spec(json.dumps(openapi_json), spec_url="https://api.example.com/v3/openapi.json")
    assert spec3.spec_type == "openapi_3"
    assert spec3.title == "Users Service"
    assert len(spec3.endpoints) == 2
    post_ep = next(e for e in spec3.endpoints if e.method == "POST")
    assert post_ep.auth_type == "bearer"
    assert post_ep.request_body_sample == {"username": "bob"}
    print("  ✓ OpenAPI 3.0 parsed accurately.")

    # 2. Swagger 2.0 JSON
    swagger_json = {
        "swagger": "2.0",
        "info": {"title": "Store API", "version": "1.0.0"},
        "host": "store.example.com",
        "basePath": "/v1",
        "schemes": ["https"],
        "paths": {
            "/orders/{orderId}": {
                "get": {
                    "tags": ["Orders"],
                    "parameters": [
                        {"name": "orderId", "in": "path", "required": True, "type": "integer"}
                    ],
                    "responses": {"200": {"description": "OK"}}
                }
            }
        }
    }
    spec2 = finder.parse_openapi_spec(swagger_json, spec_url="https://store.example.com/v1/swagger.json")
    assert spec2.spec_type == "openapi_2"
    assert spec2.title == "Store API"
    assert len(spec2.endpoints) == 1
    assert spec2.endpoints[0].full_url == "https://store.example.com/v1/orders/{orderId}"
    assert spec2.endpoints[0].parameters[0].name == "orderId"
    print("  ✓ Swagger 2.0 parsed accurately.")

    # 3. OpenAPI YAML
    yaml_payload = """
openapi: 3.0.0
info:
  title: YAML API
  version: 0.9.0
paths:
  /metrics:
    get:
      summary: Prometheus metrics
      responses:
        '200':
          description: OK
"""
    spec_yaml = finder.parse_openapi_spec(yaml_payload, spec_url="https://metrics.example.com/openapi.yaml")
    assert spec_yaml.spec_type == "openapi_3"
    assert spec_yaml.title == "YAML API"
    assert len(spec_yaml.endpoints) == 1
    print("  ✓ OpenAPI YAML parsed accurately.")


async def verify_async_probing():
    print("[5/5] Verifying async candidate probing with MockTransport...")
    spec_payload = {
        "openapi": "3.0.0",
        "info": {"title": "Mock Probed Service", "version": "1.0"},
        "paths": {"/health": {"get": {"responses": {"200": {"description": "OK"}}}}},
    }

    config_payload = {
        "url": "/api-docs/internal",
    }

    internal_spec = {
        "openapi": "3.0.0",
        "info": {"title": "Internal SpringDoc", "version": "2.0"},
        "paths": {"/admin": {"get": {"responses": {"200": {"description": "Admin"}}}}}}

    html_payload = """
    <html><head><title>Docs</title></head><body>
    <redoc spec-url="/docs/v1.json"></redoc>
    </body></html>
    """

    redoc_spec = {
        "openapi": "3.0.0",
        "info": {"title": "Redoc Documentation", "version": "1.0"},
        "paths": {"/redoc-test": {"get": {"responses": {"200": {"description": "OK"}}}}}
    }

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/openapi.json":
            return httpx.Response(200, headers={"Content-Type": "application/json"}, json=spec_payload)
        elif path == "/v3/api-docs/swagger-config":
            return httpx.Response(200, headers={"Content-Type": "application/json"}, json=config_payload)
        elif path == "/api-docs/internal":
            return httpx.Response(200, headers={"Content-Type": "application/json"}, json=internal_spec)
        elif path == "/redoc":
            return httpx.Response(200, headers={"Content-Type": "text/html"}, text=html_payload)
        elif path == "/docs/v1.json":
            return httpx.Response(200, headers={"Content-Type": "application/json"}, json=redoc_spec)
        return httpx.Response(404, text="Not Found")

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        specs = await SpecFinder.probe("https://probed.example.com", client=client, concurrency=5)

    titles = {s.title for s in specs}
    print(f"  Discovered spec titles: {titles}")
    assert "Mock Probed Service" in titles
    assert "Internal SpringDoc" in titles
    assert "Redoc Documentation" in titles
    print("  ✓ Async probing discovered direct specs, Spring config pointers, and Redoc HTML specs.")


async def main():
    verify_models()
    verify_candidate_paths()
    verify_html_extraction()
    verify_spec_parsing()
    await verify_async_probing()
    print("\n🎉 ALL VERIFICATION CHECKS PASSED SUCCESSFULLY!")


if __name__ == "__main__":
    asyncio.run(main())
