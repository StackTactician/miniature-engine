"""
Unit and integration tests for api_tool.prober.coordinator:
- APIProber / ProberCoordinator
- ProberResult dataclass serialization and fields
- SSRF protection guard integration
- Endpoint normalization, merging, and deduplication
- End-to-end probing flow with mock HTTP transports (OpenAPI, GraphQL, live HTTP)
- Feature flags: probe_specs, probe_graphql, probe_http, run_introspection
- Managed client lifecycle and error resilience
"""

import asyncio
import json
import unittest
from typing import Any, Dict, List

import httpx
from graphql import (
    build_schema,
    get_introspection_query,
    graphql_sync,
)

from api_tool.models import (
    DiscoveredEndpoint,
    DiscoveredParameter,
    DiscoveredResponse,
)
from api_tool.prober import (
    APIProber,
    ProberCoordinator,
    ProberResult,
    SpecFinder,
    DiscoveredSpec,
    SafeHTTPProber,
    ProbeResult,
    GraphQLProber,
    GraphQLProbeResult,
    is_safe_target,
)


class TestProberExportsAndModels(unittest.TestCase):
    """Verifies module exports and dataclass representations."""

    def test_imports_and_aliases(self):
        """Verifies all required classes and helpers are exported correctly."""
        self.assertIs(APIProber, ProberCoordinator)
        self.assertTrue(issubclass(ProberResult, object))
        self.assertTrue(issubclass(APIProber, object))
        self.assertTrue(issubclass(SpecFinder, object))
        self.assertTrue(issubclass(DiscoveredSpec, object))
        self.assertTrue(issubclass(SafeHTTPProber, object))
        self.assertTrue(issubclass(ProbeResult, object))
        self.assertTrue(issubclass(GraphQLProber, object))
        self.assertTrue(issubclass(GraphQLProbeResult, object))
        self.assertTrue(callable(is_safe_target))

    def test_prober_result_defaults_and_serialization(self):
        """Tests ProberResult default values, to_dict(), and to_json()."""
        res = ProberResult()
        self.assertEqual(res.probed_endpoints, [])
        self.assertEqual(res.discovered_specs, [])
        self.assertEqual(res.graphql_results, [])
        self.assertEqual(res.http_probe_results, [])
        self.assertEqual(res.summary, {})

        # Populate sample result
        ep = DiscoveredEndpoint(path="/api/v1/users", method="GET", base_url="https://api.example.com", active_status=200)
        spec = DiscoveredSpec(url="https://api.example.com/openapi.json", spec_type="openapi_3", title="Test API")
        gql = GraphQLProbeResult(endpoint_url="https://api.example.com/graphql", is_active=True, introspection_enabled=True)
        probe = ProbeResult(endpoint=ep, status_code=200, allowed_methods=["GET", "OPTIONS"], cors_reflected=True)

        res2 = ProberResult(
            probed_endpoints=[ep],
            discovered_specs=[spec],
            graphql_results=[gql],
            http_probe_results=[probe],
            summary={"total_probed": 1, "live_endpoints": 1},
        )

        d = res2.to_dict()
        self.assertEqual(len(d["probed_endpoints"]), 1)
        self.assertEqual(d["probed_endpoints"][0]["path"], "/api/v1/users")
        self.assertEqual(len(d["discovered_specs"]), 1)
        self.assertEqual(d["discovered_specs"][0]["title"], "Test API")
        self.assertEqual(len(d["graphql_results"]), 1)
        self.assertTrue(d["graphql_results"][0]["is_active"])
        self.assertEqual(len(d["http_probe_results"]), 1)
        self.assertTrue(d["http_probe_results"][0]["cors_reflected"])
        self.assertEqual(d["summary"]["total_probed"], 1)

        # JSON serialization
        j = res2.to_json()
        parsed = json.loads(j)
        self.assertEqual(parsed["summary"]["live_endpoints"], 1)


class TestProberSSRFGuard(unittest.IsolatedAsyncioTestCase):
    """Tests SSRF protection at the coordinator level."""

    async def test_ssrf_blocked_target(self):
        """Verifies dangerous targets are blocked when allow_private_ips=False."""
        prober = APIProber(allow_private_ips=False)
        blocked_targets = [
            "http://127.0.0.1:8000",
            "http://169.254.169.254",
            "http://metadata.google.internal",
            "http://[::1]",
        ]
        for target in blocked_targets:
            res = await prober.probe(target)
            self.assertEqual(len(res.probed_endpoints), 0)
            self.assertEqual(len(res.discovered_specs), 0)
            self.assertEqual(len(res.graphql_results), 0)
            self.assertEqual(len(res.http_probe_results), 0)
            self.assertIn("error", res.summary)
            self.assertIn("SSRF protection blocked target", res.summary["error"])

    async def test_empty_target(self):
        """Verifies empty or whitespace base_url returns an empty ProberResult immediately."""
        prober = APIProber()
        res = await prober.probe("")
        self.assertEqual(res.probed_endpoints, [])
        self.assertEqual(res.summary, {})


class TestEndpointNormalizationAndMerging(unittest.TestCase):
    """Tests normalization, deduplication, and merging logic."""

    def test_normalize_endpoint(self):
        prober = APIProber()

        # Relative path without leading slash
        ep1 = DiscoveredEndpoint(path="api/v1/users", method="get")
        prober._normalize_endpoint(ep1, "https://api.example.com")
        self.assertEqual(ep1.path, "/api/v1/users")
        self.assertEqual(ep1.method, "GET")
        self.assertEqual(ep1.base_url, "https://api.example.com")
        self.assertEqual(ep1.full_url, "https://api.example.com/api/v1/users")

        # Path with trailing slash (non-root)
        ep2 = DiscoveredEndpoint(path="/api/v1/items/", method="post")
        prober._normalize_endpoint(ep2, "https://api.example.com")
        self.assertEqual(ep2.path, "/api/v1/items")
        self.assertEqual(ep2.method, "POST")

        # Root path preserves single slash
        ep3 = DiscoveredEndpoint(path="/", method="GET")
        prober._normalize_endpoint(ep3, "https://api.example.com")
        self.assertEqual(ep3.path, "/")

        # Full URL in path
        ep4 = DiscoveredEndpoint(path="https://other.example.com/api/v2/orders", method="delete")
        prober._normalize_endpoint(ep4, "https://api.example.com")
        self.assertEqual(ep4.path, "/api/v2/orders")
        self.assertEqual(ep4.base_url, "https://other.example.com")
        self.assertEqual(ep4.method, "DELETE")

    def test_merge_and_deduplicate_endpoints(self):
        prober = APIProber()

        ep_static = DiscoveredEndpoint(
            path="/api/v1/users",
            method="GET",
            source="static",
            tags=["users"],
            parameters=[DiscoveredParameter(name="page", location="query", param_type="string")],
            summary="Extracted REST endpoint: /api/v1/users",
        )

        ep_spec = DiscoveredEndpoint(
            path="/api/v1/users",
            method="GET",
            source="spec",
            tags=["accounts", "users"],
            parameters=[
                DiscoveredParameter(name="page", location="query", param_type="integer", required=False, description="Page number"),
                DiscoveredParameter(name="limit", location="query", param_type="integer", description="Items per page"),
            ],
            summary="List all registered users",
            description="Returns paginated users list",
            responses=[DiscoveredResponse(status_code=200, content_type="application/json")],
        )

        merged_list = prober._deduplicate_endpoints([ep_static, ep_spec], "https://api.example.com")
        self.assertEqual(len(merged_list), 1)
        merged = merged_list[0]

        # Spec source takes precedence
        self.assertEqual(merged.source, "spec")
        # Tags are unioned
        self.assertEqual(sorted(merged.tags), ["accounts", "users"])
        # Parameters merged and enriched
        self.assertEqual(len(merged.parameters), 2)
        param_by_name = {p.name: p for p in merged.parameters}
        self.assertEqual(param_by_name["page"].param_type, "integer")
        self.assertEqual(param_by_name["page"].description, "Page number")
        self.assertEqual(param_by_name["limit"].param_type, "integer")
        # Summary and description preserved from spec
        self.assertEqual(merged.summary, "List all registered users")
        self.assertEqual(merged.description, "Returns paginated users list")
        self.assertEqual(len(merged.responses), 1)


class TestAPIProberEndToEnd(unittest.IsolatedAsyncioTestCase):
    """End-to-end tests with mock HTTP transports."""

    def setUp(self):
        # Prepare GraphQL schema for test introspection
        schema_sdl = """
        type Query {
            me: User
            users: [User!]!
        }
        type User {
            id: ID!
            name: String!
        }
        """
        compiled = build_schema(schema_sdl)
        intro_res = graphql_sync(compiled, get_introspection_query(descriptions=True))
        self.intro_data = intro_res.data

        # Sample OpenAPI 3.0 specification
        self.openapi_spec = {
            "openapi": "3.0.0",
            "info": {
                "title": "Mock Petstore API",
                "version": "1.0.0",
            },
            "servers": [{"url": "http://testserver"}],
            "paths": {
                "/api/v1/pets": {
                    "get": {
                        "summary": "List all pets",
                        "responses": {"200": {"description": "Pet list"}},
                    },
                    "post": {
                        "summary": "Create a pet",
                        "responses": {"201": {"description": "Created"}},
                    },
                },
                "/api/v1/pets/{id}": {
                    "get": {
                        "summary": "Get pet by id",
                        "parameters": [
                            {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}
                        ],
                        "responses": {"200": {"description": "Pet item"}},
                    }
                },
            },
        }

    async def test_full_pipeline_mock_server(self):
        """
        Tests end-to-end execution of:
        - Spec discovery (/openapi.json)
        - GraphQL discovery and introspection (/graphql)
        - HTTP probing with OPTIONS, CORS reflection, and Allow headers
        - Merging and summary calculation
        """
        def mock_handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            method = request.method

            # 1. Spec Finder route
            if path == "/openapi.json" and method == "GET":
                return httpx.Response(
                    200,
                    headers={"Content-Type": "application/json"},
                    json=self.openapi_spec,
                )

            # 2. GraphQL route
            if path == "/graphql":
                if method == "POST":
                    body = json.loads(request.read().decode("utf-8"))
                    q = body.get("query", "")
                    if "__typename" in q:
                        return httpx.Response(200, json={"data": {"__typename": "Query"}})
                    if "__schema" in q:
                        return httpx.Response(200, json={"data": self.intro_data})
                elif method == "OPTIONS":
                    return httpx.Response(
                        200,
                        headers={
                            "Allow": "GET, POST, OPTIONS",
                            "Access-Control-Allow-Origin": "*",
                        },
                    )

            # 3. REST endpoints
            if path == "/api/v1/pets":
                if method == "OPTIONS":
                    return httpx.Response(
                        200,
                        headers={
                            "Allow": "GET, POST, OPTIONS",
                            "Access-Control-Allow-Origin": "https://probe.cors-test.local",
                            "Access-Control-Allow-Credentials": "true",
                        },
                    )
                if method == "GET":
                    return httpx.Response(200, json=[{"id": "1", "name": "Fido"}])
                if method == "POST":
                    return httpx.Response(201, json={"id": "2", "name": "Rex"})

            if path.startswith("/api/v1/pets/"):
                if method == "OPTIONS":
                    return httpx.Response(
                        200,
                        headers={"Allow": "GET, OPTIONS"},
                    )

            # Input custom endpoint /api/v1/auth/login
            if path == "/api/v1/auth/login":
                if method == "OPTIONS":
                    return httpx.Response(
                        200,
                        headers={"Allow": "POST, OPTIONS"},
                    )

            return httpx.Response(404, text="Not Found")

        transport = httpx.MockTransport(mock_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            prober = APIProber(
                concurrency=5,
                allow_private_ips=True,
                request_timeout=5.0,
            )

            # Pass pre-existing static endpoint
            input_endpoints = [
                DiscoveredEndpoint(path="/api/v1/auth/login", method="POST", source="static_js"),
                DiscoveredEndpoint(path="/api/v1/pets", method="GET", source="crawler"),  # Duplicate with spec
            ]

            result = await prober.probe(
                base_url="http://testserver",
                endpoints=input_endpoints,
                probe_specs=True,
                probe_graphql=True,
                probe_http=True,
                run_introspection=True,
                client=client,
            )

            # 1. Spec check
            self.assertEqual(len(result.discovered_specs), 1)
            self.assertEqual(result.discovered_specs[0].title, "Mock Petstore API")
            self.assertEqual(result.discovered_specs[0].spec_type, "openapi_3")

            # 2. GraphQL check
            self.assertEqual(len(result.graphql_results), 1)
            gql_res = result.graphql_results[0]
            self.assertTrue(gql_res.is_active)
            self.assertTrue(gql_res.introspection_enabled)
            self.assertIn("me", gql_res.query_fields)
            self.assertIn("users", gql_res.query_fields)
            self.assertIsNotNone(gql_res.schema_sdl)

            # 3. Probed Endpoints check
            paths_and_methods = {(e.path, e.method) for e in result.probed_endpoints}
            self.assertIn(("/api/v1/pets", "GET"), paths_and_methods)
            self.assertIn(("/api/v1/pets", "POST"), paths_and_methods)
            self.assertIn(("/api/v1/pets/{id}", "GET"), paths_and_methods)
            self.assertIn(("/api/v1/auth/login", "POST"), paths_and_methods)
            self.assertIn(("/graphql", "POST"), paths_and_methods)

            # Ensure /api/v1/pets GET source was upgraded from 'crawler' to 'spec'
            pets_get = next(e for e in result.probed_endpoints if e.path == "/api/v1/pets" and e.method == "GET")
            self.assertEqual(pets_get.source, "spec")
            self.assertEqual(pets_get.active_status, 200)

            # 4. HTTP Probe Results check
            self.assertEqual(len(result.http_probe_results), len(result.probed_endpoints))
            pets_probe = next(p for p in result.http_probe_results if p.endpoint.path == "/api/v1/pets" and p.endpoint.method == "GET")
            self.assertTrue(pets_probe.cors_reflected)
            self.assertTrue(pets_probe.cors_allow_credentials)
            self.assertIn("POST", pets_probe.allowed_methods)

            # 5. Summary check
            summary = result.summary
            self.assertEqual(summary["specs_found"], 1)
            self.assertEqual(summary["graphql_services_detected"], 1)
            self.assertGreaterEqual(summary["live_endpoints"], 4)
            self.assertGreaterEqual(summary["cors_reflections"], 1)
            self.assertEqual(summary["total_probed"], len(result.probed_endpoints))

    async def test_probe_specs_flag_false(self):
        """Verifies setting probe_specs=False skips spec probing."""
        spec_requested = False

        def mock_handler(request: httpx.Request) -> httpx.Response:
            nonlocal spec_requested
            if "openapi" in request.url.path or "swagger" in request.url.path:
                spec_requested = True
            return httpx.Response(404)

        transport = httpx.MockTransport(mock_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            prober = APIProber(allow_private_ips=True)
            res = await prober.probe(
                base_url="http://testserver",
                endpoints=[DiscoveredEndpoint(path="/api/status", method="GET")],
                probe_specs=False,
                probe_graphql=False,
                probe_http=False,
                client=client,
            )
            self.assertFalse(spec_requested)
            self.assertEqual(len(res.discovered_specs), 0)
            self.assertEqual(len(res.probed_endpoints), 1)

    async def test_probe_graphql_flag_false(self):
        """Verifies setting probe_graphql=False skips GraphQL discovery."""
        gql_requested = False

        def mock_handler(request: httpx.Request) -> httpx.Response:
            nonlocal gql_requested
            if "graphql" in request.url.path:
                gql_requested = True
            return httpx.Response(404)

        transport = httpx.MockTransport(mock_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            prober = APIProber(allow_private_ips=True)
            res = await prober.probe(
                base_url="http://testserver",
                probe_specs=False,
                probe_graphql=False,
                probe_http=False,
                client=client,
            )
            self.assertFalse(gql_requested)
            self.assertEqual(len(res.graphql_results), 0)

    async def test_probe_http_flag_false(self):
        """Verifies setting probe_http=False disables active route testing."""
        def mock_handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/openapi.json":
                return httpx.Response(200, json=self.openapi_spec)
            return httpx.Response(404)

        transport = httpx.MockTransport(mock_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            prober = APIProber(allow_private_ips=True)
            res = await prober.probe(
                base_url="http://testserver",
                probe_specs=True,
                probe_graphql=False,
                probe_http=False,
                client=client,
            )
            self.assertEqual(len(res.discovered_specs), 1)
            self.assertGreater(len(res.probed_endpoints), 0)
            # http_probe_results must be empty
            self.assertEqual(len(res.http_probe_results), 0)
            self.assertEqual(res.summary["total_probed"], len(res.probed_endpoints))

    async def test_run_introspection_flag_false(self):
        """Verifies run_introspection=False probes active GraphQL status without dumping schema SDL."""
        intro_called = False

        def mock_handler(request: httpx.Request) -> httpx.Response:
            nonlocal intro_called
            if request.url.path == "/graphql" and request.method == "POST":
                body = json.loads(request.read())
                q = body.get("query", "")
                if "__typename" in q:
                    return httpx.Response(200, json={"data": {"__typename": "Query"}})
                if "__schema" in q:
                    intro_called = True
                    return httpx.Response(200, json={"data": self.intro_data})
            return httpx.Response(404)

        transport = httpx.MockTransport(mock_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            prober = APIProber(allow_private_ips=True)
            res = await prober.probe(
                base_url="http://testserver",
                probe_specs=False,
                probe_graphql=True,
                probe_http=False,
                run_introspection=False,
                client=client,
            )
            self.assertEqual(len(res.graphql_results), 1)
            gql = res.graphql_results[0]
            self.assertTrue(gql.is_active)
            self.assertFalse(intro_called)
            self.assertFalse(gql.introspection_enabled)
            self.assertIsNone(gql.schema_sdl)

    async def test_custom_graphql_candidate_in_endpoints(self):
        """Verifies candidate GraphQL endpoints inside input endpoints are probed."""
        custom_called = False

        def mock_handler(request: httpx.Request) -> httpx.Response:
            nonlocal custom_called
            if request.url.path == "/internal/v3/gql" and request.method == "POST":
                custom_called = True
                return httpx.Response(200, json={"data": {"__typename": "Query"}})
            return httpx.Response(404)

        transport = httpx.MockTransport(mock_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            prober = APIProber(allow_private_ips=True)
            input_ep = DiscoveredEndpoint(path="/internal/v3/gql", method="POST", tags=["graphql"])
            res = await prober.probe(
                base_url="http://testserver",
                endpoints=[input_ep],
                probe_specs=False,
                probe_graphql=True,
                probe_http=False,
                run_introspection=False,
                client=client,
            )
            self.assertTrue(custom_called)
            self.assertTrue(any(g.endpoint_url.endswith("/internal/v3/gql") for g in res.graphql_results))

    async def test_resilience_on_network_failure(self):
        """Verifies that network / transport exceptions do not crash the probe pipeline."""
        def mock_handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("Connection refused by testserver")

        transport = httpx.MockTransport(mock_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            prober = APIProber(allow_private_ips=True)
            res = await prober.probe(
                base_url="http://testserver",
                endpoints=[DiscoveredEndpoint(path="/api/test", method="GET")],
                probe_specs=True,
                probe_graphql=True,
                probe_http=True,
                client=client,
            )
            self.assertEqual(len(res.discovered_specs), 0)
            self.assertEqual(len(res.graphql_results), 0)
            self.assertEqual(len(res.probed_endpoints), 1)
            # HTTP probe result should reflect the error
            self.assertEqual(len(res.http_probe_results), 1)
            self.assertIsNotNone(res.http_probe_results[0].error)


if __name__ == "__main__":
    unittest.main()
