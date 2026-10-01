"""
Unit tests for api_tool.prober.graphql_prober: GraphQLProber and GraphQLProbeResult.

Tests:
1. Clean imports from api_tool.models and api_tool.prober.
2. Non-destructive { __typename } query probing via POST and GET.
3. POST-only and GET-only endpoint probing.
4. Non-GraphQL / 404 endpoint rejection.
5. Network / protocol failure handling without crashing.
6. Embedded IDE UI detection (Apollo Sandbox, GraphiQL, GraphQL Playground, Altair).
7. Schema introspection and SDL generation with root field extraction via graphql-core.
8. Disabled / blocked introspection handling (Apollo Server 400, 403 Forbidden, null schema).
9. Introspection fallback when 'description' field is unsupported.
10. discover_and_probe candidate combination and discovery.
11. Conversion to DiscoveredEndpoint model.
"""

import json
import unittest
from typing import Dict, Any

import httpx
from graphql import (
    build_schema,
    get_introspection_query,
    graphql_sync,
)

from api_tool.models import (
    GraphQLProbeResult,
    GraphQLProber,
    DiscoveredEndpoint,
)


class TestGraphQLProber(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.prober = GraphQLProber(timeout=5.0)

        # Standard test schema for introspection tests
        self.sample_schema_sdl = """
        type Query {
            me: User
            users(limit: Int): [User!]!
            search(query: String!): [String!]!
        }

        type User {
            id: ID!
            username: String!
            email: String
        }

        type Mutation {
            createUser(username: String!, email: String): User!
            deleteUser(id: ID!): Boolean!
        }

        type Subscription {
            userCreated: User!
        }
        """
        self.compiled_schema = build_schema(self.sample_schema_sdl)
        intro_res = graphql_sync(self.compiled_schema, get_introspection_query(descriptions=True))
        self.introspection_data = intro_res.data

    def test_clean_imports_from_models(self):
        """Verifies clean imports from api_tool.models and dataclass defaults."""
        result = GraphQLProbeResult(endpoint_url="https://api.example.com/graphql")
        self.assertEqual(result.endpoint_url, "https://api.example.com/graphql")
        self.assertFalse(result.is_active)
        self.assertFalse(result.supports_post)
        self.assertFalse(result.supports_get)
        self.assertFalse(result.introspection_enabled)
        self.assertIsNone(result.schema_sdl)
        self.assertEqual(result.types_count, 0)
        self.assertEqual(result.query_fields, [])
        self.assertEqual(result.mutation_fields, [])
        self.assertEqual(result.subscription_fields, [])
        self.assertIsNone(result.error)

        d = result.to_dict()
        self.assertEqual(d["endpoint_url"], "https://api.example.com/graphql")
        self.assertIn("is_active", d)

    async def test_probe_active_post_and_get(self):
        """Tests endpoint supporting both POST and GET __typename query."""
        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "POST":
                body = json.loads(request.read())
                if "__typename" in body.get("query", ""):
                    return httpx.Response(200, json={"data": {"__typename": "Query"}})
            elif request.method == "GET":
                if "__typename" in request.url.params.get("query", ""):
                    return httpx.Response(200, json={"data": {"__typename": "Query"}})
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            result = await self.prober.probe_endpoint("http://testserver/graphql", client=client)

        self.assertTrue(result.is_active)
        self.assertTrue(result.supports_post)
        self.assertTrue(result.supports_get)
        self.assertIsNone(result.error)

    async def test_probe_active_post_only(self):
        """Tests endpoint supporting POST but rejecting GET with 405."""
        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "POST":
                body = json.loads(request.read())
                if "__typename" in body.get("query", ""):
                    return httpx.Response(200, json={"data": {"__typename": "Query"}})
            elif request.method == "GET":
                return httpx.Response(405, text="Method Not Allowed")
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            result = await self.prober.probe_endpoint("http://testserver/graphql", client=client)

        self.assertTrue(result.is_active)
        self.assertTrue(result.supports_post)
        self.assertFalse(result.supports_get)
        self.assertIsNone(result.error)

    async def test_probe_active_get_only(self):
        """Tests endpoint supporting GET but rejecting POST with 405."""
        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "POST":
                return httpx.Response(405, text="Method Not Allowed")
            elif request.method == "GET":
                if "__typename" in request.url.params.get("query", ""):
                    return httpx.Response(200, json={"data": {"__typename": "Query"}})
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            result = await self.prober.probe_endpoint("http://testserver/graphql", client=client)

        self.assertTrue(result.is_active)
        self.assertFalse(result.supports_post)
        self.assertTrue(result.supports_get)
        self.assertIsNone(result.error)

    async def test_probe_inactive_endpoint(self):
        """Tests non-GraphQL endpoint returning 404."""
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404, text="Not Found")

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            result = await self.prober.probe_endpoint("http://testserver/not-graphql", client=client)

        self.assertFalse(result.is_active)
        self.assertFalse(result.supports_post)
        self.assertFalse(result.supports_get)

    async def test_probe_network_error_graceful(self):
        """Tests handling of network connection failures gracefully."""
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("Connection refused by peer", request=request)

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            result = await self.prober.probe_endpoint("http://unreachable:9999/graphql", client=client)

        self.assertFalse(result.is_active)
        self.assertIsNotNone(result.error)
        self.assertIn("Connection refused", result.error)

    async def test_ui_detection_apollo_sandbox(self):
        """Tests detection of Apollo Sandbox HTML interface."""
        html_content = """
        <!DOCTYPE html>
        <html>
        <head><title>Apollo Sandbox</title></head>
        <body>
        <div id="sandbox"></div>
        <script src="https://embeddable-sandbox.cdn.apollographql.com/_latest/embeddable-sandbox.umd.production.min.js"></script>
        <script>
          new window.EmbeddedSandbox({ target: '#sandbox', initialEndpoint: '/graphql' });
        </script>
        </body>
        </html>
        """
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, headers={"Content-Type": "text/html"}, text=html_content)

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            result = await self.prober.probe_endpoint("http://testserver/graphql", client=client)

        self.assertTrue(result.is_active)
        self.assertEqual(result.detected_ui, "Apollo Sandbox")

    async def test_ui_detection_graphiql(self):
        """Tests detection of GraphiQL HTML interface."""
        html_content = """
        <!DOCTYPE html>
        <html>
        <head><title>GraphiQL</title></head>
        <body>
          <div id="graphiql">Loading GraphQL IDE...</div>
          <script src="/static/graphiql.min.js"></script>
        </body>
        </html>
        """
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, headers={"Content-Type": "text/html"}, text=html_content)

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            result = await self.prober.probe_endpoint("http://testserver/graphql", client=client)

        self.assertTrue(result.is_active)
        self.assertEqual(result.detected_ui, "GraphiQL")

    async def test_ui_detection_graphql_playground(self):
        """Tests detection of GraphQL Playground HTML interface."""
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
          <title>GraphQL Playground</title>
          <link rel="stylesheet" href="//cdn.jsdelivr.net/npm/graphql-playground-react/build/static/css/index.css" />
        </head>
        <body>
          <div id="root"></div>
          <script src="//cdn.jsdelivr.net/npm/graphql-playground-react/build/static/js/middleware.js"></script>
          <script>
            window.addEventListener('load', function() { GraphQLPlayground.init(document.getElementById('root')) })
          </script>
        </body>
        </html>
        """
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, headers={"Content-Type": "text/html"}, text=html_content)

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            result = await self.prober.probe_endpoint("http://testserver/graphql", client=client)

        self.assertTrue(result.is_active)
        self.assertEqual(result.detected_ui, "GraphQL Playground")

    async def test_ui_detection_altair(self):
        """Tests detection of Altair GraphQL Client HTML interface."""
        html_content = """
        <!DOCTYPE html>
        <html>
        <head><title>Altair GraphQL Client</title></head>
        <body>
          <app-root></app-root>
          <script src="altair-static/main.js"></script>
        </body>
        </html>
        """
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, headers={"Content-Type": "text/html"}, text=html_content)

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            result = await self.prober.probe_endpoint("http://testserver/graphql", client=client)

        self.assertTrue(result.is_active)
        self.assertEqual(result.detected_ui, "Altair GraphQL")

    async def test_introspection_success_and_sdl_generation(self):
        """Tests full introspection query execution, SDL generation, and field extraction."""
        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "POST":
                body = json.loads(request.read())
                q = body.get("query", "")
                if "__typename" in q:
                    return httpx.Response(200, json={"data": {"__typename": "Query"}})
                elif "__schema" in q:
                    return httpx.Response(200, json={"data": self.introspection_data})
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            result = await self.prober.run_introspection("http://testserver/graphql", client=client)

        self.assertTrue(result.is_active)
        self.assertTrue(result.introspection_enabled)
        self.assertIsNotNone(result.schema_sdl)
        self.assertIn("type Query", result.schema_sdl)
        self.assertIn("type Mutation", result.schema_sdl)
        self.assertIn("type Subscription", result.schema_sdl)
        self.assertIn("type User", result.schema_sdl)

        # Verify fields and types
        self.assertEqual(sorted(result.query_fields), ["me", "search", "users"])
        self.assertEqual(sorted(result.mutation_fields), ["createUser", "deleteUser"])
        self.assertEqual(sorted(result.subscription_fields), ["userCreated"])
        self.assertGreater(result.types_count, 5)
        self.assertIsNone(result.error)

    async def test_introspection_blocked_apollo_server_400(self):
        """Tests handling when Apollo Server blocks introspection with HTTP 400 error."""
        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "POST":
                body = json.loads(request.read())
                q = body.get("query", "")
                if "__typename" in q:
                    return httpx.Response(200, json={"data": {"__typename": "Query"}})
                elif "__schema" in q:
                    return httpx.Response(
                        400,
                        json={
                            "errors": [
                                {
                                    "message": "GraphQL introspection is not allowed by Apollo Server, but the query contained __schema or __type.",
                                    "extensions": {"code": "GRAPHQL_VALIDATION_FAILED"},
                                }
                            ]
                        },
                    )
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            result = await self.prober.run_introspection("http://testserver/graphql", client=client)

        self.assertTrue(result.is_active)
        self.assertFalse(result.introspection_enabled)
        self.assertIsNone(result.schema_sdl)
        self.assertEqual(result.query_fields, [])
        self.assertIsNotNone(result.error)
        self.assertIn("GraphQL introspection is not allowed", result.error)

    async def test_introspection_forbidden_403(self):
        """Tests handling when introspection endpoint returns HTTP 403 Forbidden."""
        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "POST":
                body = json.loads(request.read())
                q = body.get("query", "")
                if "__typename" in q:
                    return httpx.Response(200, json={"data": {"__typename": "Query"}})
                elif "__schema" in q:
                    return httpx.Response(403, text="Forbidden: Introspection queries are restricted")
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            result = await self.prober.run_introspection("http://testserver/graphql", client=client)

        self.assertTrue(result.is_active)
        self.assertFalse(result.introspection_enabled)
        self.assertIsNone(result.schema_sdl)
        self.assertIsNotNone(result.error)
        self.assertIn("403", result.error)

    async def test_introspection_null_schema_200(self):
        """Tests handling when introspection returns null schema without error."""
        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "POST":
                body = json.loads(request.read())
                q = body.get("query", "")
                if "__typename" in q:
                    return httpx.Response(200, json={"data": {"__typename": "Query"}})
                elif "__schema" in q:
                    return httpx.Response(200, json={"data": {"__schema": None}})
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            result = await self.prober.run_introspection("http://testserver/graphql", client=client)

        self.assertTrue(result.is_active)
        self.assertFalse(result.introspection_enabled)
        self.assertIsNone(result.schema_sdl)
        self.assertIsNotNone(result.error)

    async def test_discover_and_probe_with_candidate_endpoints(self):
        """Tests discover_and_probe combining custom candidate endpoints with defaults."""
        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            # Only /custom/gql and /graphql respond as active GraphQL
            if path == "/custom/gql":
                if request.method == "POST":
                    body = json.loads(request.read())
                    if "__typename" in body.get("query", ""):
                        return httpx.Response(200, json={"data": {"__typename": "Query"}})
                    if "__schema" in body.get("query", ""):
                        return httpx.Response(200, json={"data": self.introspection_data})
            elif path == "/graphql":
                if request.method == "POST":
                    body = json.loads(request.read())
                    if "__typename" in body.get("query", ""):
                        return httpx.Response(200, json={"data": {"__typename": "Query"}})
                    if "__schema" in body.get("query", ""):
                        return httpx.Response(200, json={"data": self.introspection_data})
            return httpx.Response(404, text="Not Found")

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            results = await self.prober.discover_and_probe(
                base_url="http://testserver",
                candidate_endpoints=["/custom/gql"],
                client=client,
                active_only=True,
            )

        self.assertEqual(len(results), 2)
        urls = [r.endpoint_url for r in results]
        self.assertIn("http://testserver/custom/gql", urls)
        self.assertIn("http://testserver/graphql", urls)
        self.assertTrue(all(r.is_active for r in results))
        self.assertTrue(all(r.introspection_enabled for r in results))
        self.assertTrue(all(r.schema_sdl is not None for r in results))

    async def test_discover_and_probe_all_results_flag(self):
        """Tests discover_and_probe with active_only=False returns both active and inactive results."""
        def handler(request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            if url_str == "http://testserver/graphql":
                if request.method == "POST":
                    body = json.loads(request.read())
                    if "__typename" in body.get("query", ""):
                        return httpx.Response(200, json={"data": {"__typename": "Query"}})
            return httpx.Response(404, text="Not Found")

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            results = await self.prober.discover_and_probe(
                base_url="http://testserver",
                client=client,
                active_only=False,
            )

        self.assertEqual(len(results), len(GraphQLProber.CANDIDATE_PATHS))
        active = [r for r in results if r.is_active]
        inactive = [r for r in results if not r.is_active]
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0].endpoint_url, "http://testserver/graphql")
        self.assertEqual(len(inactive), len(GraphQLProber.CANDIDATE_PATHS) - 1)

    def test_to_discovered_endpoint_conversion(self):
        """Tests converting a GraphQLProbeResult to api_tool DiscoveredEndpoint model."""
        res = GraphQLProbeResult(
            endpoint_url="https://api.example.com/graphql",
            is_active=True,
            supports_post=True,
            introspection_enabled=True,
            types_count=12,
            query_fields=["users", "me"],
            mutation_fields=["createUser"],
        )
        ep = res.to_discovered_endpoint()
        self.assertIsInstance(ep, DiscoveredEndpoint)
        self.assertEqual(ep.path, "https://api.example.com/graphql")
        self.assertEqual(ep.method, "POST")
        self.assertEqual(ep.active_status, 200)
        self.assertIn("graphql", ep.tags)
        self.assertIn("users", ep.description)


if __name__ == "__main__":
    unittest.main()
