#!/usr/bin/env python3
"""
Standalone verification script for api_tool.prober.graphql_prober.
Verifies:
1. Clean imports from api_tool.models and api_tool.prober.
2. Safe non-destructive { __typename } query validation via POST and GET.
3. Embedded IDE UI detection (Apollo Sandbox, GraphiQL, GraphQL Playground, Altair).
4. Mocked introspection schema generation via graphql-core with SDL and field extraction.
5. Graceful handling of blocked or disabled introspection without crashing.
6. discover_and_probe candidate combination and active service introspection.
"""

import asyncio
import json
import sys

import httpx
from graphql import build_schema, get_introspection_query, graphql_sync

# 1. Verify clean imports from api_tool.models
try:
    from api_tool.models import GraphQLProbeResult, GraphQLProber
    print("[PASS] 1. Clean import from api_tool.models: GraphQLProbeResult, GraphQLProber")
except Exception as e:
    print(f"[FAIL] 1. Import from api_tool.models failed: {e}")
    sys.exit(1)


async def main():
    prober = GraphQLProber()

    # 2. Test { __typename } query validation
    def typename_handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            body = json.loads(request.read())
            if "__typename" in body.get("query", ""):
                return httpx.Response(200, json={"data": {"__typename": "Query"}})
        elif request.method == "GET":
            if "__typename" in request.url.params.get("query", ""):
                return httpx.Response(200, json={"data": {"__typename": "Query"}})
        return httpx.Response(404)

    transport = httpx.MockTransport(typename_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        res = await prober.probe_endpoint("http://test/graphql", client=client)
        assert res.is_active is True, "Expected is_active=True"
        assert res.supports_post is True, "Expected supports_post=True"
        assert res.supports_get is True, "Expected supports_get=True"
        print("[PASS] 2. Non-destructive { __typename } query validation (POST & GET)")

    # 3. Test embedded UI detection
    sandbox_html = '<html><body><script src="https://embeddable-sandbox.cdn.apollographql.com/_latest/embeddable-sandbox.umd.production.min.js"></script><script>new window.EmbeddedSandbox()</script></body></html>'
    ui_transport = httpx.MockTransport(lambda req: httpx.Response(200, headers={"Content-Type": "text/html"}, text=sandbox_html))
    async with httpx.AsyncClient(transport=ui_transport) as client:
        ui_res = await prober.probe_endpoint("http://test/graphql", client=client)
        assert ui_res.is_active is True, "Expected is_active=True for UI"
        assert ui_res.detected_ui == "Apollo Sandbox", f"Expected 'Apollo Sandbox', got {ui_res.detected_ui}"
        print(f"[PASS] 3. Embedded IDE UI detection: {ui_res.detected_ui}")

    # 4. Test mocked introspection schema generation via graphql-core
    mock_sdl = """
    type Query {
        organization(id: ID!): Organization
        members: [User!]!
    }
    type Organization {
        id: ID!
        name: String!
    }
    type User {
        id: ID!
        email: String!
    }
    type Mutation {
        inviteMember(email: String!, orgId: ID!): Boolean!
    }
    type Subscription {
        memberJoined: User!
    }
    """
    schema = build_schema(mock_sdl)
    intro_data = graphql_sync(schema, get_introspection_query()).data

    def intro_handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            body = json.loads(request.read())
            q = body.get("query", "")
            if "__typename" in q:
                return httpx.Response(200, json={"data": {"__typename": "Query"}})
            if "__schema" in q:
                return httpx.Response(200, json={"data": intro_data})
        return httpx.Response(404)

    intro_transport = httpx.MockTransport(intro_handler)
    async with httpx.AsyncClient(transport=intro_transport) as client:
        intro_res = await prober.run_introspection("http://test/graphql", client=client)
        assert intro_res.is_active is True
        assert intro_res.introspection_enabled is True
        assert intro_res.schema_sdl is not None
        assert "type Query" in intro_res.schema_sdl
        assert "type Mutation" in intro_res.schema_sdl
        assert "type Subscription" in intro_res.schema_sdl
        assert sorted(intro_res.query_fields) == ["members", "organization"]
        assert intro_res.mutation_fields == ["inviteMember"]
        assert intro_res.subscription_fields == ["memberJoined"]
        assert intro_res.types_count >= 5
        print(f"[PASS] 4. Schema introspection & SDL generation: {intro_res.types_count} types, "
              f"queries={intro_res.query_fields}, mutations={intro_res.mutation_fields}")

    # 5. Test disabled introspection handling
    def disabled_handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            body = json.loads(request.read())
            q = body.get("query", "")
            if "__typename" in q:
                return httpx.Response(200, json={"data": {"__typename": "Query"}})
            if "__schema" in q:
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

    disabled_transport = httpx.MockTransport(disabled_handler)
    async with httpx.AsyncClient(transport=disabled_transport) as client:
        dis_res = await prober.run_introspection("http://test/graphql", client=client)
        assert dis_res.is_active is True
        assert dis_res.introspection_enabled is False
        assert dis_res.schema_sdl is None
        assert dis_res.error is not None
        assert "GraphQL introspection is not allowed" in dis_res.error
        print(f"[PASS] 5. Disabled introspection handling gracefully: error='{dis_res.error}'")

    # 6. Test discover_and_probe combining candidates and probing
    def discover_handler(request: httpx.Request) -> httpx.Response:
        p = request.url.path
        if p == "/api/v1/graphql":
            if request.method == "POST":
                body = json.loads(request.read())
                if "__typename" in body.get("query", ""):
                    return httpx.Response(200, json={"data": {"__typename": "Query"}})
                if "__schema" in body.get("query", ""):
                    return httpx.Response(200, json={"data": intro_data})
        return httpx.Response(404)

    disc_transport = httpx.MockTransport(discover_handler)
    async with httpx.AsyncClient(transport=disc_transport) as client:
        results = await prober.discover_and_probe(
            base_url="http://testservice",
            candidate_endpoints=["/api/v1/graphql"],
            client=client,
            active_only=True,
        )
        assert len(results) == 1
        assert results[0].endpoint_url == "http://testservice/api/v1/graphql"
        assert results[0].is_active is True
        assert results[0].introspection_enabled is True
        print(f"[PASS] 6. discover_and_probe: successfully discovered and introspected {results[0].endpoint_url}")

    print("\nALL VERIFICATION CHECKS COMPLETED SUCCESSFULLY!")


if __name__ == "__main__":
    asyncio.run(main())
