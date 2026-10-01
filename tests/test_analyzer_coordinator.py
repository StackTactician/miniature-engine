"""
Unit and integration tests for api_tool.analyzer.coordinator (StaticAnalyzer & StaticAnalysisResult).
Tests:
- StaticAnalysisResult dataclass, serialization, to_dict, to_json
- Synchronous analyze_code:
  - REST endpoints extraction
  - Client configurations discovery (Axios, Ky, ofetch, env vars)
  - Next.js Server Actions extraction
  - GraphQL operations extraction
  - Inline source map unpacking & original file inspection
  - Base URL resolution & deduplication
- Asynchronous analyze_script:
  - Single script bundle fetching & analysis
  - Remote source map fetching (comment URL & probing)
  - Unpacked sourcesContent deep analysis
  - Error and 404 handling
- Asynchronous analyze_scripts:
  - Concurrent multi-script analysis with semaphore bounding
  - Aggregation and deduplication across multiple bundles
"""

import asyncio
import base64
import json
import unittest
import httpx

from api_tool.analyzer.coordinator import StaticAnalyzer, StaticAnalysisResult
from api_tool.models import DiscoveredEndpoint, GraphQLOperation
from api_tool.analyzer.sourcemap import SourceMapResult, SourceMapFile


class TestStaticAnalysisResult(unittest.TestCase):
    def test_defaults_and_to_dict(self):
        res = StaticAnalysisResult()
        self.assertEqual(res.endpoints, [])
        self.assertEqual(res.graphql_operations, [])
        self.assertEqual(res.base_urls, [])
        self.assertEqual(res.source_map_results, [])
        self.assertEqual(res.client_configs, {})

        d = res.to_dict()
        self.assertIn("endpoints", d)
        self.assertIn("graphql_operations", d)
        self.assertIn("base_urls", d)
        self.assertIn("source_map_results", d)
        self.assertIn("client_configs", d)
        self.assertEqual(d["endpoints"], [])

    def test_serialization_with_data(self):
        ep = DiscoveredEndpoint(
            path="/api/v1/users",
            method="GET",
            base_url="https://api.example.com",
            tags=["users"],
        )
        gql = GraphQLOperation(
            operation_type="query",
            operation_name="GetViewer",
            query_string="query GetViewer { viewer { id } }",
            endpoint="/graphql",
        )
        sm = SourceMapResult(js_url="https://example.com/app.js", discovery_source="inline")
        res = StaticAnalysisResult(
            endpoints=[ep],
            graphql_operations=[gql],
            base_urls=["https://api.example.com"],
            source_map_results=[sm],
            client_configs={"base_urls": ["https://api.example.com"], "axios": []},
        )

        d = res.to_dict()
        self.assertEqual(len(d["endpoints"]), 1)
        self.assertEqual(d["endpoints"][0]["path"], "/api/v1/users")
        self.assertEqual(d["endpoints"][0]["full_url"], "https://api.example.com/api/v1/users")
        self.assertEqual(len(d["graphql_operations"]), 1)
        self.assertEqual(d["graphql_operations"][0]["operation_name"], "GetViewer")
        self.assertEqual(len(d["source_map_results"]), 1)

        # to_json test
        json_str = res.to_json()
        parsed = json.loads(json_str)
        self.assertEqual(parsed["endpoints"][0]["path"], "/api/v1/users")


class TestStaticAnalyzerAnalyzeCode(unittest.TestCase):
    def setUp(self):
        self.analyzer = StaticAnalyzer()

    def test_empty_or_invalid_code(self):
        res1 = self.analyzer.analyze_code("")
        self.assertEqual(res1.endpoints, [])
        self.assertEqual(res1.graphql_operations, [])
        self.assertEqual(res1.base_urls, [])

        res2 = self.analyzer.analyze_code(None)  # type: ignore
        self.assertEqual(res2.endpoints, [])

    def test_rest_endpoints_and_method_inference(self):
        code = """
        const res1 = await fetch('/api/v1/users', { method: 'GET' });
        const res2 = await axios.post('/api/v1/login', { username, password });
        const res3 = await ky.delete('/api/v1/posts/42');
        """
        res = self.analyzer.analyze_code(code, base_url="https://app.test")

        self.assertGreaterEqual(len(res.endpoints), 3)
        paths_methods = {(e.path, e.method) for e in res.endpoints}
        self.assertIn(("/api/v1/users", "GET"), paths_methods)
        self.assertIn(("/api/v1/login", "POST"), paths_methods)
        self.assertIn(("/api/v1/posts/42", "DELETE"), paths_methods)

        for ep in res.endpoints:
            self.assertEqual(ep.base_url, "https://app.test")
            self.assertTrue(ep.full_url.startswith("https://app.test/api/v1/"))

    def test_client_configs_extraction(self):
        code = """
        const api = axios.create({ baseURL: 'https://backend.acme.org/api' });
        const client = ky.create({ prefixUrl: 'https://ky.acme.org' });
        const f = ofetch.create({ baseURL: '/internal/fetch' });
        const NEXT_PUBLIC_API_URL = "https://env.acme.org";
        """
        res = self.analyzer.analyze_code(code, base_url="https://app.test")

        self.assertIn("https://backend.acme.org/api", res.client_configs["axios"])
        self.assertIn("https://ky.acme.org", res.client_configs["ky"])
        self.assertIn("/internal/fetch", res.client_configs["ofetch"])
        self.assertIn("NEXT_PUBLIC_API_URL", res.client_configs["env_vars"])

        # Base URLs list should contain base_url and discovered base URLs
        self.assertIn("https://app.test", res.base_urls)
        self.assertIn("https://backend.acme.org/api", res.base_urls)
        self.assertIn("https://ky.acme.org", res.base_urls)
        # Relative client config (/internal/fetch) resolved against base_url
        self.assertIn("https://app.test/internal/fetch", res.base_urls)

    def test_server_actions_extraction(self):
        action_id_1 = "a" * 40
        action_id_2 = "b" * 40
        code = f"""
        const act1 = createServerReference("{action_id_1}");
        const act2 = (0, r.createServerReference)("{action_id_2}");
        """
        res = self.analyzer.analyze_code(code, base_url="https://next.app")

        actions = [e for e in res.endpoints if "server_action" in e.tags]
        self.assertEqual(len(actions), 2)
        action_headers = {e.headers.get("Next-Action") for e in actions}
        self.assertIn(action_id_1, action_headers)
        self.assertIn(action_id_2, action_headers)
        for act in actions:
            self.assertEqual(act.method, "POST")
            self.assertEqual(act.base_url, "https://next.app")

    def test_graphql_operations_extraction(self):
        code = """
        const GET_USER = gql`
            query GetUser($id: ID!) {
                user(id: $id) {
                    id
                    name
                }
            }
        `;
        const MUTATE_USER = gql`
            mutation UpdateUser($name: String!) {
                updateUser(name: $name) {
                    id
                }
            }
        `;
        """
        res = self.analyzer.analyze_code(code, base_url="https://gql.app")

        self.assertEqual(len(res.graphql_operations), 2)
        op_types = {op.operation_type for op in res.graphql_operations}
        op_names = {op.operation_name for op in res.graphql_operations}
        self.assertIn("query", op_types)
        self.assertIn("mutation", op_types)
        self.assertIn("GetUser", op_names)
        self.assertIn("UpdateUser", op_names)

    def test_inline_source_map_extraction_and_unpacked_analysis(self):
        # Create an inline source map containing an original TypeScript file
        original_ts = """
        const userApi = '/api/v2/members';
        export async function fetchMembers() {
            return fetch(userApi);
        }
        export const ACTION = createServerReference("c" * 40);
        const GET_SETTINGS = gql`
            query GetSettings {
                settings {
                    theme
                }
            }
        `;
        """.replace('"c" * 40', '"' + 'c' * 40 + '"')

        map_dict = {
            "version": 3,
            "sources": ["src/app/api/auth/route.ts", "src/services/memberService.ts"],
            "sourcesContent": [
                "export async function GET() {}\nexport async function POST() {}",
                original_ts,
            ],
        }
        b64_map = base64.b64encode(json.dumps(map_dict).encode("utf-8")).decode("utf-8")
        bundle_code = f"""
        console.log("bundle running");
        fetch('/api/bundle/health');
        //# sourceMappingURL=data:application/json;base64,{b64_map}
        """

        res = self.analyzer.analyze_code(bundle_code, base_url="https://example.com")

        # Source map results present
        self.assertEqual(len(res.source_map_results), 1)
        self.assertEqual(res.source_map_results[0].discovery_source, "inline")

        # Check endpoints discovered from route file (src/app/api/auth/route.ts)
        route_endpoints = [e for e in res.endpoints if e.path == "/api/auth"]
        self.assertGreaterEqual(len(route_endpoints), 2)
        route_methods = {e.method for e in route_endpoints}
        self.assertIn("GET", route_methods)
        self.assertIn("POST", route_methods)

        # Check endpoint discovered from unpacked memberService.ts
        member_endpoints = [e for e in res.endpoints if e.path == "/api/v2/members"]
        self.assertEqual(len(member_endpoints), 1)

        # Check Server Action from unpacked memberService.ts
        actions = [e for e in res.endpoints if e.headers.get("Next-Action") == "c" * 40]
        self.assertEqual(len(actions), 1)

        # Check GraphQL operation from unpacked memberService.ts
        gql_names = [g.operation_name for g in res.graphql_operations]
        self.assertIn("GetSettings", gql_names)

    def test_deduplication(self):
        # Code containing identical endpoints called multiple times
        code = """
        fetch('/api/v1/items');
        axios.get('/api/v1/items');
        window.fetch('/api/v1/items');
        const Q1 = gql`query TestQ { id }`;
        const Q2 = gql`query TestQ { id }`;
        """
        res = self.analyzer.analyze_code(code, base_url="https://dedup.test")

        items_eps = [e for e in res.endpoints if e.path == "/api/v1/items" and e.method == "GET"]
        self.assertEqual(len(items_eps), 1)

        test_gql = [g for g in res.graphql_operations if g.operation_name == "TestQ"]
        self.assertEqual(len(test_gql), 1)


class TestStaticAnalyzerAsyncScript(unittest.TestCase):
    def setUp(self):
        self.analyzer = StaticAnalyzer(request_timeout=5.0)

    def test_analyze_script_remote_sourcemap_comment(self):
        map_json = json.dumps({
            "version": 3,
            "sources": ["src/app/api/checkout/route.ts", "src/client.ts"],
            "sourcesContent": [
                "export async function POST() {}",
                "export const API = '/api/client/orders';\nfetch(API);",
            ],
        })

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url == httpx.URL("https://example.com/static/bundle.js"):
                return httpx.Response(
                    200,
                    text="fetch('/api/v1/status');\n//# sourceMappingURL=bundle.js.map",
                )
            elif request.url == httpx.URL("https://example.com/static/bundle.js.map"):
                return httpx.Response(200, headers={"Content-Type": "application/json"}, text=map_json)
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport)

        async def run():
            return await self.analyzer.analyze_script(
                "https://example.com/static/bundle.js",
                base_url="https://example.com",
                client=client,
            )

        res = asyncio.run(run())

        self.assertEqual(len(res.source_map_results), 1)
        self.assertEqual(res.source_map_results[0].discovery_source, "comment")

        paths = {e.path for e in res.endpoints}
        self.assertIn("/api/v1/status", paths)
        self.assertIn("/api/checkout", paths)
        self.assertIn("/api/client/orders", paths)

    def test_analyze_script_probe_hidden_sourcemap(self):
        map_json = json.dumps({
            "version": 3,
            "sources": ["src/hidden/secret.ts"],
            "sourcesContent": ["const SECRET_ENDPOINT = '/api/internal/secrets'; fetch(SECRET_ENDPOINT);"],
        })

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url == httpx.URL("https://example.com/app.min.js"):
                # No sourceMappingURL comment in JS bundle
                return httpx.Response(200, text="console.log('minified bundle');")
            elif request.url == httpx.URL("https://example.com/app.min.js.map"):
                return httpx.Response(200, headers={"Content-Type": "application/json"}, text=map_json)
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport)

        async def run():
            return await self.analyzer.analyze_script(
                "https://example.com/app.min.js",
                base_url="https://example.com",
                client=client,
            )

        res = asyncio.run(run())
        self.assertEqual(len(res.source_map_results), 1)
        self.assertEqual(res.source_map_results[0].discovery_source, "probe")

        paths = {e.path for e in res.endpoints}
        self.assertIn("/api/internal/secrets", paths)

    def test_analyze_script_404_error(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport)

        async def run():
            return await self.analyzer.analyze_script(
                "https://example.com/notfound.js",
                base_url="https://example.com",
                client=client,
            )

        res = asyncio.run(run())
        self.assertEqual(res.endpoints, [])
        self.assertEqual(res.source_map_results, [])

    def test_analyze_script_empty_url(self):
        res = asyncio.run(self.analyzer.analyze_script(""))
        self.assertEqual(res.endpoints, [])


class TestStaticAnalyzerAsyncScripts(unittest.TestCase):
    def setUp(self):
        self.analyzer = StaticAnalyzer(concurrency=3)

    def test_analyze_scripts_concurrent(self):
        def handler(request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            if url_str == "https://example.com/chunk1.js":
                return httpx.Response(200, text="fetch('/api/v1/chunk1'); axios.create({ baseURL: 'https://api1.com' });")
            elif url_str == "https://example.com/chunk2.js":
                return httpx.Response(200, text="fetch('/api/v1/chunk2'); const Q = gql`query Q2 { id }`;")
            elif url_str == "https://example.com/chunk3.js":
                return httpx.Response(200, text="fetch('/api/v1/chunk1');")  # Duplicate endpoint
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport)

        scripts = [
            "https://example.com/chunk1.js",
            "https://example.com/chunk2.js",
            "https://example.com/chunk3.js",
        ]

        async def run():
            return await self.analyzer.analyze_scripts(
                scripts,
                base_url="https://example.com",
                concurrency=2,
                client=client,
            )

        res = asyncio.run(run())

        # Should have deduplicated /api/v1/chunk1
        chunk1_eps = [e for e in res.endpoints if e.path == "/api/v1/chunk1"]
        self.assertEqual(len(chunk1_eps), 1)

        chunk2_eps = [e for e in res.endpoints if e.path == "/api/v1/chunk2"]
        self.assertEqual(len(chunk2_eps), 1)

        # GraphQL operations from chunk 2
        q2_ops = [g for g in res.graphql_operations if g.operation_name == "Q2"]
        self.assertEqual(len(q2_ops), 1)

        # Discovered base URLs
        self.assertIn("https://example.com", res.base_urls)
        self.assertIn("https://api1.com", res.base_urls)

    def test_analyze_scripts_empty_list(self):
        res = asyncio.run(self.analyzer.analyze_scripts([]))
        self.assertEqual(res.endpoints, [])


if __name__ == "__main__":
    unittest.main()
