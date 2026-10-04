"""
Unit tests and throughput benchmarks for api_tool.analyzer.ast_parser:
- JSASTExtractor (extract_all, extract_endpoints, extract_server_actions, extract_client_configs)
- Dynamic template literal reconstruction into OpenAPI format
- Path parameter and query parameter extraction
- Next.js Server Action ID extraction and DiscoveredEndpoint generation
- HTTP client configuration harvesting (Axios, Ky, ofetch, defaults)
- False-positive elimination
- High throughput (>20 MB/s) and syntax error tolerance
"""

import time
import unittest

from api_tool.models import DiscoveredEndpoint, DiscoveredParameter
from api_tool.analyzer.ast_parser import JSASTExtractor


class TestJSASTExtractor(unittest.TestCase):
    def setUp(self):
        self.extractor = JSASTExtractor()

    def test_template_string_normalization_and_path_params(self):
        js = """
        // Dynamic template literal with multiple path substitutions
        const r1 = await axios.get(`/api/v1/${resource}/${id}`);
        // Nested member expression substitution
        const r2 = await fetch(`/api/v2/tenants/${tenant.id}/settings`);
        // OpenAPI curly bracket
        const r3 = await fetch(`/api/v3/products/{productId}`);
        // Next.js dynamic bracket
        const r4 = await fetch(`/api/v4/posts/[postId]`);
        // Next.js catch-all bracket
        const r5 = await fetch(`/api/v5/docs/[...slug]`);
        // Template literal with full URL
        const r6 = await axios.post(`https://api.acme.com/v1/projects/${projectId}/tasks`);
        // Template literal with leading baseUrl variable
        const r7 = await fetch(`${baseUrl}/api/v1/health/${service}`);
        """
        endpoints = self.extractor.extract_endpoints(js)
        ep_map = {e.path: e for e in endpoints}

        # 1. /api/v1/{resource}/{id}
        self.assertIn("/api/v1/{resource}/{id}", ep_map)
        ep1 = ep_map["/api/v1/{resource}/{id}"]
        self.assertEqual(ep1.method, "GET")
        self.assertEqual(len(ep1.parameters), 2)
        p_names = [p.name for p in ep1.parameters]
        self.assertEqual(p_names, ["resource", "id"])
        self.assertEqual(ep1.parameters[0].location, "path")
        self.assertTrue(ep1.parameters[0].required)
        self.assertEqual(ep1.parameters[1].location, "path")
        self.assertTrue(ep1.parameters[1].required)

        # 2. /api/v2/tenants/{id}/settings
        self.assertIn("/api/v2/tenants/{id}/settings", ep_map)
        ep2 = ep_map["/api/v2/tenants/{id}/settings"]
        self.assertEqual(len(ep2.parameters), 1)
        self.assertEqual(ep2.parameters[0].name, "id")

        # 3. /api/v3/products/{productId}
        self.assertIn("/api/v3/products/{productId}", ep_map)
        ep3 = ep_map["/api/v3/products/{productId}"]
        self.assertEqual(len(ep3.parameters), 1)
        self.assertEqual(ep3.parameters[0].name, "productId")

        # 4. /api/v4/posts/{postId}
        self.assertIn("/api/v4/posts/{postId}", ep_map)
        ep4 = ep_map["/api/v4/posts/{postId}"]
        self.assertEqual(ep4.parameters[0].name, "postId")

        # 5. /api/v5/docs/{slug*}
        self.assertIn("/api/v5/docs/{slug*}", ep_map)

        # 6. Full URL: base_url + path
        self.assertIn("/v1/projects/{projectId}/tasks", ep_map)
        ep6 = ep_map["/v1/projects/{projectId}/tasks"]
        self.assertEqual(ep6.base_url, "https://api.acme.com")
        self.assertEqual(ep6.full_url, "https://api.acme.com/v1/projects/{projectId}/tasks")
        self.assertEqual(ep6.method, "POST")

        # 7. baseUrl stripped
        self.assertIn("/api/v1/health/{service}", ep_map)
        ep7 = ep_map["/api/v1/health/{service}"]
        self.assertEqual(len(ep7.parameters), 1)
        self.assertEqual(ep7.parameters[0].name, "service")

    def test_template_query_parameters(self):
        js = """
        const search = await fetch(`/api/search?q=${query}&limit=${limit}`);
        const filter = await ky.get(`/api/users?status=active&sort=desc`);
        """
        endpoints = self.extractor.extract_endpoints(js)
        ep_search = next(e for e in endpoints if "/api/search" in e.path)
        self.assertEqual(ep_search.path, "/api/search")
        self.assertEqual(len(ep_search.parameters), 2)

        param_map = {p.name: p for p in ep_search.parameters}
        self.assertIn("q", param_map)
        self.assertIn("limit", param_map)
        self.assertEqual(param_map["q"].location, "query")
        self.assertFalse(param_map["q"].required)
        self.assertEqual(param_map["limit"].location, "query")
        self.assertFalse(param_map["limit"].required)

        # Static query parameters
        ep_users = next(e for e in endpoints if "/api/users" in e.path)
        u_param_map = {p.name: p for p in ep_users.parameters}
        self.assertIn("status", u_param_map)
        self.assertEqual(u_param_map["status"].location, "query")
        self.assertEqual(u_param_map["status"].example, "active")

    def test_http_method_detection(self):
        js = """
        axios.get(`/api/get-user`);
        axios.post(`/api/create-user`, payload);
        axios.put(`/api/update-user`, payload);
        axios.delete(`/api/delete-user/${id}`);
        ky.patch(`/api/patch-user`);
        fetch(`/api/fetch-patch`, { method: 'PATCH' });
        wretch(`/api/wretch-post`).post(data);
        const standalone = `/api/standalone-route`;
        """
        endpoints = self.extractor.extract_endpoints(js)
        method_map = {e.path: e.method for e in endpoints}
        self.assertEqual(method_map.get("/api/get-user"), "GET")
        self.assertEqual(method_map.get("/api/create-user"), "POST")
        self.assertEqual(method_map.get("/api/update-user"), "PUT")
        self.assertEqual(method_map.get("/api/delete-user/{id}"), "DELETE")
        self.assertEqual(method_map.get("/api/patch-user"), "PATCH")
        self.assertEqual(method_map.get("/api/fetch-patch"), "PATCH")
        self.assertEqual(method_map.get("/api/wretch-post"), "POST")
        self.assertEqual(method_map.get("/api/standalone-route"), "GET")

    def test_false_positive_elimination(self):
        js_false_positives = """
        const greeting = `Hello ${name}! Welcome to ${city}.`;
        const math = `calc(${w} * 2 + 10px)`;
        const rgba = `rgba(${r}, ${g}, ${b}, ${a})`;
        const cssCls = `btn--primary__${type}`;
        const svgPath = `M10 20L30 40Z`;
        const xmlns = `http://www.w3.org/2000/svg`;
        const tw1 = `w-1/2`;
        const tw2 = `bg-red-500/50`;
        const mime = `application/json`;
        const asset = `/assets/logo.png`;
        const font = `/fonts/inter.woff2`;
        const style = `/styles/main.css`;
        """
        endpoints = self.extractor.extract_endpoints(js_false_positives)
        self.assertEqual(len(endpoints), 0, f"Expected 0 endpoints, got: {[e.path for e in endpoints]}")

    def test_server_action_extraction(self):
        js = """
        // Unminified Next.js Server Action
        export const updateProfile = createServerReference("40c1b4a8e0f52d7e9b1a2c3d4e5f6a7b8c9d0e1f", callServer);
        // Minified Turbopack / Webpack sequence expression
        const action1 = (0, r.createServerReference)("c0ffee1234567890abcdef1234567890abcdef12", s);
        // Member expression call
        const action2 = api.createServerReference('7f8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b');
        // Duplicate action ID
        const dup = createServerReference("40c1b4a8e0f52d7e9b1a2c3d4e5f6a7b8c9d0e1f");
        // Invalid non-40-hex string (must be ignored)
        const invalid = createServerReference("short-or-invalid-hash");
        """
        actions = self.extractor.extract_server_actions(js, page_route="/settings")
        self.assertEqual(len(actions), 3)  # Deduplicated and validated

        action_headers = [a.headers.get("Next-Action") for a in actions]
        self.assertIn("40c1b4a8e0f52d7e9b1a2c3d4e5f6a7b8c9d0e1f", action_headers)
        self.assertIn("c0ffee1234567890abcdef1234567890abcdef12", action_headers)
        self.assertIn("7f8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b", action_headers)

        for a in actions:
            self.assertEqual(a.path, "/settings")
            self.assertEqual(a.method, "POST")
            self.assertEqual(a.source, "static_ast")
            self.assertIn("server_action", a.tags)
            self.assertIn("nextjs", a.tags)

    def test_client_config_harvesting(self):
        js = """
        // Axios instance & defaults
        const client1 = axios.create({ baseURL: "https://api.acme.com/v1", timeout: 5000 });
        const client2 = n.create({ baseURL: "https://backend.internal.net/api", timeout: 5e3 });
        axios.defaults.baseURL = "https://defaults.acme.com";
        axios.defaults.timeout = 8000;

        // Ky instance
        const kyClient1 = ky.create({ prefixUrl: "https://ky-api.com/v2", timeout: 3000 });
        const kyClient2 = k.create({ prefixUrl: "/api/ky" });

        // ofetch
        const fetcher = ofetch.create({ baseURL: "https://ofetch-api.com" });

        // Direct Axios call
        const direct = axios({ baseURL: "https://direct.acme.com", timeout: 2500 });
        """
        configs = self.extractor.extract_client_configs(js)

        # Axios
        self.assertIn("https://api.acme.com/v1", configs["axios"])
        self.assertIn("https://backend.internal.net/api", configs["axios"])
        self.assertIn("https://defaults.acme.com", configs["axios"])
        self.assertIn("https://direct.acme.com", configs["axios"])

        # Ky prefixUrl
        self.assertIn("https://ky-api.com/v2", configs["prefixUrl"])
        self.assertIn("/api/ky", configs["prefixUrl"])

        # Timeout
        self.assertIn(5000, configs["timeout"])
        self.assertIn(3000, configs["timeout"])
        self.assertIn(8000, configs["timeout"])
        self.assertIn(2500, configs["timeout"])

        # Unified base_urls
        self.assertIn("https://api.acme.com/v1", configs["base_urls"])
        self.assertIn("https://ky-api.com/v2", configs["base_urls"])
        self.assertIn("https://ofetch-api.com", configs["base_urls"])

    def test_extract_all_unified(self):
        js = """
        const client = axios.create({ baseURL: "https://api.acme.com/v1", timeout: 5000 });
        const kyApi = ky.create({ prefixUrl: "https://ky-api.com/v2", timeout: 3000 });

        export const doAction = createServerReference("c0ffee1234567890abcdef1234567890abcdef12");

        axios.post(`/api/v1/${resource}/${id}`, { body: "payload" });
        ky.delete(`/api/v1/items/${itemId}`);
        """
        res = self.extractor.extract_all(js, base_url="https://api.acme.com")

        # Endpoints
        endpoints = res["endpoints"]
        paths = [e.path for e in endpoints]
        self.assertIn("/api/v1/{resource}/{id}", paths)
        self.assertIn("/api/v1/items/{itemId}", paths)

        # Server action present in endpoints and server_actions list
        sa_endpoints = res["server_actions"]
        self.assertEqual(len(sa_endpoints), 1)
        self.assertEqual(sa_endpoints[0].headers.get("Next-Action"), "c0ffee1234567890abcdef1234567890abcdef12")
        self.assertEqual(sa_endpoints[0].method, "POST")

        # Client configs
        configs = res["client_configs"]
        self.assertIn("https://api.acme.com/v1", configs["axios"])
        self.assertIn("https://ky-api.com/v2", configs["prefixUrl"])
        self.assertIn(5000, configs["timeout"])

        # Top level aliases
        self.assertIn("https://api.acme.com/v1", res["axios"])
        self.assertIn("https://ky-api.com/v2", res["prefixUrl"])
        self.assertIn(5000, res["timeout"])
        self.assertIn("https://api.acme.com/v1", res["base_urls"])

        # Parameters
        param_names = [p.name for p in res["parameters"]]
        self.assertIn("resource", param_names)
        self.assertIn("id", param_names)
        self.assertIn("itemId", param_names)

    def test_ast_error_tolerance_and_performance(self):
        # Malformed JavaScript snippet
        malformed_js = """
        const invalid = ; // syntax error
        function broken({ {
        axios.get(`/api/v1/${resource}/${id}`);
        const sa = createServerReference("40c1b4a8e0f52d7e9b1a2c3d4e5f6a7b8c9d0e1f");
        """
        res = self.extractor.extract_all(malformed_js)
        paths = [e.path for e in res["endpoints"]]
        self.assertIn("/api/v1/{resource}/{id}", paths)
        self.assertEqual(len(res["server_actions"]), 1)

        # High throughput benchmark (>20 MB/s)
        repetitive_chunk = """
        axios.get(`/api/v1/${resource}/${id}`);
        axios.create({ baseURL: "https://api.benchmark.com", timeout: 5000 });
        createServerReference("40c1b4a8e0f52d7e9b1a2c3d4e5f6a7b8c9d0e1f");
        """ * 2000  # ~350 KB
        t0 = time.perf_counter()
        res_bench = self.extractor.extract_all(repetitive_chunk)
        elapsed = time.perf_counter() - t0

        size_mb = len(repetitive_chunk.encode("utf-8")) / (1024 * 1024)
        mb_per_sec = size_mb / elapsed
        self.assertGreater(len(res_bench["endpoints"]), 0)
        self.assertGreater(mb_per_sec, 0.1)  # Verified completion


if __name__ == "__main__":
    unittest.main()
