"""
Unit tests and ReDoS benchmarks for api_tool.analyzer.js_regex:
- JSRegexExtractor (extract_endpoints, extract_client_configs, extract_server_actions)
- Multi-stage false-positive filtering
- Linear O(N) execution guarantees (STRICTLY NO catastrophic backtracking / ReDoS)
"""

import time
import unittest

from api_tool.models import DiscoveredEndpoint, DiscoveredParameter
from api_tool.analyzer.js_regex import JSRegexExtractor, shannon_entropy


class TestJSRegexExtractor(unittest.TestCase):
    def setUp(self):
        self.extractor = JSRegexExtractor()

    def test_extract_endpoints_rest_and_full_urls(self):
        js = """
        const users = await fetch('/api/v1/users');
        const login = await axios.post("https://auth.acme.com/oauth/token", { user, pass });
        const orders = await ky.get('/v2/orders/recent');
        const internal = await fetch('api/v1/internal/health');
        """
        endpoints = self.extractor.extract_endpoints(js)
        paths = [e.path for e in endpoints]
        self.assertIn("/api/v1/users", paths)
        self.assertIn("/oauth/token", paths)
        self.assertIn("/v2/orders/recent", paths)
        self.assertIn("/api/v1/internal/health", paths)

        # Check full URL resolution
        auth_ep = next(e for e in endpoints if e.path == "/oauth/token")
        self.assertEqual(auth_ep.base_url, "https://auth.acme.com")
        self.assertEqual(auth_ep.method, "POST")
        self.assertEqual(auth_ep.full_url, "https://auth.acme.com/oauth/token")

    def test_extract_path_parameters(self):
        js = """
        // Express route param
        const r1 = await axios.get("/api/v1/users/:userId/profile");
        // Template literal
        const r2 = await ky.delete(`/api/v1/items/${itemId}`);
        const r3 = await fetch(`/api/v2/tenants/${tenant.id}/settings`);
        // OpenAPI curly bracket
        const r4 = await fetch('/api/v3/products/{productId}');
        // Next.js dynamic route
        const r5 = await fetch('/api/v4/posts/[postId]');
        """
        endpoints = self.extractor.extract_endpoints(js)
        ep_map = {e.path: e for e in endpoints}

        # Express: :userId -> {userId}
        self.assertIn("/api/v1/users/{userId}/profile", ep_map)
        ep1 = ep_map["/api/v1/users/{userId}/profile"]
        self.assertEqual(len(ep1.parameters), 1)
        self.assertEqual(ep1.parameters[0].name, "userId")
        self.assertEqual(ep1.parameters[0].location, "path")
        self.assertTrue(ep1.parameters[0].required)

        # Template literal: ${itemId} -> {itemId}
        self.assertIn("/api/v1/items/{itemId}", ep_map)
        ep2 = ep_map["/api/v1/items/{itemId}"]
        self.assertEqual(ep2.method, "DELETE")
        self.assertEqual(ep2.parameters[0].name, "itemId")

        # Nested template literal: ${tenant.id} -> {id}
        self.assertIn("/api/v2/tenants/{id}/settings", ep_map)
        ep3 = ep_map["/api/v2/tenants/{id}/settings"]
        self.assertEqual(ep3.parameters[0].name, "id")

        # OpenAPI bracket: {productId}
        self.assertIn("/api/v3/products/{productId}", ep_map)
        ep4 = ep_map["/api/v3/products/{productId}"]
        self.assertEqual(ep4.parameters[0].name, "productId")

        # Next.js dynamic bracket: [postId] -> {postId}
        self.assertIn("/api/v4/posts/{postId}", ep_map)
        ep5 = ep_map["/api/v4/posts/{postId}"]
        self.assertEqual(ep5.parameters[0].name, "postId")

    def test_extract_query_parameters(self):
        js = """
        const search = await fetch('/api/search?q=cyber&category=security&limit=25');
        const filter = await ky.get('/api/users?status=active');
        """
        endpoints = self.extractor.extract_endpoints(js)
        ep_search = next(e for e in endpoints if "/api/search" in e.path)
        self.assertEqual(len(ep_search.parameters), 3)

        param_names = [p.name for p in ep_search.parameters]
        self.assertIn("q", param_names)
        self.assertIn("category", param_names)
        self.assertIn("limit", param_names)

        q_param = next(p for p in ep_search.parameters if p.name == "q")
        self.assertEqual(q_param.location, "query")
        self.assertEqual(q_param.example, "cyber")

    def test_method_detection(self):
        js = """
        axios.post('/api/create-user', payload);
        axios.put("/api/update-user", payload);
        axios.delete(`/api/delete-user`);
        axios.patch('/api/patch-user', payload);
        ky.post('/api/ky-post');
        wretch('/api/wretch-post').post(data);
        fetch('/api/fetch-post', { method: 'POST', body });
        fetch('/api/fetch-get');
        """
        endpoints = self.extractor.extract_endpoints(js)
        method_map = {e.path: e.method for e in endpoints}
        self.assertEqual(method_map.get("/api/create-user"), "POST")
        self.assertEqual(method_map.get("/api/update-user"), "PUT")
        self.assertEqual(method_map.get("/api/delete-user"), "DELETE")
        self.assertEqual(method_map.get("/api/patch-user"), "PATCH")
        self.assertEqual(method_map.get("/api/ky-post"), "POST")
        self.assertEqual(method_map.get("/api/wretch-post"), "POST")
        self.assertEqual(method_map.get("/api/fetch-post"), "POST")
        self.assertEqual(method_map.get("/api/fetch-get"), "GET")

    def test_false_positive_elimination(self):
        js_false_positives = """
        const svgPath1 = "M10 20L30 40Z";
        const svgPath2 = "M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z";
        const xmlns1 = "http://www.w3.org/2000/svg";
        const xmlns2 = "http://www.w3.org/1999/xlink";
        const tw1 = "w-1/2";
        const tw2 = "aspect-16/9";
        const tw3 = "inset-x-1/2";
        const tw4 = "translate-x-1/2";
        const tw5 = "bg-red-500/50";
        const tw6 = "text-black/75";
        const tw7 = "border-white/20";
        const frac1 = "/1/2";
        const frac2 = "/16/9";
        const cssMod = "styles._header_1x8q9_12";
        const bem = "btn--primary__icon";
        const mime1 = "application/json";
        const mime2 = "/application/json";
        const mime3 = "image/svg+xml";
        const mime4 = "text/html";
        const uuid1 = "123e4567-e89b-12d3-a456-426614174000";
        const uuid2 = "/123e4567-e89b-12d3-a456-426614174000";
        const date1 = "YYYY/MM/DD";
        const date2 = "2026/09/30";
        const date3 = "/2026/09/30";
        const ast1 = "Identifier/Literal";
        const ast2 = "MemberExpression/CallExpression";
        const b64 = "/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAP//////////////////////////////////////////////////////////////////////////////////////";
        const b64Png = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=";
        const icon = "/assets/icon.png";
        const font = "/fonts/inter.woff2";
        const css = "/styles/app.css";
        """
        endpoints = self.extractor.extract_endpoints(js_false_positives)
        self.assertEqual(len(endpoints), 0, f"Expected 0 endpoints, got: {[e.path for e in endpoints]}")

    def test_extract_client_configs(self):
        js = """
        // Axios instance & defaults
        const client1 = axios.create({ baseURL: "https://api.acme.com/v1", timeout: 5000 });
        const client2 = n.create({baseURL:"https://backend.internal.net/api",timeout:5e3});
        axios.defaults.baseURL = "https://defaults.acme.com";

        // Ky instance
        const kyClient1 = ky.create({ prefixUrl: "https://ky-api.com/v2" });
        const kyClient2 = k.create({prefixUrl:"/api/ky"});
        const kyClient3 = ky.create({baseUrl:"https://ky-api2.com"});

        // ofetch
        const fetcher1 = ofetch.create({ baseURL: "https://ofetch-api.com" });
        const fetcher2 = $fetch.create({ baseURL: "/nuxt/api" });

        // Wretch
        const w1 = wretch("https://wretch-api.com/api").get();
        const w2 = wretch.url("https://wretch-url.com/v1");

        // tRPC links
        const link1 = httpBatchLink({ url: "https://trpc.acme.com/trpc" });
        const link2 = httpLink({ url: "/trpc/v1" });

        // Inlined environment variables
        const env1 = { NEXT_PUBLIC_API_URL: "https://next-api.acme.com/v1" };
        process.env.NEXT_PUBLIC_GATEWAY = "https://gateway.acme.com";
        import.meta.env.VITE_BACKEND_URL = "https://vite-api.acme.com";
        process.env["REACT_APP_API"] = "https://react-api.acme.com";
        """
        configs = self.extractor.extract_client_configs(js)

        # Axios
        self.assertIn("https://api.acme.com/v1", configs["axios"])
        self.assertIn("https://backend.internal.net/api", configs["axios"])
        self.assertIn("https://defaults.acme.com", configs["axios"])

        # Ky
        self.assertIn("https://ky-api.com/v2", configs["ky"])
        self.assertIn("/api/ky", configs["ky"])
        self.assertIn("https://ky-api2.com", configs["ky"])

        # ofetch
        self.assertIn("https://ofetch-api.com", configs["ofetch"])
        self.assertIn("/nuxt/api", configs["ofetch"])

        # Wretch
        self.assertIn("https://wretch-api.com/api", configs["wretch"])
        self.assertIn("https://wretch-url.com/v1", configs["wretch"])

        # tRPC
        self.assertIn("https://trpc.acme.com/trpc", configs["trpc"])
        self.assertIn("/trpc/v1", configs["trpc"])

        # Env vars
        self.assertEqual(configs["env_vars"].get("NEXT_PUBLIC_API_URL"), "https://next-api.acme.com/v1")
        self.assertEqual(configs["env_vars"].get("NEXT_PUBLIC_GATEWAY"), "https://gateway.acme.com")
        self.assertEqual(configs["env_vars"].get("VITE_BACKEND_URL"), "https://vite-api.acme.com")
        self.assertEqual(configs["env_vars"].get("REACT_APP_API"), "https://react-api.acme.com")

        # Merged base_urls
        self.assertIn("https://api.acme.com/v1", configs["base_urls"])
        self.assertIn("https://ky-api.com/v2", configs["base_urls"])
        self.assertIn("https://ofetch-api.com", configs["base_urls"])
        self.assertIn("https://next-api.acme.com/v1", configs["base_urls"])

    def test_extract_server_actions(self):
        js = """
        // Unminified
        export const updateUser = createServerReference("40c1b4a8e0f52d7e9b1a2c3d4e5f6a7b8c9d0e1f", callServer);
        // Minified Turbopack / Webpack
        const action1 = (0, r.createServerReference)("c0ffee1234567890abcdef1234567890abcdef12", s);
        // Another reference
        const action2 = (0, a.createServerReference)('7f8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b', callServer);
        // Duplicate action ID
        const dup = createServerReference("40c1b4a8e0f52d7e9b1a2c3d4e5f6a7b8c9d0e1f", callServer);
        """
        actions = self.extractor.extract_server_actions(js, page_route="/dashboard")
        self.assertEqual(len(actions), 3)  # Deduplicated

        action_headers = [a.headers.get("Next-Action") for a in actions]
        self.assertIn("40c1b4a8e0f52d7e9b1a2c3d4e5f6a7b8c9d0e1f", action_headers)
        self.assertIn("c0ffee1234567890abcdef1234567890abcdef12", action_headers)
        self.assertIn("7f8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b", action_headers)

        for a in actions:
            self.assertEqual(a.path, "/dashboard")
            self.assertEqual(a.method, "POST")
            self.assertEqual(a.source, "static_js")
            self.assertIn("server_action", a.tags)

    def test_redos_safety_linear_time(self):
        """
        Verify strict linear O(N) regex evaluation.
        Adversarial inputs designed to cause exponential catastrophic backtracking
        in non-linear engines must complete in milliseconds.
        """
        # Adversarial candidate 1: 50,000 slashes and characters without closing quote
        adversarial_input_1 = "'" + "/a" * 25000 + "!"
        t0 = time.perf_counter()
        res1 = self.extractor.extract_endpoints(adversarial_input_1)
        elapsed1 = time.perf_counter() - t0
        self.assertEqual(len(res1), 0)
        self.assertLess(elapsed1, 0.2, f"ReDoS suspected: took {elapsed1:.4f}s")

        # Adversarial candidate 2: 50,000 coordinates without closing quote
        adversarial_input_2 = '"' + "M0 0 " * 10000 + "Z"
        t0 = time.perf_counter()
        res2 = self.extractor.extract_endpoints(adversarial_input_2)
        elapsed2 = time.perf_counter() - t0
        self.assertEqual(len(res2), 0)
        self.assertLess(elapsed2, 0.2, f"ReDoS suspected: took {elapsed2:.4f}s")

        # Adversarial candidate 3: 50,000 chars of nested brackets / config lookalike
        adversarial_input_3 = "axios.create({ " + "baseURL: 'http://" * 2000 + "invalid"
        t0 = time.perf_counter()
        configs = self.extractor.extract_client_configs(adversarial_input_3)
        elapsed3 = time.perf_counter() - t0
        self.assertLess(elapsed3, 0.2, f"ReDoS suspected: took {elapsed3:.4f}s")


if __name__ == "__main__":
    unittest.main()
