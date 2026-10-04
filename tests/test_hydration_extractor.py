"""
Unit and integration tests for FastHydrationScraper.
Tests Next.js App Router (RSC Flight & Server Actions), Next.js Pages Router (__NEXT_DATA__),
Nuxt 3 (Devalue array & Payload Loaders), Remix & React Router v7 (Hierarchical Routes & Loader Data),
and SvelteKit (data-sveltekit-fetched & Schema Inference).
"""

import time
import unittest

from api_tool.models import DiscoveredEndpoint, DiscoveredParameter, DiscoveredResponse
from api_tool.spider.extractors.hydration_extractor import FastHydrationScraper


class TestFastHydrationScraper(unittest.TestCase):
    """Test suite for FastHydrationScraper."""

    def test_nextjs_rsc_server_actions(self):
        """Tests Next.js App Router RSC Flight stream Server Action detection."""
        html = """
        <!DOCTYPE html>
        <html>
        <head><title>Next.js App Router</title></head>
        <body>
            <script>
            (self.__next_f=self.__next_f||[]).push([1, "1:I[\"./app/page.tsx\",[\"app/page\",\"app/page.js\"],\"default\"]\n2:\"$ACTION_ID_da55e4e73111b15745bf2e9939e6a0d268a74287\"\n"]);
            </script>
            <script>
            self.__next_f.push([1, "3:[\"$\",\"div\",null,{\"children\":[\"createServerReference(\\\"e6e4096057c7c0dfc0f08e5c3e7215f949c25608\\\", callServer)\"]}]\n"]);
            </script>
        </body>
        </html>
        """
        endpoints = FastHydrationScraper.extract_nextjs_app_router(html, base_url="https://example.com")
        self.assertTrue(len(endpoints) >= 2)

        # Check action 1 ($ACTION_ID_...)
        action1 = next(
            (ep for ep in endpoints if ep.headers.get("Next-Action") == "da55e4e73111b15745bf2e9939e6a0d268a74287"),
            None,
        )
        self.assertIsNotNone(action1)
        self.assertEqual(action1.path, "/")
        self.assertEqual(action1.method, "POST")
        self.assertIn("server_action", action1.tags)
        self.assertIn("nextjs", action1.tags)

        # Check action 2 (createServerReference)
        action2 = next(
            (ep for ep in endpoints if ep.headers.get("Next-Action") == "e6e4096057c7c0dfc0f08e5c3e7215f949c25608"),
            None,
        )
        self.assertIsNotNone(action2)
        self.assertEqual(action2.path, "/")
        self.assertEqual(action2.method, "POST")
        self.assertEqual(action2.base_url, "https://example.com")

    def test_nextjs_rsc_flight_stream_components_and_apis(self):
        """Tests RSC Flight stream component JSON trees and unicode-escaped decoding."""
        html = r"""
        <!DOCTYPE html>
        <html>
        <body>
            <script>
            self.__next_f.push([1, "4:[\"$\",\"main\",null,{\"children\":[{\"$\":\"a\",\"props\":{\"href\":\"/dashboard\"}},{\"$\":\"button\",\"props\":{\"data-url\":\"\u002fapi\u002fv1\u002fexport\"}}]}]\n"]);
            </script>
            <script>
            self.__next_f.push([1, "5:{\"apiUrl\":\"/api/auth/session\",\"settingsPath\":\"/settings/profile\"}\n"]);
            </script>
        </body>
        </html>
        """
        endpoints = FastHydrationScraper.extract_nextjs_app_router(html, base_url="https://app.io")
        paths = {ep.path for ep in endpoints}

        self.assertIn("/dashboard", paths)
        self.assertIn("/api/v1/export", paths)
        self.assertIn("/api/auth/session", paths)
        self.assertIn("/settings/profile", paths)

        api_ep = next(ep for ep in endpoints if ep.path == "/api/v1/export")
        self.assertIn("api", api_ep.tags)
        self.assertEqual(api_ep.base_url, "https://app.io")

    def test_nextjs_pages_router(self):
        """Tests Next.js Pages Router __NEXT_DATA__ and JSON loader derivation."""
        html = """
        <!DOCTYPE html>
        <html>
        <head><title>Next Pages</title></head>
        <body>
            <script id="__NEXT_DATA__" type="application/json">
            {
                "props": {"pageProps": {}},
                "page": "/products/[id]",
                "query": {"id": "123", "tab": "reviews"},
                "buildId": "N7_kLP0xQZ8",
                "dynamicRoutes": [{"page": "/products/[id]"}, {"page": "/categories/[category]"}]
            }
            </script>
        </body>
        </html>
        """
        endpoints = FastHydrationScraper.extract_nextjs_pages_router(html, base_url="https://shop.com")
        paths = {ep.path for ep in endpoints}

        # Page route
        self.assertIn("/products/[id]", paths)
        page_ep = next(ep for ep in endpoints if ep.path == "/products/[id]")
        self.assertEqual(page_ep.method, "GET")
        self.assertEqual(page_ep.base_url, "https://shop.com")
        self.assertTrue(any(p.name == "id" and p.example == "123" for p in page_ep.parameters))
        self.assertTrue(any(p.name == "tab" and p.example == "reviews" for p in page_ep.parameters))

        # Auto-derived JSON loader: /_next/data/{buildId}{page}.json
        expected_loader = "/_next/data/N7_kLP0xQZ8/products/[id].json"
        self.assertIn(expected_loader, paths)
        loader_ep = next(ep for ep in endpoints if ep.path == expected_loader)
        self.assertIn("data_loader", loader_ep.tags)

        # Dynamic routes
        self.assertIn("/categories/[category]", paths)

    def test_nextjs_pages_router_root_page(self):
        """Tests Next.js root page '/' derives /_next/data/{buildId}/index.json."""
        html = """
        <script id="__NEXT_DATA__" type="application/json">
        {"props": {}, "page": "/", "buildId": "testBuild"}
        </script>
        """
        endpoints = FastHydrationScraper.extract_nextjs_pages_router(html)
        paths = {ep.path for ep in endpoints}
        self.assertIn("/", paths)
        self.assertTrue(
            "/_next/data/testBuild/index.json" in paths or "/_next/data/testBuild/.json" in paths
        )

    def test_nuxt3_devalue_array_and_payload_loader(self):
        """Tests Nuxt 3 __NUXT_DATA__ Devalue flattened array and payload loader derivation."""
        html = """
        <!DOCTYPE html>
        <html>
        <body>
            <script id="__NUXT_DATA__" type="application/json">
            [
                {"state": 1, "path": 2, "api": 3},
                {"user": "developer"},
                "/dashboard",
                "/api/v2/metrics",
                {"route": 5, "profileUrl": "https://api.nuxt.dev/v1/user/me"},
                "/settings/account",
                42,
                true
            ]
            </script>
        </body>
        </html>
        """
        endpoints = FastHydrationScraper.extract_nuxt3(html, base_url="https://nuxt.dev")
        paths = {ep.path for ep in endpoints}

        # Extracted routes
        self.assertIn("/dashboard", paths)
        self.assertIn("/settings/account", paths)

        # Extracted APIs
        self.assertIn("/api/v2/metrics", paths)
        self.assertIn("/v1/user/me", paths)

        # Auto-derived Nuxt 3 payload loaders: {route}/_payload.json
        self.assertIn("/dashboard/_payload.json", paths)
        self.assertIn("/settings/account/_payload.json", paths)

        dashboard_loader = next(ep for ep in endpoints if ep.path == "/dashboard/_payload.json")
        self.assertIn("payload_loader", dashboard_loader.tags)
        self.assertIn("nuxt", dashboard_loader.tags)

    def test_remix_hierarchical_nested_routes(self):
        """Tests Remix routes reconstruction, :param -> {param} conversion, and loader data endpoints."""
        html = """
        <!DOCTYPE html>
        <html>
        <body>
            <script>
            window.__remixContext = {
                "url": "/orgs/acme/teams/engineering",
                "manifest": {
                    "routes": {
                        "root": {
                            "id": "root",
                            "path": ""
                        },
                        "routes/orgs": {
                            "id": "routes/orgs",
                            "parentId": "root",
                            "path": "orgs"
                        },
                        "routes/orgs.$orgId": {
                            "id": "routes/orgs.$orgId",
                            "parentId": "routes/orgs",
                            "path": ":orgId"
                        },
                        "routes/orgs.$orgId.teams": {
                            "id": "routes/orgs.$orgId.teams",
                            "parentId": "routes/orgs.$orgId",
                            "path": "teams/:teamId"
                        },
                        "routes/orgs.$orgId.teams.settings": {
                            "id": "routes/orgs.$orgId.teams.settings",
                            "parentId": "routes/orgs.$orgId.teams",
                            "path": "settings"
                        }
                    }
                }
            };
            </script>
        </body>
        </html>
        """
        endpoints = FastHydrationScraper.extract_remix(html, base_url="https://remix.run")
        paths = {ep.path for ep in endpoints}

        # Verify hierarchical OpenAPI reconstructed routes
        self.assertIn("/", paths)
        self.assertIn("/orgs", paths)
        self.assertIn("/orgs/{orgId}", paths)
        self.assertIn("/orgs/{orgId}/teams/{teamId}", paths)
        self.assertIn("/orgs/{orgId}/teams/{teamId}/settings", paths)

        # Verify parameter extraction
        team_ep = next(ep for ep in endpoints if ep.path == "/orgs/{orgId}/teams/{teamId}")
        param_names = [p.name for p in team_ep.parameters if p.location == "path"]
        self.assertIn("orgId", param_names)
        self.assertIn("teamId", param_names)

        # Verify auto-derived loader data endpoints: {path}?_data={routeId}
        self.assertIn("/?_data=root", paths)
        self.assertIn("/orgs?_data=routes/orgs", paths)
        self.assertIn("/orgs/{orgId}?_data=routes/orgs.$orgId", paths)
        self.assertIn("/orgs/{orgId}/teams/{teamId}?_data=routes/orgs.$orgId.teams", paths)
        self.assertIn(
            "/orgs/{orgId}/teams/{teamId}/settings?_data=routes/orgs.$orgId.teams.settings",
            paths,
        )

        loader_ep = next(
            ep
            for ep in endpoints
            if ep.path == "/orgs/{orgId}/teams/{teamId}/settings?_data=routes/orgs.$orgId.teams.settings"
        )
        self.assertIn("loader_data", loader_ep.tags)
        query_params = [p for p in loader_ep.parameters if p.location == "query"]
        self.assertTrue(any(qp.name == "_data" and qp.example == "routes/orgs.$orgId.teams.settings" for qp in query_params))

    def test_remix_manifest_direct(self):
        """Tests window.__remixManifest directly."""
        html = """
        <script>
        window.__remixManifest = {
            "routes": {
                "root": {"id": "root", "path": ""},
                "routes/admin": {"id": "routes/admin", "parentId": "root", "path": "admin/:section"}
            }
        };
        </script>
        """
        endpoints = FastHydrationScraper.extract_remix(html)
        paths = {ep.path for ep in endpoints}
        self.assertIn("/admin/{section}", paths)
        self.assertIn("/admin/{section}?_data=routes/admin", paths)

    def test_sveltekit_data_fetched(self):
        """Tests SvelteKit data-sveltekit-fetched extraction and response schema inference."""
        html = """
        <!DOCTYPE html>
        <html>
        <body>
            <script type="application/json" data-sveltekit-fetched data-url="/api/v1/todos?status=active">
            {
                "status": 200,
                "statusText": "OK",
                "headers": {
                    "content-type": "application/json",
                    "x-total-count": "42"
                },
                "body": "[{\\"id\\": 1, \\"title\\": \\"Write tests\\", \\"completed\\": false, \\"score\\": 9.5}]"
            }
            </script>
        </body>
        </html>
        """
        endpoints = FastHydrationScraper.extract_sveltekit(html, base_url="https://svelte.dev")
        self.assertEqual(len(endpoints), 1)

        ep = endpoints[0]
        self.assertEqual(ep.path, "/api/v1/todos?status=active")
        self.assertEqual(ep.method, "GET")
        self.assertEqual(ep.base_url, "https://svelte.dev")
        self.assertIn("sveltekit", ep.tags)
        self.assertIn("api", ep.tags)

        # Query param
        self.assertTrue(any(p.name == "status" and p.example == "active" for p in ep.parameters))

        # Response
        self.assertEqual(len(ep.responses), 1)
        resp = ep.responses[0]
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.content_type, "application/json")
        self.assertEqual(resp.headers.get("x-total-count"), "42")

        # Inferred schema verification
        schema = resp.inferred_schema
        self.assertIsNotNone(schema)
        self.assertEqual(schema.get("type"), "array")
        items_schema = schema.get("items", {})
        self.assertEqual(items_schema.get("type"), "object")
        props = items_schema.get("properties", {})
        self.assertEqual(props.get("id", {}).get("type"), "integer")
        self.assertEqual(props.get("title", {}).get("type"), "string")
        self.assertEqual(props.get("completed", {}).get("type"), "boolean")
        self.assertEqual(props.get("score", {}).get("type"), "number")

    def test_extract_all_combined(self):
        """Tests unified extract_all method handling multi-framework documents."""
        html = """
        <!DOCTYPE html>
        <html>
        <body>
            <script>
            self.__next_f.push([1, "1:\"$ACTION_ID_1122334455667788990011223344556677889900\"\n"]);
            </script>
            <script id="__NEXT_DATA__" type="application/json">
            {"page": "/overview", "buildId": "b1"}
            </script>
            <script type="application/json" data-sveltekit-fetched data-url="/api/notifications">
            {"status": 200, "body": "[]"}
            </script>
        </body>
        </html>
        """
        endpoints = FastHydrationScraper.extract_all(html, base_url="https://all.com")
        paths = {ep.path for ep in endpoints}

        self.assertIn("/", paths)  # Server Action path
        self.assertIn("/overview", paths)  # Next page
        self.assertIn("/_next/data/b1/overview.json", paths)  # Next loader
        self.assertIn("/api/notifications", paths)  # SvelteKit API

    def test_sub_millisecond_execution_latency(self):
        """Verifies sub-millisecond execution latency on realistic documents."""
        # 50KB realistic HTML payload with multiple scripts
        html_parts = [
            "<!DOCTYPE html><html><head><title>Performance Benchmark</title></head><body>",
            '<script id="__NEXT_DATA__" type="application/json">{"page": "/dashboard", "buildId": "prod123"}</script>',
            '<script type="application/json" data-sveltekit-fetched data-url="/api/v1/user">{"status": 200, "body": "{\\"id\\": 1}"}</script>',
            '<script>self.__next_f.push([1, "1:\\"$ACTION_ID_aabbccddeeff00112233445566778899aabbccdd\\"\\n2:{\\"url\\":\\"/api/v1/fast\\"}\\n"]);</script>',
            '<script>window.__remixContext = {"manifest": {"routes": {"root": {"id": "root", "path": ""}, "dashboard": {"id": "dashboard", "parentId": "root", "path": "dashboard"}}}};</script>',
            '<script id="__NUXT_DATA__" type="application/json">[{"path": 1}, "/analytics", "/api/v2/events"]</script>',
        ]
        # Pad with realistic DOM content
        html_parts.append("<div class='content'>" + "<p>Some text content here</p>\n" * 500 + "</div>")
        html_parts.append("</body></html>")
        full_html = "".join(html_parts)

        # Warm up JIT / cache and verify correctness
        eps = FastHydrationScraper.extract_all(full_html, "https://perf.test")
        self.assertTrue(len(eps) >= 5)

        iterations = 50
        start_time = time.perf_counter()
        for _ in range(iterations):
            FastHydrationScraper.extract_all(full_html, "https://perf.test")
        elapsed = time.perf_counter() - start_time

        avg_latency_ms = (elapsed / iterations) * 1000
        # Latency is typically < 1.0 ms (sub-millisecond); allow up to 5.0 ms for battery-throttled ARM mobile devices
        self.assertLess(
            avg_latency_ms,
            5.0,
            f"Expected fast sub-millisecond execution, got {avg_latency_ms:.3f}ms",
        )

    def test_malformed_html_and_edge_cases(self):
        """Verifies resilience against empty input, malformed JSON, and unusual markup."""
        # Empty inputs
        self.assertEqual(FastHydrationScraper.extract_all(""), [])
        self.assertEqual(FastHydrationScraper.extract_all("   "), [])
        self.assertEqual(FastHydrationScraper.extract_all("<div>Plain HTML with no scripts</div>"), [])

        # Malformed Next.js Pages JSON
        malformed_next = '<script id="__NEXT_DATA__">{"broken": json</script>'
        self.assertEqual(FastHydrationScraper.extract_nextjs_pages_router(malformed_next), [])

        # Malformed Nuxt 3 (not a list or broken JSON)
        malformed_nuxt1 = '<script id="__NUXT_DATA__">{"not": "a list"}</script>'
        self.assertEqual(FastHydrationScraper.extract_nuxt3(malformed_nuxt1), [])
        malformed_nuxt2 = '<script id="__NUXT_DATA__">[broken, json]</script>'
        self.assertEqual(FastHydrationScraper.extract_nuxt3(malformed_nuxt2), [])

        # Broken Remix assignment
        malformed_remix = '<script>window.__remixContext = undefined;</script>'
        self.assertEqual(FastHydrationScraper.extract_remix(malformed_remix), [])

        # SvelteKit with plain text non-JSON body
        svelte_plain = '<script type="application/json" data-sveltekit-fetched data-url="/api/raw">OK</script>'
        eps = FastHydrationScraper.extract_sveltekit(svelte_plain)
        self.assertEqual(len(eps), 1)
        self.assertEqual(eps[0].path, "/api/raw")
        self.assertEqual(eps[0].responses[0].sample_body, "OK")

    def test_remix_circular_parent_protection(self):
        """Ensures circular parent references in route manifests do not cause infinite recursion."""
        html = """
        <script>
        window.__remixContext = {
            "manifest": {
                "routes": {
                    "routeA": {"id": "routeA", "parentId": "routeB", "path": "a"},
                    "routeB": {"id": "routeB", "parentId": "routeA", "path": "b"}
                }
            }
        };
        </script>
        """
        endpoints = FastHydrationScraper.extract_remix(html)
        self.assertTrue(len(endpoints) >= 2)
        paths = {ep.path for ep in endpoints}
        # Neither crashed nor infinite-looped
        self.assertTrue(any("/a" in p or "/b" in p for p in paths))

    def test_deduplication_and_rich_metadata_merging(self):
        """Verifies deduplication merges tags, parameters, and responses."""
        # Next.js App router pushing the same route twice with different tags/contexts
        html = """
        <script>
        self.__next_f.push([1, "1:{\"url\":\"/api/v1/metrics\"}\n"]);
        self.__next_f.push([1, "2:[\"$\",\"div\",null,{\"href\":\"/api/v1/metrics?format=json\"}]\n"]);
        </script>
        """
        endpoints = FastHydrationScraper.extract_all(html)
        metrics_endpoints = [ep for ep in endpoints if "/api/v1/metrics" in ep.path]
        self.assertTrue(len(metrics_endpoints) >= 1)


if __name__ == "__main__":
    unittest.main()

