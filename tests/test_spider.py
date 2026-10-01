"""
Unit and integration tests for api_tool.spider modules:
- crawler (URLNormalizer, RoutePatternCollapser, AsyncSpider)
- manifest (Next.js, Nuxt, Webpack manifest parser)
- passive (Wayback CDX & AlienVault OTX harvesters)
"""

import asyncio
import json
import unittest
import httpx

from api_tool.models import DiscoveredEndpoint, DiscoveredParameter
from api_tool.spider.crawler import (
    AsyncSpider,
    CrawlResult,
    RoutePatternCollapser,
    URLNormalizer,
)
from api_tool.spider.manifest import ManifestExtractor, ManifestResult
from api_tool.spider.passive import PassiveHarvester, PassiveHarvestResult


class TestURLNormalizer(unittest.TestCase):
    def setUp(self):
        self.normalizer = URLNormalizer()

    def test_normalize_basic(self):
        url = "HTTP://EXAMPLE.COM:80/api//v1/users?b=2&utm_source=twitter&a=1#section1"
        normalized = self.normalizer.normalize(url)
        self.assertEqual(normalized, "http://example.com/api/v1/users?a=1&b=2")

    def test_normalize_https_default_port(self):
        url = "HTTPS://API.EXAMPLE.COM:443/graphql/"
        normalized = self.normalizer.normalize(url)
        self.assertEqual(normalized, "https://api.example.com/graphql/")

    def test_normalize_relative_url(self):
        base = "https://example.com/v1/api/"
        rel = "../v2/orders?gclid=xyz&token=abc"
        normalized = self.normalizer.normalize(rel, base_url=base)
        self.assertEqual(normalized, "https://example.com/v1/v2/orders?token=abc")

    def test_strip_tracking_parameters(self):
        url = "https://example.com/item?fbclid=123&mc_eid=abc&id=99&utm_campaign=winter"
        normalized = self.normalizer.normalize(url)
        self.assertEqual(normalized, "https://example.com/item?id=99")

    def test_loop_detection_repeated_segments(self):
        # Repeated single segment
        loop_url = "https://example.com/blog/blog/blog/blog/post"
        self.assertTrue(self.normalizer.is_loop(loop_url, max_segment_repeats=2))

        safe_url = "https://example.com/blog/categories/tech/post"
        self.assertFalse(self.normalizer.is_loop(safe_url))

    def test_loop_detection_cycles(self):
        # Repeating alternating segments: /a/b/a/b/a/b
        cycle_url = "https://example.com/en/shop/en/shop/en/shop"
        self.assertTrue(self.normalizer.is_loop(cycle_url, max_cycle_repeats=2))

        safe_url = "https://example.com/en/shop/cart"
        self.assertFalse(self.normalizer.is_loop(safe_url))

    def test_domain_matching(self):
        self.assertTrue(self.normalizer.is_same_domain("https://sub.example.com/api", "example.com"))
        self.assertTrue(self.normalizer.is_same_domain("https://example.com/api", "https://example.com/"))
        self.assertFalse(self.normalizer.is_same_domain("https://sub.example.com/api", "example.com", allow_subdomains=False))
        self.assertFalse(self.normalizer.is_same_domain("https://attacker.com", "example.com"))

    def test_static_asset_detection(self):
        self.assertTrue(self.normalizer.is_static_asset("https://example.com/image.png"))
        self.assertTrue(self.normalizer.is_static_asset("https://example.com/font.woff2"))
        self.assertTrue(self.normalizer.is_static_asset("https://example.com/style.css"))
        self.assertFalse(self.normalizer.is_static_asset("https://example.com/bundle.js"))
        self.assertFalse(self.normalizer.is_static_asset("https://example.com/api/v1/users"))


class TestRoutePatternCollapser(unittest.TestCase):
    def test_collapse_numeric_ids(self):
        path = "/api/v1/users/42/orders/1001"
        collapsed = RoutePatternCollapser.collapse_path(path)
        self.assertEqual(collapsed, "/api/v1/users/{id}/orders/{id}")

    def test_collapse_uuid(self):
        path = "/items/123e4567-e89b-12d3-a456-426614174000/details"
        collapsed = RoutePatternCollapser.collapse_path(path)
        self.assertEqual(collapsed, "/items/{uuid}/details")

    def test_collapse_hex_id(self):
        # 24-character MongoDB ObjectID
        path = "/api/v2/document/507f1f77bcf86cd799439011"
        collapsed = RoutePatternCollapser.collapse_path(path)
        self.assertEqual(collapsed, "/api/v2/document/{hex_id}")

    def test_collapse_date(self):
        path = "/articles/2023-11-05/announcements"
        collapsed = RoutePatternCollapser.collapse_path(path)
        self.assertEqual(collapsed, "/articles/{date}/announcements")

    def test_collapse_slug_id(self):
        path = "/posts/spring-release-98765"
        collapsed = RoutePatternCollapser.collapse_path(path)
        self.assertEqual(collapsed, "/posts/{slug_id}")


class TestAsyncSpider(unittest.TestCase):
    def test_html_link_and_asset_extraction(self):
        spider = AsyncSpider()
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <script src="/static/js/main.chunk.js"></script>
            <link rel="preload" href="/static/js/vendor.chunk.js" as="script">
            <link rel="stylesheet" href="/static/css/main.css">
            <link rel="preload" href="/fonts/inter.woff2" as="font">
        </head>
        <body>
            <a href="/about">About Us</a>
            <a href="https://example.com/contact?utm_source=mail">Contact</a>
            <a href="javascript:void(0)">Do not follow</a>
            <a href="/logo.png">Logo</a>
            <form action="/api/v1/search" method="GET">
                <input name="q" value="test">
            </form>
        </body>
        </html>
        """
        page_url = "https://example.com/home"
        links, scripts, assets = spider._extract_links_and_assets(html, page_url)

        self.assertIn("https://example.com/static/js/main.chunk.js", scripts)
        self.assertIn("https://example.com/static/js/vendor.chunk.js", scripts)
        self.assertIn("https://example.com/about", links)
        self.assertIn("https://example.com/contact", links)
        self.assertIn("https://example.com/api/v1/search", links)
        # static image not in links
        self.assertNotIn("https://example.com/logo.png", links)
        self.assertIn("https://example.com/static/css/main.css", assets)

    def test_crawl_flow_with_mock_transport(self):
        def handler(request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            if url_str == "https://example.com/":
                return httpx.Response(
                    200,
                    text="""
                    <html><body>
                        <script src="/app.js"></script>
                        <a href="/users/1">User 1</a>
                        <a href="/users/2">User 2</a>
                        <a href="/users/3">User 3</a>
                        <a href="/users/4">User 4</a>
                        <a href="/api/health">Health</a>
                    </body></html>
                    """,
                    headers={"content-type": "text/html"},
                )
            elif "/users/" in url_str:
                return httpx.Response(
                    200,
                    text="<html><body>Profile page</body></html>",
                    headers={"content-type": "text/html"},
                )
            elif url_str == "https://example.com/api/health":
                return httpx.Response(
                    200,
                    text='{"status":"ok"}',
                    headers={"content-type": "application/json"},
                )
            return httpx.Response(404, text="Not Found")

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport)

        spider = AsyncSpider(
            allowed_domains=["example.com"],
            max_depth=2,
            max_pages=10,
            max_per_template=2,  # Cardinality limit of 2 for /users/{id}
            client=client,
        )

        result = asyncio.run(spider.crawl("https://example.com/"))

        self.assertIn("https://example.com/app.js", result.scripts)
        # Verify /users/{id} was crawled at most 2 times
        users_crawled = [u for u in result.visited_urls if "/users/" in u]
        self.assertLessEqual(len(users_crawled), 2)

        # Check endpoints created
        paths = [e.path for e in result.endpoints]
        self.assertIn("/", paths)
        self.assertIn("/api/health", paths)


class TestManifestExtractor(unittest.TestCase):
    def setUp(self):
        self.extractor = ManifestExtractor()

    def test_extract_next_data_from_html(self):
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <script id="__NEXT_DATA__" type="application/json">
            {
                "props": {"pageProps": {}},
                "page": "/dashboard",
                "query": {"tab": "overview"},
                "buildId": "k3f8d9a2b1c4e5",
                "assetPrefix": ""
            }
            </script>
        </head>
        <body><div>Next App</div></body>
        </html>
        """
        result = self.extractor.extract_from_html(html, "https://demo.nextjs.org")
        self.assertEqual(result.framework, "nextjs")
        self.assertEqual(result.build_id, "k3f8d9a2b1c4e5")
        self.assertIn("/dashboard", result.routes)

    def test_parse_next_build_manifest(self):
        manifest_js = """
        self.__BUILD_MANIFEST = function(s, a, c) {
            return {
                __rewrites: {
                    beforeFiles: [],
                    afterFiles: [
                        { source: "/api/proxy/:path*", destination: "https://backend.api.internal/:path*" }
                    ],
                    fallback: []
                },
                "/": [s, "static/chunks/pages/index-123.js"],
                "/users/[id]": [s, "static/chunks/pages/users/[id]-456.js"],
                "/api/auth/[...nextauth]": ["static/chunks/pages/api/auth/[...nextauth]-789.js"],
                sortedPages: ["/", "/_app", "/_error", "/users/[id]", "/api/auth/[...nextauth]"]
            };
        }(1, 2, 3);
        self.__BUILD_MANIFEST_CB && self.__BUILD_MANIFEST_CB();
        """
        routes, chunks, rewrites = self.extractor.parse_next_build_manifest(
            manifest_js, "https://demo.nextjs.org"
        )
        self.assertIn("/users/[id]", routes)
        self.assertIn("/api/auth/[...nextauth]", routes)
        self.assertIn("/api/proxy/:path*", routes)
        self.assertTrue(any("static/chunks/pages/index-123.js" in c for c in chunks))
        self.assertEqual(len(rewrites), 1)
        self.assertEqual(rewrites[0]["destination"], "https://backend.api.internal/:path*")

    def test_parse_next_ssg_manifest(self):
        ssg_js = """
        self.__SSG_MANIFEST = new Set([
            "/docs/introduction",
            "/docs/[slug]",
            "/blog/first-post"
        ]);
        """
        routes = self.extractor.parse_next_ssg_manifest(ssg_js)
        self.assertIn("/docs/introduction", routes)
        self.assertIn("/docs/[slug]", routes)
        self.assertIn("/blog/first-post", routes)

    def test_convert_routes_to_endpoints_parameter_extraction(self):
        routes = ["/users/[id]", "/docs/[...slug]", "/api/settings"]
        endpoints = self.extractor._convert_routes_to_endpoints(
            routes, "https://example.com", "nextjs"
        )
        endpoints_by_path = {e.path: e for e in endpoints}

        self.assertIn("/users/{id}", endpoints_by_path)
        user_ep = endpoints_by_path["users/{id}" if "users/{id}" in endpoints_by_path else "/users/{id}"]
        self.assertEqual(len(user_ep.parameters), 1)
        self.assertEqual(user_ep.parameters[0].name, "id")
        self.assertEqual(user_ep.parameters[0].location, "path")
        self.assertTrue(user_ep.parameters[0].required)

        docs_ep = endpoints_by_path["/docs/{slug*}"]
        self.assertEqual(docs_ep.parameters[0].name, "slug")
        self.assertEqual(docs_ep.parameters[0].param_type, "array")

    def test_extract_nuxt_data(self):
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <script id="__NUXT_DATA__" type="application/json">
            ["Shallow", "/dashboard", "/api/v1/profile", "active", {"path": "/admin/settings"}]
            </script>
        </head>
        <body><div>Nuxt App</div></body>
        </html>
        """
        result = self.extractor.extract_from_html(html, "https://nuxt.example.com")
        self.assertEqual(result.framework, "nuxt")
        self.assertIn("/dashboard", result.routes)
        self.assertIn("/api/v1/profile", result.routes)
        self.assertIn("/admin/settings", result.routes)

    def test_webpack_chunk_maps(self):
        script = """
        __webpack_require__.u = function(chunkId) {
            return "" + chunkId + "." + {
                101: "a8f3b2c1",
                102: "9d7e6f4a"
            }[chunkId] + ".chunk.js";
        };
        """
        _, chunk_map = self.extractor._extract_webpack_chunk_maps(
            script, "https://example.com"
        )
        self.assertEqual(chunk_map.get("101"), "a8f3b2c1")
        self.assertEqual(chunk_map.get("102"), "9d7e6f4a")


class TestPassiveHarvester(unittest.TestCase):
    def setUp(self):
        self.harvester = PassiveHarvester()

    def test_url_to_endpoint(self):
        url = "https://api.example.com/v1/users?limit=50&active=true"
        ep, script = self.harvester._url_to_endpoint(url, source_tag="wayback", status_code=200)
        self.assertIsNotNone(ep)
        self.assertIsNone(script)
        self.assertEqual(ep.method, "GET")
        self.assertEqual(ep.base_url, "https://api.example.com")
        self.assertIn("/v1/users", ep.path)
        self.assertEqual(ep.active_status, 200)
        param_names = [p.name for p in ep.parameters]
        self.assertIn("limit", param_names)
        self.assertIn("active", param_names)

    def test_url_to_script(self):
        url = "https://example.com/static/js/vendor-7a8b9c.js"
        ep, script = self.harvester._url_to_endpoint(url, source_tag="wayback", status_code=200)
        self.assertEqual(script, "https://example.com/static/js/vendor-7a8b9c.js")

    def test_mock_harvest_all(self):
        def mock_handler(request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            if "web.archive.org/cdx" in url_str:
                cdx_data = [
                    ["original", "mimetype", "statuscode", "timestamp"],
                    ["https://example.com/api/v1/products", "application/json", "200", "20220101"],
                    ["https://example.com/static/bundle.js", "application/javascript", "200", "20220101"],
                    ["https://example.com/logo.png", "image/png", "200", "20220101"],
                ]
                return httpx.Response(200, json=cdx_data)
            elif "otx.alienvault.com" in url_str:
                otx_data = {
                    "url_list": [
                        {"url": "https://example.com/api/v1/orders?status=shipped", "httpcode": 200},
                        {"url": "https://example.com/api/v1/products", "httpcode": 200},
                    ],
                    "page": 1,
                    "has_next": False,
                }
                return httpx.Response(200, json=otx_data)
            return httpx.Response(404)

        transport = httpx.MockTransport(mock_handler)
        client = httpx.AsyncClient(transport=transport)
        harvester = PassiveHarvester(client=client)

        result = asyncio.run(harvester.harvest_all("https://example.com/"))

        self.assertEqual(result.target_domain, "example.com")
        self.assertIn("https://example.com/static/bundle.js", result.scripts)
        # Verify deduplication of /api/v1/products and tagging
        paths = [e.path for e in result.endpoints]
        self.assertIn("/api/v1/products", paths)
        order_ep = [e for e in result.endpoints if "/api/v1/orders" in e.path][0]
        self.assertIn("status", [p.name for p in order_ep.parameters])

        products_ep = [e for e in result.endpoints if e.path == "/api/v1/products"][0]
        # Both wayback and alienvault should be in tags
        self.assertIn("wayback", products_ep.tags)
        self.assertIn("alienvault_otx", products_ep.tags)


if __name__ == "__main__":
    unittest.main()
