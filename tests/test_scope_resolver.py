"""
Unit and integration tests for CDNScopeResolver and Spider scope engine:
- ScopePolicy defaults and customization
- CSP header and HTML meta parsing (script-src, connect-src, default-src)
- Trusted multi-tenant CDN matching (CloudFront, Fastly, Akamai, cdnjs, unpkg, jsdelivr, AzureEdge, Shopify)
- Strict analytics and ad tracker blocking (Google Analytics, Sentry, Datadog, etc.)
- Three-tier scope verification: is_page_in_scope, is_asset_in_scope, is_api_in_scope
- Spider integration: _extract_links_and_assets scope filtering and AsyncSpider.fetch_chunks concurrent downloader
"""

import asyncio
import unittest
import httpx

from api_tool.spider.crawler import AsyncSpider
from api_tool.spider.scope_resolver import CDNScopeResolver, ScopePolicy


class TestScopePolicy(unittest.TestCase):
    def test_default_policy(self):
        policy = ScopePolicy()
        self.assertTrue(policy.allow_subdomains)
        self.assertTrue(policy.allow_trusted_cdns)
        self.assertTrue(policy.allow_csp_hosts)
        self.assertTrue(policy.block_analytics_trackers)
        self.assertEqual(len(policy.trusted_cdns), 0)
        self.assertEqual(len(policy.blocked_trackers), 0)

    def test_custom_policy(self):
        policy = ScopePolicy(
            allow_subdomains=False,
            allow_trusted_cdns=False,
            allow_csp_hosts=False,
            block_analytics_trackers=False,
            trusted_cdns={"customcdn.example.org"},
            blocked_trackers={"customtracker.com"},
        )
        self.assertFalse(policy.allow_subdomains)
        self.assertFalse(policy.allow_trusted_cdns)
        self.assertFalse(policy.allow_csp_hosts)
        self.assertFalse(policy.block_analytics_trackers)
        self.assertIn("customcdn.example.org", policy.trusted_cdns)
        self.assertIn("customtracker.com", policy.blocked_trackers)


class TestCDNScopeResolver(unittest.TestCase):
    def setUp(self):
        self.resolver = CDNScopeResolver(target_domain="example.com")

    def test_csp_header_parsing(self):
        csp = (
            "default-src 'self' https://default.example.com; "
            "script-src 'self' 'unsafe-inline' https://scripts.target.org https://*.cloudfront.net; "
            "connect-src 'self' https://api.gateway.io:443 https://*.api-backend.net wss://ws.target.com; "
            "style-src 'self' 'unsafe-inline'"
        )
        self.resolver.update_from_csp(csp)

        self.assertIn("scripts.target.org", self.resolver.csp_script_hosts)
        self.assertIn("*.cloudfront.net", self.resolver.csp_script_hosts)
        self.assertIn("api.gateway.io", self.resolver.csp_connect_hosts)
        self.assertIn("*.api-backend.net", self.resolver.csp_connect_hosts)
        self.assertIn("ws.target.com", self.resolver.csp_connect_hosts)
        self.assertIn("default.example.com", self.resolver.csp_default_hosts)

    def test_csp_html_meta_parsing(self):
        html = """
        <html>
        <head>
            <meta http-equiv="Content-Security-Policy" content="script-src https://cdn.internal-app.com; connect-src https://apigw.internal-app.com">
        </head>
        <body>Test</body>
        </html>
        """
        self.resolver.update_from_html(html)
        self.assertIn("cdn.internal-app.com", self.resolver.csp_script_hosts)
        self.assertIn("apigw.internal-app.com", self.resolver.csp_connect_hosts)

    def test_trusted_cdn_matching(self):
        trusted_asset_urls = [
            "https://d123456abcdef.cloudfront.net/static/chunks/main.js",
            "https://cdnjs.cloudflare.com/ajax/libs/react/18.2.0/umd/react.production.min.js",
            "https://unpkg.com/lodash@4.17.21/lodash.min.js",
            "https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js",
            "https://jsdelivr.net/gh/user/repo@v1.0/bundle.js",
            "https://static.fastly.net/assets/vendor.js",
            "https://edge.akamaized.net/scripts/core.js",
            "https://mytenant.azureedge.net/lib/app.js",
            "https://cdn.shopify.com/s/files/1/0000/0001/t/1/assets/theme.js",
        ]
        for url in trusted_asset_urls:
            self.assertTrue(
                self.resolver.is_asset_in_scope(url),
                f"Trusted CDN asset URL should be in scope: {url}",
            )

        # Disallow trusted CDNs
        strict_resolver = CDNScopeResolver(
            target_domain="example.com",
            policy=ScopePolicy(allow_trusted_cdns=False),
        )
        for url in trusted_asset_urls:
            self.assertFalse(
                strict_resolver.is_asset_in_scope(url),
                f"Trusted CDN asset should be blocked when allow_trusted_cdns=False: {url}",
            )

    def test_analytics_and_tracker_blocking(self):
        tracker_urls = [
            "https://www.google-analytics.com/analytics.js",
            "https://googletagmanager.com/gtm.js?id=GTM-12345",
            "https://stats.g.doubleclick.net/r/collect",
            "https://browser.sentry-cdn.com/7.50.0/bundle.min.js",
            "https://o123456.ingest.sentry.io/api/12345/envelope/",
            "https://browser-http-intake.logs.datadoghq.com/v1/input/test",
            "https://cdn.segment.com/analytics.js/v1/key/analytics.min.js",
            "https://api.mixpanel.com/track",
            "https://static.hotjar.com/c/hotjar-12345.js",
            "https://www.clarity.ms/tag/abcde",
        ]

        # Even if a tracker is present in CSP, it MUST be blocked
        csp = (
            "script-src 'self' https://www.google-analytics.com https://browser.sentry-cdn.com; "
            "connect-src 'self' https://o123456.ingest.sentry.io https://api.mixpanel.com"
        )
        self.resolver.update_from_csp(csp)

        for url in tracker_urls:
            self.assertFalse(
                self.resolver.is_page_in_scope(url),
                f"Tracker page should be blocked: {url}",
            )
            self.assertFalse(
                self.resolver.is_asset_in_scope(url),
                f"Tracker asset should be blocked: {url}",
            )
            self.assertFalse(
                self.resolver.is_api_in_scope(url),
                f"Tracker API should be blocked: {url}",
            )

    def test_three_tier_scope_separation(self):
        csp = (
            "default-src 'self'; "
            "script-src 'self' https://assets.custom-vendor.org; "
            "connect-src 'self' https://gateway.service.io"
        )
        self.resolver.update_from_csp(csp)

        # 1. Target domain & subdomains
        self.assertTrue(self.resolver.is_page_in_scope("https://example.com/about"))
        self.assertTrue(self.resolver.is_page_in_scope("https://sub.example.com/app"))
        self.assertTrue(self.resolver.is_page_in_scope("/relative/path"))

        # External pages out of scope
        self.assertFalse(self.resolver.is_page_in_scope("https://assets.custom-vendor.org/index.html"))
        self.assertFalse(self.resolver.is_page_in_scope("https://gateway.service.io/dashboard"))
        self.assertFalse(self.resolver.is_page_in_scope("https://attacker.com/"))

        # 2. Asset scope
        # Target asset -> True
        self.assertTrue(self.resolver.is_asset_in_scope("https://example.com/static/bundle.js"))
        self.assertTrue(self.resolver.is_asset_in_scope("/static/bundle.js"))
        # CSP script-src host -> True
        self.assertTrue(self.resolver.is_asset_in_scope("https://assets.custom-vendor.org/widget.js"))
        # Trusted CDN -> True
        self.assertTrue(self.resolver.is_asset_in_scope("https://unpkg.com/vue@3/dist/vue.global.js"))
        # CSP connect-src host (not script-src) -> False
        self.assertFalse(self.resolver.is_asset_in_scope("https://gateway.service.io/bundle.js"))
        # Arbitrary external host -> False
        self.assertFalse(self.resolver.is_asset_in_scope("https://random-site.com/evil.js"))

        # 3. API scope
        # Target API -> True
        self.assertTrue(self.resolver.is_api_in_scope("https://example.com/api/v1/users"))
        self.assertTrue(self.resolver.is_api_in_scope("/api/v1/orders"))
        # CSP connect-src host -> True
        self.assertTrue(self.resolver.is_api_in_scope("https://gateway.service.io/v1/graphql"))
        # CSP script-src host -> False (not in connect-src)
        self.assertFalse(self.resolver.is_api_in_scope("https://assets.custom-vendor.org/v1/graphql"))
        # Trusted CDNs -> False (CDNs are for assets, not APIs)
        self.assertFalse(self.resolver.is_api_in_scope("https://unpkg.com/api/test"))
        self.assertFalse(self.resolver.is_api_in_scope("https://d123.cloudfront.net/api/test"))

    def test_subdomains_disallowed(self):
        strict_resolver = CDNScopeResolver(
            target_domain="example.com",
            policy=ScopePolicy(allow_subdomains=False),
        )
        self.assertTrue(strict_resolver.is_page_in_scope("https://example.com/home"))
        self.assertFalse(strict_resolver.is_page_in_scope("https://sub.example.com/home"))


class TestSpiderScopeIntegration(unittest.TestCase):
    def test_extract_links_and_assets_with_scope_resolver(self):
        resolver = CDNScopeResolver(target_domain="target.com")
        spider = AsyncSpider(allowed_domains=["target.com"], scope_resolver=resolver)

        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta http-equiv="Content-Security-Policy" content="script-src 'self' https://partner-scripts.org">
            <script src="/static/app.js"></script>
            <script src="https://partner-scripts.org/lib.js"></script>
            <script src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
            <script src="https://www.google-analytics.com/analytics.js"></script>
            <link rel="preload" href="https://external-unknown.com/bad.js" as="script">
        </head>
        <body>
            <a href="/dashboard">Dashboard</a>
            <a href="https://target.com/settings">Settings</a>
            <a href="https://sub.target.com/profile">Profile</a>
            <a href="https://partner-scripts.org/docs">Partner Docs (External)</a>
            <a href="https://attacker.com/malicious">Attacker</a>
        </body>
        </html>
        """

        links, scripts, assets = spider._extract_links_and_assets(html, "https://target.com/")

        # Scripts: target + CSP partner-scripts.org + unpkg trusted CDN. Google Analytics & unknown dropped.
        self.assertIn("https://target.com/static/app.js", scripts)
        self.assertIn("https://partner-scripts.org/lib.js", scripts)
        self.assertIn("https://unpkg.com/react@18/umd/react.production.min.js", scripts)
        self.assertNotIn("https://www.google-analytics.com/analytics.js", scripts)
        self.assertNotIn("https://external-unknown.com/bad.js", scripts)

        # Links: only target.com and sub.target.com. External sites dropped.
        self.assertIn("https://target.com/dashboard", links)
        self.assertIn("https://target.com/settings", links)
        self.assertIn("https://sub.target.com/profile", links)
        self.assertNotIn("https://partner-scripts.org/docs", links)
        self.assertNotIn("https://attacker.com/malicious", links)

    def test_fetch_chunks(self):
        def handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "chunk-429.js" in url:
                # Mock a single 429 then succeed
                if not hasattr(handler, "attempt"):
                    handler.attempt = 1
                    return httpx.Response(429, headers={"retry-after": "0.01"})
                return httpx.Response(200, text="console.log('chunk-429 success');")
            elif "chunk1.js" in url:
                return httpx.Response(200, text="console.log('chunk1');")
            elif "chunk2.js" in url:
                return httpx.Response(200, text="console.log('chunk2');")
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport)

        resolver = CDNScopeResolver(target_domain="example.com")
        spider = AsyncSpider(
            allowed_domains=["example.com"],
            scope_resolver=resolver,
            client=client,
            backoff_factor=0.01,
        )

        urls = [
            "https://example.com/static/chunk1.js",
            "https://example.com/static/chunk2.js",
            "https://example.com/static/chunk-429.js",
            "https://example.com/static/chunk1.js",  # Duplicate
            "https://www.google-analytics.com/analytics.js",  # Out-of-scope tracker
            "https://attacker.com/evil.js",  # Out-of-scope domain
        ]

        results = asyncio.run(spider.fetch_chunks(urls))

        self.assertIn("https://example.com/static/chunk1.js", results)
        self.assertIn("https://example.com/static/chunk2.js", results)
        self.assertIn("https://example.com/static/chunk-429.js", results)
        self.assertEqual(results["https://example.com/static/chunk1.js"], "console.log('chunk1');")
        self.assertEqual(results["https://example.com/static/chunk-429.js"], "console.log('chunk-429 success');")
        self.assertNotIn("https://www.google-analytics.com/analytics.js", results)
        self.assertNotIn("https://attacker.com/evil.js", results)


if __name__ == "__main__":
    unittest.main()
