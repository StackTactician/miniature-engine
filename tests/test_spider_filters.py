"""
Unit and integration tests for URLFilterEngine and Safety Layer:
- SSRF & Private Network Guard (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16,
  169.254.169.254, ::1, localhost, metadata.google.internal)
- OAuth / Identity Provider Guard (Google, Microsoft, Apple, GitHub, GitLab, Auth0, Okta)
- Dangerous Action Guard (logout, signout, sign-out, logoff, exit, deauth, revoke, delete,
  destroy, remove, cancel, terminate, drop, purge, erase, unsubscribe, reset-password,
  change-password, kill-switch, clear-cache)
- Rabbit-Hole Guard (calendar loops, deep pagination, repeated query parameter loops)
- Scope Integration with CDNScopeResolver (in-scope vs out-of-scope, trackers, CDNs)
- User Include / Exclude Regex patterns
- Clean Navigation URLs acceptance
"""

import unittest

from api_tool.spider.filters import (
    DANGEROUS_ACTIONS_REGEX,
    DEFAULT_OAUTH_DOMAINS,
    OAUTH_DOMAINS,
    RABBIT_HOLE_REGEX,
    URLFilterEngine,
    extract_host,
    is_oauth_domain,
    is_private_or_ssrf_host,
)
from api_tool.spider.scope_resolver import CDNScopeResolver, ScopePolicy


class TestSSRFAndPrivateNetworkGuard(unittest.TestCase):
    """Tests SSRF and Private Network Guard functions."""

    def test_loopback_ips(self):
        loopbacks = [
            "127.0.0.1",
            "127.0.0.2",
            "127.255.255.255",
            "127.0.0.1:8080",
            "::1",
            "[::1]",
            "[::1]:8080",
            "http://127.0.0.1:3000/api",
            "https://[::1]:8443/status",
        ]
        for ip in loopbacks:
            self.assertTrue(is_private_or_ssrf_host(ip), f"Expected {ip} to be blocked as SSRF/loopback")
            self.assertTrue(URLFilterEngine.is_private_or_ssrf_host(ip))

    def test_private_rfc1918_ips(self):
        privates = [
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.0.1",
            "192.168.1.100",
            "http://10.0.0.5:8000/internal",
            "https://192.168.1.1/router",
        ]
        for ip in privates:
            self.assertTrue(is_private_or_ssrf_host(ip), f"Expected {ip} to be blocked as RFC 1918 private IP")

    def test_link_local_and_cloud_metadata(self):
        metadata_targets = [
            "169.254.169.254",
            "169.254.1.1",
            "http://169.254.169.254/latest/meta-data/",
            "metadata.google.internal",
            "sub.metadata.google.internal",
            "metadata",
            "instance-data",
        ]
        for target in metadata_targets:
            self.assertTrue(
                is_private_or_ssrf_host(target),
                f"Expected {target} to be blocked as cloud metadata / link-local",
            )

    def test_localhost_and_cidr_notation(self):
        hosts = [
            "localhost",
            "sub.localhost",
            "http://localhost:8080/secret",
            "127.0.0.0/8",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
        ]
        for h in hosts:
            self.assertTrue(is_private_or_ssrf_host(h), f"Expected {h} to be blocked as localhost/CIDR")

    def test_public_and_valid_hosts(self):
        publics = [
            "8.8.8.8",
            "1.1.1.1",
            "example.com",
            "api.example.com",
            "https://example.com/docs",
        ]
        for p in publics:
            self.assertFalse(is_private_or_ssrf_host(p), f"Expected {p} NOT to be blocked as SSRF")

    def test_extract_host_helper(self):
        self.assertEqual(extract_host("127.0.0.1"), "127.0.0.1")
        self.assertEqual(extract_host("127.0.0.1:8080"), "127.0.0.1")
        self.assertEqual(extract_host("[::1]:9000"), "::1")
        self.assertEqual(extract_host("http://user:pass@api.target.com:443/path"), "api.target.com")
        self.assertEqual(extract_host("https://example.com/"), "example.com")


class TestOAuthGuard(unittest.TestCase):
    """Tests OAuth / Identity Provider Guard."""

    def test_oauth_domains_membership(self):
        expected_domains = {
            "accounts.google.com",
            "login.microsoftonline.com",
            "appleid.apple.com",
            "github.com",
            "gitlab.com",
            "auth0.com",
            "okta.com",
        }
        for d in expected_domains:
            self.assertIn(d, DEFAULT_OAUTH_DOMAINS)
            self.assertIn(d, OAUTH_DOMAINS)
            self.assertIn(d, URLFilterEngine.OAUTH_DOMAINS)

    def test_oauth_domain_detection(self):
        oauth_urls = [
            "https://accounts.google.com/o/oauth2/v2/auth",
            "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            "https://appleid.apple.com/auth/authorize",
            "https://github.com/login/oauth/authorize",
            "https://api.github.com/user",
            "https://gitlab.com/oauth/authorize",
            "https://my-tenant.auth0.com/authorize",
            "https://acme-corp.okta.com/oauth2/default/v1/authorize",
        ]
        for url in oauth_urls:
            self.assertTrue(is_oauth_domain(url), f"Expected {url} to be flagged as OAuth domain")

    def test_non_oauth_domains(self):
        safe_urls = [
            "https://google.com/search?q=test",
            "https://example.com/login",
            "https://notgithub.com/page",
            "https://okta-community.com/forum",
            "https://api.target.org/auth/token",
        ]
        for url in safe_urls:
            self.assertFalse(is_oauth_domain(url), f"Expected {url} NOT to be flagged as external OAuth domain")


class TestDangerousActionGuard(unittest.TestCase):
    """Tests Dangerous Action Guard regex filtering."""

    def test_all_dangerous_action_keywords(self):
        dangerous_urls = [
            "https://example.com/logout",
            "https://example.com/auth/signout",
            "https://example.com/auth/sign-out",
            "https://example.com/user/logoff.php",
            "https://example.com/portal/exit",
            "https://example.com/api/deauth",
            "https://example.com/tokens/revoke?token=abc",
            "https://example.com/items/123/delete",
            "https://example.com/account/destroy",
            "https://example.com/cart/remove?item_id=12",
            "https://example.com/subscription/cancel",
            "https://example.com/session/terminate",
            "https://example.com/database/drop",
            "https://example.com/cache/purge",
            "https://example.com/data/erase",
            "https://example.com/email/unsubscribe?key=xyz",
            "https://example.com/auth/reset-password",
            "https://example.com/auth/change-password",
            "https://example.com/ops/kill-switch",
            "https://example.com/system/clear-cache",
            "/logout",
            "/api/delete?id=1",
            "https://example.com/action?do=reset_password",
        ]
        for url in dangerous_urls:
            self.assertTrue(
                bool(DANGEROUS_ACTIONS_REGEX.search(url)),
                f"Expected {url} to match DANGEROUS_ACTIONS_REGEX",
            )
            self.assertTrue(
                URLFilterEngine.is_dangerous_action(url),
                f"Expected URLFilterEngine.is_dangerous_action({url}) to be True",
            )

    def test_benign_urls_not_matching_dangerous_actions(self):
        safe_urls = [
            "https://example.com/dropbox",
            "https://example.com/ui/dropdown",
            "https://example.com/devices/removable-media",
            "https://example.com/lexite",
            "https://example.com/credit/card",
            "https://example.com/api/v1/users",
            "https://example.com/blog/how-to-configure-switch",
            "https://example.com/catalog/items",
            "https://example.com/documentation/overview",
        ]
        for url in safe_urls:
            self.assertFalse(
                bool(DANGEROUS_ACTIONS_REGEX.search(url)),
                f"Expected {url} NOT to match DANGEROUS_ACTIONS_REGEX",
            )
            self.assertFalse(
                URLFilterEngine.is_dangerous_action(url),
                f"Expected URLFilterEngine.is_dangerous_action({url}) to be False",
            )


class TestRabbitHoleGuard(unittest.TestCase):
    """Tests Rabbit-Hole Guard for calendar loops, deep pagination, and repeated query params."""

    def test_calendar_loops(self):
        calendar_urls = [
            "https://example.com/2024/05/12",
            "https://example.com/2024/05",
            "https://example.com/events/2023-11",
            "https://example.com/events/2023-11/agenda",
            "https://example.com/calendar/2024/05/12",
            "https://example.com/archive/2022/10/01",
            "https://example.com/blog/2023/04",
            "/2024/05/12",
            "/events/2023-11",
        ]
        for url in calendar_urls:
            self.assertTrue(
                bool(RABBIT_HOLE_REGEX.search(url)),
                f"Expected calendar loop {url} to match RABBIT_HOLE_REGEX",
            )
            self.assertTrue(
                URLFilterEngine.is_rabbit_hole(url),
                f"Expected URLFilterEngine.is_rabbit_hole({url}) to be True",
            )

    def test_deep_pagination(self):
        deep_paginated_urls = [
            "https://example.com/catalog?page=9999",
            "https://example.com/items?p=5000",
            "https://example.com/search?offset=20000",
            "https://example.com/data?start=15000",
            "https://example.com/users?skip=10000",
            "https://example.com/records?pg=500",
        ]
        for url in deep_paginated_urls:
            self.assertTrue(
                bool(RABBIT_HOLE_REGEX.search(url)),
                f"Expected deep pagination {url} to match RABBIT_HOLE_REGEX",
            )
            self.assertTrue(
                URLFilterEngine.is_rabbit_hole(url),
                f"Expected URLFilterEngine.is_rabbit_hole({url}) to be True",
            )

    def test_repeated_query_parameter_loops(self):
        loop_urls = [
            "https://example.com/products?sort=asc&sort=desc",
            "https://example.com/search?tag=a&other=1&tag=b",
            "https://example.com/items?sort=asc&page=1&filter=shoes&sort=desc",
            "https://example.com/api?id=1&id=2",
        ]
        for url in loop_urls:
            self.assertTrue(
                URLFilterEngine.is_rabbit_hole(url),
                f"Expected repeated param loop {url} to be detected as rabbit hole",
            )

    def test_benign_navigation_urls(self):
        safe_urls = [
            "https://example.com/products/shoes",
            "https://example.com/about/contact",
            "https://example.com/api/v1/users",
            "https://example.com/catalog?page=2",
            "https://example.com/items?offset=20",
            "https://example.com/items?limit=10&offset=50",
            "https://example.com/search?q=laptop&sort=price_asc",
            "https://example.com/docs/version-2.0",
        ]
        for url in safe_urls:
            self.assertFalse(
                URLFilterEngine.is_rabbit_hole(url),
                f"Expected clean URL {url} NOT to be flagged as rabbit hole",
            )


class TestURLFilterEngineCoordination(unittest.TestCase):
    """Tests overall URLFilterEngine coordination with CDNScopeResolver and filters."""

    def setUp(self):
        self.scope_resolver = CDNScopeResolver(
            target_domain="example.com",
            policy=ScopePolicy(allow_subdomains=True),
        )
        self.engine = URLFilterEngine(scope_resolver=self.scope_resolver)

    def test_clean_navigation_url(self):
        clean_urls = [
            "https://example.com/",
            "https://example.com/about",
            "https://example.com/products/view/123",
            "https://sub.example.com/dashboard",
            "/internal/page",
        ]
        for u in clean_urls:
            self.assertTrue(
                self.engine.should_crawl_page(u),
                f"Expected clean URL {u} to be allowed by should_crawl_page",
            )

    def test_scope_rejection(self):
        out_of_scope_urls = [
            "https://another-domain.org/about",
            "https://attacker.com/evil",
            "https://cdn.jsdelivr.net/npm/bootstrap@5.0.0/dist/js/bootstrap.min.js",
            "https://google-analytics.com/analytics.js",
        ]
        for u in out_of_scope_urls:
            self.assertFalse(
                self.engine.should_crawl_page(u),
                f"Expected out-of-scope URL {u} to be rejected",
            )

    def test_ssrf_rejection_in_engine(self):
        ssrf_urls = [
            "http://127.0.0.1/admin",
            "http://127.0.0.1:8080/",
            "http://localhost:3000/",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://10.0.0.1/network",
            "http://192.168.1.1/settings",
            "http://[::1]:8080/",
        ]
        for u in ssrf_urls:
            self.assertFalse(
                self.engine.should_crawl_page(u),
                f"Expected SSRF URL {u} to be rejected by should_crawl_page",
            )

    def test_oauth_rejection_in_engine(self):
        oauth_urls = [
            "https://accounts.google.com/signin/oauth",
            "https://login.microsoftonline.com/oauth2/authorize",
            "https://appleid.apple.com/auth/authorize",
            "https://github.com/login/oauth/authorize",
            "https://gitlab.com/oauth/authorize",
            "https://corp.okta.com/oauth2/v1/authorize",
            "https://auth.auth0.com/authorize",
        ]
        for u in oauth_urls:
            self.assertFalse(
                self.engine.should_crawl_page(u),
                f"Expected OAuth URL {u} to be rejected by should_crawl_page",
            )

    def test_dangerous_action_rejection_in_engine(self):
        dangerous_urls = [
            "https://example.com/logout",
            "https://example.com/api/delete",
            "https://example.com/user/cancel",
            "https://example.com/kill-switch",
            "https://example.com/cache/clear-cache",
        ]
        for u in dangerous_urls:
            self.assertFalse(
                self.engine.should_crawl_page(u),
                f"Expected dangerous action URL {u} to be rejected by should_crawl_page",
            )

    def test_rabbit_hole_rejection_in_engine(self):
        rabbit_holes = [
            "https://example.com/2024/05/12",
            "https://example.com/events/2023-11",
            "https://example.com/items?page=9999",
            "https://example.com/items?p=5000",
            "https://example.com/items?offset=20000",
            "https://example.com/items?sort=asc&sort=desc",
        ]
        for u in rabbit_holes:
            self.assertFalse(
                self.engine.should_crawl_page(u),
                f"Expected rabbit hole URL {u} to be rejected by should_crawl_page",
            )

    def test_include_exclude_regex(self):
        engine = URLFilterEngine(
            scope_resolver=self.scope_resolver,
            include_regex=r"^https://example\.com/api/.*",
            exclude_regex=r".*/admin/.*",
        )
        # In include, not in exclude -> ALLOW
        self.assertTrue(engine.should_crawl_page("https://example.com/api/v1/users"))
        # In include, but in exclude -> REJECT
        self.assertFalse(engine.should_crawl_page("https://example.com/api/v1/admin/keys"))
        # Not in include -> REJECT
        self.assertFalse(engine.should_crawl_page("https://example.com/blog/post-1"))

    def test_toggle_guards(self):
        # Allow dangerous actions if explicitly disabled
        engine_no_danger = URLFilterEngine(
            scope_resolver=self.scope_resolver,
            block_dangerous_actions=False,
        )
        self.assertTrue(engine_no_danger.should_crawl_page("https://example.com/logout"))

        # Allow rabbit holes if explicitly disabled
        engine_no_rabbit = URLFilterEngine(
            scope_resolver=self.scope_resolver,
            block_rabbit_holes=False,
        )
        self.assertTrue(engine_no_rabbit.should_crawl_page("https://example.com/catalog?page=9999"))

    def test_pseudo_schemes_and_invalid_inputs(self):
        invalids = [
            "",
            "   ",
            None,
            12345,
            "javascript:alert(1)",
            "mailto:admin@example.com",
            "tel:+1234567890",
            "data:text/html,<h1>Hello</h1>",
            "#anchor-only",
            "ftp://example.com/files",
        ]
        for inv in invalids:
            self.assertFalse(self.engine.should_crawl_page(inv))  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
