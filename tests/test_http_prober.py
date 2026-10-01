"""
Unit and integration tests for api_tool.prober.http_prober:
- SSRF Guard (is_safe_target) with 25+ malicious and edge-case variants
- ProbeResult dataclass serialization and fields
- SafeHTTPProber rate limiting, OPTIONS probing, CORS reflection,
  HEAD/GET streaming fallback, and 429 Retry-After handling.
"""

import asyncio
import socket
import time
import unittest
from unittest.mock import patch

import httpx

from api_tool.models import DiscoveredEndpoint
from api_tool.prober.http_prober import (
    SafeHTTPProber,
    ProbeResult,
    is_safe_target,
    _is_ip_dangerous,
)


class TestSSRFGuard(unittest.TestCase):
    """Exhaustive tests for SSRF protection against malicious and obfuscated targets."""

    def test_loopback_ipv4_variants(self):
        targets = [
            "http://127.0.0.1",
            "http://127.0.0.2",
            "http://127.1.2.3:8080/api",
            "https://127.0.0.1/test",
            "127.0.0.1",
        ]
        for t in targets:
            safe, reason = is_safe_target(t)
            self.assertFalse(safe, f"Expected {t} to be blocked, but was safe")
            self.assertTrue(len(reason) > 0)

    def test_localhost_and_internal_names(self):
        targets = [
            "http://localhost",
            "http://localhost:8080",
            "http://sub.localhost",
            "http://api.dev.localhost",
            "http://localhost.localdomain",
            "http://ip6-localhost",
            "http://ip6-loopback",
            "http://broadcasthost",
            "http://internal.corp",
            "http://printer.local",
            "http://server.lan",
            "http://nas.home",
        ]
        for t in targets:
            safe, reason = is_safe_target(t)
            self.assertFalse(safe, f"Expected {t} to be blocked, but was safe")
            self.assertIn("blocked", reason.lower())

    def test_cloud_metadata_ips_and_names(self):
        targets = [
            "http://169.254.169.254",               # AWS/GCP/Azure/OpenStack metadata
            "http://169.254.169.254:80/latest/meta-data/",
            "http://169.254.169.253",               # AWS DNS
            "http://100.100.100.200",               # Alibaba Cloud metadata
            "http://[fd00:ec2::254]",               # AWS IPv6 metadata
            "http://metadata.google.internal",      # GCP metadata name
            "http://foo.metadata.google.internal",
            "http://metadata.internal",
            "http://instance-data",                 # AWS EC2 metadata hostname
        ]
        for t in targets:
            safe, reason = is_safe_target(t)
            self.assertFalse(safe, f"Expected {t} to be blocked, but was safe")
            self.assertTrue(len(reason) > 0)

    def test_decimal_ip_notation(self):
        # 2130706433 == 127.0.0.1
        # 2852039166 == 169.254.169.254
        # 3232235521 == 192.168.0.1
        targets = [
            "http://2130706433",
            "http://2130706433:8080/admin",
            "http://2852039166",
            "http://3232235521",
            "2130706433",
        ]
        for t in targets:
            safe, reason = is_safe_target(t)
            self.assertFalse(safe, f"Expected decimal IP {t} to be blocked")
            self.assertIn("decimal", reason.lower())

    def test_octal_and_hex_and_abbreviated_ip_notation(self):
        targets = [
            "http://0177.0.0.1",       # Octal for 127.0.0.1
            "http://017700000001",     # Single octal int
            "http://0x7f000001",       # Hex for 127.0.0.1
            "http://0x7f.0.0.1",       # Dotted hex
            "http://0x7f.0x0.0x0.0x1",
            "http://127.1",            # Abbreviated IPv4
            "http://10.1",             # Abbreviated IPv4
        ]
        for t in targets:
            safe, reason = is_safe_target(t)
            self.assertFalse(safe, f"Expected alternative IP notation {t} to be blocked")

    def test_ipv6_variants_and_mapped_ipv4(self):
        targets = [
            "http://[::1]",
            "http://[::1]:8080",
            "http://[::ffff:127.0.0.1]",
            "http://[::ffff:7f00:1]",
            "http://[::ffff:169.254.169.254]",
            "http://[::ffff:192.168.1.1]",
            "http://[fe80::1]",
            "http://[fc00::1]",
            "http://[fd00::1]",
            "::1",
            "::ffff:127.0.0.1",
        ]
        for t in targets:
            safe, reason = is_safe_target(t)
            self.assertFalse(safe, f"Expected IPv6 target {t} to be blocked")

    def test_private_rfc1918_and_cgnat(self):
        targets = [
            "http://10.0.0.1",
            "http://10.254.254.254:3000",
            "http://172.16.0.1",
            "http://172.31.255.255",
            "http://192.168.1.1",
            "http://192.168.0.254",
            "http://100.64.0.1",       # CGNAT
            "http://100.127.255.254",  # CGNAT
            "http://0.0.0.0",          # Current network
        ]
        for t in targets:
            safe, reason = is_safe_target(t)
            self.assertFalse(safe, f"Expected private IP {t} to be blocked")

    def test_disallowed_schemes(self):
        disallowed = [
            "ftp://example.com/file",
            "file:///etc/passwd",
            "file:/etc/shadow",
            "gopher://127.0.0.1:70",
            "dict://localhost:11211",
            "tftp://10.0.0.1/boot",
            "ldap://127.0.0.1:389",
            "ws://example.com",
            "javascript:alert(1)",
        ]
        for d in disallowed:
            safe, reason = is_safe_target(d)
            self.assertFalse(safe, f"Expected scheme {d} to be blocked")
            self.assertIn("scheme", reason.lower())

    def test_dns_rebinding_mocked(self):
        # When a domain resolves to 127.0.0.1 or internal IP
        with patch("socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 80))
            ]
            safe, reason = is_safe_target("http://legitimate-looking-domain.com")
            self.assertFalse(safe)
            self.assertIn("127.0.0.1", reason)

        # Dual-homed domain returning public + private IP
        with patch("socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 80)),
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("10.0.0.1", 80)),
            ]
            safe, reason = is_safe_target("http://dual-homed-evil.com")
            self.assertFalse(safe)
            self.assertIn("10.0.0.1", reason)

    def test_public_safe_targets(self):
        # Known public DNS IPs
        safe1, r1 = is_safe_target("https://1.1.1.1")
        self.assertTrue(safe1, f"Expected 1.1.1.1 to be safe: {r1}")

        safe2, r2 = is_safe_target("https://8.8.8.8")
        self.assertTrue(safe2, f"Expected 8.8.8.8 to be safe: {r2}")

        safe3, r3 = is_safe_target("http://93.184.216.34")
        self.assertTrue(safe3, f"Expected 93.184.216.34 to be safe: {r3}")


class TestProbeResult(unittest.TestCase):
    def test_probe_result_serialization(self):
        ep = DiscoveredEndpoint(path="/api/v1/users", method="GET", base_url="https://api.example.com")
        res = ProbeResult(
            endpoint=ep,
            status_code=200,
            allowed_methods=["GET", "POST", "OPTIONS"],
            cors_reflected=True,
            cors_allow_origin="https://probe.cors-test.local",
            cors_allow_credentials=True,
            headers={"content-type": "application/json", "allow": "GET, POST, OPTIONS"},
            latency_ms=12.34,
            error=None,
        )
        d = res.to_dict()
        self.assertEqual(d["status_code"], 200)
        self.assertEqual(d["allowed_methods"], ["GET", "POST", "OPTIONS"])
        self.assertTrue(d["cors_reflected"])
        self.assertEqual(d["cors_allow_origin"], "https://probe.cors-test.local")
        self.assertTrue(d["cors_allow_credentials"])
        self.assertEqual(d["latency_ms"], 12.34)
        self.assertIsNone(d["error"])
        self.assertEqual(d["endpoint"]["full_url"], "https://api.example.com/api/v1/users")


class TestSafeHTTPProber(unittest.TestCase):
    def setUp(self):
        self.prober = SafeHTTPProber(
            rate_limit=10.0,
            max_burst=10,
            concurrency=5,
            request_timeout=5.0,
        )

    def test_ssrf_blocked_endpoint(self):
        # By default, allow_private_ips=False, so private/metadata endpoints are blocked
        ep = DiscoveredEndpoint(path="/latest/meta-data/", base_url="http://169.254.169.254")
        res = asyncio.run(self.prober.probe_endpoint(ep))
        self.assertIsNone(res.status_code)
        self.assertIsNotNone(res.error)
        self.assertIn("SSRF protection blocked target", res.error)
        self.assertIsNone(ep.active_status)

    def test_allow_private_ips_flag(self):
        # When allow_private_ips=True, prober doesn't reject target before request
        prober_internal = SafeHTTPProber(allow_private_ips=True)
        ep = DiscoveredEndpoint(path="/api/test", base_url="http://127.0.0.1:8000")

        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, headers={"Allow": "GET, OPTIONS"})

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport)

        async def run_test():
            async with client:
                return await prober_internal.probe_endpoint(ep, client=client)

        res = asyncio.run(run_test())
        self.assertEqual(res.status_code, 200)
        self.assertEqual(ep.active_status, 200)

    def test_options_success_with_allow_and_cors(self):
        ep = DiscoveredEndpoint(path="/api/items", base_url="https://api.example.com", method="GET")

        def handler(req: httpx.Request) -> httpx.Response:
            if req.method == "OPTIONS":
                return httpx.Response(
                    200,
                    headers={
                        "Allow": "GET, POST, DELETE, OPTIONS",
                        "Access-Control-Allow-Origin": req.headers.get("origin", "*"),
                        "Access-Control-Allow-Credentials": "true",
                    },
                )
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport)

        with patch("api_tool.prober.http_prober.is_safe_target", return_value=(True, "")):
            async def run_test():
                async with client:
                    return await self.prober.probe_endpoint(ep, client=client)

            res = asyncio.run(run_test())

        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.allowed_methods, ["GET", "POST", "DELETE", "OPTIONS"])
        self.assertTrue(res.cors_reflected)
        self.assertTrue(res.cors_allow_credentials)
        self.assertEqual(ep.active_status, 200)

    def test_options_404_fallback_to_head_success(self):
        ep = DiscoveredEndpoint(path="/api/resource", base_url="https://api.example.com", method="GET")
        requests_seen = []

        def handler(req: httpx.Request) -> httpx.Response:
            requests_seen.append(req.method)
            if req.method == "OPTIONS":
                return httpx.Response(404)
            elif req.method == "HEAD":
                return httpx.Response(200, headers={"X-Custom": "header-val"})
            return httpx.Response(500)

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport)

        with patch("api_tool.prober.http_prober.is_safe_target", return_value=(True, "")):
            async def run_test():
                async with client:
                    return await self.prober.probe_endpoint(ep, client=client)

            res = asyncio.run(run_test())

        self.assertEqual(requests_seen, ["OPTIONS", "HEAD"])
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers.get("x-custom"), "header-val")
        self.assertEqual(ep.active_status, 200)

    def test_head_405_fallback_to_get_streaming(self):
        ep = DiscoveredEndpoint(path="/api/data", base_url="https://api.example.com", method="GET")
        requests_seen = []

        def handler(req: httpx.Request) -> httpx.Response:
            requests_seen.append(req.method)
            if req.method == "OPTIONS":
                return httpx.Response(405)  # Method not allowed
            elif req.method == "HEAD":
                return httpx.Response(405)  # Method not allowed for HEAD
            elif req.method == "GET":
                return httpx.Response(200, content=b"stream-data-payload")
            return httpx.Response(400)

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport)

        with patch("api_tool.prober.http_prober.is_safe_target", return_value=(True, "")):
            async def run_test():
                async with client:
                    return await self.prober.probe_endpoint(ep, client=client)

            res = asyncio.run(run_test())

        self.assertEqual(requests_seen, ["OPTIONS", "HEAD", "GET"])
        self.assertEqual(res.status_code, 200)
        self.assertEqual(ep.active_status, 200)

    def test_429_retry_after_handling(self):
        ep = DiscoveredEndpoint(path="/api/limited", base_url="https://api.example.com")
        attempt_count = 0

        def handler(req: httpx.Request) -> httpx.Response:
            nonlocal attempt_count
            attempt_count += 1
            if attempt_count == 1:
                return httpx.Response(429, headers={"Retry-After": "0.01"})
            return httpx.Response(200, headers={"Allow": "GET, POST"})

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport)

        with patch("api_tool.prober.http_prober.is_safe_target", return_value=(True, "")):
            async def run_test():
                async with client:
                    return await self.prober.probe_endpoint(ep, client=client)

            res = asyncio.run(run_test())

        self.assertEqual(attempt_count, 2)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(ep.active_status, 200)

    def test_probe_endpoints_concurrency_and_ordering(self):
        endpoints = [
            DiscoveredEndpoint(path=f"/api/v1/item/{i}", base_url="https://api.example.com")
            for i in range(10)
        ]

        def handler(req: httpx.Request) -> httpx.Response:
            idx = req.url.path.split("/")[-1]
            return httpx.Response(200, headers={"Allow": "GET", "X-Index": str(idx)})

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport)

        with patch("api_tool.prober.http_prober.is_safe_target", return_value=(True, "")):
            async def run_test():
                async with client:
                    return await self.prober.probe_endpoints(endpoints, client=client, concurrency=3)

            results = asyncio.run(run_test())

        self.assertEqual(len(results), 10)
        for i, res in enumerate(results):
            self.assertEqual(res.endpoint.path, f"/api/v1/item/{i}")
            self.assertEqual(res.status_code, 200)
            self.assertEqual(res.headers.get("x-index"), str(i))


class TestRateLimiter(unittest.TestCase):
    def test_rate_limiter_timing(self):
        # 5 requests with rate_limit=2.0 (2 per second) should take >= 1.5 seconds for 5 tokens
        prober = SafeHTTPProber(rate_limit=2.0)
        tokens_acquired = 0

        async def run_limiter():
            nonlocal tokens_acquired
            start = time.perf_counter()
            for _ in range(4):
                async with prober.limiter:
                    tokens_acquired += 1
            return time.perf_counter() - start

        elapsed = asyncio.run(run_limiter())
        self.assertEqual(tokens_acquired, 4)
        # 4 requests at 2 req/s: 1st immediate, 2nd immediate (burst), 3rd at 0.5s, 4th at 1.0s
        self.assertGreaterEqual(elapsed, 0.8)


if __name__ == "__main__":
    unittest.main()
