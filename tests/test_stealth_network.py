"""
Tests for the stealth networking subsystem (api_tool/network/).
Covers:
- BrowserProfile (Chrome 120 impersonation profile)
- StealthResponse (status, case-insensitive headers, content, text, cookies, json, raise_for_status)
- StealthAsyncClient (with httpx.MockTransport in-memory fallback, cookie sync, verbs, lifecycle)
- WAFDetector (Cloudflare Turnstile/managed, Akamai, AWS WAF, Reddit PoW)
- RedditPoWSolver (pure Python SHA256 iteration < 5ms, challenge extraction, verification)
"""

import asyncio
import json
import time
import unittest

import httpx
from api_tool.network import (
    BrowserProfile,
    HTTPStatusError,
    RedditPoWSolver,
    StealthAsyncClient,
    StealthResponse,
    WAFDetector,
)
from api_tool.network.challenge import PoWSolution, WAFDetectionResult


class TestBrowserProfile(unittest.TestCase):
    def test_default_profile_headers(self):
        profile = BrowserProfile()
        headers = profile.get_headers()

        self.assertIn("User-Agent", headers)
        self.assertIn("Chrome/120", headers["User-Agent"])
        self.assertIn("Sec-Ch-Ua", headers)
        self.assertIn('"Chromium";v="120"', headers["Sec-Ch-Ua"])
        self.assertIn('"Google Chrome";v="120"', headers["Sec-Ch-Ua"])
        self.assertEqual(headers["Sec-Ch-Ua-Mobile"], "?0")
        self.assertEqual(headers["Sec-Ch-Ua-Platform"], '"Windows"')
        self.assertEqual(headers["Sec-Fetch-Dest"], "document")
        self.assertEqual(headers["Sec-Fetch-Mode"], "navigate")
        self.assertEqual(headers["Sec-Fetch-Site"], "none")
        self.assertEqual(headers["Sec-Fetch-User"], "?1")
        self.assertIn("en-US", headers["Accept-Language"])
        self.assertEqual(headers["Upgrade-Insecure-Requests"], "1")

    def test_custom_headers_override(self):
        profile = BrowserProfile(headers={"X-Custom-Client": "Agent-007", "Sec-Ch-Ua-Platform": '"Linux"'})
        headers = profile.get_headers()
        self.assertEqual(headers["X-Custom-Client"], "Agent-007")
        self.assertEqual(headers["Sec-Ch-Ua-Platform"], '"Linux"')
        # Non-overridden headers remain intact
        self.assertIn("Chrome/120", headers["User-Agent"])

    def test_factory_methods(self):
        p1 = BrowserProfile.chrome_120()
        p2 = BrowserProfile.default()
        self.assertEqual(p1.impersonate, "chrome120")
        self.assertEqual(p2.impersonate, "chrome120")
        self.assertEqual(p1.user_agent, p2.user_agent)

    def test_to_dict(self):
        profile = BrowserProfile()
        d = profile.to_dict()
        self.assertIsInstance(d, dict)
        self.assertEqual(d["impersonate"], "chrome120")
        self.assertIn("headers", d)
        self.assertEqual(d["headers"]["Sec-Ch-Ua-Mobile"], "?0")


class TestStealthResponse(unittest.TestCase):
    def test_response_creation_and_fields(self):
        resp = StealthResponse(
            status_code=200,
            headers={"Content-Type": "application/json; charset=utf-8"},
            content=b'{"status": "ok"}',
            url="https://example.com/api",
            cookies={"session": "xyz123"},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.url, "https://example.com/api")
        self.assertEqual(resp.cookies["session"], "xyz123")
        self.assertEqual(resp.text, '{"status": "ok"}')
        self.assertEqual(resp.content, b'{"status": "ok"}')
        self.assertEqual(resp.json(), {"status": "ok"})
        self.assertTrue(resp.is_success)
        self.assertFalse(resp.is_error)

    def test_text_and_content_auto_sync(self):
        # Initialized with text only
        r1 = StealthResponse(status_code=200, text="hello world")
        self.assertEqual(r1.content, b"hello world")

        # Initialized with content only
        r2 = StealthResponse(status_code=200, content=b"byte payload")
        self.assertEqual(r2.text, "byte payload")

    def test_case_insensitive_headers(self):
        resp = StealthResponse(
            status_code=200,
            headers={"Content-Type": "application/json", "X-Server-Id": "srv-99"},
        )
        self.assertEqual(resp.headers["content-type"], "application/json")
        self.assertEqual(resp.headers["Content-Type"], "application/json")
        self.assertEqual(resp.headers["CONTENT-TYPE"], "application/json")
        self.assertEqual(resp.headers.get("x-server-id"), "srv-99")
        self.assertIn("x-server-id", resp.headers)
        self.assertIn("X-Server-Id", resp.headers)

    def test_json_parsing(self):
        resp = StealthResponse(
            status_code=200,
            content=b'{"items": [1, 2, 3], "nested": {"key": "val"}}',
        )
        data = resp.json()
        self.assertEqual(data["items"], [1, 2, 3])
        self.assertEqual(data["nested"]["key"], "val")

        # Empty body raises ValueError
        empty_resp = StealthResponse(status_code=200, content=b"", text="")
        with self.assertRaises(ValueError):
            empty_resp.json()

    def test_raise_for_status_success(self):
        for code in (200, 201, 204, 301, 302):
            resp = StealthResponse(status_code=code, url="https://test.local")
            # Should not raise
            ret = resp.raise_for_status()
            self.assertIs(ret, resp)

    def test_raise_for_status_error(self):
        for code in (400, 401, 403, 404, 500, 502, 503):
            resp = StealthResponse(status_code=code, url="https://test.local/err")
            with self.assertRaises(HTTPStatusError) as ctx:
                resp.raise_for_status()
            self.assertEqual(ctx.exception.status_code, code)
            self.assertIs(ctx.exception.response, resp)
            self.assertIn(str(code), str(ctx.exception))

    def test_status_helper_properties(self):
        self.assertTrue(StealthResponse(status_code=200).is_success)
        self.assertTrue(StealthResponse(status_code=302).is_redirect)
        self.assertTrue(StealthResponse(status_code=403).is_client_error)
        self.assertTrue(StealthResponse(status_code=404).is_error)
        self.assertTrue(StealthResponse(status_code=500).is_server_error)
        self.assertTrue(StealthResponse(status_code=503).is_error)

    def test_to_dict(self):
        resp = StealthResponse(
            status_code=200,
            url="https://api.test/v1",
            headers={"Content-Type": "application/json"},
            cookies={"uid": "42"},
            text="{}",
        )
        d = resp.to_dict()
        self.assertEqual(d["status_code"], 200)
        self.assertEqual(d["url"], "https://api.test/v1")
        self.assertEqual(d["cookies"], {"uid": "42"})
        self.assertIn("headers", d)


class TestStealthAsyncClientWithMockTransport(unittest.IsolatedAsyncioTestCase):
    async def test_get_request(self):
        def handler(request: httpx.Request) -> httpx.Response:
            self.assertEqual(request.method, "GET")
            self.assertEqual(request.url.path, "/api/users")
            # Verify default Chrome 120 headers were sent
            self.assertIn("Chrome/120", request.headers.get("User-Agent", ""))
            self.assertIn('"Chromium";v="120"', request.headers.get("Sec-Ch-Ua", ""))
            return httpx.Response(200, json={"users": ["alice", "bob"]})

        transport = httpx.MockTransport(handler)
        client = StealthAsyncClient(mock_transport=transport)
        self.assertTrue(client.is_mock)

        resp = await client.get("https://example.com/api/users")
        self.assertIsInstance(resp, StealthResponse)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {"users": ["alice", "bob"]})
        await client.aclose()

    async def test_post_request_json_and_data(self):
        def handler(request: httpx.Request) -> httpx.Response:
            self.assertEqual(request.method, "POST")
            body = json.loads(request.read().decode())
            return httpx.Response(201, json={"created": body["name"], "id": 101})

        transport = httpx.MockTransport(handler)
        async with StealthAsyncClient(transport=transport) as client:
            resp = await client.post("https://example.com/api/items", json={"name": "Widget"})
            self.assertEqual(resp.status_code, 201)
            self.assertEqual(resp.json()["created"], "Widget")
            self.assertEqual(resp.json()["id"], 101)

    async def test_all_http_verbs(self):
        recorded_methods = []

        def handler(request: httpx.Request) -> httpx.Response:
            recorded_methods.append(request.method)
            return httpx.Response(200, text=f"ACK {request.method}")

        transport = httpx.MockTransport(handler)
        async with StealthAsyncClient(transport=transport) as client:
            await client.head("https://example.com/res")
            await client.options("https://example.com/res")
            await client.put("https://example.com/res", json={"updated": True})
            await client.patch("https://example.com/res", json={"patched": True})
            await client.delete("https://example.com/res")

        self.assertEqual(recorded_methods, ["HEAD", "OPTIONS", "PUT", "PATCH", "DELETE"])

    async def test_cookie_synchronization(self):
        call_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # First request: server sets auth token cookie
                headers = [("Set-Cookie", "auth_token=secret_xyz; Path=/"), ("Set-Cookie", "session_id=sess_1; Path=/")]
                return httpx.Response(200, headers=headers, json={"login": "ok"})
            else:
                # Second request: verify client automatically sent back the cookies
                cookie_header = request.headers.get("Cookie", "")
                self.assertIn("auth_token=secret_xyz", cookie_header)
                self.assertIn("session_id=sess_1", cookie_header)
                return httpx.Response(200, json={"auth": "confirmed"})

        transport = httpx.MockTransport(handler)
        async with StealthAsyncClient(transport=transport) as client:
            r1 = await client.post("https://example.com/login", json={"user": "admin"})
            self.assertEqual(r1.status_code, 200)
            self.assertIn("auth_token", client.cookies)
            self.assertEqual(client.cookies["auth_token"], "secret_xyz")

            r2 = await client.get("https://example.com/protected")
            self.assertEqual(r2.status_code, 200)
            self.assertEqual(r2.json()["auth"], "confirmed")

    async def test_custom_request_headers_override(self):
        def handler(request: httpx.Request) -> httpx.Response:
            self.assertEqual(request.headers.get("Authorization"), "Bearer test-jwt-token")
            self.assertEqual(request.headers.get("X-Request-Id"), "req-12345")
            # Profile headers still present
            self.assertIn("Chrome/120", request.headers.get("User-Agent"))
            return httpx.Response(200, json={"ok": True})

        transport = httpx.MockTransport(handler)
        async with StealthAsyncClient(transport=transport) as client:
            resp = await client.get(
                "https://example.com/secure",
                headers={"Authorization": "Bearer test-jwt-token", "X-Request-Id": "req-12345"},
            )
            self.assertEqual(resp.status_code, 200)

    async def test_relative_url_with_base_url(self):
        def handler(request: httpx.Request) -> httpx.Response:
            self.assertEqual(str(request.url), "https://api.gateway.internal/v2/metrics")
            return httpx.Response(200, json={"cpu": 12.5})

        transport = httpx.MockTransport(handler)
        async with StealthAsyncClient(transport=transport, base_url="https://api.gateway.internal/v2") as client:
            resp = await client.get("/metrics")
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.json()["cpu"], 12.5)

    async def test_open_and_close_lifecycle_dual_mode(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="lifecycle test")

        transport = httpx.MockTransport(handler)

        # Style 1: await client.open()
        c1 = StealthAsyncClient(transport=transport)
        res_open = await c1.open()
        self.assertIs(res_open, c1)
        r = await c1.get("https://example.com")
        self.assertEqual(r.text, "lifecycle test")
        await c1.aclose()
        self.assertTrue(c1.is_closed)

        # Style 2: synchronous client.open() chaining
        c2 = StealthAsyncClient(transport=transport).open()
        r2 = await c2.get("https://example.com")
        self.assertEqual(r2.text, "lifecycle test")
        await c2.aclose()

    async def test_raise_for_status_integration(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404, json={"error": "Endpoint not found"})

        transport = httpx.MockTransport(handler)
        async with StealthAsyncClient(transport=transport) as client:
            resp = await client.get("https://example.com/nonexistent")
            self.assertEqual(resp.status_code, 404)
            with self.assertRaises(HTTPStatusError) as ctx:
                resp.raise_for_status()
            self.assertEqual(ctx.exception.status_code, 404)

    async def test_transport_property_and_mock_client_injection(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="direct client")

        transport = httpx.MockTransport(handler)
        raw_client = httpx.AsyncClient(transport=transport)

        client = StealthAsyncClient(mock_client=raw_client)
        self.assertTrue(client.is_mock)
        self.assertIs(client.transport, transport)
        self.assertIs(client._transport, transport)

        resp = await client.get("https://example.com")
        self.assertEqual(resp.text, "direct client")
        await client.aclose()


class TestStealthAsyncClientCurlMode(unittest.IsolatedAsyncioTestCase):
    async def test_curl_session_initialization_and_close(self):
        client = StealthAsyncClient()
        self.assertFalse(client.is_mock)
        self.assertIsNotNone(client._curl_session)
        self.assertFalse(client.is_closed)
        await client.aclose()
        self.assertTrue(client.is_closed)

    async def test_curl_mode_request_and_cookie_sync(self):
        client = StealthAsyncClient()

        class MockCurlResp:
            status_code = 200
            headers = {"content-type": "application/json", "server": "cloudflare"}
            content = b'{"real_curl": true}'
            text = '{"real_curl": true}'
            url = "https://example.com/api"
            cookies = {"cf_clearance": "abc_token_123"}

        async def mock_request(*args, **kwargs):
            return MockCurlResp()

        client._curl_session.request = mock_request
        resp = await client.get("https://example.com/api")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {"real_curl": True})
        self.assertEqual(client.cookies["cf_clearance"], "abc_token_123")
        self.assertEqual(resp.cookies["cf_clearance"], "abc_token_123")
        await client.aclose()


class TestWAFDetector(unittest.TestCase):
    def test_cloudflare_turnstile_detection(self):
        html_body = """
        <!DOCTYPE html>
        <html>
        <head><title>Verify you are human</title></head>
        <body>
            <div id="turnstile-wrapper">
                <div class="cf-turnstile" data-sitekey="0x4AAAAAAABcd12345678"></div>
            </div>
            <script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script>
        </body>
        </html>
        """
        resp = StealthResponse(
            status_code=200,
            headers={"Server": "cloudflare", "cf-ray": "8432a9bcd891-DFW"},
            text=html_body,
        )
        result = WAFDetector.detect(resp)
        self.assertTrue(result.detected)
        self.assertEqual(result.waf_name, "cloudflare")
        self.assertEqual(result.challenge_type, "turnstile")
        self.assertTrue(WAFDetector.detect_cloudflare(resp))
        self.assertTrue(WAFDetector.is_challenge(resp))

    def test_cloudflare_managed_challenge(self):
        html_body = """
        <html>
        <head><title>Just a moment...</title></head>
        <body>Checking your browser before accessing example.com.
        <div class="cf-browser-verification"></div>
        </body>
        </html>
        """
        resp = StealthResponse(
            status_code=403,
            headers={"Server": "cloudflare", "cf-mitigated": "challenge", "cf-ray": "99aabbcc-EWR"},
            text=html_body,
        )
        result = WAFDetector.detect(resp)
        self.assertTrue(result.detected)
        self.assertEqual(result.waf_name, "cloudflare")
        self.assertEqual(result.challenge_type, "managed_challenge")
        self.assertTrue(WAFDetector.detect_cloudflare(resp))

    def test_akamai_bot_manager_detection(self):
        resp = StealthResponse(
            status_code=403,
            headers={"Server": "AkamaiGHost", "X-Akamai-Transformed": "9 100 0 p"},
            cookies={"_abck": "1234567890ABCDEF~0~YAAQ..."},
            text="<html><body>Access Denied. Reference #18.123456.789</body></html>",
        )
        result = WAFDetector.detect(resp)
        self.assertTrue(result.detected)
        self.assertEqual(result.waf_name, "akamai")
        self.assertEqual(result.challenge_type, "bot_manager")
        self.assertTrue(WAFDetector.detect_akamai(resp))

    def test_aws_waf_detection(self):
        resp = StealthResponse(
            status_code=403,
            headers={"x-amzn-waf-action": "block", "x-amzn-errortype": "WAFForbiddenException"},
            text="<html><body>Request blocked by AWS WAF</body></html>",
        )
        result = WAFDetector.detect(resp)
        self.assertTrue(result.detected)
        self.assertEqual(result.waf_name, "aws_waf")
        self.assertEqual(result.challenge_type, "block")
        self.assertTrue(WAFDetector.detect_aws_waf(resp))

    def test_aws_waf_captcha_detection(self):
        resp = StealthResponse(
            status_code=405,
            headers={"x-amzn-waf-action": "captcha"},
            text="<script src='https://awswaf.js'></script><div id='aws-waf-captcha'></div>",
        )
        result = WAFDetector.detect(resp)
        self.assertTrue(result.detected)
        self.assertEqual(result.waf_name, "aws_waf")
        self.assertEqual(result.challenge_type, "captcha")
        self.assertTrue(WAFDetector.detect_aws_waf(resp))

    def test_reddit_pow_detection(self):
        resp = StealthResponse(
            status_code=429,
            headers={"x-reddit-pow-challenge": json.dumps({"nonce": "pow_128", "difficulty": 4})},
            text='{"error": "rate_limited", "reddit_pow": true}',
        )
        result = WAFDetector.detect(resp)
        self.assertTrue(result.detected)
        self.assertEqual(result.waf_name, "reddit_pow")
        self.assertEqual(result.challenge_type, "pow")
        self.assertTrue(WAFDetector.detect_reddit_pow(resp))

    def test_clean_response_not_detected(self):
        resp = StealthResponse(
            status_code=200,
            headers={"Content-Type": "application/json", "Server": "nginx"},
            text='{"status": "ok", "items": [1, 2, 3]}',
        )
        result = WAFDetector.detect(resp)
        self.assertFalse(result.detected)
        self.assertIsNone(result.waf_name)
        self.assertFalse(WAFDetector.is_challenge(resp))


class TestRedditPoWSolver(unittest.TestCase):
    def test_solve_difficulty_4_under_5ms(self):
        # 'pow_128' with difficulty 4 reaches '000066c4...' at i=29 (~30 iterations)
        t0 = time.perf_counter()
        solution = RedditPoWSolver.solve("pow_128", difficulty=4)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        self.assertIsInstance(solution, PoWSolution)
        self.assertEqual(solution.nonce, "pow_128")
        self.assertEqual(solution.difficulty, 4)
        self.assertEqual(solution.solution, 29)
        self.assertTrue(solution.hash.startswith("0000"))
        # Strictly assert execution took under 5ms
        self.assertLess(elapsed_ms, 5.0, f"PoW solver took {elapsed_ms:.2f}ms (must be < 5ms)")

    def test_solve_and_verify(self):
        # 'reddit_pow_350' reaches '0000d0b2...' at i=56
        solution = RedditPoWSolver.solve("reddit_pow_350", difficulty=4)
        self.assertEqual(solution.solution, 56)
        self.assertTrue(RedditPoWSolver.verify("reddit_pow_350", solution.solution, difficulty=4))

        # Incorrect solution verification fails
        self.assertFalse(RedditPoWSolver.verify("reddit_pow_350", 999999, difficulty=4))
        self.assertFalse(RedditPoWSolver.verify("wrong_nonce", solution.solution, difficulty=4))

    def test_extract_challenge_from_header_json(self):
        resp = StealthResponse(
            status_code=429,
            headers={"x-reddit-pow-challenge": json.dumps({"nonce": "seed_xyz", "difficulty": 4})},
        )
        challenge = RedditPoWSolver.extract_challenge(resp)
        self.assertIsNotNone(challenge)
        self.assertEqual(challenge["nonce"], "seed_xyz")
        self.assertEqual(challenge["difficulty"], 4)

    def test_extract_challenge_from_header_colon(self):
        resp = StealthResponse(
            status_code=429,
            headers={"x-reddit-pow": "nonce_abc:4"},
        )
        challenge = RedditPoWSolver.extract_challenge(resp)
        self.assertIsNotNone(challenge)
        self.assertEqual(challenge["nonce"], "nonce_abc")
        self.assertEqual(challenge["difficulty"], 4)

    def test_extract_challenge_from_body_json(self):
        resp = StealthResponse(
            status_code=403,
            text=json.dumps({"error": "pow_required", "pow": {"nonce": "body_nonce_123", "difficulty": 4}}),
        )
        challenge = RedditPoWSolver.extract_challenge(resp)
        self.assertIsNotNone(challenge)
        self.assertEqual(challenge["nonce"], "body_nonce_123")
        self.assertEqual(challenge["difficulty"], 4)

    def test_max_iterations_timeout(self):
        # Restrict max iterations to 5 on a seed that requires more than 5
        with self.assertRaises(TimeoutError):
            RedditPoWSolver.solve("unsolvable_seed_test", difficulty=4, max_iterations=5)

    def test_detect_js_challenge(self):
        sample_html = """
        <html>
        <head>
        <script>
        document.addEventListener("DOMContentLoaded",async function(){
            var e=document.forms[0],n=await(async e=>e+e)("8bc5318db0b76aad");
            e.elements.namedItem("solution").value=n,e.requestSubmit()
        });
        </script>
        </head>
        <body>
        <form action="/" method="GET">
            <input type="hidden" name="solution" value="" />
            <input type="hidden" name="js_challenge" value="1" />
            <input type="hidden" name="jsc_token" value="tok_999" />
        </form>
        </body>
        </html>
        """
        res = RedditPoWSolver.detect_js_challenge(sample_html)
        self.assertIsNotNone(res)
        self.assertEqual(res["seed"], "8bc5318db0b76aad")
        self.assertEqual(res["solution"], "8bc5318db0b76aad8bc5318db0b76aad")
        self.assertEqual(res["action"], "/")
        self.assertEqual(res["inputs"]["js_challenge"], "1")
        self.assertEqual(res["inputs"]["jsc_token"], "tok_999")
        self.assertEqual(res["inputs"]["solution"], "8bc5318db0b76aad8bc5318db0b76aad")


if __name__ == "__main__":
    unittest.main()
