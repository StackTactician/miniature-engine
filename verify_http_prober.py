"""
Quick standalone verification script for SafeHTTPProber and SSRF Guard.
Tests:
1. Clean imports from api_tool.models and api_tool.prober.http_prober
2. SSRF protection against 20+ malicious IP/host variants
3. Rate-limiter token bucket acquisition with aiolimiter
4. Mocked HTTP responses: OPTIONS probing, CORS reflection, Allow header extraction
5. Fallback from OPTIONS to HEAD and streaming GET
6. 429 Retry-After backoff
"""

import asyncio
import time
import httpx

from api_tool.models import DiscoveredEndpoint, DiscoveredParameter, DiscoveredResponse
from api_tool.prober.http_prober import SafeHTTPProber, ProbeResult, is_safe_target


def verify_ssrf_guard():
    print("\n--- 1. Testing SSRF Protection against 20+ Malicious Variants ---")
    malicious_variants = [
        # Loopback IPv4
        ("http://127.0.0.1", "IPv4 loopback"),
        ("http://127.0.0.2:8080/api", "IPv4 loopback subnet"),
        ("http://127.1", "Abbreviated IPv4 loopback"),
        # Localhost hostnames
        ("http://localhost", "Localhost name"),
        ("http://localhost.localdomain", "Localhost domain"),
        ("http://sub.localhost", "Localhost subdomain"),
        ("http://ip6-localhost", "IPv6 localhost name"),
        # IPv6 loopback and mapped
        ("http://[::1]", "IPv6 loopback"),
        ("http://[::ffff:127.0.0.1]", "IPv6-mapped IPv4"),
        ("http://[::ffff:7f00:1]", "IPv6-mapped hex IPv4"),
        ("http://[::ffff:169.254.169.254]", "IPv6-mapped metadata"),
        # Decimal notation
        ("http://2130706433", "Decimal IP for 127.0.0.1"),
        ("http://2852039166", "Decimal IP for 169.254.169.254"),
        # Octal notation
        ("http://0177.0.0.1", "Octal IP for 127.0.0.1"),
        ("http://017700000001", "Octal single integer"),
        # Hex notation
        ("http://0x7f000001", "Hex single integer"),
        ("http://0x7f.0.0.1", "Dotted hex IP"),
        # Cloud metadata
        ("http://169.254.169.254", "AWS/GCP/Azure metadata IP"),
        ("http://169.254.169.253", "AWS VPC DNS/metadata"),
        ("http://100.100.100.200", "Alibaba metadata IP"),
        ("http://[fd00:ec2::254]", "AWS IPv6 metadata"),
        ("http://metadata.google.internal", "GCP metadata hostname"),
        ("http://instance-data", "AWS metadata hostname"),
        # RFC 1918 Private ranges & CGNAT
        ("http://10.0.0.1", "Private 10.0.0.0/8"),
        ("http://172.16.0.1", "Private 172.16.0.0/12"),
        ("http://192.168.1.1", "Private 192.168.0.0/16"),
        ("http://100.64.0.1", "Carrier-Grade NAT 100.64.0.0/10"),
        ("http://0.0.0.0", "Zero address"),
        # Disallowed schemes
        ("ftp://example.com/file", "Disallowed scheme ftp"),
        ("file:///etc/passwd", "Disallowed scheme file"),
        ("gopher://127.0.0.1:70", "Disallowed scheme gopher"),
    ]

    blocked_count = 0
    for target, label in malicious_variants:
        safe, reason = is_safe_target(target)
        assert not safe, f"FAIL: Expected {target} ({label}) to be blocked, but was allowed!"
        blocked_count += 1
        print(f"  [BLOCKED] {label:<30} -> {target:<35} | {reason}")

    # Verify legitimate public endpoints pass
    public_targets = [
        "https://1.1.1.1",
        "https://8.8.8.8",
        "http://93.184.216.34",
    ]
    for target in public_targets:
        safe, reason = is_safe_target(target)
        assert safe, f"FAIL: Expected public IP {target} to be safe, but was blocked: {reason}"
        print(f"  [ALLOWED] Public target safe: {target}")

    print(f"\n[PASS] Verified {blocked_count} malicious targets successfully blocked.")


async def verify_rate_limiter():
    print("\n--- 2. Testing Rate-Limiter Token Bucket Acquisition ---")
    prober = SafeHTTPProber(rate_limit=5.0)  # 5 tokens / second
    acquired = 0
    start = time.perf_counter()
    for _ in range(6):
        async with prober.limiter:
            acquired += 1
    duration = time.perf_counter() - start
    assert acquired == 6, f"Expected 6 acquired tokens, got {acquired}"
    # 6 requests at 5 req/s requires at least ~0.2s for the 6th token
    assert duration >= 0.15, f"Expected rate limiting delay >= 0.15s, got {duration:.3f}s"
    print(f"  [PASS] Acquired {acquired} tokens in {duration:.3f}s (enforced rate limit).")


async def verify_mocked_http_responses():
    print("\n--- 3. Testing Mocked HTTP Responses & Probing Logic ---")
    prober = SafeHTTPProber(allow_private_ips=True)

    # Scenario A: OPTIONS returns 200 with Allow and CORS reflection
    ep_options = DiscoveredEndpoint(path="/api/v1/orders", base_url="http://test.api", method="POST")

    def handler_options(req: httpx.Request) -> httpx.Response:
        if req.method == "OPTIONS":
            return httpx.Response(
                200,
                headers={
                    "Allow": "GET, POST, PUT, DELETE, OPTIONS",
                    "Access-Control-Allow-Origin": req.headers.get("origin", "*"),
                    "Access-Control-Allow-Credentials": "true",
                },
            )
        return httpx.Response(404)

    client_a = httpx.AsyncClient(transport=httpx.MockTransport(handler_options))
    async with client_a:
        res_a = await prober.probe_endpoint(ep_options, client=client_a)

    assert res_a.status_code == 200
    assert "POST" in res_a.allowed_methods and "DELETE" in res_a.allowed_methods
    assert res_a.cors_reflected is True
    assert res_a.cors_allow_credentials is True
    assert ep_options.active_status == 200
    print("  [PASS] Scenario A (OPTIONS + CORS + Allow) verified successfully.")

    # Scenario B: OPTIONS 404 -> Fallback to HEAD 200
    ep_head = DiscoveredEndpoint(path="/api/v1/status", base_url="http://test.api", method="GET")

    def handler_head(req: httpx.Request) -> httpx.Response:
        if req.method == "OPTIONS":
            return httpx.Response(404)
        elif req.method == "HEAD":
            return httpx.Response(200, headers={"Server": "nginx/1.24"})
        return httpx.Response(500)

    client_b = httpx.AsyncClient(transport=httpx.MockTransport(handler_head))
    async with client_b:
        res_b = await prober.probe_endpoint(ep_head, client=client_b)

    assert res_b.status_code == 200
    assert res_b.headers.get("server") == "nginx/1.24"
    assert ep_head.active_status == 200
    print("  [PASS] Scenario B (OPTIONS 404 -> HEAD 200 fallback) verified successfully.")

    # Scenario C: OPTIONS 405, HEAD 405 -> Fallback to Streaming GET 200
    ep_get = DiscoveredEndpoint(path="/api/v1/stream", base_url="http://test.api", method="GET")

    def handler_stream(req: httpx.Request) -> httpx.Response:
        if req.method in ("OPTIONS", "HEAD"):
            return httpx.Response(405)
        elif req.method == "GET":
            return httpx.Response(200, content=b"chunked_response_data")
        return httpx.Response(400)

    client_c = httpx.AsyncClient(transport=httpx.MockTransport(handler_stream))
    async with client_c:
        res_c = await prober.probe_endpoint(ep_get, client=client_c)

    assert res_c.status_code == 200
    assert ep_get.active_status == 200
    print("  [PASS] Scenario C (OPTIONS 405 -> HEAD 405 -> GET streaming 200) verified successfully.")

    # Scenario D: 429 Rate-Limited with Retry-After backoff
    ep_retry = DiscoveredEndpoint(path="/api/v1/rate-limit", base_url="http://test.api")
    attempts = 0

    def handler_retry(req: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return httpx.Response(429, headers={"Retry-After": "0.01"})
        return httpx.Response(200, headers={"Allow": "GET"})

    client_d = httpx.AsyncClient(transport=httpx.MockTransport(handler_retry))
    async with client_d:
        res_d = await prober.probe_endpoint(ep_retry, client=client_d)

    assert attempts == 2
    assert res_d.status_code == 200
    assert ep_retry.active_status == 200
    print("  [PASS] Scenario D (429 Retry-After backoff and recovery) verified successfully.")

    # Scenario E: Probe multiple endpoints concurrently
    endpoints = [
        DiscoveredEndpoint(path=f"/api/item/{i}", base_url="http://test.api")
        for i in range(5)
    ]

    def handler_multi(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Allow": "GET, HEAD"})

    client_e = httpx.AsyncClient(transport=httpx.MockTransport(handler_multi))
    async with client_e:
        results = await prober.probe_endpoints(endpoints, client=client_e, concurrency=3)

    assert len(results) == 5
    for i, r in enumerate(results):
        assert r.endpoint.path == f"/api/item/{i}"
        assert r.status_code == 200
    print("  [PASS] Scenario E (Concurrent multi-endpoint probing) verified successfully.")


def main():
    print("================================================================")
    print(" SafeHTTPProber Standalone Verification Suite")
    print("================================================================")
    verify_ssrf_guard()
    asyncio.run(verify_rate_limiter())
    asyncio.run(verify_mocked_http_responses())
    print("\n================================================================")
    print(" ALL HTTP PROBER VERIFICATIONS PASSED SUCCESSFULLY!")
    print("================================================================")


if __name__ == "__main__":
    main()
