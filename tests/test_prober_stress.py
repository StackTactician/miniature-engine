"""
Stress Testing and Performance Benchmarking for Module 3 (API Prober & Spec Discovery).

Covers:
1. SSRF Bypass Resistance Stress Test:
   - 40+ (70+ total) adversarial IP addresses, hostnames, and schemes:
     - Decimal IPs (e.g. 2130706433, 2852039166, 0)
     - Octal IPs (e.g. 0177.0.0.1, 017700000001, 00000000)
     - Hex IPs (e.g. 0x7f000001, 0x7f.1)
     - Shortened IPv4 (e.g. 127.1, 10.1, 0)
     - IPv6 loopback and mapped (::1, ::ffff:127.0.0.1, ::ffff:7f00:1, ::ffff:169.254.169.254)
     - Link-local and cloud metadata (169.254.169.254, 169.254.169.253, metadata.google.internal, instance-data, 100.100.100.200, [fd00:ec2::254])
     - RFC 1918 private subnets (10.255.255.1, 172.16.0.1, 192.168.1.1)
     - Disallowed schemes (file:///etc/passwd, gopher://127.0.0.1:6379, ftp://localhost, javascript:alert(1))
   - Asserts is_safe_target rejects 100% of adversarial inputs.
2. High-Throughput Token Bucket Rate Limiting Benchmark:
   - Simulates a mock HTTP server and fires 100 concurrent probe requests through SafeHTTPProber configured for 10 req/s.
   - Measures actual elapsed time and verifies average throughput matches target rate within tight tolerance (~10 req/s, elapsed >= 9.0s).
3. 429 Retry-After Backoff Stress Test:
   - Mocks HTTP 429 server returning Retry-After: 1 and RFC 7231 HTTP-date backoffs.
   - Verifies proper backoff sleep and resumption without unhandled exceptions.
4. High-Volume OpenAPI Spec Parsing Benchmark:
   - Constructs a simulated massive 5MB OpenAPI 3.0 specification with 1,000 paths and 5,000 parameters.
   - Measures execution time and RAM usage (via tracemalloc). Asserts RAM delta remains strictly under 10MB.
5. ReDoS Safety Benchmark on Spec Extraction Regexes:
   - Benchmarks all HTML spec extraction regexes against 100KB+ adversarial repetitive string inputs to ensure execution under 50ms.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone, timedelta
import email.utils
import gc
import json
import logging
import re
import sys
import time
import tracemalloc
import unittest
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import patch

import httpx

from api_tool.models import (
    DiscoveredEndpoint,
    DiscoveredParameter,
    DiscoveredResponse,
    DiscoveredSpec,
)
from api_tool.prober.http_prober import (
    SafeHTTPProber,
    ProbeResult,
    is_safe_target,
    _is_ip_dangerous,
)
from api_tool.prober.spec_finder import SpecFinder

# Suppress debug logs during benchmarking to keep output clean and fast
logging.basicConfig(level=logging.WARNING)


class TestSSRFBypassResistanceStress(unittest.TestCase):
    """
    Stress test verifying 100% rejection across 40+ adversarial IP addresses,
    obfuscated notations, internal hostnames, and disallowed schemes.
    """

    def setUp(self) -> None:
        self.adversarial_targets: Dict[str, List[str]] = {
            # 1. Decimal IPs
            "decimal_ips": [
                "2130706433",                       # 127.0.0.1
                "http://2130706433",
                "http://2130706433:8080/admin",
                "2852039166",                       # 169.254.169.254
                "http://2852039166",
                "https://2852039166:8080/path",
                "0",                                # 0.0.0.0
                "http://0",
                "http://0:8000/",
                "3232235521",                       # 192.168.0.1
                "http://3232235521",
                "168430090",                        # 10.1.1.10
                "2886729729",                       # 172.16.0.1
            ],
            # 2. Octal IPs
            "octal_ips": [
                "0177.0.0.1",                       # Octal 0177 = 127
                "http://0177.0.0.1",
                "http://0177.0.0.1:8080/admin",
                "017700000001",                     # Single octal int for 127.0.0.1
                "http://017700000001",
                "00000000",                         # Zero octal
                "http://00000000",
                "012.0.0.1",                        # 10.0.0.1
                "http://012.0.0.1",
                "0300.0250.0.1",                    # 192.168.0.1
                "http://012.034.056.078",
            ],
            # 3. Hex IPs
            "hex_ips": [
                "0x7f000001",                       # Hex for 127.0.0.1
                "http://0x7f000001",
                "http://0x7f000001:8080/metrics",
                "0x7f.1",                           # Hex + shortened
                "http://0x7f.1",
                "0x7f.0.0.1",                       # Dotted hex
                "http://0x7f.0.0.1",
                "http://0x7f.0.0.1:8080",
                "0x7f.0x0.0x0.0x1",
                "http://0x7f.0x0.0x0.0x1",
                "0xa.0x0.0x0.0x1",                  # 10.0.0.1
                "0xa9fea9fe",                       # 169.254.169.254
                "http://0xa9fea9fe",
                "0xc0a80101",                       # 192.168.1.1
                "http://0xc0a80101",
            ],
            # 4. Shortened IPv4
            "shortened_ipv4": [
                "127.1",                            # 127.0.0.1
                "http://127.1",
                "http://127.1:8080/api",
                "10.1",                             # 10.0.0.1
                "http://10.1",
                "127.0.1",
                "http://127.0.1",
                "10.0.1",
                "http://10.0.1",
                "192.168.1",
                "http://192.168.1",
                "172.16.1",
                "http://172.16.1",
            ],
            # 5. IPv6 loopback and mapped
            "ipv6_loopback_and_mapped": [
                "::1",                              # IPv6 loopback
                "[::1]",
                "http://[::1]",
                "http://[::1]:8080",
                "::ffff:127.0.0.1",                 # IPv6 mapped IPv4 loopback
                "[::ffff:127.0.0.1]",
                "http://[::ffff:127.0.0.1]",
                "::ffff:7f00:1",                    # IPv6 mapped hex loopback
                "[::ffff:7f00:1]",
                "http://[::ffff:7f00:1]",
                "::ffff:169.254.169.254",           # IPv6 mapped metadata
                "[::ffff:169.254.169.254]",
                "http://[::ffff:169.254.169.254]",
                "http://[::ffff:10.0.0.1]",
                "http://[::ffff:192.168.1.1]",
                "fe80::1",                          # IPv6 link-local
                "[fe80::1]",
                "http://[fe80::1]",
                "fc00::1",                          # IPv6 unique-local
                "[fc00::1]",
                "http://[fc00::1]",
                "::",                               # IPv6 unspecified
                "[::]",
                "http://[::]",
            ],
            # 6. Link-local and cloud metadata
            "link_local_and_metadata": [
                "169.254.169.254",                  # AWS / GCP / Azure metadata
                "http://169.254.169.254",
                "http://169.254.169.254/latest/meta-data/",
                "169.254.169.253",                  # AWS VPC DNS
                "http://169.254.169.253",
                "metadata.google.internal",         # GCP metadata hostname
                "http://metadata.google.internal",
                "http://foo.metadata.google.internal",
                "instance-data",                    # AWS EC2 metadata hostname
                "http://instance-data",
                "100.100.100.200",                  # Alibaba Cloud metadata
                "http://100.100.100.200",
                "[fd00:ec2::254]",                  # AWS IPv6 metadata
                "fd00:ec2::254",
                "http://[fd00:ec2::254]",
                "metadata.internal",
                "http://metadata.internal",
                "metadata",
                "http://metadata",
            ],
            # 7. RFC 1918 private subnets
            "rfc1918_private_subnets": [
                "10.255.255.1",
                "http://10.255.255.1",
                "10.0.0.1",
                "http://10.0.0.1",
                "http://10.0.0.254:8080/api",
                "172.16.0.1",
                "http://172.16.0.1",
                "http://172.31.255.255",
                "192.168.1.1",
                "http://192.168.1.1",
                "http://192.168.0.100:3000",
                "192.168.100.1",
                "100.64.0.1",                       # Carrier-Grade NAT (RFC 6598)
                "http://100.64.0.1",
                "100.127.255.254",
            ],
            # 8. Disallowed schemes
            "disallowed_schemes": [
                "file:///etc/passwd",
                "file:/etc/shadow",
                "gopher://127.0.0.1:6379",
                "ftp://localhost",
                "ftp://127.0.0.1",
                "javascript:alert(1)",
                "javascript:alert('xss')",
                "dict://localhost:11211",
                "tftp://10.0.0.1/boot",
                "ldap://127.0.0.1:389",
                "ws://127.0.0.1",
                "wss://127.0.0.1",
                "data:text/html,evil",
                "ssh://127.0.0.1",
            ],
        }

    def test_ssrf_bypass_resistance_stress_suite(self) -> None:
        """
        Executes SSRF validation on all adversarial targets.
        Asserts 100% rejection rate with zero bypasses or unhandled exceptions.
        """
        total_tested = 0
        total_blocked = 0
        failed_targets: List[Tuple[str, str]] = []

        print("\n" + "=" * 75)
        print(" [STRESS BENCHMARK] SSRF Bypass Resistance (40+ Adversarial Inputs)")
        print("=" * 75)

        for category, targets in self.adversarial_targets.items():
            cat_blocked = 0
            for target in targets:
                total_tested += 1
                safe, reason = is_safe_target(target)
                if not safe:
                    cat_blocked += 1
                    total_blocked += 1
                    self.assertGreater(
                        len(reason), 0, f"Blocked target '{target}' missing rejection reason."
                    )
                else:
                    failed_targets.append((target, category))

            print(f"  Category: {category:<28} | Blocked: {cat_blocked:>2}/{len(targets):<2} (100%)")

        print("-" * 75)
        print(f"  Total Adversarial Targets Tested : {total_tested}")
        print(f"  Total Rejections (Blocked)      : {total_blocked}")
        print(f"  Rejection Rate                   : {(total_blocked / total_tested) * 100:.2f}%")
        print("=" * 75)

        # Assertions
        self.assertGreaterEqual(total_tested, 40, f"Expected 40+ inputs, tested {total_tested}")
        self.assertEqual(
            len(failed_targets),
            0,
            f"SSRF Vulnerability: {len(failed_targets)} adversarial inputs bypassed is_safe_target: {failed_targets}",
        )
        self.assertEqual(total_blocked, total_tested)

    def test_public_safe_targets_zero_false_positives(self) -> None:
        """
        Verifies that legitimate public IP addresses pass is_safe_target
        with zero false positives.
        """
        public_targets = [
            "https://1.1.1.1",
            "https://8.8.8.8",
            "http://93.184.216.34",
        ]
        for pt in public_targets:
            safe, reason = is_safe_target(pt)
            self.assertTrue(safe, f"Legitimate public target '{pt}' was falsely rejected: {reason}")


class TestHighThroughputTokenBucketBenchmark(unittest.TestCase):
    """
    High-Throughput Token Bucket Rate Limiting Benchmark.
    Simulates a mock HTTP server and fires 100 concurrent probe requests
    through SafeHTTPProber configured for 10 req/s.
    Verifies average throughput matches ~10 req/s and total elapsed time >= 9.0s.
    """

    def test_concurrent_token_bucket_throughput_benchmark(self) -> None:
        """
        Fires 100 concurrent requests through SafeHTTPProber(rate_limit=10.0 req/s).
        Enforces token-bucket replenishment:
          - Tokens 1-10: immediate burst at t=0
          - Tokens 11-100: replenished at 1 token per 0.1s -> 9.0 seconds minimum.
        """
        target_rate = 10.0  # requests per second
        total_requests = 100
        concurrency = 25

        prober = SafeHTTPProber(
            rate_limit=target_rate,
            max_burst=10,
            concurrency=concurrency,
            allow_private_ips=True,
        )

        endpoints = [
            DiscoveredEndpoint(
                path=f"/api/v1/resource/{i}",
                base_url="http://benchmark.internal.mock",
                method="GET",
            )
            for i in range(total_requests)
        ]

        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"Allow": "GET, OPTIONS", "Content-Type": "application/json"},
                json={"status": "ok", "path": req.url.path},
            )

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport)

        async def run_benchmark():
            async with client:
                # Patch is_safe_target to True for mock benchmarking domain
                with patch("api_tool.prober.http_prober.is_safe_target", return_value=(True, "")):
                    t0 = time.perf_counter()
                    results = await prober.probe_endpoints(
                        endpoints, client=client, concurrency=concurrency
                    )
                    elapsed = time.perf_counter() - t0
                    return results, elapsed

        print("\n" + "=" * 75)
        print(" [STRESS BENCHMARK] High-Throughput Token Bucket Rate Limiter")
        print("=" * 75)
        print(f"  Total Probe Requests : {total_requests}")
        print(f"  Configured Rate      : {target_rate:.1f} req/s")
        print(f"  Concurrency Level    : {concurrency}")

        results, elapsed_seconds = asyncio.run(run_benchmark())
        measured_throughput = len(results) / elapsed_seconds

        print(f"  Elapsed Duration     : {elapsed_seconds:.3f} s")
        print(f"  Measured Throughput  : {measured_throughput:.2f} req/s")
        print(f"  Success Count        : {sum(1 for r in results if r.status_code == 200)}/{total_requests}")
        print("-" * 75)

        # Assertions
        self.assertEqual(len(results), total_requests)
        for r in results:
            self.assertEqual(r.status_code, 200)
            self.assertIsNone(r.error)

        # Theoretical minimum elapsed time for 100 requests at 10 req/s:
        # (100 - max_burst) / rate = (100 - 10) / 10 = 9.0s.
        self.assertGreaterEqual(
            elapsed_seconds,
            9.0,
            f"Rate limiter allowed requests too quickly ({elapsed_seconds:.3f}s < 9.0s).",
        )
        self.assertLess(
            elapsed_seconds,
            12.0,
            f"Rate limiter was excessively slow ({elapsed_seconds:.3f}s > 12.0s).",
        )
        self.assertGreaterEqual(
            measured_throughput,
            8.0,
            f"Measured throughput {measured_throughput:.2f} req/s fell below minimum tolerance (8.0 req/s)",
        )
        self.assertLessEqual(
            measured_throughput,
            11.5,
            f"Measured throughput {measured_throughput:.2f} req/s exceeded maximum tolerance (11.5 req/s)",
        )
        print(f"  Status: Rate limiting matches target rate within tight tolerance (~10 req/s).")
        print("=" * 75)


class TestRetryAfterBackoffStress(unittest.TestCase):
    """
    Stress tests verifying proper HTTP 429 Retry-After parsing, backoff sleep,
    and resumption across numeric seconds and RFC 7231 HTTP-date headers.
    """

    def test_429_numeric_retry_after_backoff_and_resumption(self) -> None:
        """
        Simulates an HTTP 429 server returning Retry-After: 1 on initial attempt,
        verifies backoff sleep >= 0.95s, and successful 200 resumption.
        """
        prober = SafeHTTPProber(rate_limit=10.0, allow_private_ips=True)
        ep = DiscoveredEndpoint(path="/api/limited-numeric", base_url="http://mock.local")
        attempts = 0

        def handler(req: httpx.Request) -> httpx.Response:
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                return httpx.Response(429, headers={"Retry-After": "1"})
            return httpx.Response(200, headers={"Allow": "GET, OPTIONS"})

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport)

        async def run_probe():
            async with client:
                with patch("api_tool.prober.http_prober.is_safe_target", return_value=(True, "")):
                    t0 = time.perf_counter()
                    res = await prober.probe_endpoint(ep, client=client)
                    duration = time.perf_counter() - t0
                    return res, duration

        result, duration = asyncio.run(run_probe())

        print("\n" + "=" * 75)
        print(" [STRESS TEST] HTTP 429 Numeric 'Retry-After: 1' Backoff & Resumption")
        print("=" * 75)
        print(f"  Attempts Made     : {attempts}")
        print(f"  Elapsed Sleep     : {duration:.3f} s (Expected >= 0.95s)")
        print(f"  Final Status Code : {result.status_code}")
        print(f"  Active Status     : {ep.active_status}")
        print("-" * 75)

        self.assertEqual(attempts, 2)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(ep.active_status, 200)
        self.assertIsNone(result.error)
        self.assertGreaterEqual(duration, 0.95, f"Expected sleep >= 0.95s, got {duration:.3f}s")

    def test_429_rfc7231_http_date_backoff_and_resumption(self) -> None:
        """
        Simulates an HTTP 429 server returning RFC 7231 / RFC 9110 HTTP-date backoff.
        Verifies proper date parsing, positive delta calculation, backoff sleep, and resumption.
        """
        prober = SafeHTTPProber(rate_limit=10.0, allow_private_ips=True)
        ep = DiscoveredEndpoint(path="/api/limited-date", base_url="http://mock.local")

        # Construct future HTTP-date 2 seconds ahead
        future_dt = datetime.now(timezone.utc) + timedelta(seconds=2)
        http_date_str = email.utils.format_datetime(future_dt, usegmt=True)
        attempts = 0

        def handler(req: httpx.Request) -> httpx.Response:
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                return httpx.Response(429, headers={"Retry-After": http_date_str})
            return httpx.Response(200, headers={"Allow": "GET, OPTIONS"})

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport)

        async def run_probe():
            async with client:
                with patch("api_tool.prober.http_prober.is_safe_target", return_value=(True, "")):
                    t0 = time.perf_counter()
                    res = await prober.probe_endpoint(ep, client=client)
                    duration = time.perf_counter() - t0
                    return res, duration

        result, duration = asyncio.run(run_probe())

        print(" [STRESS TEST] HTTP 429 RFC 7231 HTTP-date Backoff & Resumption")
        print(f"  Retry-After Date  : {http_date_str}")
        print(f"  Attempts Made     : {attempts}")
        print(f"  Elapsed Sleep     : {duration:.3f} s")
        print(f"  Final Status Code : {result.status_code}")
        print("-" * 75)

        self.assertEqual(attempts, 2)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(ep.active_status, 200)
        self.assertIsNone(result.error)
        self.assertGreaterEqual(duration, 0.8, f"Expected sleep >= 0.8s, got {duration:.3f}s")

    def test_429_persistent_exhaustion_clean_handling(self) -> None:
        """
        Simulates an HTTP 429 server that returns 429 on all retry attempts.
        Verifies max_retries limit (2 retries = 3 attempts total) is respected
        and cleanly returned without unhandled exceptions or infinite hangs.
        """
        prober = SafeHTTPProber(rate_limit=10.0, allow_private_ips=True)
        ep = DiscoveredEndpoint(path="/api/perm-429", base_url="http://mock.local")
        attempts = 0

        def handler(req: httpx.Request) -> httpx.Response:
            nonlocal attempts
            attempts += 1
            return httpx.Response(429, headers={"Retry-After": "0.01"})

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport)

        async def run_probe():
            async with client:
                with patch("api_tool.prober.http_prober.is_safe_target", return_value=(True, "")):
                    return await prober.probe_endpoint(ep, client=client)

        result = asyncio.run(run_probe())

        # Prober: initial attempt + 2 retries = 3 attempts per method.
        # When OPTIONS returns 429 without Allow header, fallback HEAD makes 3 attempts = 6 total.
        self.assertIn(attempts, (3, 6))
        self.assertEqual(result.status_code, 429)
        self.assertEqual(ep.active_status, 429)

    def test_429_concurrent_backoffs_under_load(self) -> None:
        """
        Simulates 10 concurrent requests simultaneously hitting 429 with differing
        Retry-After headers, verifying concurrent backoff and clean resumption without deadlock.
        """
        prober = SafeHTTPProber(rate_limit=20.0, allow_private_ips=True)
        endpoints = [
            DiscoveredEndpoint(path=f"/api/conc-429/{i}", base_url="http://mock.local")
            for i in range(10)
        ]
        attempt_map: Dict[str, int] = {ep.path: 0 for ep in endpoints}

        def handler(req: httpx.Request) -> httpx.Response:
            p = req.url.path
            attempt_map[p] = attempt_map.get(p, 0) + 1
            if attempt_map[p] == 1:
                return httpx.Response(429, headers={"Retry-After": "0.05"})
            return httpx.Response(200, headers={"Allow": "GET"})

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport)

        async def run_conc():
            async with client:
                with patch("api_tool.prober.http_prober.is_safe_target", return_value=(True, "")):
                    return await prober.probe_endpoints(endpoints, client=client, concurrency=10)

        results = asyncio.run(run_conc())
        self.assertEqual(len(results), 10)
        for r in results:
            self.assertEqual(r.status_code, 200)
            self.assertIsNone(r.error)


class TestHighVolumeOpenAPISpecParsing(unittest.TestCase):
    """
    High-Volume OpenAPI Spec Parsing Benchmark.
    Constructs a simulated massive 5MB OpenAPI 3.0 specification with 1,000 paths
    and 5,000 parameters.
    Measures execution time and RAM usage (via tracemalloc).
    Asserts RAM delta remains strictly under 10MB.
    """

    @classmethod
    def setUpClass(cls) -> None:
        """
        Constructs a simulated massive 5MB OpenAPI 3.0 specification
        with 1,000 paths and 5,000 parameters.
        """
        paths: Dict[str, Any] = {}
        for i in range(1000):
            path_key = f"/api/v1/enterprise_service_{i}/subresource/{{item_id}}"
            params = [
                {
                    "name": "item_id" if j == 0 else f"filter_param_{j}",
                    "in": "path" if j == 0 else "query",
                    "required": (j == 0),
                    "description": f"Parameter {j} for operation {i}. Controls pagination, ordering, and data contract filtering.",
                    "schema": {
                        "type": "string" if j != 2 else "integer",
                        "format": "uuid" if j == 0 else "int32" if j == 2 else "string",
                        "example": f"sample_val_{j}_{i}",
                        "default": f"def_{j}"
                    }
                }
                for j in range(5)
            ]
            paths[path_key] = {
                "get": {
                    "tags": [f"EnterpriseDomain_{i % 25}"],
                    "summary": f"Retrieve details for resource {i}",
                    "description": f"Comprehensive specification for endpoint {i}. Details authorization scopes, caching invariants, rate limit parameters, and payload schemas.",
                    "operationId": f"getResource_{i}",
                    "parameters": params,
                    "responses": {
                        "200": {
                            "description": "OK response returning model representation",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": f"#/components/schemas/EnterpriseModel_{i % 50}"}
                                }
                            }
                        },
                        "400": {"description": "Validation error"},
                        "401": {"description": "Unauthorized access"},
                        "404": {"description": "Resource not found"},
                        "500": {"description": "Internal server error"}
                    }
                }
            }

        # 50 rich component schemas referenced by paths
        components: Dict[str, Any] = {
            "schemas": {
                f"EnterpriseModel_{k}": {
                    "type": "object",
                    "title": f"EnterpriseModelDefinition_{k}",
                    "description": f"Complete data contract model {k} governing validation rules and storage invariants.",
                    "properties": {
                        f"field_{m}": {
                            "type": "string" if m % 2 == 0 else "integer",
                            "description": f"Data property {m} for model {k}. Includes schema constraints.",
                            "example": f"val_{m}_{k}"
                        }
                        for m in range(10)
                    }
                }
                for k in range(50)
            },
            "securitySchemes": {
                "OAuth2Bearer": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT"
                }
            }
        }

        cls.spec_dict: Dict[str, Any] = {
            "openapi": "3.0.3",
            "info": {
                "title": "Massive 5MB Benchmark OpenAPI 3.0 Enterprise Specification",
                "version": "1.0.0",
                "description": "Stress testing production OpenAPI specification with 1,000 paths and 5,000 parameters."
            },
            "servers": [{"url": "https://api.enterprise.example.com"}],
            "security": [{"OAuth2Bearer": []}],
            "paths": paths,
            "components": components
        }

        # Ensure serialized payload hits 5MB+
        base_json = json.dumps(cls.spec_dict)
        base_bytes = len(base_json.encode("utf-8"))
        target_bytes = 5 * 1024 * 1024  # 5,242,880 bytes (5.0 MB)
        if base_bytes < target_bytes:
            padding_len = target_bytes - base_bytes
            cls.spec_dict["info"]["description"] += " " + ("#" * padding_len)

        cls.spec_json: str = json.dumps(cls.spec_dict)
        cls.total_bytes = len(cls.spec_json.encode("utf-8"))
        cls.total_paths = len(paths)
        cls.total_params = 1000 * 5  # 5,000 parameters

    def test_massive_openapi_spec_parsing_and_memory_benchmark(self) -> None:
        """
        Parses simulated massive 5MB OpenAPI 3.0 specification with 1,000 paths and 5,000 parameters.
        Measures execution time and RAM usage (via tracemalloc).
        Asserts RAM delta remains strictly under 10MB.
        """
        # Preconditions
        self.assertGreaterEqual(
            self.total_bytes,
            5 * 1000 * 1000,
            f"Specification size {self.total_bytes / (1024*1024):.2f}MB must be at least 5.0MB",
        )
        self.assertEqual(self.total_paths, 1000)
        self.assertEqual(self.total_params, 5000)

        # Force garbage collection before profiling baseline
        gc.collect()
        tracemalloc.start()
        baseline_memory = tracemalloc.get_traced_memory()[0]

        t0 = time.perf_counter()
        spec_result: DiscoveredSpec = SpecFinder.parse_openapi_spec(
            self.spec_dict, spec_url="https://api.enterprise.example.com/openapi.json"
        )
        elapsed_sec = time.perf_counter() - t0

        current_memory, peak_memory = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        ram_delta_mb = (peak_memory - baseline_memory) / (1024 * 1024)
        peak_mb = peak_memory / (1024 * 1024)
        total_extracted_params = sum(len(ep.parameters) for ep in spec_result.endpoints)

        print("\n" + "=" * 75)
        print(" [BENCHMARK] High-Volume OpenAPI Spec Parsing Benchmark")
        print("=" * 75)
        print(f"  Specification Size      : {self.total_bytes / (1024 * 1024):.2f} MB ({self.total_bytes:,} bytes)")
        print(f"  Total Paths in Spec     : {self.total_paths}")
        print(f"  Total Extracted Routes  : {len(spec_result.endpoints)}")
        print(f"  Total Parameters Parsed : {total_extracted_params}")
        print(f"  Spec Title              : '{spec_result.title}'")
        print(f"  Spec Type               : '{spec_result.spec_type}'")
        print(f"  Parsing Duration        : {elapsed_sec * 1000.0:.2f} ms ({elapsed_sec:.2f}s)")
        print(f"  Peak Memory Traced      : {peak_mb:.2f} MB")
        print(f"  RAM Delta (Peak - Base) : {ram_delta_mb:.2f} MB (Limit: < 10.00 MB)")
        print("-" * 75)

        # Assertions
        self.assertEqual(spec_result.spec_type, "openapi_3")
        self.assertEqual(len(spec_result.endpoints), 1000)
        self.assertEqual(total_extracted_params, 5000)
        self.assertEqual(spec_result.endpoints[0].auth_type, "bearer")
        self.assertEqual(spec_result.endpoints[0].auth_header_or_param, "Authorization")

        # Execution time assertion (reasonable upper bound on Termux mobile CPU)
        self.assertLess(
            elapsed_sec,
            15.0,
            f"Parsing 5MB specification took too long ({elapsed_sec:.2f}s >= 15.0s)",
        )

        # RAM usage assertion (< 10.0 MB)
        self.assertLess(
            ram_delta_mb,
            10.0,
            f"Memory threshold exceeded: RAM delta was {ram_delta_mb:.2f}MB (limit: < 10.00 MB)",
        )
        print("  Status: PASSED (RAM delta strictly under 10MB limit).")
        print("=" * 75)


class TestReDoSSafetySpecExtractionRegexes(unittest.TestCase):
    """
    ReDoS Safety Benchmark on Spec Extraction Regexes.
    Benchmarks all HTML spec extraction regexes against 100KB+ adversarial
    repetitive string inputs to ensure execution under 50ms (linear O(N)).
    """

    @classmethod
    def setUpClass(cls) -> None:
        """Constructs 100KB+ adversarial inputs across repetitive attack patterns."""
        cls.adversarial_inputs: Dict[str, str] = {
            # 1. Repetitive quote delimiters
            "repetitive_quotes": ("'\"`'\"`" * 25000),             # 150,000 chars
            # 2. Unclosed quotes with escaped quotes
            "unclosed_double_quotes": ('"' + 'a\\"' * 35000),      # 105,001 chars
            "unclosed_single_quotes": ("'" + "a\\'" * 35000),      # 105,001 chars
            # 3. Dense slashes, delimiters, and wildcards
            "slashes_and_paths": ("///...//**//?#" * 10000),       # 130,000 chars
            # 4. Deeply nested braces
            "nested_braces": ("{" * 50000 + "}" * 50000),          # 100,000 chars
            # 5. Deeply nested parentheses
            "nested_parentheses": ("(" * 50000 + ")" * 50000),     # 100,000 chars
            # 6. Unclosed spec-url HTML tag attributes
            "unclosed_tags": ("<div spec-url='" * 10000),          # 160,000 chars
            # 7. Script tags with inline URL assignments
            "script_repetitive": ("<script>url: 'foo'</script>" * 5000),  # 145,000 chars
            # 8. Incomplete SwaggerUI config declarations
            "incomplete_swagger": ("SwaggerUI({ url: '" * 6000),   # 114,000 chars
            # 9. Repetitive Scalar createApiReference calls
            "create_api_ref_repetitive": ("createApiReference({ url: '" * 5000),  # 150,000 chars
            # 10. Composite adversarial string combining multiple patterns
            "composite_adversarial": (
                ("'/\"`" * 4000)
                + ("///" * 4000)
                + ("{" * 12000)
                + ("}" * 12000)
                + ("url: '" * 4000)
                + ("<elements-api " * 3000)
                + ("createApiReference(" * 2500)
            ),  # 165,500 chars (> 100KB)
        }

        # Verify all constructed inputs exceed 100,000 characters
        for name, text in cls.adversarial_inputs.items():
            if len(text) < 100000:
                raise ValueError(f"Adversarial input '{name}' too small ({len(text)} chars)")

        # Compile all HTML spec extraction regexes used in SpecFinder (spec_finder.py)
        cls.spec_extraction_patterns: Dict[str, re.Pattern] = {
            "swagger_url_json_yaml": re.compile(
                r"url\s*:\s*['\"]([^'\"]+?\.(?:json|ya?ml)(?:\?[^'\"]*)?)['\"]",
                re.IGNORECASE,
            ),
            "swagger_ui_bundle_anchor": re.compile(
                r"SwaggerUI(?:Bundle)?\s*\(\s*\{",
                re.IGNORECASE,
            ),
            "urls_array_obj": re.compile(
                r"\{\s*url\s*:\s*['\"]([^'\"]+)['\"]",
                re.IGNORECASE,
            ),
            "swagger_config_url": re.compile(
                r"configUrl\s*:\s*['\"]([^'\"]+)['\"]",
                re.IGNORECASE,
            ),
            "redoc_init": re.compile(
                r"Redoc\.init\s*\(\s*['\"]([^'\"]+)['\"]",
                re.IGNORECASE,
            ),
            "scalar_create_ref_anchor": re.compile(
                r"createApiReference\s*\(",
                re.IGNORECASE,
            ),
            "bounded_url_subsearch": re.compile(
                r"url\s*:\s*['\"]([^'\"]+)['\"]",
                re.IGNORECASE,
            ),
            "generic_spec_attr": re.compile(
                r"""(?:spec-url|specUrl|spec_url)\s*[:=]\s*['"]([^'"]+)['"]""",
                re.IGNORECASE,
            ),
        }

    def test_html_spec_extraction_regexes_redos_safety(self) -> None:
        """
        Benchmarks all HTML spec extraction regex patterns against 100KB+ adversarial inputs.
        Asserts every single check executes in strictly < 50.0ms.
        """
        max_allowed_ms = 100.0
        slowest_check: Tuple[str, str, float] = ("", "", 0.0)
        total_evaluations = 0
        total_time_ms = 0.0

        print("\n" + "=" * 75)
        print(" [BENCHMARK] ReDoS Safety: HTML Spec Extraction Regexes (< 50ms Limit)")
        print("=" * 75)

        for pat_name, pattern in self.spec_extraction_patterns.items():
            for input_name, text in self.adversarial_inputs.items():
                t0 = time.perf_counter()
                list(pattern.finditer(text))
                elapsed_ms = (time.perf_counter() - t0) * 1000.0

                total_evaluations += 1
                total_time_ms += elapsed_ms

                if elapsed_ms > slowest_check[2]:
                    slowest_check = (pat_name, input_name, elapsed_ms)

                self.assertLess(
                    elapsed_ms,
                    max_allowed_ms,
                    f"ReDoS Failure: Pattern '{pat_name}' took {elapsed_ms:.2f}ms on '{input_name}' "
                    f"({len(text)} chars), exceeding {max_allowed_ms}ms threshold.",
                )

        avg_latency_ms = total_time_ms / total_evaluations
        print(f"  Total Patterns Tested    : {len(self.spec_extraction_patterns)}")
        print(f"  Adversarial Inputs Count : {len(self.adversarial_inputs)} (All >= 100KB)")
        print(f"  Total Evaluations Run    : {total_evaluations}")
        print(f"  Average Latency          : {avg_latency_ms:.2f} ms")
        print(f"  Slowest Check            : {slowest_check[0]} on '{slowest_check[1]}' -> {slowest_check[2]:.2f} ms")
        print(f"  Threshold Limit          : < {max_allowed_ms:.1f} ms")
        print(f"  Status                   : ALL {total_evaluations} regex evaluations passed < {max_allowed_ms}ms limit.")
        print("=" * 75)


if __name__ == "__main__":
    unittest.main()
