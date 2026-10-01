"""
Stress Testing and Performance Benchmarking for Module 1 (Spider & Manifest).

Covers:
1. Redirect Loop Stress Test:
   - Cyclical 301/302 redirect loops (/loop1 -> /loop2 -> /loop1)
   - Verifies the crawler aborts safely without hanging or infinite loops.
2. Rate-Limiting & 429 Backoff Test:
   - Mock HTTP 429 response with `Retry-After: 1`
   - Verifies crawler backs off gracefully, tracks metrics, and succeeds on retry.
3. Memory & High Cardinality Benchmark:
   - Simulates a page containing 1,000 dynamic URLs (/products/1 to /products/1000).
   - Measures Python memory usage via `tracemalloc`.
   - Verifies RoutePatternCollapser clamps crawling to max_per_template (2 requests).
   - Verifies RAM delta remains strictly under 10MB.
4. High Volume Manifest Benchmark:
   - Evaluates ManifestExtractor performance with high route counts.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import email.utils
import sys
import time
import tracemalloc
import unittest
from typing import Dict, List

import httpx

from api_tool.spider.crawler import (
    AsyncSpider,
    CrawlResult,
    RoutePatternCollapser,
    URLNormalizer,
)
from api_tool.spider.manifest import ManifestExtractor


class TestRedirectLoopStress(unittest.TestCase):
    """Stress tests verifying that AsyncSpider safely aborts cyclical redirect loops."""

    def test_cyclical_301_302_redirect_loop_aborts_safely(self):
        """
        Verify that a cyclical 301/302 redirect loop (/loop1 -> /loop2 -> /loop1)
        aborts safely without hanging, timing out, or consuming unbounded resources.
        """
        redirect_counts: Dict[str, int] = {"/loop1": 0, "/loop2": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if path == "/loop1":
                redirect_counts["/loop1"] += 1
                return httpx.Response(
                    301,
                    headers={"Location": "https://example.com/loop2"},
                    text="Moved Permanently to /loop2",
                )
            elif path == "/loop2":
                redirect_counts["/loop2"] += 1
                return httpx.Response(
                    302,
                    headers={"Location": "https://example.com/loop1"},
                    text="Found at /loop1",
                )
            return httpx.Response(404, text="Not Found")

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport)

        spider = AsyncSpider(
            allowed_domains=["example.com"],
            max_depth=5,
            max_pages=10,
            request_timeout=3.0,
            client=client,
        )

        async def run_crawl():
            return await spider.crawl("https://example.com/loop1")

        start_time = time.perf_counter()
        # Ensure crawl completes well within timeout (no infinite hang)
        result = asyncio.run(asyncio.wait_for(run_crawl(), timeout=5.0))
        elapsed = time.perf_counter() - start_time

        # Assertions
        start_url = "https://example.com/loop1"
        self.assertIn(start_url, result.failed_urls)
        err_msg = result.failed_urls[start_url]
        self.assertTrue(
            "redirect" in err_msg.lower() or "toomanyredirects" in err_msg.lower(),
            f"Expected redirect error, got: {err_msg}",
        )
        self.assertLess(elapsed, 2.0, f"Crawl took too long ({elapsed:.2f}s); may have hung.")
        # Ensure the mock handled redirects up to httpx safety limit (around 20) and then aborted
        total_redirects = redirect_counts["/loop1"] + redirect_counts["/loop2"]
        self.assertGreater(total_redirects, 0)
        self.assertLessEqual(total_redirects, 30)

        print(
            f"\n[BENCHMARK] Redirect Loop Stress Test:"
            f"\n  Total redirect hops handled: {total_redirects}"
            f"\n  Abort elapsed time: {elapsed * 1000:.2f} ms"
            f"\n  Failure recorded: {err_msg}"
        )

    def test_redirect_loop_in_subpage_allows_other_pages_to_succeed(self):
        """
        Verify that a redirect loop discovered during subpage crawling aborts
        safely for that specific route while other valid pages continue to be crawled.
        """
        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if path == "/":
                return httpx.Response(
                    200,
                    text="""
                    <html><body>
                        <a href="/valid-page">Valid Page</a>
                        <a href="/loop1">Redirect Loop</a>
                    </body></html>
                    """,
                    headers={"content-type": "text/html"},
                )
            elif path == "/valid-page":
                return httpx.Response(
                    200,
                    text="<html><body><h1>Valid Page Content</h1></body></html>",
                    headers={"content-type": "text/html"},
                )
            elif path == "/loop1":
                return httpx.Response(301, headers={"Location": "https://example.com/loop2"})
            elif path == "/loop2":
                return httpx.Response(302, headers={"Location": "https://example.com/loop1"})
            return httpx.Response(404, text="Not Found")

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport)

        spider = AsyncSpider(
            allowed_domains=["example.com"],
            max_depth=3,
            max_pages=10,
            client=client,
        )

        result = asyncio.run(asyncio.wait_for(spider.crawl("https://example.com/"), timeout=5.0))

        # Valid pages should have been visited and recorded
        self.assertIn("https://example.com/", result.visited_urls)
        self.assertIn("https://example.com/valid-page", result.visited_urls)

        # The loop route should be in failed_urls
        self.assertIn("https://example.com/loop1", result.failed_urls)
        paths = [e.path for e in result.endpoints]
        self.assertIn("/", paths)
        self.assertIn("/valid-page", paths)


class TestRateLimiting429Backoff(unittest.TestCase):
    """Tests verifying HTTP 429 rate limiting and backoff compliance."""

    def test_429_retry_after_numeric_backoff(self):
        """
        Mock an HTTP 429 response with `Retry-After: 1` on the first call,
        then 200 OK on the retry. Verify that the crawler backs off gracefully,
        measures the elapsed delay, and succeeds on retry.
        """
        request_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal request_count
            request_count += 1
            if request_count == 1:
                return httpx.Response(
                    429,
                    headers={"Retry-After": "1", "content-type": "application/json"},
                    text='{"error": "Too Many Requests", "retry_after": 1}',
                )
            return httpx.Response(
                200,
                headers={"content-type": "text/html"},
                text="<html><body><h1>Recovered Page</h1></body></html>",
            )

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport)

        spider = AsyncSpider(
            allowed_domains=["example.com"],
            max_retries=3,
            client=client,
        )

        t_start = time.perf_counter()
        result = asyncio.run(spider.crawl("https://example.com/rate-limited"))
        t_elapsed = time.perf_counter() - t_start

        # Verification
        self.assertEqual(request_count, 2, "Expected exactly 2 requests (1 failed 429 + 1 retry)")
        self.assertEqual(result.rate_limited_count, 1, "Expected rate_limited_count to be 1")
        self.assertAlmostEqual(result.total_backoff_seconds, 1.0, delta=0.05)
        self.assertGreaterEqual(
            t_elapsed, 1.0, f"Elapsed time ({t_elapsed:.3f}s) must be >= 1.0s to respect Retry-After: 1"
        )
        self.assertIn("https://example.com/rate-limited", result.visited_urls)
        self.assertEqual(len(result.endpoints), 1)
        self.assertEqual(result.endpoints[0].active_status, 200)

        print(
            f"\n[BENCHMARK] Rate-Limiting & 429 Backoff Test:"
            f"\n  HTTP Requests Made: {request_count}"
            f"\n  429 Rate Limits Hit: {result.rate_limited_count}"
            f"\n  Configured Retry-After: 1.0s"
            f"\n  Total Backoff Waited: {result.total_backoff_seconds:.2f}s"
            f"\n  Total Wall Time: {t_elapsed:.3f}s"
            f"\n  Final Active Status: {result.endpoints[0].active_status}"
        )

    def test_429_retry_after_http_date_backoff(self):
        """
        Verify that `Retry-After` formatted as an HTTP-date string (RFC 7231 / RFC 9110)
        is correctly parsed into a delta delay and backed off.
        """
        request_count = 0
        now_dt = datetime.now(timezone.utc)
        # Set Retry-After to 1.5 seconds in the future
        future_timestamp = now_dt.timestamp() + 1.5
        http_date_str = email.utils.formatdate(future_timestamp, usegmt=True)

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal request_count
            request_count += 1
            if request_count == 1:
                return httpx.Response(
                    429,
                    headers={"Retry-After": http_date_str, "content-type": "application/json"},
                    text='{"error": "Too Many Requests"}',
                )
            return httpx.Response(
                200,
                headers={"content-type": "text/html"},
                text="<html><body><h1>Success After Date Backoff</h1></body></html>",
            )

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport)

        spider = AsyncSpider(
            allowed_domains=["example.com"],
            max_retries=2,
            client=client,
        )

        t_start = time.perf_counter()
        result = asyncio.run(spider.crawl("https://example.com/date-limited"))
        t_elapsed = time.perf_counter() - t_start

        self.assertEqual(request_count, 2)
        self.assertEqual(result.rate_limited_count, 1)
        self.assertGreater(result.total_backoff_seconds, 0.0)
        self.assertIn("https://example.com/date-limited", result.visited_urls)
        self.assertEqual(result.endpoints[0].active_status, 200)

    def test_429_max_retries_exhaustion_does_not_loop(self):
        """
        Verify that if the server continuously returns 429, the crawler backs off
        up to max_retries times, then aborts retrying without hanging.
        """
        request_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal request_count
            request_count += 1
            return httpx.Response(
                429,
                headers={"Retry-After": "0.01"},
                text='{"error": "Permanent 429"}',
            )

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport)

        spider = AsyncSpider(
            allowed_domains=["example.com"],
            max_retries=2,
            backoff_factor=0.01,
            max_backoff_delay=0.05,
            client=client,
        )

        result = asyncio.run(asyncio.wait_for(spider.crawl("https://example.com/perm-429"), timeout=3.0))

        # Initial request + 2 retries = 3 requests total
        self.assertEqual(request_count, 3)
        self.assertEqual(result.rate_limited_count, 2)
        self.assertEqual(len(result.endpoints), 1)
        self.assertEqual(result.endpoints[0].active_status, 429)


class TestHighCardinalityMemoryBenchmark(unittest.TestCase):
    """
    Stress tests and memory benchmarks for high cardinality URL patterns.
    Simulates large volumes of dynamic URLs (/products/1 .. /products/1000)
    and measures RAM delta via tracemalloc.
    """

    def test_high_cardinality_1000_dynamic_urls_ram_benchmark(self):
        """
        Simulate a page containing 1,000 dynamic URLs (/products/1 to /products/1000).
        Measure Python memory usage via tracemalloc to verify that RoutePatternCollapser
        clamps crawling to at most max_per_template (2 requests) and RAM delta remains
        under 10MB.
        """
        total_simulated_products = 1000
        max_per_template = 2

        product_request_count = 0
        requested_product_urls: List[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal product_request_count
            url_str = str(request.url)
            path = request.url.path

            if path == "/catalog":
                # Build HTML containing 1,000 product links
                links_html = "".join(
                    f'<a href="/products/{i}">Product {i} Details</a>\n'
                    for i in range(1, total_simulated_products + 1)
                )
                html_body = f"""
                <!DOCTYPE html>
                <html>
                <head><title>Product Catalog</title></head>
                <body>
                    <h1>Catalog of {total_simulated_products} Products</h1>
                    <a href="/api/status">System Status</a>
                    <div class="product-grid">
                        {links_html}
                    </div>
                </body>
                </html>
                """
                return httpx.Response(
                    200,
                    text=html_body,
                    headers={"content-type": "text/html; charset=utf-8"},
                )

            elif path.startswith("/products/"):
                product_request_count += 1
                requested_product_urls.append(url_str)
                prod_id = path.split("/")[-1]
                return httpx.Response(
                    200,
                    text=f"<html><body><h1>Product {prod_id}</h1></body></html>",
                    headers={"content-type": "text/html; charset=utf-8"},
                )

            elif path == "/api/status":
                return httpx.Response(
                    200,
                    text='{"status": "online"}',
                    headers={"content-type": "application/json"},
                )

            return httpx.Response(404, text="Not Found")

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport)

        spider = AsyncSpider(
            allowed_domains=["example.com"],
            max_depth=2,
            max_pages=50,
            max_per_template=max_per_template,
            client=client,
        )

        # Start tracing memory allocations
        tracemalloc.start()
        tracemalloc.reset_peak()
        start_current, _ = tracemalloc.get_traced_memory()

        t0 = time.perf_counter()
        result = asyncio.run(spider.crawl("https://example.com/catalog"))
        duration = time.perf_counter() - t0

        final_current, peak_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        ram_delta_bytes = peak_mem - start_current
        ram_delta_mb = ram_delta_bytes / (1024 * 1024)
        peak_mb = peak_mem / (1024 * 1024)

        # Filter visited product URLs
        visited_products = [u for u in result.visited_urls if "/products/" in u]

        # 1. Assert RoutePatternCollapser clamped product requests to at most max_per_template
        self.assertLessEqual(
            len(visited_products),
            max_per_template,
            f"Expected at most {max_per_template} product URLs crawled, but crawled {len(visited_products)}: {visited_products}",
        )
        self.assertEqual(
            product_request_count,
            max_per_template,
            f"Expected exactly {max_per_template} HTTP requests to /products/*, but made {product_request_count}",
        )

        # 2. Verify template counts recorded in CrawlResult
        self.assertEqual(
            result.template_counts.get("/products/{id}", 0),
            max_per_template,
            f"Template count for /products/{{id}} was not clamped to {max_per_template}",
        )

        # 3. Assert RAM delta is strictly under 10MB
        self.assertLess(
            ram_delta_mb,
            10.0,
            f"RAM delta exceeded 10MB limit: {ram_delta_mb:.2f} MB",
        )

        # 4. Verify other distinct endpoints are still crawled normally
        self.assertIn("https://example.com/catalog", result.visited_urls)
        self.assertIn("https://example.com/api/status", result.visited_urls)

        pruned_urls_count = total_simulated_products - product_request_count
        pruned_percentage = (pruned_urls_count / total_simulated_products) * 100.0

        print(
            f"\n[BENCHMARK] Memory & High Cardinality Benchmark:"
            f"\n  Total dynamic URLs on page: {total_simulated_products}"
            f"\n  max_per_template setting: {max_per_template}"
            f"\n  Product HTTP requests executed: {product_request_count}"
            f"\n  Product URLs visited: {len(visited_products)}"
            f"\n  Pruned/Clamped URLs: {pruned_urls_count} ({pruned_percentage:.1f}% reduction)"
            f"\n  Peak Memory: {peak_mb:.2f} MB"
            f"\n  RAM Delta: {ram_delta_mb:.2f} MB (Limit: < 10.00 MB)"
            f"\n  Execution Time: {duration * 1000:.2f} ms"
        )

    def test_multi_pattern_high_cardinality(self):
        """
        Test multiple high-cardinality dynamic patterns simultaneously:
        - 300 Numeric IDs: /users/1 .. /users/300
        - 300 UUIDs: /orders/<uuid-1> .. /orders/<uuid-300>
        - 300 Hex IDs: /docs/<24-char-hex> .. /docs/<hex-300>
        Verifies that each pattern template is independently clamped to max_per_template.
        """
        max_per_template = 2
        counts = {"users": 0, "orders": 0, "docs": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if path == "/":
                users_html = "".join(f'<a href="/users/{i}">User {i}</a>\n' for i in range(1, 301))
                orders_html = "".join(
                    f'<a href="/orders/123e4567-e89b-12d3-a456-{i:012d}">Order {i}</a>\n'
                    for i in range(1, 301)
                )
                docs_html = "".join(
                    f'<a href="/docs/507f1f77bcf86cd79943{i:04d}">Doc {i}</a>\n'
                    for i in range(1, 301)
                )
                return httpx.Response(
                    200,
                    text=f"<html><body>{users_html}{orders_html}{docs_html}</body></html>",
                    headers={"content-type": "text/html"},
                )
            elif "/users/" in path:
                counts["users"] += 1
                return httpx.Response(200, text="User")
            elif "/orders/" in path:
                counts["orders"] += 1
                return httpx.Response(200, text="Order")
            elif "/docs/" in path:
                counts["docs"] += 1
                return httpx.Response(200, text="Doc")
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport)

        spider = AsyncSpider(
            allowed_domains=["example.com"],
            max_per_template=max_per_template,
            client=client,
        )

        tracemalloc.start()
        tracemalloc.reset_peak()
        start_mem, _ = tracemalloc.get_traced_memory()

        result = asyncio.run(spider.crawl("https://example.com/"))

        _, peak_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        ram_delta_mb = (peak_mem - start_mem) / (1024 * 1024)

        self.assertEqual(counts["users"], max_per_template)
        self.assertEqual(counts["orders"], max_per_template)
        self.assertEqual(counts["docs"], max_per_template)
        self.assertLess(ram_delta_mb, 10.0)

        print(
            f"\n[BENCHMARK] Multi-Pattern High Cardinality:"
            f"\n  Total Links (900 across 3 patterns): clamped to 2 each (6 total requests)"
            f"\n  RAM Delta: {ram_delta_mb:.2f} MB"
        )


class TestManifestExtractionStress(unittest.TestCase):
    """Stress tests on ManifestExtractor with high volume data."""

    def test_huge_manifest_extraction_performance(self):
        """
        Verify ManifestExtractor handles parsing Next.js build manifests
        with 1,000 route entries and chunk references efficiently and under 10MB RAM.
        """
        extractor = ManifestExtractor()
        routes_dict_lines = [
            f'"{f"/api/v1/resource-{i}/[id]"}": ["static/chunks/chunk-{i}.js"]'
            for i in range(1, 1001)
        ]
        manifest_js = (
            "self.__BUILD_MANIFEST = function(s) {\n"
            "  return {\n"
            + ",\n".join(routes_dict_lines)
            + ',\n    sortedPages: ["/"]\n'
            "  };\n"
            "}(1);\n"
        )

        tracemalloc.start()
        tracemalloc.reset_peak()
        start_mem, _ = tracemalloc.get_traced_memory()

        t0 = time.perf_counter()
        routes, chunks, rewrites = extractor.parse_next_build_manifest(
            manifest_js, "https://example.com"
        )
        duration = time.perf_counter() - t0

        _, peak_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        ram_delta_mb = (peak_mem - start_mem) / (1024 * 1024)

        self.assertEqual(len(routes), 1001)  # 1000 dynamic routes + sortedPage "/"
        self.assertEqual(len(set(chunks)), 1000)
        self.assertLess(ram_delta_mb, 10.0)
        self.assertLess(duration, 5.0)

        print(
            f"\n[BENCHMARK] High-Volume Manifest Extraction:"
            f"\n  Manifest Routes Parsed: {len(routes)}"
            f"\n  Chunk Scripts Extracted: {len(chunks)}"
            f"\n  Parse Duration: {duration * 1000:.2f} ms"
            f"\n  RAM Delta: {ram_delta_mb:.2f} MB"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
