"""
Unit tests for API-First Priority Queue and Kirsch-Mitzenmacher Bloom Filter:
- PurePythonBloomFilter: insertions, membership, bounded false positive rate, memory footprint
- URLScorer: priority scoring heuristics (specs > manifests > js > api > content > pagination)
- PrioritizedRequest: min-heap ordering and comparison
- PriorityURLScheduler: async queue scheduling and FIFO tie-breaking
"""

import asyncio
import unittest

from api_tool.spider.priority_queue import (
    PrioritizedRequest,
    PriorityURLScheduler,
    PurePythonBloomFilter,
    URLScorer,
)


class TestPurePythonBloomFilter(unittest.TestCase):
    def test_default_initialization_and_footprint(self):
        """Test default 1M URL capacity allocates ~1.71 MB RAM (bytearray(1797199))."""
        bf = PurePythonBloomFilter()
        self.assertEqual(bf.capacity, 1_000_000)
        self.assertEqual(bf.false_positive_rate, 0.001)
        self.assertEqual(bf.count, 0)
        self.assertEqual(len(bf), 0)

        # Expected size: bytearray(1797199)
        self.assertEqual(bf.size_bytes, 1_797_199)
        megabytes = bf.size_bytes / (1024 * 1024)
        self.assertAlmostEqual(megabytes, 1.714, places=2)
        self.assertEqual(bf.k, 10)
        self.assertEqual(bf.num_bits, 14_377_588)

    def test_insertions_and_membership(self):
        """Test adding items, membership checking, and duplicate rejection."""
        bf = PurePythonBloomFilter(capacity=10_000, false_positive_rate=0.001)
        url1 = "https://api.example.com/v1/users"
        url2 = "https://api.example.com/v1/orders"
        url3 = "https://api.example.com/v1/products"

        # Initially absent
        self.assertNotIn(url1, bf)
        self.assertNotIn(url2, bf)
        self.assertNotIn(url3, bf)

        # Add url1: returns True for newly added
        self.assertTrue(bf.add(url1))
        self.assertIn(url1, bf)
        self.assertEqual(bf.count, 1)

        # Re-adding url1: returns False (already present)
        self.assertFalse(bf.add(url1))
        self.assertEqual(bf.count, 1)

        # Add url2
        self.assertTrue(bf.add(url2))
        self.assertIn(url2, bf)
        self.assertEqual(bf.count, 2)

        # url3 still not added
        self.assertNotIn(url3, bf)

    def test_false_positive_rate_bounded(self):
        """Test that measured false positive rate is bounded below 1% (< 0.01)."""
        capacity = 5_000
        target_fp = 0.001
        bf = PurePythonBloomFilter(capacity=capacity, false_positive_rate=target_fp)

        # Insert capacity items
        added_urls = []
        for i in range(capacity):
            url = f"https://example.com/resource/{i}"
            if bf.add(url):
                added_urls.append(url)

        # Verify all successfully added URLs test positive
        for url in added_urls:
            self.assertIn(url, bf)

        # Test false positive rate on 5,000 distinct items not inserted
        false_positives = 0
        test_count = 5_000
        for i in range(capacity, capacity + test_count):
            url = f"https://example.com/never_inserted/{i}"
            if url in bf:
                false_positives += 1

        measured_fp_rate = false_positives / test_count
        # Target was 0.001 (0.1%); must be strictly bounded < 1% (0.01)
        self.assertLess(measured_fp_rate, 0.01)

    def test_clear_and_reset(self):
        """Test resetting the filter with clear()."""
        bf = PurePythonBloomFilter(capacity=1_000, false_positive_rate=0.01)
        for i in range(100):
            bf.add(f"https://example.com/item/{i}")

        self.assertEqual(bf.count, 100)
        bf.clear()
        self.assertEqual(bf.count, 0)
        self.assertNotIn("https://example.com/item/0", bf)

    def test_invalid_parameters(self):
        """Test validation on capacity and false_positive_rate."""
        with self.assertRaises(ValueError):
            PurePythonBloomFilter(capacity=0)

        with self.assertRaises(ValueError):
            PurePythonBloomFilter(capacity=-10)

        with self.assertRaises(ValueError):
            PurePythonBloomFilter(false_positive_rate=0.0)

        with self.assertRaises(ValueError):
            PurePythonBloomFilter(false_positive_rate=1.0)


class TestPrioritizedRequest(unittest.TestCase):
    def test_ordering_and_comparison(self):
        """Test min-heap ordering: sort_priority, then depth, then sequence_id."""
        # Lower sort_priority pops first
        req_high = PrioritizedRequest(sort_priority=-100, depth=0, sequence_id=1, url="high")
        req_low = PrioritizedRequest(sort_priority=-50, depth=0, sequence_id=0, url="low")
        self.assertLess(req_high, req_low)

        # Equal sort_priority: lower depth pops first
        req_shallow = PrioritizedRequest(sort_priority=-50, depth=1, sequence_id=5, url="shallow")
        req_deep = PrioritizedRequest(sort_priority=-50, depth=2, sequence_id=0, url="deep")
        self.assertLess(req_shallow, req_deep)

        # Equal sort_priority and equal depth: FIFO by sequence_id
        req_fifo1 = PrioritizedRequest(sort_priority=-50, depth=1, sequence_id=2, url="first")
        req_fifo2 = PrioritizedRequest(sort_priority=-50, depth=1, sequence_id=3, url="second")
        self.assertLess(req_fifo1, req_fifo2)

    def test_url_and_template_not_compared(self):
        """Ensure url, template, and source_tag do not interfere with comparison."""
        req1 = PrioritizedRequest(sort_priority=-50, depth=0, sequence_id=0, url="zzz", template="zzz")
        req2 = PrioritizedRequest(sort_priority=-50, depth=0, sequence_id=0, url="aaa", template="aaa")
        # Identical compare keys (sort_priority, depth, sequence_id) means equal
        self.assertEqual(req1, req2)


class TestURLScorer(unittest.TestCase):
    def setUp(self):
        self.scorer = URLScorer

    def test_heuristics_hierarchy(self):
        """
        Verify the required priority order:
        specs > manifests > js > api > content > pagination
        """
        score_spec = self.scorer.score("https://example.com/openapi.json")
        score_manifest = self.scorer.score("https://example.com/_buildManifest.js")
        score_js = self.scorer.score("https://example.com/static/bundle.js")
        score_api = self.scorer.score("https://example.com/api/v1/users")
        score_content = self.scorer.score("https://example.com/blog/2026/hello")
        score_pagination = self.scorer.score("https://example.com/items?page=2")

        # Explicit expected scores
        self.assertEqual(score_spec, 100)
        self.assertEqual(score_manifest, 85)
        self.assertEqual(score_js, 60)
        self.assertEqual(score_api, 50)
        self.assertEqual(score_content, -35)
        self.assertEqual(score_pagination, -60)

        # Required order check: specs > manifests > js > api > content > pagination
        self.assertGreater(score_spec, score_manifest)
        self.assertGreater(score_manifest, score_js)
        self.assertGreater(score_js, score_api)
        self.assertGreater(score_api, score_content)
        self.assertGreater(score_content, score_pagination)

    def test_api_spec_variations(self):
        """Test API Specs & Gateways (+100)."""
        urls = [
            "https://example.com/swagger/v1/swagger.json",
            "https://example.com/openapi.yaml",
            "https://example.com/v1/api-docs",
            "https://example.com/schema.json",
            "https://example.com/graphql",
            "https://example.com/.well-known/openid-configuration",
        ]
        for url in urls:
            with self.subTest(url=url):
                self.assertEqual(self.scorer.score(url), 100)

    def test_framework_manifest_variations(self):
        """Test Framework Manifests (+85)."""
        urls = [
            "https://example.com/_next/static/hash/_buildManifest.js",
            "https://example.com/_next/static/hash/_ssgManifest.js",
            "https://example.com/_next/static/hash/_middlewareManifest.js",
            "https://example.com/__NUXT_DATA__",
        ]
        for url in urls:
            with self.subTest(url=url):
                self.assertEqual(self.scorer.score(url), 85)

    def test_disallowed_routes(self):
        """Test disallowed routes in robots.txt (+75)."""
        score = self.scorer.score("https://example.com/admin/portal", is_disallowed_robots=True)
        self.assertEqual(score, 75)

        # Fits properly between manifests (+85) and scripts (+60)
        score_manifest = self.scorer.score("https://example.com/_buildManifest.js")
        score_js = self.scorer.score("https://example.com/bundle.js")
        self.assertGreater(score_manifest, score)
        self.assertGreater(score, score_js)

    def test_script_bundles(self):
        """Test Script bundles (.js, .mjs) (+60)."""
        self.assertEqual(self.scorer.score("https://example.com/app.js"), 60)
        self.assertEqual(self.scorer.score("https://example.com/chunks/vendor.mjs"), 60)
        self.assertEqual(self.scorer.score("https://example.com/script.js?v=123"), 60)

    def test_api_routes(self):
        """Test API Routes (/api/, /rest/, /v1/, /rpc/) (+50)."""
        self.assertEqual(self.scorer.score("https://example.com/api/v2/items"), 50)
        self.assertEqual(self.scorer.score("https://example.com/rest/users"), 50)
        self.assertEqual(self.scorer.score("https://example.com/v1/checkout"), 50)
        self.assertEqual(self.scorer.score("https://example.com/rpc/submit"), 50)

    def test_neutral_navigation(self):
        """Test Neutral navigation (/, /login, /dashboard, /docs) (+10)."""
        self.assertEqual(self.scorer.score("https://example.com/"), 10)
        self.assertEqual(self.scorer.score("https://example.com"), 10)
        self.assertEqual(self.scorer.score("https://example.com/login"), 10)
        self.assertEqual(self.scorer.score("https://example.com/dashboard"), 10)
        self.assertEqual(self.scorer.score("https://example.com/docs"), 10)

    def test_content_paths(self):
        """Test Content paths (/blog/, /news/, /articles/, /events/) (-35)."""
        self.assertEqual(self.scorer.score("https://example.com/blog/hello"), -35)
        self.assertEqual(self.scorer.score("https://example.com/news/update"), -35)
        self.assertEqual(self.scorer.score("https://example.com/articles/guide"), -35)
        self.assertEqual(self.scorer.score("https://example.com/events/2026"), -35)

    def test_traps_and_pagination_params(self):
        """Test Traps/pagination params (page=, offset=, sort=, filter=) (-60)."""
        self.assertEqual(self.scorer.score("https://example.com/items?page=2"), -60)
        self.assertEqual(self.scorer.score("https://example.com/items?offset=50"), -60)
        self.assertEqual(self.scorer.score("https://example.com/items?sort=desc"), -60)
        self.assertEqual(self.scorer.score("https://example.com/items?filter=active"), -60)

    def test_decay_and_cardinality_penalties(self):
        """Test depth decay (- depth * 15) and template cardinality (- count * 25)."""
        url = "https://example.com/api/v1/users"
        base = 50

        # Depth decay: -15 per depth level
        self.assertEqual(self.scorer.score(url, depth=1), base - 15)
        self.assertEqual(self.scorer.score(url, depth=2), base - 30)

        # Template cardinality penalty: -25 per count
        self.assertEqual(self.scorer.score(url, depth=0, template_count=1), base - 25)
        self.assertEqual(self.scorer.score(url, depth=0, template_count=2), base - 50)

        # Combined penalties
        self.assertEqual(self.scorer.score(url, depth=2, template_count=3), base - 30 - 75)

    def test_sort_priority_inversion(self):
        """Test that calculate_sort_priority returns exact negation of score."""
        url = "https://example.com/openapi.json"
        score = self.scorer.score(url)
        sort_pri = self.scorer.calculate_sort_priority(url)
        self.assertEqual(sort_pri, -score)


class TestPriorityURLScheduler(unittest.IsolatedAsyncioTestCase):
    async def test_scheduler_priority_ordering(self):
        """Test that scheduler pops highest-priority items first."""
        scheduler = PriorityURLScheduler()
        self.assertTrue(scheduler.empty())
        self.assertEqual(scheduler.qsize(), 0)

        # Push items with different priorities
        items = [
            ("https://example.com/items?page=2", "pagination"),
            ("https://example.com/blog/my-post", "content"),
            ("https://example.com/dashboard", "neutral"),
            ("https://example.com/api/v1/users", "api"),
            ("https://example.com/static/bundle.js", "js"),
            ("https://example.com/_buildManifest.js", "manifest"),
            ("https://example.com/openapi.json", "spec"),
        ]

        for url, tag in items:
            await scheduler.push(url=url, depth=0, template="", template_count=0, source_tag=tag)

        self.assertFalse(scheduler.empty())
        self.assertEqual(scheduler.qsize(), 7)

        popped_tags = []
        while not scheduler.empty():
            req = await scheduler.pop()
            popped_tags.append(req.source_tag)

        # Expect highest score first
        expected = ["spec", "manifest", "js", "api", "neutral", "content", "pagination"]
        self.assertEqual(popped_tags, expected)
        self.assertTrue(scheduler.empty())

    async def test_fifo_tie_breaking(self):
        """Test that items with equal priority and depth break ties via FIFO sequence_id."""
        scheduler = PriorityURLScheduler()

        for i in range(10):
            await scheduler.push(
                url=f"https://example.com/api/users/{i}",
                depth=1,
                template="/api/users/{id}",
                template_count=0,
                source_tag=f"req_{i}",
            )

        self.assertEqual(scheduler.qsize(), 10)

        popped = []
        while not scheduler.empty():
            req = await scheduler.pop()
            popped.append(req.source_tag)

        expected = [f"req_{i}" for i in range(10)]
        self.assertEqual(popped, expected)

    async def test_depth_tie_breaking(self):
        """Test that items with equal priority break ties with shallower depth popping first."""
        scheduler = PriorityURLScheduler()

        await scheduler.push("https://example.com/api/depth3", depth=3, source_tag="d3")
        await scheduler.push("https://example.com/api/depth1", depth=1, source_tag="d1")
        await scheduler.push("https://example.com/api/depth2", depth=2, source_tag="d2")

        popped = []
        while not scheduler.empty():
            req = await scheduler.pop()
            popped.append(req.source_tag)

        # Depth 1 has least penalty (-15) -> highest score -> pops first
        # Depth 2 has -30 -> pops second
        # Depth 3 has -45 -> pops third
        self.assertEqual(popped, ["d1", "d2", "d3"])

    def test_push_nowait_and_pop_nowait(self):
        """Test synchronous push_nowait and pop_nowait methods."""
        scheduler = PriorityURLScheduler()
        scheduler.push_nowait("https://example.com/openapi.json", depth=0, source_tag="spec")
        scheduler.push_nowait("https://example.com/api/users", depth=0, source_tag="api")

        self.assertEqual(scheduler.qsize(), 2)
        req1 = scheduler.pop_nowait()
        req2 = scheduler.pop_nowait()

        self.assertEqual(req1.source_tag, "spec")
        self.assertEqual(req2.source_tag, "api")
        self.assertTrue(scheduler.empty())


if __name__ == "__main__":
    unittest.main()
