"""
Unit and integration tests for PassiveSeedHarvester:
- robots.txt Disallow parsing (wildcards, anchors, empty, comments, base URL normalization)
- robots.txt Sitemap directive parsing (absolute and relative)
- robots.txt Crawl-delay parsing (integer, float, invalid)
- Low-memory streaming XML Sitemap parser (linear byte regex, XML entities, CDATA)
- Auto-decompression for .xml.gz sitemaps
- Recursive <sitemapindex> child sitemap traversal with cycle prevention
- Standard well-known and API gateway probe generation
- End-to-end discover_seeds with httpx.MockTransport
- Network error and resilience handling
"""

import asyncio
import gzip
import unittest
from typing import Dict
from urllib.parse import urlsplit

import httpx

from api_tool.spider.crawler import URLNormalizer
from api_tool.spider.passive_seed import (
    PassiveSeedHarvester,
    STANDARD_GATEWAY_PROBES,
    LOC_BYTE_REGEX,
    SITEMAP_INDEX_REGEX,
)


class TestPassiveSeedRobotsParsing(unittest.TestCase):
    """Tests for robots.txt parsing logic."""

    def setUp(self) -> None:
        self.normalizer = URLNormalizer()
        self.harvester = PassiveSeedHarvester(normalizer=self.normalizer)
        self.base_url = "https://example.com"

    def test_disallow_wildcards_and_anchors(self) -> None:
        robots = """
        User-agent: *
        Disallow: /admin/*
        Disallow: /secret$
        Disallow: /private/*$
        Disallow: /api/*#comment
        Disallow: /*
        Disallow: *
        Disallow: 
        Disallow: /login
        """
        disallows, sitemaps, delay = self.harvester.parse_robots_txt(robots, self.base_url)

        # /admin/* -> /admin/
        self.assertIn("https://example.com/admin/", disallows)
        # /secret$ -> /secret
        self.assertIn("https://example.com/secret", disallows)
        # /private/*$ -> /private/
        self.assertIn("https://example.com/private/", disallows)
        # /api/* -> /api/
        self.assertIn("https://example.com/api/", disallows)
        # /* -> /
        self.assertIn("https://example.com/", disallows)
        # /login -> /login
        self.assertIn("https://example.com/login", disallows)

        # * stripped to empty or empty disallow should NOT produce invalid URLs
        self.assertNotIn("https://example.com/*", disallows)

    def test_sitemap_directives(self) -> None:
        robots = """
        User-agent: *
        Disallow: /hidden
        Sitemap: https://example.com/sitemap.xml
        sitemap: /sitemap_relative.xml
        SITEMAP: https://cdn.example.com/sitemap_index.xml.gz
        """
        disallows, sitemaps, delay = self.harvester.parse_robots_txt(robots, self.base_url)

        self.assertIn("https://example.com/sitemap.xml", sitemaps)
        self.assertIn("https://example.com/sitemap_relative.xml", sitemaps)
        self.assertIn("https://cdn.example.com/sitemap_index.xml.gz", sitemaps)
        self.assertEqual(len(sitemaps), 3)

    def test_crawl_delay_directives(self) -> None:
        # Integer crawl-delay
        robots1 = "User-agent: *\nCrawl-delay: 5\n"
        _, _, delay1 = self.harvester.parse_robots_txt(robots1, self.base_url)
        self.assertEqual(delay1, 5.0)

        # Float crawl-delay
        robots2 = "User-agent: *\nCrawl-delay: 1.5\n"
        _, _, delay2 = self.harvester.parse_robots_txt(robots2, self.base_url)
        self.assertEqual(delay2, 1.5)

        # Case-insensitive crawldelay
        robots3 = "User-agent: *\ncrawldelay: 0.25\n"
        _, _, delay3 = self.harvester.parse_robots_txt(robots3, self.base_url)
        self.assertEqual(delay3, 0.25)

        # Invalid crawl-delay ignored
        robots4 = "User-agent: *\nCrawl-delay: immediate\n"
        _, _, delay4 = self.harvester.parse_robots_txt(robots4, self.base_url)
        self.assertIsNone(delay4)

    def test_utf8_bom_and_bytes_input(self) -> None:
        robots_bytes = "\ufeffUser-agent: *\nDisallow: /bom_path/*\n".encode("utf-8")
        disallows, sitemaps, delay = self.harvester.parse_robots_txt(robots_bytes, self.base_url)
        self.assertIn("https://example.com/bom_path/", disallows)


class TestStreamingSitemapParser(unittest.TestCase):
    """Tests for low-memory streaming XML sitemap parser."""

    def setUp(self) -> None:
        self.normalizer = URLNormalizer()
        self.harvester = PassiveSeedHarvester(normalizer=self.normalizer)
        self.base_url = "https://example.com"

    def test_linear_byte_regex_plain_xml(self) -> None:
        xml_content = b"""<?xml version="1.0" encoding="UTF-8"?>
        <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
            <url>
                <loc>https://example.com/page1</loc>
                <lastmod>2026-01-01</lastmod>
            </url>
            <url>
                <loc>  https://example.com/page2  </loc>
            </url>
            <url>
                <loc>https://example.com/search?q=test&amp;lang=en</loc>
            </url>
        </urlset>
        """
        urls, is_index = self.harvester.parse_sitemap_content(xml_content, self.base_url)

        self.assertFalse(is_index)
        self.assertIn("https://example.com/page1", urls)
        self.assertIn("https://example.com/page2", urls)
        self.assertIn("https://example.com/search?lang=en&q=test", urls)

    def test_cdata_loc_tags(self) -> None:
        xml_content = b"""<?xml version="1.0" encoding="UTF-8"?>
        <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
            <url>
                <loc><![CDATA[https://example.com/cdata_endpoint]]></loc>
            </url>
        </urlset>
        """
        urls, is_index = self.harvester.parse_sitemap_content(xml_content, self.base_url)
        self.assertFalse(is_index)
        self.assertIn("https://example.com/cdata_endpoint", urls)

    def test_gzipped_sitemap_decompression(self) -> None:
        xml_content = b"""<?xml version="1.0" encoding="UTF-8"?>
        <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
            <url>
                <loc>https://example.com/gzipped-page-1</loc>
            </url>
            <url>
                <loc>https://example.com/gzipped-page-2</loc>
            </url>
        </urlset>
        """
        gzipped_bytes = gzip.compress(xml_content)

        urls, is_index = self.harvester.parse_sitemap_content(gzipped_bytes, self.base_url)
        self.assertFalse(is_index)
        self.assertIn("https://example.com/gzipped-page-1", urls)
        self.assertIn("https://example.com/gzipped-page-2", urls)

    def test_sitemap_index_detection(self) -> None:
        index_xml = b"""<?xml version="1.0" encoding="UTF-8"?>
        <sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
            <sitemap>
                <loc>https://example.com/sitemap1.xml</loc>
            </sitemap>
            <sitemap>
                <loc>https://example.com/sitemap2.xml.gz</loc>
            </sitemap>
        </sitemapindex>
        """
        urls, is_index = self.harvester.parse_sitemap_content(index_xml, self.base_url)
        self.assertTrue(is_index)
        self.assertIn("https://example.com/sitemap1.xml", urls)
        self.assertIn("https://example.com/sitemap2.xml.gz", urls)


class TestGatewayProbeGeneration(unittest.TestCase):
    """Tests for Standard Well-Known & Gateway Seed Probes."""

    def setUp(self) -> None:
        self.normalizer = URLNormalizer()
        self.harvester = PassiveSeedHarvester(normalizer=self.normalizer)

    def test_all_standard_probes_generated(self) -> None:
        probes = self.harvester.generate_gateway_probes("https://example.com")

        expected_endpoints = [
            "https://example.com/.well-known/security.txt",
            "https://example.com/.well-known/openid-configuration",
            "https://example.com/.well-known/assetlinks.json",
            "https://example.com/.well-known/apple-app-site-association",
            "https://example.com/openapi.json",
            "https://example.com/swagger.json",
            "https://example.com/v3/api-docs",
            "https://example.com/api-docs",
        ]
        for exp in expected_endpoints:
            self.assertIn(exp, probes)

        self.assertEqual(len(probes), 8)

    def test_probe_generation_with_custom_port(self) -> None:
        probes = self.harvester.generate_gateway_probes("http://localhost:8080/api")
        self.assertIn("http://localhost:8080/.well-known/security.txt", probes)
        self.assertIn("http://localhost:8080/openapi.json", probes)


class TestPassiveSeedHarvesterEndToEnd(unittest.TestCase):
    """End-to-end tests using httpx.MockTransport."""

    def test_discover_seeds_end_to_end(self) -> None:
        # Prepare sitemap payloads
        child_xml_1 = b"""<?xml version="1.0" encoding="UTF-8"?>
        <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
            <url><loc>https://example.com/users</loc></url>
            <url><loc>https://example.com/products</loc></url>
        </urlset>
        """

        child_xml_2 = b"""<?xml version="1.0" encoding="UTF-8"?>
        <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
            <url><loc>https://example.com/pricing</loc></url>
            <url><loc>https://example.com/docs</loc></url>
        </urlset>
        """
        child_xml_2_gz = gzip.compress(child_xml_2)

        sitemap_index_xml = b"""<?xml version="1.0" encoding="UTF-8"?>
        <sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
            <sitemap><loc>https://example.com/sitemap_pages.xml</loc></sitemap>
            <sitemap><loc>https://example.com/sitemap_other.xml.gz</loc></sitemap>
        </sitemapindex>
        """

        robots_txt = """User-agent: *
Disallow: /admin/*
Disallow: /internal/metrics$
Sitemap: https://example.com/sitemap_index.xml
Crawl-delay: 2.5
"""

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            if url_str == "https://example.com/robots.txt":
                return httpx.Response(200, text=robots_txt)
            elif url_str == "https://example.com/sitemap_index.xml":
                return httpx.Response(200, content=sitemap_index_xml, headers={"content-type": "application/xml"})
            elif url_str == "https://example.com/sitemap_pages.xml":
                return httpx.Response(200, content=child_xml_1, headers={"content-type": "application/xml"})
            elif url_str == "https://example.com/sitemap_other.xml.gz":
                return httpx.Response(200, content=child_xml_2_gz, headers={"content-type": "application/gzip"})
            return httpx.Response(404)

        transport = httpx.MockTransport(mock_handler)
        client = httpx.AsyncClient(transport=transport)
        normalizer = URLNormalizer()

        harvester = PassiveSeedHarvester(client=client, normalizer=normalizer)

        discovered_seeds, disallow_urls = asyncio.run(harvester.discover_seeds("https://example.com/"))

        # Verify Disallow extraction
        self.assertIn("https://example.com/admin/", disallow_urls)
        self.assertIn("https://example.com/internal/metrics", disallow_urls)
        self.assertEqual(len(disallow_urls), 2)

        # Verify Crawl-delay
        self.assertEqual(harvester.crawl_delay, 2.5)

        # Verify Sitemaps were fetched recursively (including gzipped child)
        self.assertIn("https://example.com/users", discovered_seeds)
        self.assertIn("https://example.com/products", discovered_seeds)
        self.assertIn("https://example.com/pricing", discovered_seeds)
        self.assertIn("https://example.com/docs", discovered_seeds)

        # Verify Standard Gateway Probes were generated into discovered_seeds
        for probe_path in STANDARD_GATEWAY_PROBES:
            full_probe = f"https://example.com{probe_path}"
            self.assertIn(full_probe, discovered_seeds)

    def test_robots_404_resilience(self) -> None:
        def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404)

        transport = httpx.MockTransport(mock_handler)
        client = httpx.AsyncClient(transport=transport)
        normalizer = URLNormalizer()
        harvester = PassiveSeedHarvester(client=client, normalizer=normalizer)

        discovered_seeds, disallow_urls = asyncio.run(harvester.discover_seeds("https://no-robots.com"))

        # Disallow should be empty
        self.assertEqual(disallow_urls, [])
        self.assertIsNone(harvester.crawl_delay)

        # Gateway probes should still be generated
        self.assertIn("https://no-robots.com/.well-known/security.txt", discovered_seeds)
        self.assertIn("https://no-robots.com/openapi.json", discovered_seeds)

    def test_recursive_sitemap_loop_protection(self) -> None:
        loop_sitemap_xml = b"""<?xml version="1.0" encoding="UTF-8"?>
        <sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
            <sitemap><loc>https://example.com/loop_sitemap.xml</loc></sitemap>
        </sitemapindex>
        """

        def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=loop_sitemap_xml)

        transport = httpx.MockTransport(mock_handler)
        client = httpx.AsyncClient(transport=transport)
        harvester = PassiveSeedHarvester(client=client, normalizer=URLNormalizer())

        # Should finish quickly without recursion error
        pages = asyncio.run(harvester.harvest_sitemaps(["https://example.com/loop_sitemap.xml"], "https://example.com"))
        self.assertEqual(pages, [])


if __name__ == "__main__":
    unittest.main()
