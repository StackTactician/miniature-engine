"""
Spider and Manifest Module for api-tool.
Provides:
- AsyncSpider: High-performance async crawler with anti-loop detection and route collapsing
- URLNormalizer: URL sanitization, tracking parameter removal, and loop detection
- RoutePatternCollapser: Path parameter abstraction (/users/123 -> /users/{id})
- ManifestExtractor: Next.js (__NEXT_DATA__, _buildManifest), Nuxt.js, and Webpack chunk maps
- PassiveHarvester: Historical passive endpoint harvesting from Wayback Machine CDX and AlienVault OTX
"""

from api_tool.spider.crawler import (
    AsyncSpider,
    CrawlResult,
    DiscoveredAsset,
    RoutePatternCollapser,
    URLNormalizer,
)
from api_tool.spider.manifest import (
    ManifestExtractor,
    ManifestResult,
)
from api_tool.spider.passive import (
    PassiveHarvester,
    PassiveHarvestResult,
)
from api_tool.spider.scope_resolver import (
    CDNScopeResolver,
    ScopePolicy,
)

__all__ = [
    "AsyncSpider",
    "CDNScopeResolver",
    "CrawlResult",
    "DiscoveredAsset",
    "ManifestExtractor",
    "ManifestResult",
    "PassiveHarvester",
    "PassiveHarvestResult",
    "RoutePatternCollapser",
    "ScopePolicy",
    "URLNormalizer",
]
