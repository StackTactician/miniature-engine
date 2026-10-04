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
from api_tool.spider.passive_seed import (
    PassiveSeedHarvester,
    STANDARD_GATEWAY_PROBES,
)
from api_tool.spider.filters import (
    DANGEROUS_ACTIONS_REGEX,
    OAUTH_DOMAINS,
    RABBIT_HOLE_REGEX,
    URLFilterEngine,
    is_private_or_ssrf_host,
)
from api_tool.spider.priority_queue import (
    PrioritizedRequest,
    PriorityURLScheduler,
    PurePythonBloomFilter,
    URLScorer,
)
from api_tool.spider.scope_resolver import (
    CDNScopeResolver,
    ScopePolicy,
)
from api_tool.spider.extractors import (
    DOMExtractor,
    FastHydrationScraper,
    FormControl,
    FormExtractor,
    FormPayloadGenerator,
    HTMXEndpoint,
)

__all__ = [
    "AsyncSpider",
    "CDNScopeResolver",
    "CrawlResult",
    "DANGEROUS_ACTIONS_REGEX",
    "DiscoveredAsset",
    "DOMExtractor",
    "FastHydrationScraper",
    "FormControl",
    "FormExtractor",
    "FormPayloadGenerator",
    "HTMXEndpoint",
    "is_private_or_ssrf_host",
    "ManifestExtractor",
    "ManifestResult",
    "OAUTH_DOMAINS",
    "PassiveHarvester",
    "PassiveHarvestResult",
    "PassiveSeedHarvester",
    "PrioritizedRequest",
    "PriorityURLScheduler",
    "PurePythonBloomFilter",
    "RABBIT_HOLE_REGEX",
    "RoutePatternCollapser",
    "ScopePolicy",
    "STANDARD_GATEWAY_PROBES",
    "URLFilterEngine",
    "URLNormalizer",
    "URLScorer",
]

