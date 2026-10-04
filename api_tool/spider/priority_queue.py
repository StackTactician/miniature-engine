"""
API-First Priority Queue and Kirsch-Mitzenmacher Bloom Filter for api-tool spider.

Provides:
- PurePythonBloomFilter: High-efficiency probabilistic URL deduplication filter
  using the Kirsch-Mitzenmacher 2-hash optimization with blake2b.
- PrioritizedRequest: Ordered dataclass for min-heap prioritization with FIFO tie-breaking.
- URLScorer: Heuristic prioritization scorer weighting API specs, manifests, routes,
  and penalizing traps/pagination, depth, and template cardinality.
- PriorityURLScheduler: Asynchronous URL scheduling queue wrapping asyncio.PriorityQueue.
"""

from __future__ import annotations

import asyncio
import hashlib
import math
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Set, Tuple
from urllib.parse import urlsplit


class PurePythonBloomFilter:
    """
    Pure Python Bloom Filter implementing the Kirsch-Mitzenmacher 2-hash technique.
    Zero external C dependencies. Uses bytearray and hashlib.blake2b(digest_size=16).

    Theoretical false positive rate: p
    Number of bits: m = ceil(- (n * ln(p)) / (ln(2)^2))
    Number of bytes: (m + 7) // 8
    Number of hash functions: k = round((m / n) * ln(2))
    Simulated hashes: g_i(x) = (h_1(x) + i * h_2(x)) mod m
    """

    def __init__(
        self,
        capacity: int = 1_000_000,
        false_positive_rate: float = 0.001,
    ) -> None:
        if capacity <= 0:
            raise ValueError(f"Capacity must be a positive integer, got {capacity}")
        if not (0 < false_positive_rate < 1):
            raise ValueError(
                f"False positive rate must be between 0 and 1 exclusive, got {false_positive_rate}"
            )

        self._capacity = capacity
        self._fp_rate = false_positive_rate

        # Calculate bit array size m and hash function count k
        self._num_bits = int(
            math.ceil(- (capacity * math.log(false_positive_rate)) / (math.log(2) ** 2))
        )
        self._num_bytes = (self._num_bits + 7) // 8
        self._bitarray = bytearray(self._num_bytes)
        self._k = max(1, round((self._num_bits / capacity) * math.log(2)))
        self._count = 0

    @property
    def capacity(self) -> int:
        """Configured maximum capacity of the filter."""
        return self._capacity

    @property
    def false_positive_rate(self) -> float:
        """Configured target false positive probability."""
        return self._fp_rate

    @property
    def count(self) -> int:
        """Number of items added to the filter."""
        return self._count

    @property
    def size_bytes(self) -> int:
        """Memory footprint of the underlying bytearray in bytes."""
        return len(self._bitarray)

    @property
    def k(self) -> int:
        """Number of simulated hash functions."""
        return self._k

    @property
    def num_bits(self) -> int:
        """Total bit count m."""
        return self._num_bits

    def _get_hashes(self, item: str) -> Tuple[int, int]:
        """Extract two 64-bit hashes h1 and h2 from a 16-byte blake2b digest."""
        if not isinstance(item, str):
            item = str(item)
        digest = hashlib.blake2b(item.encode("utf-8"), digest_size=16).digest()
        h1 = int.from_bytes(digest[:8], byteorder="big")
        h2 = int.from_bytes(digest[8:], byteorder="big")
        return h1, h2

    def add(self, item: str) -> bool:
        """
        Add an item to the Bloom filter.
        Returns True if newly added, False if item was already present.
        """
        h1, h2 = self._get_hashes(item)
        already_present = True
        for i in range(self._k):
            bit_idx = (h1 + i * h2) % self._num_bits
            byte_idx = bit_idx >> 3
            bit_mask = 1 << (bit_idx & 7)
            if not (self._bitarray[byte_idx] & bit_mask):
                already_present = False
                self._bitarray[byte_idx] |= bit_mask

        if already_present:
            return False

        self._count += 1
        return True

    def __contains__(self, item: str) -> bool:
        """
        Check if an item is possibly in the Bloom filter.
        Returns True if item is possibly present, False if definitely absent.
        """
        h1, h2 = self._get_hashes(item)
        for i in range(self._k):
            bit_idx = (h1 + i * h2) % self._num_bits
            byte_idx = bit_idx >> 3
            bit_mask = 1 << (bit_idx & 7)
            if not (self._bitarray[byte_idx] & bit_mask):
                return False
        return True

    def __len__(self) -> int:
        return self._count

    def clear(self) -> None:
        """Reset the filter to empty state."""
        self._bitarray = bytearray(self._num_bytes)
        self._count = 0

    def __repr__(self) -> str:
        return (
            f"PurePythonBloomFilter(count={self._count}, "
            f"capacity={self._capacity}, "
            f"fp_rate={self._fp_rate}, "
            f"size_bytes={self.size_bytes})"
        )


@dataclass(order=True)
class PrioritizedRequest:
    """
    Represents a prioritized crawling request.
    Sorted in min-heap by (sort_priority, depth, sequence_id).

    Higher crawler scores produce smaller (more negative) sort_priority values,
    ensuring they pop earliest. Equal priority items break ties by shallower
    depth, then FIFO sequence_id.
    """
    sort_priority: int
    depth: int
    sequence_id: int
    url: str = field(compare=False)
    template: str = field(default="", compare=False)
    source_tag: str = field(default="discovery", compare=False)


class URLScorer:
    """
    Heuristic priority scorer for URLs discovered during crawling.
    Prioritizes API discovery (specs, manifests, endpoints) and penalizes
    deep/content/paginated crawl traps.
    """

    # Base category scores
    SCORE_API_SPECS: int = 100
    SCORE_FRAMEWORK_MANIFESTS: int = 85
    SCORE_DISALLOWED_ROBOTS: int = 75
    SCORE_SCRIPT_BUNDLES: int = 60
    SCORE_API_ROUTES: int = 50
    SCORE_NEUTRAL_NAVIGATION: int = 10
    SCORE_CONTENT_PATHS: int = -35

    # Penalties
    PENALTY_TRAPS_PAGINATION: int = -60
    PENALTY_DEPTH_MULTIPLIER: int = 15
    PENALTY_TEMPLATE_MULTIPLIER: int = 25

    # Pattern definitions
    API_SPEC_KEYWORDS: Tuple[str, ...] = (
        "swagger",
        "openapi",
        "api-docs",
        "schema",
        "graphql",
        ".well-known",
    )

    MANIFEST_KEYWORDS: Tuple[str, ...] = (
        "_buildmanifest",
        "_ssgmanifest",
        "_middlewaremanifest",
        "__nuxt_data__",
    )

    SCRIPT_EXTENSIONS: Tuple[str, ...] = (
        ".js",
        ".mjs",
    )

    API_ROUTE_KEYWORDS: Tuple[str, ...] = (
        "/api/",
        "/rest/",
        "/v1/",
        "/rpc/",
    )

    NEUTRAL_NAV_KEYWORDS: Tuple[str, ...] = (
        "/login/",
        "/dashboard/",
        "/docs/",
    )

    CONTENT_PATH_KEYWORDS: Tuple[str, ...] = (
        "/blog/",
        "/news/",
        "/articles/",
        "/events/",
    )

    TRAP_PARAM_KEYWORDS: Tuple[str, ...] = (
        "page=",
        "offset=",
        "sort=",
        "filter=",
    )

    @classmethod
    def score(
        cls,
        url: str,
        depth: int = 0,
        template_count: int = 0,
        is_disallowed_robots: bool = False,
        **kwargs: Any,
    ) -> int:
        """
        Calculate heuristic priority score for a URL.
        """
        if not url:
            return 0

        url_lower = url.lower()
        parts = urlsplit(url_lower)
        path = parts.path
        query = parts.query

        # Ensure trailing slash on path for boundary segment matching
        norm_path = path if path.endswith("/") else path + "/"

        # Check for traps / pagination params in query or path
        has_traps = any(trap in url_lower for trap in cls.TRAP_PARAM_KEYWORDS)

        # Disallowed flag check
        is_disallowed = (
            is_disallowed_robots
            or kwargs.get("is_disallowed", False)
            or kwargs.get("disallowed", False)
        )

        # Base category scoring in strict priority order:
        # 1. API Specs & Gateways (+100)
        if any(kw in url_lower for kw in cls.API_SPEC_KEYWORDS):
            base_score = cls.SCORE_API_SPECS
        # 2. Framework Manifests (+85)
        elif any(kw in url_lower for kw in cls.MANIFEST_KEYWORDS):
            base_score = cls.SCORE_FRAMEWORK_MANIFESTS
        # 3. Disallowed routes in robots.txt (+75)
        elif is_disallowed:
            base_score = cls.SCORE_DISALLOWED_ROBOTS
        # 4. Script bundles (.js, .mjs) (+60)
        elif path.endswith(cls.SCRIPT_EXTENSIONS):
            base_score = cls.SCORE_SCRIPT_BUNDLES
        # 5. API Routes (/api/, /rest/, /v1/, /rpc/) (+50)
        elif any(kw in norm_path for kw in cls.API_ROUTE_KEYWORDS):
            base_score = cls.SCORE_API_ROUTES
        # 6. Neutral navigation (/, /login, /dashboard, /docs) (+10)
        elif any(p in norm_path for p in cls.NEUTRAL_NAV_KEYWORDS) or (
            path in ("", "/") and not has_traps
        ):
            base_score = cls.SCORE_NEUTRAL_NAVIGATION
        # 7. Content paths (/blog/, /news/, /articles/, /events/) (-35)
        elif any(c in norm_path for c in cls.CONTENT_PATH_KEYWORDS):
            base_score = cls.SCORE_CONTENT_PATHS
        else:
            base_score = 0

        score = base_score

        # Traps / pagination penalty (-60)
        if has_traps:
            score += cls.PENALTY_TRAPS_PAGINATION

        # Depth decay penalty (- depth * 15)
        score -= max(0, depth) * cls.PENALTY_DEPTH_MULTIPLIER

        # Template cardinality penalty (- template_count * 25)
        score -= max(0, template_count) * cls.PENALTY_TEMPLATE_MULTIPLIER

        return score

    @classmethod
    def calculate_score(cls, *args: Any, **kwargs: Any) -> int:
        """Alias for score."""
        return cls.score(*args, **kwargs)

    @classmethod
    def calculate_sort_priority(cls, *args: Any, **kwargs: Any) -> int:
        """Return inverted score suitable for min-heap sort_priority."""
        return -cls.score(*args, **kwargs)

    def __call__(self, *args: Any, **kwargs: Any) -> int:
        return self.score(*args, **kwargs)


class PriorityURLScheduler:
    """
    Priority URL scheduling engine wrapping asyncio.PriorityQueue.
    Uses URLScorer to automatically calculate sort_priority and maintains
    monotonic sequence_id for strict FIFO tie-breaking.
    """

    def __init__(
        self,
        maxsize: int = 0,
        scorer: Optional[URLScorer] = None,
        bloom_filter: Optional[PurePythonBloomFilter] = None,
    ) -> None:
        self._queue: asyncio.PriorityQueue[PrioritizedRequest] = asyncio.PriorityQueue(
            maxsize=maxsize
        )
        self._sequence_id: int = 0
        self._scorer = scorer or URLScorer
        self._bloom_filter = bloom_filter

    @property
    def sequence_id(self) -> int:
        """Current sequence ID counter."""
        return self._sequence_id

    @property
    def bloom_filter(self) -> Optional[PurePythonBloomFilter]:
        """Optional associated Bloom filter."""
        return self._bloom_filter

    async def push(
        self,
        url: str,
        depth: int = 0,
        template: str = "",
        template_count: int = 0,
        source_tag: str = "discovery",
        is_disallowed_robots: bool = False,
        **kwargs: Any,
    ) -> None:
        """
        Score and push a URL to the priority queue.
        """
        score = self._scorer.score(
            url=url,
            depth=depth,
            template_count=template_count,
            is_disallowed_robots=is_disallowed_robots,
            **kwargs,
        )
        sort_priority = -score
        seq = self._sequence_id
        self._sequence_id += 1

        req = PrioritizedRequest(
            sort_priority=sort_priority,
            depth=depth,
            sequence_id=seq,
            url=url,
            template=template,
            source_tag=source_tag,
        )
        await self._queue.put(req)

    def push_nowait(
        self,
        url: str,
        depth: int = 0,
        template: str = "",
        template_count: int = 0,
        source_tag: str = "discovery",
        is_disallowed_robots: bool = False,
        **kwargs: Any,
    ) -> None:
        """
        Synchronously push a URL to the priority queue without awaiting.
        """
        score = self._scorer.score(
            url=url,
            depth=depth,
            template_count=template_count,
            is_disallowed_robots=is_disallowed_robots,
            **kwargs,
        )
        sort_priority = -score
        seq = self._sequence_id
        self._sequence_id += 1

        req = PrioritizedRequest(
            sort_priority=sort_priority,
            depth=depth,
            sequence_id=seq,
            url=url,
            template=template,
            source_tag=source_tag,
        )
        self._queue.put_nowait(req)

    async def pop(self) -> PrioritizedRequest:
        """
        Pop the highest-priority request from the scheduler.
        """
        return await self._queue.get()

    def pop_nowait(self) -> PrioritizedRequest:
        """
        Synchronously pop the highest-priority request without awaiting.
        """
        return self._queue.get_nowait()

    def empty(self) -> bool:
        """Check if queue is empty."""
        return self._queue.empty()

    def qsize(self) -> int:
        """Return the number of requests currently queued."""
        return self._queue.qsize()

    def task_done(self) -> None:
        """Indicate that a formerly enqueued task is complete."""
        self._queue.task_done()

    async def join(self) -> None:
        """Block until all items in the queue have been processed."""
        await self._queue.join()

    def __len__(self) -> int:
        return self._queue.qsize()
