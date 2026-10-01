"""
Safe HTTP Prober module for api-tool.

Provides:
- SSRF protection guard blocking private IPs, cloud metadata, loopback,
  IPv6-mapped IPv4, decimal, octal, and localhost variants.
- Global token-bucket rate limiting via aiolimiter.AsyncLimiter.
- Non-destructive probing using OPTIONS, HEAD, and lightweight streaming GET.
- CORS reflection and header inspection.
- Concurrent probing bounded by semaphores and rate limiters.
"""

import asyncio
from dataclasses import dataclass, field, asdict
import email.utils
from datetime import datetime, timezone
import ipaddress
import logging
import re
import socket
import time
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlsplit

import httpx
from aiolimiter import AsyncLimiter

from api_tool.models import DiscoveredEndpoint

logger = logging.getLogger(__name__)

# Cloud metadata IP addresses to block explicitly
CLOUD_METADATA_IPS = {
    ipaddress.ip_address("169.254.169.254"),  # AWS/GCP/Azure/OpenStack/DigitalOcean metadata
    ipaddress.ip_address("169.254.169.253"),  # AWS VPC DNS/metadata
    ipaddress.ip_address("100.100.100.200"),  # Alibaba Cloud metadata
    ipaddress.ip_address("fd00:ec2::254"),    # AWS IPv6 metadata
}

# Special-use / reserved network ranges
SPECIAL_RANGES = [
    ipaddress.ip_network("100.64.0.0/10"),    # Carrier-Grade NAT / Shared Address Space (RFC 6598)
    ipaddress.ip_network("198.18.0.0/15"),    # Network Benchmark Tests (RFC 2544)
    ipaddress.ip_network("192.0.0.0/24"),     # IETF Protocol Assignments (RFC 6890)
    ipaddress.ip_network("192.0.2.0/24"),     # TEST-NET-1 (RFC 5737)
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2 (RFC 5737)
    ipaddress.ip_network("203.0.113.0/24"),   # TEST-NET-3 (RFC 5737)
    ipaddress.ip_network("0.0.0.0/8"),        # This network / "zero" address (RFC 1122)
    ipaddress.ip_network("240.0.0.0/4"),      # Reserved for future use (RFC 1112)
]

# Blocked localhost names and internal TLDs / suffixes
LOCAL_HOSTNAME_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".corp",
    ".lan",
    ".home",
)

BLOCKED_EXACT_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "broadcasthost",
    "metadata.google.internal",
    "metadata.internal",
    "metadata",
    "instance-data",
}


def _is_ip_dangerous(ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> Tuple[bool, str]:
    """
    Checks if an IP address belongs to any restricted or private network ranges.
    Returns (True, reason) if dangerous, (False, "") if safe.
    """
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            # Check the embedded IPv4 address
            is_bad, reason = _is_ip_dangerous(ip.ipv4_mapped)
            if is_bad:
                return True, f"IPv6-mapped IPv4 address ({ip.ipv4_mapped}): {reason}"
            return True, f"IPv6-mapped IPv4 address ({ip})"

        if ip.is_loopback:
            return True, "IPv6 loopback address (::1)"
        if ip.is_private:
            return True, "IPv6 private/unique-local address (fc00::/7)"
        if ip.is_link_local:
            return True, "IPv6 link-local address (fe80::/10)"
        if ip.is_reserved:
            return True, "IPv6 reserved address"
        if ip.is_multicast:
            return True, "IPv6 multicast address"
        if ip.is_unspecified:
            return True, "IPv6 unspecified address (::)"
        if ip in CLOUD_METADATA_IPS:
            return True, f"Cloud metadata IPv6 address ({ip})"
        return False, ""

    # IPv4 checks
    if ip.is_loopback:
        return True, f"Loopback address ({ip})"
    if ip.is_private:
        return True, f"Private network address ({ip})"
    if ip.is_link_local:
        return True, f"Link-local address ({ip})"
    if ip.is_reserved:
        return True, f"Reserved address ({ip})"
    if ip.is_multicast:
        return True, f"Multicast address ({ip})"
    if ip.is_unspecified:
        return True, "Unspecified address (0.0.0.0)"
    if ip in CLOUD_METADATA_IPS:
        return True, f"Cloud metadata IP address ({ip})"

    for net in SPECIAL_RANGES:
        if ip in net:
            return True, f"Restricted network range ({net})"

    return False, ""


def is_safe_target(url_or_host: str) -> Tuple[bool, str]:
    """
    Validates a target URL or hostname against Server-Side Request Forgery (SSRF).

    Performs:
    1. Scheme validation: only 'http' and 'https' are allowed.
    2. Hostname extraction and normalization.
    3. Blocking localhost names, metadata hostnames, and internal suffixes.
    4. Blocking decimal, octal, hex, and abbreviated IPv4 notations.
    5. Direct IP check for private/loopback/link-local/cloud-metadata/IPv6-mapped.
    6. DNS resolution via socket.getaddrinfo and inspection of EVERY resolved IP.

    Returns:
        (True, "") if the target is safe to probe.
        (False, reason) if the target is dangerous or disallowed.
    """
    if not url_or_host or not isinstance(url_or_host, str):
        return False, "Target URL or host is empty"

    target_str = url_or_host.strip()

    # Fast path: check if target is directly an IP literal (e.g. "::1", "127.0.0.1", "::ffff:127.0.0.1")
    unbracketed = target_str.strip("[]")
    try:
        ip_obj = ipaddress.ip_address(unbracketed)
        is_bad, reason = _is_ip_dangerous(ip_obj)
        if is_bad:
            return False, f"Blocked IP address '{target_str}': {reason}"
        return True, ""
    except ValueError:
        pass

    # 1. Scheme Validation
    if "://" in target_str:
        parsed = urlsplit(target_str)
        scheme = parsed.scheme.lower()
        if scheme not in ("http", "https"):
            return False, f"Scheme '{scheme}' is not allowed (only http and https are permitted)"
        raw_host = parsed.hostname
        try:
            port = parsed.port or (443 if scheme == "https" else 80)
        except ValueError:
            return False, f"Invalid port specification in URL: '{target_str}'"
    else:
        # Check for non-http/https schemes without :// (e.g. file:/etc/passwd, javascript:...)
        parsed = urlsplit(target_str)
        if parsed.scheme and parsed.scheme.lower() not in ("http", "https"):
            return False, f"Scheme '{parsed.scheme}' is not allowed (only http and https are permitted)"

        # Handle bare IPv6 or host:port
        if target_str.startswith("[") and "]" in target_str:
            parsed = urlsplit(f"http://{target_str}")
        elif ":" in target_str and target_str.count(":") > 1:
            parsed = urlsplit(f"http://[{target_str}]")
        else:
            parsed = urlsplit(f"http://{target_str}")

        raw_host = parsed.hostname
        try:
            port = parsed.port or 80
        except ValueError:
            return False, f"Invalid port specification in URL: '{target_str}'"

    if not raw_host:
        return False, "Target has no valid hostname or IP address"

    raw_host = raw_host.strip("[]")
    host_lower = raw_host.lower().rstrip(".")

    # 2. Block Localhost & Internal Hostnames
    if host_lower in BLOCKED_EXACT_HOSTNAMES:
        return False, f"Blocked localhost or internal hostname: '{raw_host}'"

    for suffix in LOCAL_HOSTNAME_SUFFIXES:
        if host_lower.endswith(suffix):
            return False, f"Blocked internal hostname suffix '{suffix}': '{raw_host}'"

    if "metadata.google.internal" in host_lower:
        return False, f"Blocked cloud metadata hostname: '{raw_host}'"

    # 3. Block Decimal, Octal, Hex, and Loose IPv4 Notations
    # Pure decimal integer notation (e.g. 2130706433 -> 127.0.0.1)
    if re.fullmatch(r"\d+", host_lower):
        try:
            val = int(host_lower)
            if 0 <= val <= 0xFFFFFFFF:
                return False, f"Blocked decimal IP notation: '{raw_host}' (resolves to {ipaddress.IPv4Address(val)})"
        except ValueError:
            pass
        return False, f"Blocked decimal IP notation: '{raw_host}'"

    # Hex IP notation (e.g. 0x7f000001 or 0x7f.0.0.1)
    if host_lower.startswith("0x") or any(p.lower().startswith("0x") for p in host_lower.split(".")):
        return False, f"Blocked hex IP notation: '{raw_host}'"

    # Dotted notation with octal parts (leading zeros) or abbreviated parts
    parts = host_lower.split(".")
    if len(parts) > 1 and all(p.isdigit() for p in parts):
        if any(p.startswith("0") and len(p) > 1 for p in parts):
            return False, f"Blocked octal IP notation: '{raw_host}'"
        if len(parts) < 4:
            return False, f"Blocked abbreviated IPv4 notation: '{raw_host}'"

    # 4. Direct IP address check (handles IPv4 and IPv6 string literals)
    try:
        ip_obj = ipaddress.ip_address(raw_host)
        is_bad, reason = _is_ip_dangerous(ip_obj)
        if is_bad:
            return False, f"Blocked IP address '{raw_host}': {reason}"
    except ValueError:
        pass  # Not a direct IP literal; proceed to DNS resolution

    # 5. DNS Resolution via socket.getaddrinfo
    try:
        addr_info = socket.getaddrinfo(raw_host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        return False, f"DNS resolution failed for {raw_host}: {e}"
    except Exception as e:
        return False, f"Hostname resolution error for {raw_host}: {e}"

    if not addr_info:
        return False, f"DNS resolution returned no addresses for {raw_host}"

    # Verify EVERY resolved IP address
    for res in addr_info:
        sockaddr = res[4]
        resolved_ip_str = sockaddr[0]
        try:
            resolved_ip = ipaddress.ip_address(resolved_ip_str)
        except ValueError:
            return False, f"Resolved invalid IP address: {resolved_ip_str}"

        is_bad, reason = _is_ip_dangerous(resolved_ip)
        if is_bad:
            return False, f"Resolved IP {resolved_ip_str} is dangerous: {reason}"

    return True, ""


@dataclass
class ProbeResult:
    """
    Structured outcome of an HTTP probe on a DiscoveredEndpoint.
    """
    endpoint: DiscoveredEndpoint
    status_code: Optional[int] = None
    allowed_methods: List[str] = field(default_factory=list)
    cors_reflected: bool = False
    cors_allow_origin: Optional[str] = None
    cors_allow_credentials: bool = False
    headers: Dict[str, str] = field(default_factory=dict)
    latency_ms: float = 0.0
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serializes result into a JSON-serializable dictionary."""
        ep_data = self.endpoint.to_dict() if hasattr(self.endpoint, "to_dict") else asdict(self.endpoint)
        return {
            "endpoint": ep_data,
            "status_code": self.status_code,
            "allowed_methods": self.allowed_methods,
            "cors_reflected": self.cors_reflected,
            "cors_allow_origin": self.cors_allow_origin,
            "cors_allow_credentials": self.cors_allow_credentials,
            "headers": self.headers,
            "latency_ms": self.latency_ms,
            "error": self.error,
        }


class SafeHTTPProber:
    """
    Safe, rate-limited HTTP prober designed for API endpoint discovery.

    Features:
    - SSRF prevention (is_safe_target)
    - aiolimiter.AsyncLimiter token-bucket rate limiting
    - OPTIONS probing with CORS reflection and Allow header extraction
    - Non-destructive HEAD/GET streaming fallback
    - 429 Retry-After backoff handling
    """

    def __init__(
        self,
        rate_limit: float = 5.0,
        max_burst: int = 10,
        concurrency: int = 5,
        request_timeout: float = 10.0,
        user_agent: Optional[str] = None,
        allow_private_ips: bool = False,
    ):
        self.rate_limit = rate_limit
        self.max_burst = max_burst
        self.concurrency = concurrency
        self.request_timeout = request_timeout
        self.user_agent = user_agent or "api-tool/1.0 (Safe HTTP Prober)"
        self.allow_private_ips = allow_private_ips

        # Token-bucket rate limiter (rate_limit tokens per 1.0 second)
        self.limiter = AsyncLimiter(max_rate=rate_limit, time_period=1.0)
        self._semaphore = asyncio.Semaphore(concurrency)
        self.max_retries = 2
        self.max_backoff_delay = 10.0

    def _parse_retry_after(self, retry_after: Optional[str], default_delay: float = 1.0) -> float:
        """
        Parses the Retry-After header supporting seconds and HTTP-date strings.
        """
        if not retry_after:
            return default_delay

        clean_val = retry_after.strip()
        # 1. Numeric seconds
        try:
            return max(0.0, float(clean_val))
        except ValueError:
            pass

        # 2. HTTP-date format (RFC 7231 / RFC 9110)
        try:
            dt = email.utils.parsedate_to_datetime(clean_val)
            now = datetime.now(timezone.utc)
            delta = (dt - now).total_seconds()
            return max(0.0, delta)
        except Exception:
            pass

        return default_delay

    async def _send_request(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        headers: Dict[str, str],
    ) -> httpx.Response:
        """
        Executes an HTTP request with rate limiter acquisition and 429 Retry-After backoff.
        """
        attempt = 0
        while True:
            async with self.limiter:
                resp = await client.request(method, url, headers=headers)

            if resp.status_code == 429 and attempt < self.max_retries:
                attempt += 1
                backoff = self._parse_retry_after(resp.headers.get("retry-after"))
                backoff = min(backoff, self.max_backoff_delay)
                logger.warning(
                    "Rate-limited (429) for %s. Backing off for %.2fs (attempt %d/%d).",
                    url,
                    backoff,
                    attempt,
                    self.max_retries,
                )
                await asyncio.sleep(backoff)
                continue

            return resp

    async def probe_endpoint(
        self,
        endpoint: DiscoveredEndpoint,
        client: Optional[httpx.AsyncClient] = None,
    ) -> ProbeResult:
        """
        Safely probes a single endpoint:
        1. SSRF check (unless allow_private_ips=True).
        2. Acquires rate limiter token.
        3. Sends OPTIONS request to detect allowed methods and CORS reflection.
        4. If OPTIONS returns 404/405/501 or no Allow header, sends lightweight HEAD
           (or GET with streaming limit if HEAD fails).
        5. Updates endpoint.active_status and returns ProbeResult.
        """
        url = endpoint.full_url
        if not url:
            return ProbeResult(
                endpoint=endpoint,
                error="Endpoint has empty URL",
            )

        # SSRF Verification
        if not self.allow_private_ips:
            safe, reason = is_safe_target(url)
            if not safe:
                logger.warning("SSRF blocked probe for %s: %s", url, reason)
                return ProbeResult(
                    endpoint=endpoint,
                    error=f"SSRF protection blocked target: {reason}",
                )

        if client is not None:
            return await self._probe_with_client(endpoint, client)

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(self.request_timeout),
            headers={"User-Agent": self.user_agent},
            follow_redirects=True,
        ) as default_client:
            return await self._probe_with_client(endpoint, default_client)

    async def _probe_with_client(
        self,
        endpoint: DiscoveredEndpoint,
        client: httpx.AsyncClient,
    ) -> ProbeResult:
        url = endpoint.full_url
        configured_method = (endpoint.method or "GET").upper()
        probe_origin = "https://probe.cors-test.local"

        base_headers = dict(endpoint.headers) if endpoint.headers else {}
        options_headers = {
            **base_headers,
            "Origin": probe_origin,
            "Access-Control-Request-Method": configured_method,
        }

        start_time = time.perf_counter()
        status_code: Optional[int] = None
        allowed_methods: List[str] = []
        cors_reflected = False
        cors_allow_origin: Optional[str] = None
        cors_allow_credentials = False
        headers_dict: Dict[str, str] = {}
        latency_ms = 0.0

        try:
            # 1. Send OPTIONS request
            options_resp = await self._send_request(
                client=client,
                method="OPTIONS",
                url=url,
                headers=options_headers,
            )
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            status_code = options_resp.status_code
            headers_dict = dict(options_resp.headers)

            # Check CORS headers
            for k, v in headers_dict.items():
                k_lower = k.lower()
                if k_lower == "access-control-allow-origin":
                    cors_allow_origin = v
                    if v == "*" or v == probe_origin:
                        cors_reflected = True
                elif k_lower == "access-control-allow-credentials":
                    cors_allow_credentials = (v.strip().lower() == "true")
                elif k_lower in ("allow", "access-control-allow-methods"):
                    for m in v.split(","):
                        m_clean = m.strip().upper()
                        if m_clean and m_clean not in allowed_methods:
                            allowed_methods.append(m_clean)

            # 2. Check if Fallback is needed
            # "If OPTIONS returns 404/405/501 or no Allow header, sends lightweight HEAD (or GET with streaming limit if HEAD fails)"
            has_allow_header = any(k.lower() == "allow" for k in headers_dict)
            needs_fallback = (status_code in (404, 405, 501)) or (not has_allow_header)

            if needs_fallback:
                fallback_headers = {
                    **base_headers,
                    "Origin": probe_origin,
                }
                head_success = False

                # Try lightweight HEAD first
                try:
                    head_start = time.perf_counter()
                    head_resp = await self._send_request(
                        client=client,
                        method="HEAD",
                        url=url,
                        headers=fallback_headers,
                    )
                    head_latency = (time.perf_counter() - head_start) * 1000.0

                    # 405/501 means server rejects HEAD; fallback to GET stream
                    if head_resp.status_code not in (405, 501):
                        head_success = True
                        status_code = head_resp.status_code
                        latency_ms = head_latency
                        headers_dict = dict(head_resp.headers)
                except Exception:
                    head_success = False

                # If HEAD failed or returned 405/501, send GET (or configured method) with streaming limit
                if not head_success:
                    stream_method = configured_method if configured_method != "HEAD" else "GET"
                    stream_start = time.perf_counter()

                    attempt = 0
                    while True:
                        async with self.limiter:
                            async with client.stream(
                                stream_method,
                                url,
                                headers=fallback_headers,
                            ) as stream_resp:
                                if stream_resp.status_code == 429 and attempt < self.max_retries:
                                    attempt += 1
                                    backoff = self._parse_retry_after(stream_resp.headers.get("retry-after"))
                                    backoff = min(backoff, self.max_backoff_delay)
                                    await asyncio.sleep(backoff)
                                    continue

                                status_code = stream_resp.status_code
                                latency_ms = (time.perf_counter() - stream_start) * 1000.0
                                headers_dict = dict(stream_resp.headers)
                                # Consume at most a small slice (1024 bytes) to avoid body buffering
                                async for _ in stream_resp.aiter_bytes(chunk_size=1024):
                                    break
                                break

                # Extract CORS & Allow headers from fallback if not already captured
                for k, v in headers_dict.items():
                    k_lower = k.lower()
                    if k_lower == "access-control-allow-origin" and not cors_allow_origin:
                        cors_allow_origin = v
                        if v == "*" or v == probe_origin:
                            cors_reflected = True
                    elif k_lower == "access-control-allow-credentials":
                        cors_allow_credentials = (v.strip().lower() == "true")
                    elif k_lower in ("allow", "access-control-allow-methods"):
                        for m in v.split(","):
                            m_clean = m.strip().upper()
                            if m_clean and m_clean not in allowed_methods:
                                allowed_methods.append(m_clean)

            # Update endpoint active status
            endpoint.active_status = status_code

            return ProbeResult(
                endpoint=endpoint,
                status_code=status_code,
                allowed_methods=allowed_methods,
                cors_reflected=cors_reflected,
                cors_allow_origin=cors_allow_origin,
                cors_allow_credentials=cors_allow_credentials,
                headers=headers_dict,
                latency_ms=round(latency_ms, 2),
                error=None,
            )

        except Exception as exc:
            logger.debug("Probe failed for %s: %s", url, exc)
            return ProbeResult(
                endpoint=endpoint,
                status_code=status_code,
                allowed_methods=allowed_methods,
                cors_reflected=cors_reflected,
                cors_allow_origin=cors_allow_origin,
                cors_allow_credentials=cors_allow_credentials,
                headers=headers_dict,
                latency_ms=round(latency_ms, 2),
                error=str(exc),
            )

    async def probe_endpoints(
        self,
        endpoints: List[DiscoveredEndpoint],
        client: Optional[httpx.AsyncClient] = None,
        concurrency: Optional[int] = None,
    ) -> List[ProbeResult]:
        """
        Concurrently probes a list of endpoints bounded by semaphore and rate limiter.
        Returns a list of ProbeResult objects in the same order as input endpoints.
        """
        if not endpoints:
            return []

        sem = asyncio.Semaphore(concurrency) if concurrency is not None else self._semaphore

        async def _worker(ep: DiscoveredEndpoint, c: httpx.AsyncClient) -> ProbeResult:
            async with sem:
                return await self.probe_endpoint(ep, client=c)

        if client is not None:
            tasks = [_worker(ep, client) for ep in endpoints]
            return await asyncio.gather(*tasks)

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(self.request_timeout),
            headers={"User-Agent": self.user_agent},
            follow_redirects=True,
        ) as default_client:
            tasks = [_worker(ep, default_client) for ep in endpoints]
            return await asyncio.gather(*tasks)
