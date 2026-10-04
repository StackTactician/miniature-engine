"""
Safety, scope, and anti-rabbit-hole filter engine for web spidering.
Guards against SSRF, private network pivoting, OAuth redirection traps,
destructive actions, and recursive crawl loops.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
from typing import Optional, Pattern, Set, Union
from urllib.parse import parse_qsl, urlsplit

from api_tool.spider.scope_resolver import CDNScopeResolver

logger = logging.getLogger(__name__)


# SSRF & Cloud Metadata host targets
METADATA_HOSTNAMES: Set[str] = {
    "metadata.google.internal",
    "metadata.goog",
    "metadata",
    "instance-data",
    "169.254.169.254",
}

# Carrier Grade NAT network (RFC 6598)
CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")

# OAuth and third-party Identity Provider domains to prevent auth-flow trapping
DEFAULT_OAUTH_DOMAINS: Set[str] = {
    "accounts.google.com",
    "login.microsoftonline.com",
    "appleid.apple.com",
    "github.com",
    "gitlab.com",
    "auth0.com",
    "okta.com",
}
OAUTH_DOMAINS: Set[str] = DEFAULT_OAUTH_DOMAINS

# Session-destroying or destructive actions strictly blocked from automated spidering
DANGEROUS_ACTIONS_LIST = [
    r"logout",
    r"signout",
    r"sign[-_]out",
    r"logoff",
    r"exit",
    r"deauth",
    r"revoke",
    r"delete",
    r"destroy",
    r"remove",
    r"cancel",
    r"terminate",
    r"drop",
    r"purge",
    r"erase",
    r"unsubscribe",
    r"reset[-_]password",
    r"change[-_]password",
    r"kill[-_]switch",
    r"clear[-_]cache",
]

DANGEROUS_ACTIONS_PATTERN = (
    r"(?:^|[/._?&=;:-])(?:"
    + "|".join(DANGEROUS_ACTIONS_LIST)
    + r")(?:[/._?&=;:-]|$)"
)
DANGEROUS_ACTIONS_REGEX: Pattern[str] = re.compile(DANGEROUS_ACTIONS_PATTERN, re.IGNORECASE)

# Infinite rabbit-hole patterns: calendar/archive loops, deep pagination, repeated query params
RABBIT_HOLE_PATTERNS = [
    # Calendar & archive loops (e.g. /2024/05/12, /events/2023-11)
    r"(?:/(?:19|20)\d{2}[/-](?:0?[1-9]|1[0-2])(?:[/-](?:0?[1-9]|[12]\d|3[01]))?(?=/|$|[?#]))",
    # Deep pagination loops (e.g. ?page=9999, ?p=5000, ?offset=20000)
    r"(?:[?&](?:page|p|pg)=(?:[1-9]\d{2,}))",
    r"(?:[?&](?:offset|start|skip)=(?:[1-9]\d{3,}))",
    # Repeated query parameter loops (e.g. ?sort=asc&sort=desc)
    r"(?:[?&](?P<rabbit_param>[a-zA-Z0-9_-]+)=[^&#\s]*&(?:[^#\s]*&)*(?P=rabbit_param)=)",
]
RABBIT_HOLE_REGEX: Pattern[str] = re.compile("|".join(RABBIT_HOLE_PATTERNS), re.IGNORECASE)


def extract_host(host_or_url: str) -> str:
    """
    Extracts normalized host from a URL or host:port string.
    """
    if not host_or_url:
        return ""
    s = host_or_url.strip()
    if "://" in s or s.startswith("//"):
        parsed = urlsplit(s if "://" in s else "http:" + s)
        host = parsed.netloc
    else:
        host = s.split("/")[0]

    if "@" in host:
        host = host.split("@")[-1]

    if host.startswith("["):
        host_clean, _, _ = host[1:].partition("]")
        return host_clean.lower()
    elif ":" in host:
        if host.count(":") == 1:
            host = host.split(":")[0]

    return host.strip().lower().rstrip(".")


def _is_private_or_reserved_ip(ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> bool:
    """Checks if an IP address belongs to private, loopback, link-local, or reserved ranges."""
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    ):
        return True
    if isinstance(ip, ipaddress.IPv4Address) and ip in CGNAT_NETWORK:
        return True
    return False


def is_private_or_ssrf_host(host: str) -> bool:
    """
    Checks if a host resolves or is a private, loopback, link-local, or cloud metadata IP:
    127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.169.254, ::1,
    localhost, metadata.google.internal.
    """
    clean_host = extract_host(host)
    if not clean_host:
        return False

    # 1. Exact string and suffix matches for known local and cloud metadata endpoints
    if clean_host == "localhost" or clean_host.endswith(".localhost"):
        return True
    if clean_host == "metadata.google.internal" or clean_host.endswith(".metadata.google.internal"):
        return True
    if clean_host in METADATA_HOSTNAMES:
        return True

    # 2. CIDR notation check (if host is passed in CIDR notation e.g. 127.0.0.0/8)
    if "/" in clean_host:
        try:
            net = ipaddress.ip_network(clean_host, strict=False)
            return (
                net.is_private
                or net.is_loopback
                or net.is_link_local
                or net.is_reserved
                or net.is_multicast
                or net.is_unspecified
            )
        except ValueError:
            pass

    # 3. Direct IP address check
    try:
        ip = ipaddress.ip_address(clean_host)
        return _is_private_or_reserved_ip(ip)
    except ValueError:
        pass

    # 4. DNS resolution check (catches domains resolving to private/internal IPs)
    try:
        addr_info = socket.getaddrinfo(clean_host, None)
        for res in addr_info:
            ip_str = res[4][0]
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                if _is_private_or_reserved_ip(ip_obj):
                    return True
            except ValueError:
                continue
    except (socket.gaierror, socket.herror, OSError, UnicodeError):
        pass

    return False


def is_oauth_domain(host_or_url: str, oauth_domains: Optional[Set[str]] = None) -> bool:
    """
    Checks if host or URL matches any known OAuth / Identity Provider domain.
    """
    clean_host = extract_host(host_or_url)
    if not clean_host:
        return False
    targets = oauth_domains if oauth_domains is not None else DEFAULT_OAUTH_DOMAINS
    for domain in targets:
        d = domain.lower()
        if clean_host == d or clean_host.endswith("." + d):
            return True
    return False


class URLFilterEngine:
    """
    Safety, scope, and anti-rabbit-hole filter engine.
    Ensures spider crawling strictly adheres to allowed scope and refuses to crawl
    destructive links, auth services, SSRF targets, or infinite pagination loops.
    """

    OAUTH_DOMAINS: Set[str] = DEFAULT_OAUTH_DOMAINS
    DANGEROUS_ACTIONS_REGEX: Pattern[str] = DANGEROUS_ACTIONS_REGEX
    RABBIT_HOLE_REGEX: Pattern[str] = RABBIT_HOLE_REGEX

    def __init__(
        self,
        scope_resolver: Optional[CDNScopeResolver] = None,
        include_regex: Optional[Union[str, Pattern[str]]] = None,
        exclude_regex: Optional[Union[str, Pattern[str]]] = None,
        block_dangerous_actions: bool = True,
        block_rabbit_holes: bool = True,
        oauth_domains: Optional[Set[str]] = None,
        allow_private_ips: bool = False,
    ) -> None:
        self.scope_resolver = scope_resolver
        self.include_regex = include_regex
        self.exclude_regex = exclude_regex
        self.block_dangerous_actions = block_dangerous_actions
        self.block_rabbit_holes = block_rabbit_holes
        self.allow_private_ips = allow_private_ips
        self.oauth_domains: Set[str] = (
            set(oauth_domains) if oauth_domains is not None else set(self.OAUTH_DOMAINS)
        )

        if isinstance(include_regex, str) and include_regex.strip():
            self.include_pattern: Optional[Pattern[str]] = re.compile(include_regex, re.IGNORECASE)
        elif isinstance(include_regex, re.Pattern):
            self.include_pattern = include_regex
        else:
            self.include_pattern = None

        if isinstance(exclude_regex, str) and exclude_regex.strip():
            self.exclude_pattern: Optional[Pattern[str]] = re.compile(exclude_regex, re.IGNORECASE)
        elif isinstance(exclude_regex, re.Pattern):
            self.exclude_pattern = exclude_regex
        else:
            self.exclude_pattern = None

    @staticmethod
    def is_private_or_ssrf_host(host: str) -> bool:
        """Checks if host resolves or is a private, loopback, link-local, or cloud metadata IP."""
        return is_private_or_ssrf_host(host)

    def is_oauth_domain(self, host_or_url: str) -> bool:
        """Blocks links to external auth services (e.g. Google, Microsoft, Apple, GitHub, Okta)."""
        return is_oauth_domain(host_or_url, self.oauth_domains)

    @classmethod
    def is_dangerous_action(cls, url: str) -> bool:
        """Checks if URL path or query contains session-destroying or destructive actions."""
        if not url:
            return False
        return bool(cls.DANGEROUS_ACTIONS_REGEX.search(url))

    @classmethod
    def is_rabbit_hole(cls, url: str) -> bool:
        """
        Checks if URL represents an infinite crawl rabbit hole:
        - Calendar/archive loops (e.g. /2024/05/12, /events/2023-11)
        - Deep pagination (e.g. ?page=9999, ?p=5000, ?offset=20000)
        - Repeated query parameter loops (e.g. ?sort=asc&sort=desc)
        """
        if not url:
            return False
        if bool(cls.RABBIT_HOLE_REGEX.search(url)):
            return True
        if "?" in url:
            query = url.split("?", 1)[1].split("#", 1)[0]
            params = parse_qsl(query, keep_blank_values=True)
            seen = set()
            for k, _ in params:
                k_low = k.lower()
                if k_low in seen:
                    return True
                seen.add(k_low)
        return False

    def should_crawl_page(self, url: str) -> bool:
        """
        Coordinates comprehensive crawl safety and scope checks:
        1. Validates HTTP/HTTPS scheme and filters out pseudo-protocols (javascript:, mailto:, data:).
        2. SSRF check: Rejects private/loopback/cloud-metadata hosts.
        3. OAuth check: Rejects external identity provider URLs.
        4. Dangerous action check: Rejects destructive/session-terminating endpoints.
        5. Rabbit-hole check: Rejects calendar loops, deep pagination, repeated parameters.
        6. Scope verification: Enforces CDNScopeResolver.is_page_in_scope().
        7. User exclude_regex check.
        8. User include_regex check.
        """
        if not url or not isinstance(url, str):
            return False

        url_clean = url.strip()
        if not url_clean:
            return False

        # Reject non-web schemes and fragments-only
        if url_clean.startswith(("#", "javascript:", "mailto:", "tel:", "data:", "blob:", "about:")):
            return False

        parsed = urlsplit(url_clean)
        if parsed.scheme and parsed.scheme.lower() not in ("http", "https"):
            return False

        host = extract_host(url_clean)

        # 1. SSRF & Private Network Guard
        if not self.allow_private_ips and host and self.is_private_or_ssrf_host(host):
            return False

        # 2. OAuth / Identity Provider Guard
        if host and self.is_oauth_domain(host):
            return False

        # 3. Dangerous Action Guard
        if self.block_dangerous_actions and self.is_dangerous_action(url_clean):
            return False

        # 4. Rabbit-Hole Guard
        if self.block_rabbit_holes and self.is_rabbit_hole(url_clean):
            return False

        # 5. Scope Resolver check
        if self.scope_resolver is not None:
            if not self.scope_resolver.is_page_in_scope(url_clean):
                return False

        # 6. User Exclude Regex
        if self.exclude_pattern is not None:
            if self.exclude_pattern.search(url_clean):
                return False

        # 7. User Include Regex
        if self.include_pattern is not None:
            if not self.include_pattern.search(url_clean):
                return False

        return True
