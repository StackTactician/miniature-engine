"""
Cross-Domain CDN and CSP Scope Engine.
Dynamically resolves crawling, asset, and API scopes using Content Security Policy (CSP),
reputable multi-tenant CDNs, and strict analytics/tracker blocking.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Union
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)


# Reputable multi-tenant CDNs for JS chunks, sourcemaps, and frontend assets
DEFAULT_TRUSTED_CDNS: Set[str] = {
    # AWS CloudFront
    "cloudfront.net",
    # Fastly
    "fastly.net",
    "fastlylb.net",
    # Akamai
    "akamai.net",
    "akamaized.net",
    "akamaihd.net",
    "edgekey.net",
    "edgesuite.net",
    # cdnjs
    "cdnjs.cloudflare.com",
    # unpkg
    "unpkg.com",
    # jsDelivr
    "jsdelivr.net",
    "cdn.jsdelivr.net",
    # Azure CDN / Front Door
    "azureedge.net",
    "azurefd.net",
    # Shopify CDN
    "cdn.shopify.com",
}

# Analytics and ad trackers strictly blocked from crawling, asset fetching, and API mapping
DEFAULT_BLOCKED_TRACKERS: Set[str] = {
    # Google Analytics, GTM, DoubleClick, Ads
    "google-analytics.com",
    "googletagmanager.com",
    "doubleclick.net",
    "googleadservices.com",
    # Sentry error reporting
    "sentry.io",
    "browser.sentry-cdn.com",
    # Datadog APM & RUM
    "datadoghq.com",
    "datadoghq-browser-agent.com",
    # Segment / Mixpanel / Amplitude / Heap
    "segment.io",
    "segment.com",
    "mixpanel.com",
    "amplitude.com",
    "heap.io",
    "heapanalytics.com",
    # User session recording & heatmaps
    "hotjar.com",
    "hotjar.io",
    "clarity.ms",
    "fullstory.com",
    "crazyegg.com",
    "logrocket.io",
    # Social & ad networks
    "facebook.net",
    "connect.facebook.net",
    "ads-twitter.com",
    "analytics.twitter.com",
    # APM & customer messaging
    "newrelic.com",
    "nr-data.net",
    "bugsnag.com",
    "intercom.io",
    "intercomcdn.com",
}


@dataclass
class ScopePolicy:
    """
    Configurable policy rules governing spider scope determination.
    """

    allow_subdomains: bool = True
    allow_trusted_cdns: bool = True
    allow_csp_hosts: bool = True
    block_analytics_trackers: bool = True
    trusted_cdns: Set[str] = field(default_factory=set)
    blocked_trackers: Set[str] = field(default_factory=set)


class CDNScopeResolver:
    """
    Three-tier scope resolver:
    1. is_page_in_scope: HTML navigation restricted to target domain/subdomains.
    2. is_asset_in_scope: JS chunks/sourcemaps matching target, CSP script-src, or trusted CDNs.
    3. is_api_in_scope: REST/GraphQL targets matching target domain or CSP connect-src.
    """

    def __init__(
        self,
        target_domain: Optional[str] = None,
        target_domains: Optional[Union[List[str], Set[str], str]] = None,
        policy: Optional[ScopePolicy] = None,
        csp: Optional[str] = None,
    ) -> None:
        self.policy = policy or ScopePolicy()
        self.target_domains: Set[str] = set()

        if target_domain:
            self.add_target_domain(target_domain)

        if target_domains:
            if isinstance(target_domains, str):
                self.add_target_domain(target_domains)
            else:
                for td in target_domains:
                    self.add_target_domain(td)

        # Dynamic whitelists populated from CSP
        self.csp_script_hosts: Set[str] = set()
        self.csp_connect_hosts: Set[str] = set()
        self.csp_default_hosts: Set[str] = set()

        if csp:
            self.update_from_csp(csp)

    @property
    def effective_trusted_cdns(self) -> Set[str]:
        return DEFAULT_TRUSTED_CDNS | self.policy.trusted_cdns

    @property
    def effective_blocked_trackers(self) -> Set[str]:
        return DEFAULT_BLOCKED_TRACKERS | self.policy.blocked_trackers

    def add_target_domain(self, domain_or_url: str) -> None:
        """Adds a target domain or normalizes a target URL into its host."""
        if not domain_or_url:
            return
        domain_or_url = domain_or_url.strip()
        if "://" in domain_or_url:
            parsed = urlsplit(domain_or_url)
            host = parsed.netloc.split(":")[0].lower()
        else:
            host = domain_or_url.split("/")[0].split(":")[0].lower()
        if host:
            self.target_domains.add(host)

    @staticmethod
    def _extract_host_from_source(source: str) -> Optional[str]:
        """
        Extracts a clean host or wildcard host from a CSP source token.
        Returns None for keywords ('self', 'unsafe-inline', 'none'), schemes (data:, blob:), or wildcards (*).
        """
        s = source.strip()
        # Skip quoted keywords
        if (s.startswith("'") and s.endswith("'")) or (s.startswith('"') and s.endswith('"')):
            return None
        # Skip pure schemes or universal wildcards
        if s.endswith(":") or s in ("*", ""):
            return None

        # Check if URL format
        if "://" in s or s.startswith("//"):
            parsed = urlsplit(s if "://" in s else "http:" + s)
            host = parsed.netloc.split(":")[0].lower()
        else:
            host_part = s.split("/", 1)[0]
            host = host_part.split(":")[0].lower()

        if not host or host == "*":
            return None
        return host.rstrip(".")

    def parse_csp_header(self, csp_header: str) -> Dict[str, List[str]]:
        """
        Parses a Content-Security-Policy header string into a dictionary of directive -> source tokens.
        """
        directives: Dict[str, List[str]] = {}
        if not csp_header:
            return directives
        for directive_chunk in csp_header.split(";"):
            tokens = directive_chunk.strip().split()
            if not tokens:
                continue
            directive_name = tokens[0].lower()
            sources = tokens[1:]
            directives[directive_name] = sources
        return directives

    def update_from_csp(self, csp_header: str) -> None:
        """
        Parses Content Security Policy and updates dynamically whitelisted script, connect, and default hosts.
        """
        directives = self.parse_csp_header(csp_header)
        for directive_name, sources in directives.items():
            extracted_hosts: Set[str] = set()
            for src in sources:
                host = self._extract_host_from_source(src)
                if host:
                    extracted_hosts.add(host)

            if directive_name in ("script-src", "script-src-elem"):
                self.csp_script_hosts.update(extracted_hosts)
            elif directive_name in ("connect-src",):
                self.csp_connect_hosts.update(extracted_hosts)
            elif directive_name in ("default-src",):
                self.csp_default_hosts.update(extracted_hosts)

    def update_from_html(self, html: str) -> None:
        """
        Extracts meta Content-Security-Policy tags from HTML and updates whitelists.
        """
        if not html:
            return
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, "html.parser")
            for meta in soup.find_all("meta"):
                http_equiv = meta.get("http-equiv", "").lower()
                if http_equiv in ("content-security-policy", "content-security-policy-report-only"):
                    content = meta.get("content")
                    if content:
                        self.update_from_csp(content)
        except Exception as e:
            logger.debug("Failed to parse CSP from HTML: %s", e)

    @staticmethod
    def _host_matches(host: str, pattern: str, allow_subdomains: bool = True) -> bool:
        """
        Checks if host matches pattern. Supports wildcards (*.example.com) and subdomain matching.
        """
        host = host.lower()
        pattern = pattern.lower().strip()
        if not host or not pattern:
            return False

        if pattern.startswith("*."):
            base = pattern[2:]
            return host == base or host.endswith("." + base)

        if host == pattern:
            return True

        if allow_subdomains and host.endswith("." + pattern):
            return True

        return False

    def _matches_any(self, host: str, patterns: Iterable[str], allow_subdomains: bool = True) -> bool:
        return any(self._host_matches(host, p, allow_subdomains=allow_subdomains) for p in patterns)

    def is_tracker(self, host: str) -> bool:
        """
        Checks if a host matches any known analytics, advertising, or error tracking services.
        """
        if not host:
            return False
        host = host.lower().split(":")[0]
        for tracker in self.effective_blocked_trackers:
            if host == tracker or host.endswith("." + tracker):
                return True
        return False

    def _matches_target(self, host: str) -> bool:
        if not self.target_domains:
            return True
        return self._matches_any(host, self.target_domains, allow_subdomains=self.policy.allow_subdomains)

    def _matches_trusted_cdn(self, host: str) -> bool:
        return self._matches_any(host, self.effective_trusted_cdns, allow_subdomains=True)

    def _parse_url_host(self, url: str) -> Optional[str]:
        if not url:
            return None
        url_clean = url.strip()
        if url_clean.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
            return None

        parsed = urlsplit(url_clean)
        # Unsupported non-HTTP scheme
        if parsed.scheme and parsed.scheme.lower() not in ("http", "https"):
            return None

        if parsed.netloc:
            return parsed.netloc.split(":")[0].lower()

        # Relative path on target domain
        return ""

    def is_page_in_scope(self, url: str) -> bool:
        """
        HTML navigation scope: Strictly restricted to target domain/subdomains.
        Never follows CDNs, external script hosts, or trackers.
        """
        host = self._parse_url_host(url)
        if host is None:
            return False

        # Relative URL on target domain
        if host == "":
            return True

        # Tracker check
        if self.policy.block_analytics_trackers and self.is_tracker(host):
            return False

        return self._matches_target(host)

    def is_asset_in_scope(self, url: str) -> bool:
        """
        Asset scope (JS chunks, sourcemaps, CSS, fonts):
        Allowed if on target domain, matching CSP script-src/default-src, or hosted on trusted CDNs.
        """
        host = self._parse_url_host(url)
        if host is None:
            return False

        # Relative asset URL on target domain
        if host == "":
            return True

        # Tracker check
        if self.policy.block_analytics_trackers and self.is_tracker(host):
            return False

        # 1. Target domain check
        if self._matches_target(host):
            return True

        # 2. Trusted CDN check
        if self.policy.allow_trusted_cdns and self._matches_trusted_cdn(host):
            return True

        # 3. CSP script-src / default-src hosts check
        if self.policy.allow_csp_hosts:
            if self._matches_any(host, self.csp_script_hosts, allow_subdomains=self.policy.allow_subdomains):
                return True
            if self._matches_any(host, self.csp_default_hosts, allow_subdomains=self.policy.allow_subdomains):
                return True

        return False

    def is_api_in_scope(self, url: str) -> bool:
        """
        API scope (REST/GraphQL targets):
        Allowed if on target domain or matching CSP connect-src/default-src.
        Does NOT automatically whitelist CDNs.
        """
        host = self._parse_url_host(url)
        if host is None:
            return False

        # Relative API URL on target domain
        if host == "":
            return True

        # Tracker check
        if self.policy.block_analytics_trackers and self.is_tracker(host):
            return False

        # 1. Target domain check
        if self._matches_target(host):
            return True

        # 2. CSP connect-src / default-src hosts check
        if self.policy.allow_csp_hosts:
            if self._matches_any(host, self.csp_connect_hosts, allow_subdomains=self.policy.allow_subdomains):
                return True
            if self._matches_any(host, self.csp_default_hosts, allow_subdomains=self.policy.allow_subdomains):
                return True

        return False
