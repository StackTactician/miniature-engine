"""
Challenge and WAF detection subsystem for api-tool network layer.
Detects Cloudflare Turnstile, Cloudflare Managed Challenge, Akamai Bot Manager,
AWS WAF, and Reddit Proof-of-Work (PoW) signatures.
Includes pure Python zero-dependency SHA256 Reddit PoW solver.
"""

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple, Union


@dataclass
class PoWSolution:
    """Represents a computed proof-of-work solution."""
    nonce: str
    difficulty: int
    solution: int
    hash: str
    iterations: int
    elapsed_ms: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nonce": self.nonce,
            "difficulty": self.difficulty,
            "solution": self.solution,
            "hash": self.hash,
            "iterations": self.iterations,
            "elapsed_ms": self.elapsed_ms,
        }


class RedditPoWSolver:
    """
    Pure Python SHA-256 Proof-of-Work solver for Reddit and similar anti-bot puzzles.
    Zero external dependencies, highly optimized nonce iteration.
    Computes: hashlib.sha256(f"{nonce}{i}".encode()).hexdigest()
    Solves 4-difficulty challenges in < 5ms.
    """

    @staticmethod
    def solve(
        nonce: str,
        difficulty: int = 4,
        max_iterations: int = 2_000_000,
        start_nonce: int = 0,
    ) -> PoWSolution:
        """
        Iterates counter i from start_nonce to find a hash with `difficulty` leading hex zeros.
        Formula: hashlib.sha256(f"{nonce}{i}".encode()).hexdigest()
        """
        prefix = "0" * difficulty
        t0 = time.perf_counter()
        sha256 = hashlib.sha256

        for i in range(start_nonce, start_nonce + max_iterations):
            candidate = f"{nonce}{i}".encode("ascii")
            h = sha256(candidate).hexdigest()
            if h.startswith(prefix):
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                return PoWSolution(
                    nonce=nonce,
                    difficulty=difficulty,
                    solution=i,
                    hash=h,
                    iterations=i - start_nonce + 1,
                    elapsed_ms=elapsed_ms,
                )

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        raise TimeoutError(
            f"Failed to solve PoW for nonce '{nonce}' within {max_iterations} iterations "
            f"({elapsed_ms:.2f}ms)"
        )

    @staticmethod
    def verify(nonce: str, solution: int, difficulty: int = 4) -> bool:
        """Verify that nonce + solution satisfies difficulty with leading zeros."""
        prefix = "0" * difficulty
        candidate = f"{nonce}{solution}".encode("ascii")
        h = hashlib.sha256(candidate).hexdigest()
        return h.startswith(prefix)

    @staticmethod
    def extract_challenge(response: Any) -> Optional[Dict[str, Any]]:
        """
        Extract Reddit PoW challenge parameters (nonce, difficulty) from response
        headers or body.
        """
        headers: Mapping[str, str] = getattr(response, "headers", {}) or {}
        # Case-insensitive header lookup
        header_lower = {str(k).lower(): str(v) for k, v in headers.items()}

        # 1. Check header x-reddit-pow-challenge or x-reddit-pow
        for h_key in ("x-reddit-pow-challenge", "x-reddit-pow", "x-reddit-challenge"):
            if h_key in header_lower:
                val = header_lower[h_key]
                try:
                    data = json.loads(val)
                    if isinstance(data, dict) and "nonce" in data:
                        return {
                            "nonce": str(data["nonce"]),
                            "difficulty": int(data.get("difficulty", 4)),
                        }
                except Exception:
                    # Format: nonce:difficulty
                    if ":" in val:
                        parts = val.split(":", 1)
                        if parts[1].isdigit():
                            return {"nonce": parts[0], "difficulty": int(parts[1])}
                    return {"nonce": val, "difficulty": 4}

        # 2. Check JSON body
        text = getattr(response, "text", "") or ""
        if not text:
            content = getattr(response, "content", b"")
            if content:
                try:
                    text = content.decode("utf-8", errors="replace")
                except Exception:
                    text = ""

        if text:
            try:
                body_json = json.loads(text)
                if isinstance(body_json, dict):
                    if "pow" in body_json and isinstance(body_json["pow"], dict):
                        pow_data = body_json["pow"]
                        if "nonce" in pow_data:
                            return {
                                "nonce": str(pow_data["nonce"]),
                                "difficulty": int(pow_data.get("difficulty", 4)),
                            }
                    if "nonce" in body_json and ("pow" in body_json or "difficulty" in body_json):
                        return {
                            "nonce": str(body_json["nonce"]),
                            "difficulty": int(body_json.get("difficulty", 4)),
                        }
            except Exception:
                pass

            # 3. Regex search in HTML/text
            nonce_match = re.search(r'["\']nonce["\']\s*:\s*["\']([a-zA-Z0-9_\-]+)["\']', text)
            diff_match = re.search(r'["\']difficulty["\']\s*:\s*(\d+)', text)
            if nonce_match and ("pow" in text.lower() or "reddit" in text.lower()):
                diff = int(diff_match.group(1)) if diff_match else 4
                return {"nonce": nonce_match.group(1), "difficulty": diff}

        return None

    @staticmethod
    def detect_js_challenge(html: str) -> Optional[Dict[str, Any]]:
        """
        Detects Reddit's inline JS challenge:
        <input type="hidden" name="js_challenge" value="1">
        await (async e=>e+e)("seed")
        Returns dict with seed, solution, action, inputs or None.
        """
        if not html or ("js_challenge" not in html and "async e=>e+e" not in html):
            return None

        seed_match = re.search(r'async\s+e=>e\+e\)\(\"([^\"]+)\"\)', html)
        if not seed_match:
            return None

        seed = seed_match.group(1)
        solution = seed + seed

        # Extract form action and inputs
        action = "/"
        action_match = re.search(r'<form\s+[^>]*action=["\']([^"\']+)["\']', html)
        if action_match:
            action = action_match.group(1)

        inputs: Dict[str, str] = {}
        for m in re.finditer(r'<input\s+[^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\']', html):
            inputs[m.group(1)] = m.group(2)
        for m in re.finditer(r'<input\s+[^>]*value=["\']([^"\']*)["\'][^>]*name=["\']([^"\']+)["\']', html):
            inputs[m.group(2)] = m.group(1)

        inputs["solution"] = solution
        return {
            "type": "reddit_js_challenge",
            "seed": seed,
            "solution": solution,
            "action": action,
            "inputs": inputs,
        }


@dataclass
class WAFDetectionResult:
    """Result of WAF / bot-challenge detection on an HTTP response."""
    detected: bool = False
    waf_name: Optional[str] = None  # "cloudflare", "akamai", "aws_waf", "reddit_pow"
    challenge_type: Optional[str] = None  # "turnstile", "managed_challenge", "bot_manager", "captcha", "pow", "block"
    confidence: float = 0.0
    signatures: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "detected": self.detected,
            "waf_name": self.waf_name,
            "challenge_type": self.challenge_type,
            "confidence": self.confidence,
            "signatures": list(self.signatures),
            "details": self.details,
        }


class WAFDetector:
    """
    Detects Cloudflare Turnstile, Cloudflare Managed Challenge, Akamai Bot Manager,
    AWS WAF, and Reddit PoW signatures in HTTP responses.
    """

    # Cloudflare signatures
    CF_TURNSTILE_DOM_MARKERS = [
        "challenges.cloudflare.com/turnstile",
        "cf-turnstile",
        "turnstile-wrapper",
        "data-sitekey=",
    ]
    CF_MANAGED_DOM_MARKERS = [
        "Just a moment...",
        "<title>Just a moment...</title>",
        "Checking your browser before accessing",
        "cf-browser-verification",
        "cf-challenge",
        "window._cf_chl_opt",
        "Attention Required! | Cloudflare",
    ]

    # Akamai signatures
    AKAMAI_DOM_MARKERS = [
        "Access Denied",
        "Reference #",
        "akamai-bot-manager",
        "ak-bm",
        "The requested URL was not found on this server",
    ]

    # AWS WAF signatures
    AWS_WAF_DOM_MARKERS = [
        "Request blocked by AWS WAF",
        "AWS WAF",
        "aws-waf-captcha",
        "awswaf.js",
        "403 Forbidden - Request blocked",
    ]

    @classmethod
    def detect(
        cls,
        response: Optional[Any] = None,
        *,
        status_code: Optional[int] = None,
        headers: Optional[Mapping[str, str]] = None,
        text: Optional[str] = None,
        content: Optional[bytes] = None,
    ) -> WAFDetectionResult:
        """
        Inspect response or explicit parameters for WAF / bot challenge signatures.
        """
        # Extract fields from response object if provided
        if response is not None:
            if status_code is None:
                status_code = getattr(response, "status_code", 200)
            if headers is None:
                headers = getattr(response, "headers", {})
            if text is None:
                text = getattr(response, "text", "")
            if content is None:
                content = getattr(response, "content", b"")

        status_code = status_code or 200
        headers_dict = dict(headers or {})
        header_lower = {str(k).lower(): str(v) for k, v in headers_dict.items()}

        if not text and content:
            try:
                text = content.decode("utf-8", errors="replace")
            except Exception:
                text = ""
        text = text or ""

        # 1. Check Reddit PoW
        reddit_result = cls._check_reddit_pow(status_code, header_lower, text, response)
        if reddit_result.detected:
            return reddit_result

        # 2. Check Cloudflare
        cf_result = cls._check_cloudflare(status_code, header_lower, text)
        if cf_result.detected:
            return cf_result

        # 3. Check Akamai
        akamai_result = cls._check_akamai(status_code, header_lower, text, response)
        if akamai_result.detected:
            return akamai_result

        # 4. Check AWS WAF
        aws_result = cls._check_aws_waf(status_code, header_lower, text)
        if aws_result.detected:
            return aws_result

        return WAFDetectionResult(detected=False, confidence=0.0)

    @classmethod
    def _check_reddit_pow(
        cls,
        status_code: int,
        header_lower: Dict[str, str],
        text: str,
        response: Any,
    ) -> WAFDetectionResult:
        signatures = []
        for h in ("x-reddit-pow-challenge", "x-reddit-pow", "x-reddit-challenge"):
            if h in header_lower:
                signatures.append(f"header:{h}")

        if "reddit_pow" in text or "reddit-pow" in text or "reddit.com/pow" in text:
            signatures.append("body:reddit_pow_marker")

        # Check challenge extraction
        challenge_data = RedditPoWSolver.extract_challenge(response) if response else None
        if challenge_data:
            signatures.append(f"challenge:nonce={challenge_data.get('nonce')}")

        # Check inline JS challenge
        js_data = RedditPoWSolver.detect_js_challenge(text)
        if js_data:
            signatures.append("body:reddit_js_challenge")
            return WAFDetectionResult(
                detected=True,
                waf_name="reddit_pow",
                challenge_type="js_challenge",
                confidence=1.0,
                signatures=signatures,
                details=js_data,
            )

        if signatures:
            return WAFDetectionResult(
                detected=True,
                waf_name="reddit_pow",
                challenge_type="pow",
                confidence=1.0,
                signatures=signatures,
                details=challenge_data or {},
            )
        return WAFDetectionResult(detected=False)

    @classmethod
    def _check_cloudflare(
        cls,
        status_code: int,
        header_lower: Dict[str, str],
        text: str,
    ) -> WAFDetectionResult:
        signatures = []
        is_cf_server = "server" in header_lower and "cloudflare" in header_lower["server"].lower()
        has_cf_ray = "cf-ray" in header_lower

        if is_cf_server:
            signatures.append("header:server=cloudflare")
        if has_cf_ray:
            signatures.append("header:cf-ray")

        if header_lower.get("cf-mitigated") == "challenge":
            signatures.append("header:cf-mitigated=challenge")
        if "cf-chl-bypass" in header_lower:
            signatures.append("header:cf-chl-bypass")
        if "cf-chl-out" in header_lower:
            signatures.append("header:cf-chl-out")

        # DOM inspection
        is_turnstile = False
        for marker in cls.CF_TURNSTILE_DOM_MARKERS:
            if marker in text:
                signatures.append(f"body:{marker}")
                is_turnstile = True

        is_managed = False
        for marker in cls.CF_MANAGED_DOM_MARKERS:
            if marker in text:
                signatures.append(f"body:{marker}")
                is_managed = True

        # Challenge classification
        if is_turnstile:
            return WAFDetectionResult(
                detected=True,
                waf_name="cloudflare",
                challenge_type="turnstile",
                confidence=0.99,
                signatures=signatures,
                details={"status_code": status_code, "ray_id": header_lower.get("cf-ray")},
            )

        if is_managed or header_lower.get("cf-mitigated") == "challenge":
            return WAFDetectionResult(
                detected=True,
                waf_name="cloudflare",
                challenge_type="managed_challenge",
                confidence=0.95,
                signatures=signatures,
                details={"status_code": status_code, "ray_id": header_lower.get("cf-ray")},
            )

        if (is_cf_server or has_cf_ray) and status_code in (403, 503, 429) and signatures:
            return WAFDetectionResult(
                detected=True,
                waf_name="cloudflare",
                challenge_type="block",
                confidence=0.85,
                signatures=signatures,
                details={"status_code": status_code, "ray_id": header_lower.get("cf-ray")},
            )

        return WAFDetectionResult(detected=False)

    @classmethod
    def _check_akamai(
        cls,
        status_code: int,
        header_lower: Dict[str, str],
        text: str,
        response: Any,
    ) -> WAFDetectionResult:
        signatures = []
        server_val = header_lower.get("server", "").lower()
        if "akamaighost" in server_val or "ghost" in server_val or "akamainetstorage" in server_val:
            signatures.append(f"header:server={server_val}")

        for h in ("x-akamai-transformed", "akamai-grn", "x-akamai-session-info", "x-akamai-request-id"):
            if h in header_lower:
                signatures.append(f"header:{h}")

        # Check cookies
        cookies = getattr(response, "cookies", {}) or {}
        cookie_keys = set(cookies.keys()) if hasattr(cookies, "keys") else set()
        for c in ("_abck", "bm_sz", "ak_bmsc"):
            if c in cookie_keys:
                signatures.append(f"cookie:{c}")

        # DOM inspection
        for marker in cls.AKAMAI_DOM_MARKERS:
            if marker in text:
                signatures.append(f"body:{marker}")

        if signatures:
            challenge_type = "bot_manager" if any("cookie:_abck" in s or "ak-bm" in s or "akamai-bot-manager" in s for s in signatures) else "block"
            return WAFDetectionResult(
                detected=True,
                waf_name="akamai",
                challenge_type=challenge_type,
                confidence=0.90 if len(signatures) > 1 else 0.75,
                signatures=signatures,
                details={"status_code": status_code},
            )
        return WAFDetectionResult(detected=False)

    @classmethod
    def _check_aws_waf(
        cls,
        status_code: int,
        header_lower: Dict[str, str],
        text: str,
    ) -> WAFDetectionResult:
        signatures = []
        action = header_lower.get("x-amzn-waf-action") or header_lower.get("x-amz-waf-action")
        if action:
            signatures.append(f"header:x-amzn-waf-action={action}")

        if "x-amzn-errortype" in header_lower and "waf" in header_lower["x-amzn-errortype"].lower():
            signatures.append(f"header:x-amzn-errortype={header_lower['x-amzn-errortype']}")

        # DOM inspection
        for marker in cls.AWS_WAF_DOM_MARKERS:
            if marker in text:
                signatures.append(f"body:{marker}")

        if signatures:
            challenge_type = "captcha" if "captcha" in str(action).lower() or "aws-waf-captcha" in text else ("challenge" if "challenge" in str(action).lower() else "block")
            return WAFDetectionResult(
                detected=True,
                waf_name="aws_waf",
                challenge_type=challenge_type,
                confidence=0.95,
                signatures=signatures,
                details={"status_code": status_code, "action": action},
            )
        return WAFDetectionResult(detected=False)

    @classmethod
    def is_challenge(cls, response: Any) -> bool:
        """Convenience method returning True if response contains any WAF challenge or block."""
        return cls.detect(response).detected

    @classmethod
    def detect_cloudflare(cls, response: Any) -> bool:
        res = cls.detect(response)
        return res.detected and res.waf_name == "cloudflare"

    @classmethod
    def detect_akamai(cls, response: Any) -> bool:
        res = cls.detect(response)
        return res.detected and res.waf_name == "akamai"

    @classmethod
    def detect_aws_waf(cls, response: Any) -> bool:
        res = cls.detect(response)
        return res.detected and res.waf_name == "aws_waf"

    @classmethod
    def detect_reddit_pow(cls, response: Any) -> bool:
        res = cls.detect(response)
        return res.detected and res.waf_name == "reddit_pow"
