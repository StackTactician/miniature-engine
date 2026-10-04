"""
Stealth networking client and response wrappers.
Compulsory use of curl_cffi.requests.AsyncSession for real network requests with Chrome 120 impersonation.
Transparently falls back to httpx.AsyncClient when mock_transport or transport is supplied
to ensure 100% in-memory test compatibility.
"""

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Union

import httpx
from curl_cffi.requests import AsyncSession


class HTTPStatusError(httpx.HTTPStatusError):
    """Raised when an HTTP response returns an error status (4xx or 5xx)."""

    def __init__(
        self,
        message: str,
        status_code: int = 0,
        response: Any = None,
        request: Any = None,
    ):
        self.status_code = status_code
        self.response = response
        self.request = request
        httpx.HTTPError.__init__(self, message)


class CaseInsensitiveDict(dict):
    """A dictionary with case-insensitive key lookup preserving original case."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__()
        self._lower_map: Dict[str, str] = {}
        if args or kwargs:
            self.update(dict(*args, **kwargs))

    def __setitem__(self, key: str, value: Any) -> None:
        lower_key = str(key).lower()
        if lower_key in self._lower_map:
            super().__delitem__(self._lower_map[lower_key])
        self._lower_map[lower_key] = str(key)
        super().__setitem__(str(key), value)

    def __getitem__(self, key: str) -> Any:
        lower_key = str(key).lower()
        if lower_key in self._lower_map:
            return super().__getitem__(self._lower_map[lower_key])
        return super().__getitem__(key)

    def __delitem__(self, key: str) -> None:
        lower_key = str(key).lower()
        if lower_key in self._lower_map:
            actual_key = self._lower_map.pop(lower_key)
            super().__delitem__(actual_key)
        else:
            super().__delitem__(key)

    def __contains__(self, key: object) -> bool:
        return str(key).lower() in self._lower_map

    def get(self, key: str, default: Any = None) -> Any:
        lower_key = str(key).lower()
        if lower_key in self._lower_map:
            return super().__getitem__(self._lower_map[lower_key])
        return default

    def update(self, *args: Any, **kwargs: Any) -> None:
        for k, v in dict(*args, **kwargs).items():
            self[k] = v

    def copy(self) -> "CaseInsensitiveDict":
        return CaseInsensitiveDict(self)


DEFAULT_CHROME_120_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)


@dataclass
class BrowserProfile:
    """
    Browser impersonation profile matching modern desktop Google Chrome 120 on Windows.
    Provides standard Sec-Ch-Ua, Sec-Fetch-*, and Accept headers.
    """

    user_agent: str = DEFAULT_CHROME_120_USER_AGENT
    sec_ch_ua: str = '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"'
    sec_ch_ua_mobile: str = "?0"
    sec_ch_ua_platform: str = '"Windows"'
    accept_language: str = "en-US,en;q=0.9"
    accept_encoding: str = "gzip, deflate, br, zstd"
    accept: str = (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,image/apng,*/*;q=0.8,"
        "application/signed-exchange;v=b3;q=0.7"
    )
    sec_fetch_dest: str = "document"
    sec_fetch_mode: str = "navigate"
    sec_fetch_site: str = "none"
    sec_fetch_user: str = "?1"
    upgrade_insecure_requests: str = "1"
    headers: Dict[str, str] = field(default_factory=dict)
    impersonate: str = "chrome120"

    def __post_init__(self) -> None:
        base = {
            "User-Agent": self.user_agent,
            "Accept": self.accept,
            "Accept-Language": self.accept_language,
            "Accept-Encoding": self.accept_encoding,
            "Sec-Ch-Ua": self.sec_ch_ua,
            "Sec-Ch-Ua-Mobile": self.sec_ch_ua_mobile,
            "Sec-Ch-Ua-Platform": self.sec_ch_ua_platform,
            "Sec-Fetch-Dest": self.sec_fetch_dest,
            "Sec-Fetch-Mode": self.sec_fetch_mode,
            "Sec-Fetch-Site": self.sec_fetch_site,
            "Sec-Fetch-User": self.sec_fetch_user,
            "Upgrade-Insecure-Requests": self.upgrade_insecure_requests,
        }
        if self.headers:
            base.update(self.headers)
        self.headers = base

    def get_headers(self) -> Dict[str, str]:
        return dict(self.headers)

    def to_headers(self) -> Dict[str, str]:
        return dict(self.headers)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "user_agent": self.user_agent,
            "sec_ch_ua": self.sec_ch_ua,
            "sec_ch_ua_mobile": self.sec_ch_ua_mobile,
            "sec_ch_ua_platform": self.sec_ch_ua_platform,
            "accept_language": self.accept_language,
            "accept_encoding": self.accept_encoding,
            "accept": self.accept,
            "sec_fetch_dest": self.sec_fetch_dest,
            "sec_fetch_mode": self.sec_fetch_mode,
            "sec_fetch_site": self.sec_fetch_site,
            "sec_fetch_user": self.sec_fetch_user,
            "upgrade_insecure_requests": self.upgrade_insecure_requests,
            "headers": self.get_headers(),
            "impersonate": self.impersonate,
        }

    @classmethod
    def chrome_120(cls, **kwargs: Any) -> "BrowserProfile":
        return cls(**kwargs)

    @classmethod
    def default(cls, **kwargs: Any) -> "BrowserProfile":
        return cls(**kwargs)


@dataclass
class StealthResponse:
    """
    Uniform response wrapper returned by StealthAsyncClient.
    Provides status_code, headers, content, text, url, cookies, .json(), and .raise_for_status().
    """

    status_code: int
    headers: Dict[str, str] = field(default_factory=dict)
    content: bytes = b""
    text: str = ""
    url: str = ""
    cookies: Dict[str, str] = field(default_factory=dict)
    raw_response: Optional[Any] = None

    def __post_init__(self) -> None:
        if not isinstance(self.headers, CaseInsensitiveDict):
            self.headers = CaseInsensitiveDict(self.headers)
        if not self.text and self.content:
            try:
                self.text = self.content.decode("utf-8", errors="replace")
            except Exception:
                self.text = ""
        elif not self.content and self.text:
            self.content = self.text.encode("utf-8")

    def json(self, **kwargs: Any) -> Any:
        raw = self.text
        if not raw and self.content:
            raw = self.content.decode("utf-8", errors="replace")
        if not raw:
            raise ValueError("Response body is empty, cannot parse JSON")
        return json.loads(raw, **kwargs)

    def raise_for_status(self) -> "StealthResponse":
        if 400 <= self.status_code < 600:
            msg = f"HTTP {self.status_code} Error for url: {self.url}"
            raise HTTPStatusError(msg, status_code=self.status_code, response=self)
        return self

    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300

    @property
    def is_error(self) -> bool:
        return 400 <= self.status_code < 600

    @property
    def is_client_error(self) -> bool:
        return 400 <= self.status_code < 500

    @property
    def is_server_error(self) -> bool:
        return 500 <= self.status_code < 600

    @property
    def is_redirect(self) -> bool:
        return 300 <= self.status_code < 400

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status_code": self.status_code,
            "url": self.url,
            "headers": dict(self.headers),
            "cookies": dict(self.cookies),
            "text": self.text,
        }

    @classmethod
    def from_httpx(cls, resp: httpx.Response) -> "StealthResponse":
        cookie_dict = dict(resp.cookies)
        return cls(
            status_code=resp.status_code,
            headers=CaseInsensitiveDict(dict(resp.headers)),
            content=resp.content,
            text=resp.text,
            url=str(resp.url),
            cookies=cookie_dict,
            raw_response=resp,
        )

    @classmethod
    def from_curl(cls, resp: Any) -> "StealthResponse":
        cookie_dict = {}
        if hasattr(resp, "cookies"):
            if hasattr(resp.cookies, "get_dict"):
                cookie_dict = dict(resp.cookies.get_dict())
            elif hasattr(resp.cookies, "items"):
                cookie_dict = dict(resp.cookies.items())
            elif isinstance(resp.cookies, dict):
                cookie_dict = dict(resp.cookies)

        text_val = resp.text if hasattr(resp, "text") else resp.content.decode("utf-8", errors="replace")
        return cls(
            status_code=resp.status_code,
            headers=CaseInsensitiveDict(dict(resp.headers)),
            content=resp.content,
            text=text_val,
            url=str(resp.url),
            cookies=cookie_dict,
            raw_response=resp,
        )


class OpenAwaitable:
    """Helper enabling both `await client.open()` and synchronous `client.open()` chaining."""

    def __init__(self, client: "StealthAsyncClient") -> None:
        self._client = client

    def __await__(self) -> Any:
        async def _resolve() -> "StealthAsyncClient":
            return self._client

        return _resolve().__await__()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)


class StealthAsyncClient:
    """
    Stealth asynchronous HTTP client built on curl_cffi with full browser impersonation,
    integrated WAF detection, and transparent httpx test-mock transport compatibility.
    """

    def __init__(
        self,
        browser_profile: Optional[BrowserProfile] = None,
        profile: Optional[BrowserProfile] = None,
        impersonate: Optional[str] = None,
        timeout: Union[float, int, httpx.Timeout] = 30.0,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        transport: Optional[Any] = None,
        mock_transport: Optional[Any] = None,
        mock_client: Optional[httpx.AsyncClient] = None,
        client: Optional[httpx.AsyncClient] = None,
        follow_redirects: bool = True,
        verify: bool = True,
        base_url: str = "",
        proxies: Optional[Any] = None,
        proxy: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        self.browser_profile = browser_profile or profile or BrowserProfile()
        self.impersonate = impersonate or self.browser_profile.impersonate
        self.base_url = str(base_url or "")
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.verify = verify
        self.proxies = proxies or proxy
        self.cookies: Dict[str, str] = dict(cookies or {})

        # Default headers merged with custom headers
        self.headers: CaseInsensitiveDict = CaseInsensitiveDict(self.browser_profile.get_headers())
        if headers:
            self.headers.update(headers)

        self._is_closed = False
        self._mock_client: Optional[httpx.AsyncClient] = None
        self._curl_session: Optional[AsyncSession] = None

        effective_transport = mock_transport or transport
        provided_client = mock_client or client

        if provided_client is not None:
            self._is_mock = True
            self._mock_client = provided_client
            if hasattr(self._mock_client, "cookies"):
                for k, v in self._mock_client.cookies.items():
                    self.cookies[k] = v
        elif effective_transport is not None:
            self._is_mock = True
            self._mock_client = httpx.AsyncClient(
                transport=effective_transport,
                timeout=timeout,
                follow_redirects=follow_redirects,
                verify=verify,
                base_url=self.base_url,
                headers=dict(self.headers),
                cookies=self.cookies,
            )
        else:
            self._is_mock = False
            if isinstance(timeout, httpx.Timeout):
                t_val = timeout.connect or timeout.read or 30.0
            else:
                t_val = float(timeout)

            self._curl_session = AsyncSession(
                impersonate=self.impersonate,
                headers=dict(self.headers),
                cookies=self.cookies,
                timeout=t_val,
                verify=self.verify,
                allow_redirects=self.follow_redirects,
                proxies=self.proxies,
                **kwargs,
            )

    @property
    def is_mock(self) -> bool:
        return self._is_mock

    @property
    def is_closed(self) -> bool:
        return self._is_closed

    @property
    def transport(self) -> Any:
        if self._is_mock and self._mock_client is not None:
            return getattr(self._mock_client, "_transport", None)
        return None

    @property
    def _transport(self) -> Any:
        return self.transport

    def open(self) -> OpenAwaitable:
        self._is_closed = False
        return OpenAwaitable(self)

    async def aclose(self) -> None:
        if self._is_closed:
            return
        self._is_closed = True
        if self._is_mock and self._mock_client:
            await self._mock_client.aclose()
        elif not self._is_mock and self._curl_session:
            try:
                await self._curl_session.close()
            except Exception:
                pass

    async def close(self) -> None:
        await self.aclose()

    async def __aenter__(self) -> "StealthAsyncClient":
        await self.open()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.aclose()

    def _build_url(self, url: str) -> str:
        if self.base_url and not url.startswith(("http://", "https://")):
            return f"{self.base_url.rstrip('/')}/{url.lstrip('/')}"
        return url

    async def request(
        self,
        method: str,
        url: str,
        *,
        params: Optional[Any] = None,
        data: Optional[Any] = None,
        json: Optional[Any] = None,
        content: Optional[Union[bytes, str]] = None,
        headers: Optional[Mapping[str, str]] = None,
        cookies: Optional[Mapping[str, str]] = None,
        timeout: Optional[Union[float, int, httpx.Timeout]] = None,
        follow_redirects: Optional[bool] = None,
        allow_redirects: Optional[bool] = None,
        auth: Optional[Any] = None,
        **kwargs: Any,
    ) -> StealthResponse:
        """
        Send an HTTP request asynchronously and return a StealthResponse.
        """
        full_url = self._build_url(url)

        # Merge headers
        req_headers = dict(self.headers)
        if headers:
            req_headers.update(headers)

        # Merge cookies
        req_cookies = dict(self.cookies)
        if cookies:
            req_cookies.update(cookies)

        redirs = (
            follow_redirects
            if follow_redirects is not None
            else (allow_redirects if allow_redirects is not None else self.follow_redirects)
        )

        if self._is_mock and self._mock_client is not None:
            if cookies:
                self._mock_client.cookies.update(cookies)

            httpx_kwargs: Dict[str, Any] = {
                "headers": req_headers,
                "follow_redirects": redirs,
            }
            if params is not None:
                httpx_kwargs["params"] = params
            if data is not None:
                httpx_kwargs["data"] = data
            if json is not None:
                httpx_kwargs["json"] = json
            if content is not None:
                httpx_kwargs["content"] = content
            if timeout is not None:
                httpx_kwargs["timeout"] = timeout
            if auth is not None:
                httpx_kwargs["auth"] = auth

            for k in ("files", "extensions"):
                if k in kwargs:
                    httpx_kwargs[k] = kwargs[k]

            resp = await self._mock_client.request(method, full_url, **httpx_kwargs)

            # Sync cookies from mock_client jar into client cookies dictionary
            if hasattr(self._mock_client, "cookies"):
                if hasattr(self._mock_client.cookies, "jar"):
                    for c in self._mock_client.cookies.jar:
                        self.cookies[c.name] = c.value
                else:
                    try:
                        for k, v in self._mock_client.cookies.items():
                            self.cookies[k] = v
                    except Exception:
                        pass
            elif hasattr(resp, "cookies"):
                for k, v in resp.cookies.items():
                    self.cookies[k] = v

            return StealthResponse.from_httpx(resp)
        else:
            assert self._curl_session is not None, "Curl session is not initialized"
            curl_kwargs: Dict[str, Any] = {
                "headers": req_headers,
                "cookies": req_cookies,
                "allow_redirects": redirs,
            }
            if params is not None:
                curl_kwargs["params"] = params
            if data is not None:
                curl_kwargs["data"] = data
            if json is not None:
                curl_kwargs["json"] = json
            if content is not None:
                curl_kwargs["content"] = content
            if timeout is not None:
                if isinstance(timeout, httpx.Timeout):
                    curl_kwargs["timeout"] = timeout.connect or timeout.read or 30.0
                else:
                    curl_kwargs["timeout"] = float(timeout)
            if auth is not None:
                curl_kwargs["auth"] = auth

            for k, v in kwargs.items():
                if k not in curl_kwargs:
                    curl_kwargs[k] = v

            resp = await self._curl_session.request(method, full_url, **curl_kwargs)

            # Sync cookies
            if hasattr(resp, "cookies"):
                if hasattr(resp.cookies, "get_dict"):
                    self.cookies.update(resp.cookies.get_dict())
                elif hasattr(resp.cookies, "items"):
                    for k, v in resp.cookies.items():
                        self.cookies[k] = v
                elif isinstance(resp.cookies, dict):
                    self.cookies.update(resp.cookies)

            return StealthResponse.from_curl(resp)

    async def get(self, url: str, **kwargs: Any) -> StealthResponse:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> StealthResponse:
        return await self.request("POST", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> StealthResponse:
        return await self.request("HEAD", url, **kwargs)

    async def options(self, url: str, **kwargs: Any) -> StealthResponse:
        return await self.request("OPTIONS", url, **kwargs)

    async def put(self, url: str, **kwargs: Any) -> StealthResponse:
        return await self.request("PUT", url, **kwargs)

    async def patch(self, url: str, **kwargs: Any) -> StealthResponse:
        return await self.request("PATCH", url, **kwargs)

    async def delete(self, url: str, **kwargs: Any) -> StealthResponse:
        return await self.request("DELETE", url, **kwargs)
