"""SentinelX core: async HTTP client with per-host token-bucket rate limiting,
exponential backoff with jitter, timeouts, and redirect control."""

from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlsplit

import httpx


DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)


@dataclass
class ScanConfig:
    target: str
    concurrency: int = 50
    rate_per_sec: float = 10.0
    timeout: float = 15.0
    max_retries: int = 2
    max_redirects: int = 3
    user_agent: str = DEFAULT_UA
    safe_mode: bool = True
    allow_external: bool = False
    ignore_robots: bool = False
    crawl_depth: int = 2
    oob_domain: str = ""
    auth_a: str = ""
    auth_b: str = ""
    modules: list = field(default_factory=list)
    # web-UI extensions (all optional, safe defaults)
    custom_headers: dict = field(default_factory=dict)
    custom_cookies: dict = field(default_factory=dict)
    exclude_paths: list = field(default_factory=list)
    pause_event: Optional["asyncio.Event"] = None
    stats: Optional[dict] = None  # filled by engine: {"modules": {name: requests}}


class TokenBucket:
    """Per-host token bucket rate limiter."""

    def __init__(self, rate_per_sec: float):
        self.rate = max(rate_per_sec, 0.1)
        self.tokens = self.rate
        self.updated = time.monotonic()
        self.lock = asyncio.Lock()

    async def acquire(self):
        async with self.lock:
            now = time.monotonic()
            elapsed = now - self.updated
            self.tokens = min(self.rate, self.tokens + elapsed * self.rate)
            self.updated = now
            if self.tokens < 1.0:
                wait = (1.0 - self.tokens) / self.rate
                await asyncio.sleep(wait)
                self.tokens = 0.0
                self.updated = time.monotonic()
            else:
                self.tokens -= 1.0


class ScanClient:
    """Async HTTP client: rate limited, retried, timeout-guarded."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.buckets: dict[str, TokenBucket] = {}
        self.sem = asyncio.Semaphore(config.concurrency)
        self._client: Optional[httpx.AsyncClient] = None
        self.requests_made = 0

    async def __aenter__(self):
        headers = {"User-Agent": self.config.user_agent}
        for k, v in (self.config.custom_headers or {}).items():
            headers[str(k)] = str(v)
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.config.timeout, connect=10.0),
            follow_redirects=False,
            max_redirects=self.config.max_redirects,
            headers=headers,
            cookies=self.config.custom_cookies or None,
            verify=True,
            trust_env=False,
        )
        return self

    async def __aexit__(self, *exc):
        if self._client:
            await self._client.aclose()

    def _bucket(self, url: str) -> TokenBucket:
        host = urlsplit(url).netloc
        if host not in self.buckets:
            self.buckets[host] = TokenBucket(self.config.rate_per_sec)
        return self.buckets[host]

    async def request(
        self,
        method: str,
        url: str,
        *,
        params: dict | None = None,
        data: dict | bytes | None = None,
        json_data: dict | None = None,
        headers: dict | None = None,
        cookies: dict | None = None,
    ) -> httpx.Response | None:
        """Send one request with rate limiting + retry. Returns None on hard failure."""
        # pause support: park here (non-blocking for the loop) while paused
        if self.config.pause_event is not None:
            await self.config.pause_event.wait()
        # scope exclusions: skip matching paths without sending anything
        if self.config.exclude_paths:
            try:
                _p = urlsplit(url).path or "/"
                for _ex in self.config.exclude_paths:
                    if _ex and _p.startswith(_ex):
                        return None
            except Exception:
                pass
        await self._bucket(url).acquire()
        last_exc = None
        for attempt in range(self.config.max_retries + 1):
            try:
                async with self.sem:
                    self.requests_made += 1
                    resp = await self._client.request(
                        method, url, params=params, content=data,
                        json=json_data, headers=headers, cookies=cookies,
                    )
                if resp.status_code in (429, 503) and attempt < self.config.max_retries:
                    backoff = (2 ** attempt) + random.uniform(0, 1)
                    await asyncio.sleep(min(backoff, 10))
                    continue
                return resp
            except (httpx.TimeoutException, httpx.ConnectError,
                    httpx.ReadError, httpx.RemoteProtocolError) as e:
                last_exc = e
                if attempt < self.config.max_retries:
                    await asyncio.sleep(0.5 * (attempt + 1) + random.uniform(0, 0.5))
                continue
            except Exception as e:  # unexpected: do not retry blindly
                last_exc = e
                break
        return None

    async def get(self, url: str, **kw) -> httpx.Response | None:
        return await self.request("GET", url, **kw)

    async def post(self, url: str, **kw) -> httpx.Response | None:
        return await self.request("POST", url, **kw)
