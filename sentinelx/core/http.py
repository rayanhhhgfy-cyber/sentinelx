"""SentinelX core: async HTTP client with per-host token-bucket rate limiting,
exponential backoff with jitter, timeouts, and redirect control."""

from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlsplit, urlencode

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
    max_pages: int = 50  # crawler page limit
    smart: bool = True  # smart mode: tech-tuned payloads, priority queue, correlation
    no_wordlist: bool = True  # DEFAULT: pure dynamic discovery; wordlists only via --wordlist
    unsafe: bool = False  # --unsafe: skip TLS cert verification (labs with self-signed certs)
    tech_stack: set = field(default_factory=set)  # populated by techfp: {"PHP", "Flask", ...}
    # web-UI extensions (all optional, safe defaults)
    custom_headers: dict = field(default_factory=dict)
    custom_cookies: dict = field(default_factory=dict)
    exclude_paths: list = field(default_factory=list)
    pause_event: Optional["asyncio.Event"] = None
    stats: Optional[dict] = None  # filled by engine: {"modules": {name: requests}}


class TokenBucket:
    """Per-host adaptive token bucket rate limiter.

    Starts fast (2x configured rate) and backs off on 429/timeouts,
    recovering gradually on success. This replaces fixed sleeps with
    congestion-aware pacing.
    """

    def __init__(self, rate_per_sec: float):
        self.base_rate = max(rate_per_sec, 0.1)
        self.rate = min(self.base_rate * 2.0, 100.0)  # start fast
        self.tokens = self.rate
        self.updated = time.monotonic()
        self.lock = asyncio.Lock()
        self._consec_ok = 0

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

    def backoff(self):
        """Called on 429/timeout: cut rate aggressively."""
        self.rate = max(self.base_rate * 0.25, 0.5)
        self.tokens = min(self.tokens, self.rate)
        self._consec_ok = 0

    def success(self):
        """Called on clean response: recover toward fast rate."""
        self._consec_ok += 1
        if self._consec_ok >= 20:
            self._consec_ok = 0
            self.rate = min(self.rate * 1.5, self.base_rate * 2.0, 100.0)


class ScanClient:
    """Async HTTP client: rate limited, retried, timeout-guarded."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.buckets: dict[str, TokenBucket] = {}
        self.sem = asyncio.Semaphore(config.concurrency)
        self._client: Optional[httpx.AsyncClient] = None
        self.requests_made = 0
        # request dedup: (method, normalized_url) -> (response_data, timestamp)
        # only for idempotent safe requests (GET without side effects)
        self._dedup_cache: dict[str, tuple] = {}
        self._dedup_ttl = 120.0
        self._dedup_lock = asyncio.Lock()

    async def __aenter__(self):
        headers = {"User-Agent": self.config.user_agent}
        for k, v in (self.config.custom_headers or {}).items():
            headers[str(k)] = str(v)
        # --auth-a bearer token applies to ALL requests (auth-walled scanning);
        # idor.py uses auth_a vs auth_b for cross-session differential tests
        if self.config.auth_a and "Authorization" not in headers:
            headers["Authorization"] = f"Bearer {self.config.auth_a}"
        # Tuned connection pool: keep-alive reuse, bounded connections.
        # DNS is cached by httpx's connection pool via keep-alive reuse.
        limits = httpx.Limits(
            max_connections=max(self.config.concurrency * 2, 50),
            max_keepalive_connections=max(self.config.concurrency, 30),
            keepalive_expiry=30.0,
        )
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(
                self.config.timeout,      # default
                connect=5.0,              # fast fail on dead hosts
                read=self.config.timeout, # allow slow responses
                write=10.0,
                pool=5.0,
            ),
            follow_redirects=False,
            max_redirects=self.config.max_redirects,
            headers=headers,
            cookies=self.config.custom_cookies or None,
            verify=not self.config.unsafe,
            trust_env=False,
            limits=limits,
            http2=False,  # h2 adds handshake overhead; h1 keep-alive is faster for scanning
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
        dedupe: bool = True,
    ) -> httpx.Response | None:
        """Send one request with rate limiting + retry. Returns None on hard failure.

        dedupe=True (default): identical idempotent GETs within TTL return the
        cached response instead of hitting the network. Pass dedupe=False for
        timing-sensitive probes that need fresh measurements.
        """
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
        bucket = self._bucket(url)
        await bucket.acquire()

        # request dedup: only for safe idempotent GETs with no body
        dedup_key = None
        if dedupe and method == "GET" and data is None and json_data is None:
            dedup_key = f"GET|{url}|{urlencode(sorted((params or {}).items())) if params else ''}"
            async with self._dedup_lock:
                hit = self._dedup_cache.get(dedup_key)
                if hit and (time.monotonic() - hit[1]) < self._dedup_ttl:
                    return hit[0]

        last_exc = None
        for attempt in range(self.config.max_retries + 1):
            try:
                async with self.sem:
                    self.requests_made += 1
                    resp = await self._client.request(
                        method, url, params=params, content=data,
                        json=json_data, headers=headers, cookies=cookies,
                    )
                if resp.status_code in (429, 503):
                    bucket.backoff()
                    if attempt < self.config.max_retries:
                        backoff = (2 ** attempt) + random.uniform(0, 1)
                        await asyncio.sleep(min(backoff, 10))
                        continue
                else:
                    bucket.success()
                if dedup_key:
                    async with self._dedup_lock:
                        # bound cache size to avoid memory growth
                        if len(self._dedup_cache) > 2000:
                            self._dedup_cache.clear()
                        self._dedup_cache[dedup_key] = (resp, time.monotonic())
                return resp
            except (httpx.TimeoutException, httpx.ConnectError,
                    httpx.ReadError, httpx.RemoteProtocolError) as e:
                last_exc = e
                bucket.backoff()
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
