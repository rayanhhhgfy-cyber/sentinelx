"""SentinelX discovery: async BFS crawler extracting links, forms, params,
JS endpoints; scope-enforced, robots-aware."""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit, parse_qsl, urlencode

from sentinelx.core.http import ScanClient, ScanConfig


@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    params: dict = field(default_factory=dict)   # query/body params with sample values
    source: str = "crawl"                          # crawl | form | js | robots | sitemap

    def key(self) -> str:
        u = urlsplit(self.url)
        base = urlunsplit((u.scheme, u.netloc, u.path.rstrip("/") or "/", "", ""))
        return f"{self.method}|{base}|{','.join(sorted(self.params))}"


class _LinkParser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__()
        self.base = base_url
        self.links: set[str] = set()
        self.forms: list[dict] = []
        self._form = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.add(urljoin(self.base, a["href"]))
        elif tag in ("script", "iframe", "embed") and a.get("src"):
            self.links.add(urljoin(self.base, a["src"]))
        elif tag == "link" and a.get("href"):
            self.links.add(urljoin(self.base, a["href"]))
        elif tag in ("img", "source", "video", "audio") and a.get("src"):
            self.links.add(urljoin(self.base, a["src"]))
        elif tag == "object" and a.get("data"):
            self.links.add(urljoin(self.base, a["data"]))
        elif tag == "form":
            self._form = {
                "action": urljoin(self.base, a.get("action", self.base)),
                "method": (a.get("method") or "GET").upper(),
                "inputs": {},
            }
        elif tag == "input" and self._form is not None:
            name = a.get("name")
            if name:
                self._form["inputs"][name] = a.get("value", "test")
        elif tag == "textarea" and self._form is not None:
            name = a.get("name")
            if name:
                self._form["inputs"][name] = "test"

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


# skip static assets and logout URLs (never useful for vuln scanning)
SKIP_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico",
    ".css", ".js", ".map", ".woff", ".woff2", ".ttf", ".eot",
    ".mp4", ".webm", ".mp3", ".wav", ".pdf", ".zip",
}
SKIP_PATTERNS = [
    re.compile(r"/logout|/signout|/logoff", re.I),
    re.compile(r"\.(jpg|jpeg|png|gif|webp|svg|ico|css|woff2?|ttf|eot|mp4|webm|mp3|wav|pdf|zip)(\?|$)", re.I),
]


def should_skip(url: str) -> bool:
    """Skip static assets and logout URLs."""
    for pat in SKIP_PATTERNS:
        if pat.search(url):
            return True
    return False


# enhanced JS endpoint patterns: fetch(, axios, /api/ paths
JS_ENDPOINT_RE = re.compile(
    r"""(?:"|')((?:/|\./|https?://)[a-zA-Z0-9_\-./?=&%#]+)(?:"|')"""
)
FETCH_RE = re.compile(
    r"""(?:fetch|axios\.(?:get|post|put|delete|patch)|\$\.ajax|open)\s*\(\s*["']([^"']+)["']""",
)
API_PATH_RE = re.compile(
    r"""["']((?:/api/|/v\d+/|/rest/)[a-zA-Z0-9_\-./?=&%{}]+)["']"""
)


def extract_js_endpoints(js_text: str, base_url: str) -> set[str]:
    out = set()
    for m in JS_ENDPOINT_RE.finditer(js_text):
        out.add(urljoin(base_url, m.group(1)))
    for m in FETCH_RE.finditer(js_text):
        out.add(urljoin(base_url, m.group(1)))
    for m in API_PATH_RE.finditer(js_text):
        out.add(urljoin(base_url, m.group(1)))
    # only keep same-origin or path-absolute
    base_host = urlsplit(base_url).netloc
    return {u for u in out if urlsplit(u).netloc in ("", base_host)
            and not should_skip(u)}


def split_params(url: str) -> tuple[str, dict]:
    u = urlsplit(url)
    params = dict(parse_qsl(u.query, keep_blank_values=True))
    clean = urlunsplit((u.scheme, u.netloc, u.path, "", u.fragment))
    return clean, params


class Crawler:
    def __init__(self, client: ScanClient, config: ScanConfig):
        self.client = client
        self.config = config
        self.target_host = urlsplit(config.target).netloc
        self.visited: set[str] = set()
        self.endpoints: dict[str, Endpoint] = {}

    def in_scope(self, url: str) -> bool:
        u = urlsplit(url)
        if u.scheme not in ("http", "https"):
            return False
        if u.netloc == self.target_host:
            return True
        return self.config.allow_external

    def add_endpoint(self, ep: Endpoint):
        if not self.in_scope(ep.url):
            return
        k = ep.key()
        if k not in self.endpoints:
            self.endpoints[k] = ep

    async def fetch_robots(self):
        if self.config.ignore_robots:
            return
        url = f"{urlsplit(self.config.target).scheme}://{self.target_host}/robots.txt"
        resp = await self.client.get(url)
        if resp and resp.status_code == 200:
            for line in resp.text.splitlines():
                m = re.match(r"(?i)disallow:\s*(\S+)", line.strip())
                if m:
                    path = m.group(1)
                    full = urljoin(url, path)
                    clean, params = split_params(full)
                    self.add_endpoint(Endpoint(url=clean, params=params, source="robots"))

    async def crawl_page(self, url: str, depth: int) -> list[str]:
        clean, params = split_params(url)
        if params:
            self.add_endpoint(Endpoint(url=clean, params=params, source="crawl"))
        resp = await self.client.get(url)
        if not resp or resp.status_code >= 400:
            return []
        ctype = resp.headers.get("content-type", "")
        new_links: list[str] = []
        if "javascript" in ctype or url.endswith(".js"):
            for ep_url in extract_js_endpoints(resp.text, url):
                c, p = split_params(ep_url)
                self.add_endpoint(Endpoint(url=c, params=p, source="js"))
            return []
        if "html" not in ctype and "text" not in ctype:
            return []
        parser = _LinkParser(url)
        try:
            parser.feed(resp.text[:500_000])
        except Exception:
            pass
        for link in parser.links:
            if self.in_scope(link):
                new_links.append(link)
        for form in parser.forms:
            c, _ = split_params(form["action"])
            self.add_endpoint(Endpoint(
                url=c, method=form["method"], params=dict(form["inputs"]), source="form",
            ))
        # JS endpoint extraction from inline scripts
        for ep_url in extract_js_endpoints(resp.text, url):
            c, p = split_params(ep_url)
            self.add_endpoint(Endpoint(url=c, params=p, source="js"))
        return new_links

    async def run(self) -> list[Endpoint]:
        max_pages = getattr(self.config, "max_pages", 50)
        await self.fetch_robots()
        queue: list[tuple[str, int]] = [(self.config.target, 0)]
        # concurrent crawling bounded by semaphore (polite but fast)
        sem = asyncio.Semaphore(10)

        async def process(url: str, depth: int) -> list[str]:
            async with sem:
                try:
                    return await self.crawl_page(url, depth)
                except Exception:
                    return []

        while queue and len(self.visited) < max_pages:
            # take a batch of URLs to process concurrently
            batch = []
            while queue and len(batch) < 10 and len(self.visited) + len(batch) < max_pages:
                url, depth = queue.pop(0)
                norm = url.split("#")[0]
                if norm in self.visited or depth > self.config.crawl_depth:
                    continue
                if should_skip(norm):
                    continue
                self.visited.add(norm)
                batch.append((norm, depth))
            if not batch:
                break
            results = await asyncio.gather(*[process(u, d) for u, d in batch])
            for (u, d), links in zip(batch, results):
                if d < self.config.crawl_depth:
                    for link in links:
                        n = link.split("#")[0]
                        if n not in self.visited and not should_skip(n):
                            queue.append((link, d + 1))
        return list(self.endpoints.values())
