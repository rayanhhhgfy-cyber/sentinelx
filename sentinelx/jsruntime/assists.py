"""SentinelX jsruntime.assists: runtime evidence helpers for all modules.

Any vulnerability module can call ``analyze(url, html)`` to get a cached
JS execution analysis of a page: API endpoints the page's JS calls, taint
flows proven at runtime, sinks hit, storage access. This layers runtime
evidence onto existing detectors WITHOUT changing their core logic.

Usage inside a module (append findings, don't replace existing logic):

    from sentinelx.jsruntime import assists
    runtime = await assists.analyze_page(client, config, url, html)
    if runtime:
        for ep in runtime.api_endpoints:
            ...  # e.g. SSRF: does page JS fetch internal URLs?

The analysis is cached per URL for the process lifetime (bounded size),
so multiple modules analyzing the same page share one execution.
"""

from __future__ import annotations

import time
from collections import OrderedDict
from html.parser import HTMLParser

from sentinelx.jsruntime import execute, instrument, taint as taint_mod


_CACHE: OrderedDict = OrderedDict()
_CACHE_MAX = 64


class _ScriptExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.scripts: list[str] = []
        self._buf: list[str] | None = None

    def handle_starttag(self, tag, attrs):
        if tag == "script" and not dict(attrs).get("src"):
            self._buf = []

    def handle_endtag(self, tag):
        if tag == "script" and self._buf is not None:
            body = "".join(self._buf).strip()
            if body:
                self.scripts.append(body)
            self._buf = None

    def handle_data(self, data):
        if self._buf is not None:
            self._buf.append(data)


def extract_scripts(html: str) -> list[str]:
    p = _ScriptExtractor()
    try:
        p.feed(html)
    except Exception:
        pass
    return p.scripts


class PageRuntime:
    """Cached runtime analysis of one page's JavaScript."""

    def __init__(self, url: str, summary, flows: list,
                 trace: list, executed: bool):
        self.url = url
        self.summary = summary          # instrument.ExecutionSummary
        self.flows = flows              # list[taint.TaintFlow]
        self.trace = trace
        self.executed = executed

    @property
    def api_endpoints(self) -> list[dict]:
        return self.summary.api_endpoints if self.summary else []

    def fetches_url_pattern(self, pattern: str) -> list[dict]:
        """API endpoints whose URL matches a regex pattern."""
        import re
        rx = re.compile(pattern, re.I)
        return [e for e in self.api_endpoints if rx.search(e.get("url", ""))]

    def has_flow_to_sink(self, sink_prefix: str) -> list:
        return [f for f in self.flows if f.sink.startswith(sink_prefix)]


def analyze_html(url: str, html: str, timeout: float = 8.0) -> PageRuntime | None:
    """Analyze page HTML's JS (cached). Returns None if nothing to run."""
    key = url
    if key in _CACHE:
        _CACHE.move_to_end(key)
        return _CACHE[key]

    scripts = extract_scripts(html)
    # only execute scripts with security-relevant content (cheap gate)
    interesting = [s for s in scripts
                   if len(s) < 60000 and
                   any(k in s for k in (
                       "fetch(", "XMLHttpRequest", "innerHTML", "eval(",
                       "location.", "document.write", "WebSocket",
                       "localStorage", "sessionStorage", ".href", ".src"))]
    if not interesting:
        return None

    tracker = taint_mod.TaintTracker()
    hash_mark = tracker.new_mark(taint_mod.Source.FRAGMENT, "location.hash")
    search_mark = tracker.new_mark(taint_mod.Source.QUERY, "location.search")

    result = execute(
        "\n;\n".join(interesting[:6]), page_url=url,
        hash_canary=hash_mark.canary, search_canary=search_mark.canary,
        timeout=timeout,
    )
    summary = instrument.summarize(result, url)
    flows = tracker.flows_from_trace(result.trace)
    pr = PageRuntime(url, summary, flows, result.trace, result.executed)

    _CACHE[key] = pr
    while len(_CACHE) > _CACHE_MAX:
        _CACHE.popitem(last=False)
    return pr


async def analyze_page(client, config, url: str,
                       timeout: float = 8.0) -> PageRuntime | None:
    """Fetch a page and return its cached runtime analysis. Never raises."""
    if url in _CACHE:
        _CACHE.move_to_end(url)
        return _CACHE[url]
    try:
        resp = await client.get(url, headers={"User-Agent": config.user_agent})
        if not resp:
            return None
        ctype = resp.headers.get("content-type", "")
        if "html" not in ctype and "<script" not in resp.text[:20000].lower():
            return None
        return analyze_html(url, resp.text, timeout=timeout)
    except Exception:
        return None


def clear_cache() -> None:
    _CACHE.clear()
