"""SentinelX jsenv: fast static JavaScript analysis (no execution).

Complementary to mock execution: runs on every JS file (cheap), while
execution is reserved for high-value SPA pages. Extracts:

- API endpoints: fetch()/axios/XHR URLs, including template literals
- client-side routes: router definitions, pushState targets
- WebSocket / SSE URLs
- GraphQL queries (operation names + endpoints)
- hardcoded secrets/tokens in JS (API keys, tokens)
- DOM XSS sink/source patterns (for prioritization, not findings)
"""

from __future__ import annotations

import re
from urllib.parse import urljoin


# ---------------------------------------------------------------------------
# API endpoint extraction
# ---------------------------------------------------------------------------
# fetch("...") / fetch(`...`) / axios.get("...") / $.ajax({url: "..."})
_FETCH_RE = re.compile(
    r"""(?:fetch|axios\.(?:get|post|put|delete|patch|request)|\$\.(?:ajax|get|post))\s*\(\s*"""
    r"""(?:(?P<q1>['"])(?P<u1>.*?)(?P=q1)|(?P<q2>`)(?P<u2>.*?)(?P=q2))""",
    re.S,
)

_XHR_OPEN_RE = re.compile(
    r"""\.open\s*\(\s*['"](?P<m>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)['"]\s*,\s*"""
    r"""['"](?P<u>[^'"]+)['"]""",
    re.I,
)

# url: "/api/..." inside object literals (ajax configs, etc.)
_URL_PROP_RE = re.compile(
    r"""\burl\s*:\s*['"](?P<u>/[A-Za-z0-9_\-./?=&%#]+)['"]"""
)

_WS_RE = re.compile(
    r"""new\s+WebSocket\s*\(\s*['"](?P<u>[^'"]+)['"]"""
)

_SSE_RE = re.compile(
    r"""new\s+EventSource\s*\(\s*['"](?P<u>[^'"]+)['"]"""
)


def _clean_url(u: str, base_url: str) -> str | None:
    u = u.strip()
    # drop template placeholders for discovery (keep the path shape)
    u = re.sub(r"\$\{[^}]*\}", "1", u)
    u = u.split("#")[0]
    if not u or u.startswith(("javascript:", "data:", "mailto:", "tel:")):
        return None
    if u.startswith(("http://", "https://", "/", "./", "../")):
        try:
            return urljoin(base_url, u)
        except Exception:
            return None
    return None


def extract_api_calls(js_text: str, base_url: str) -> list[dict]:
    """Static extraction of network calls. Returns [{method, url, source}]."""
    out = []
    seen = set()
    for m in _FETCH_RE.finditer(js_text):
        u = m.group("u1") or m.group("u2") or ""
        # crude method guess for axios.*
        method = "GET"
        prefix = js_text[max(0, m.start() - 30):m.start()]
        am = re.search(r"axios\.(get|post|put|delete|patch)", prefix)
        if am:
            method = am.group(1).upper()
        cu = _clean_url(u, base_url)
        if cu and (method, cu) not in seen:
            seen.add((method, cu))
            out.append({"method": method, "url": cu, "source": "static-fetch"})
    for m in _XHR_OPEN_RE.finditer(js_text):
        cu = _clean_url(m.group("u"), base_url)
        if cu and (m.group("m").upper(), cu) not in seen:
            seen.add((m.group("m").upper(), cu))
            out.append({"method": m.group("m").upper(), "url": cu, "source": "static-xhr"})
    for m in _URL_PROP_RE.finditer(js_text):
        cu = _clean_url(m.group("u"), base_url)
        if cu and ("GET", cu) not in seen:
            seen.add(("GET", cu))
            out.append({"method": "GET", "url": cu, "source": "static-urlprop"})
    for m in _WS_RE.finditer(js_text):
        cu = _clean_url(m.group("u"), base_url)
        if cu and ("WS", cu) not in seen:
            seen.add(("WS", cu))
            out.append({"method": "WS", "url": cu, "source": "static-ws"})
    for m in _SSE_RE.finditer(js_text):
        cu = _clean_url(m.group("u"), base_url)
        if cu and ("SSE", cu) not in seen:
            seen.add(("SSE", cu))
            out.append({"method": "SSE", "url": cu, "source": "static-sse"})
    return out


# ---------------------------------------------------------------------------
# Route extraction
# ---------------------------------------------------------------------------
_ROUTE_RES = [
    re.compile(r"""path\s*:\s*['"](?P<r>/[A-Za-z0-9_\-/{}:]+)['"]"""),
    re.compile(r"""pushState\s*\([^,]+,[^,]+,\s*['"](?P<r>/[^'"]+)['"]"""),
    re.compile(r"""router\.push\s*\(\s*['"](?P<r>/[^'"]+)['"]"""),
    re.compile(r"""to\s*:\s*['"](?P<r>/[A-Za-z0-9_\-/]+)['"]"""),  # vue-router <router-link>
]


def extract_routes(js_text: str) -> list[str]:
    routes = []
    seen = set()
    for rx in _ROUTE_RES:
        for m in rx.finditer(js_text):
            r = m.group("r")
            r = re.sub(r"[:{][A-Za-z0-9_}]+", "1", r)  # :id -> 1
            if r not in seen:
                seen.add(r)
                routes.append(r)
    return routes


# ---------------------------------------------------------------------------
# GraphQL
# ---------------------------------------------------------------------------
_GQL_RE = re.compile(
    r"""\b(?:query|mutation)\s+(?P<name>[A-Za-z0-9_]+)""",
)


def extract_graphql(js_text: str, base_url: str) -> list[dict]:
    out = []
    for m in _GQL_RE.finditer(js_text):
        out.append({"operation": m.group("name")})
    return out


# ---------------------------------------------------------------------------
# Secrets in JS
# ---------------------------------------------------------------------------
_SECRET_RES = [
    (re.compile(r"""(?i)(?:api[_-]?key|apikey)\s*[:=]\s*['"](?P<s>[A-Za-z0-9_\-]{16,})['"]"""), "api-key"),
    (re.compile(r"""(?i)(?:secret|client_secret)\s*[:=]\s*['"](?P<s>[A-Za-z0-9_\-]{16,})['"]"""), "secret"),
    (re.compile(r"""(?i)bearer\s+['"]?(?P<s>[A-Za-z0-9_\-.]{20,})['"]?"""), "bearer-token"),
    (re.compile(r"""(?i)(?:token)\s*[:=]\s*['"](?P<s>[A-Za-z0-9_\-]{20,})['"]"""), "token"),
]


def extract_secrets(js_text: str) -> list[dict]:
    out = []
    seen = set()
    for rx, kind in _SECRET_RES:
        for m in rx.finditer(js_text):
            s = m.group("s")
            if s not in seen and "example" not in s.lower():
                seen.add(s)
                out.append({"kind": kind, "value": s[:60]})
    return out


# ---------------------------------------------------------------------------
# Sink/source pattern scan (prioritization only — NOT findings)
# ---------------------------------------------------------------------------
_SINK_RES = [
    (re.compile(r"""\.innerHTML\s*="""), "innerHTML"),
    (re.compile(r"""\.outerHTML\s*="""), "outerHTML"),
    (re.compile(r"""document\.write\s*\("""), "document.write"),
    (re.compile(r"""\beval\s*\("""), "eval"),
    (re.compile(r"""new\s+Function\s*\("""), "Function"),
    (re.compile(r"""setTimeout\s*\(\s*['"]"""), "setTimeout(string)"),
    (re.compile(r"""setInterval\s*\(\s*['"]"""), "setInterval(string)"),
]
_SOURCE_RES = [
    (re.compile(r"""location\.hash"""), "location.hash"),
    (re.compile(r"""location\.search"""), "location.search"),
    (re.compile(r"""document\.URL"""), "document.URL"),
    (re.compile(r"""document\.referrer"""), "document.referrer"),
]


def score_js_interest(js_text: str) -> tuple[int, list[str], list[str]]:
    """Return (score, sinks_found, sources_found). Higher = more worth executing."""
    sinks = sorted({name for rx, name in _SINK_RES if rx.search(js_text)})
    sources = sorted({name for rx, name in _SOURCE_RES if rx.search(js_text)})
    score = len(sinks) * 10 + len(sources) * 5
    if re.search(r"fetch\s*\(", js_text):
        score += 3
    return score, sinks, sources


def analyze_js(js_text: str, base_url: str) -> dict:
    """One-shot static analysis. Cheap — run on every script."""
    score, sinks, sources = score_js_interest(js_text)
    return {
        "api_calls": extract_api_calls(js_text, base_url),
        "routes": extract_routes(js_text),
        "graphql": extract_graphql(js_text, base_url),
        "secrets": extract_secrets(js_text),
        "sinks": sinks,
        "sources": sources,
        "interest_score": score,
    }
