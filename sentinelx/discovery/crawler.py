"""SentinelX discovery: elite async crawler.

Capabilities:
- SPA awareness: detects React/Vue/Angular, extracts client-side routes
  (react-router, vue-router) and API base URLs from JS bundles
- Deep form analysis: all input types (hidden/select/file/checkbox/radio),
  select options as values, file-upload flagging, CSRF token extraction+replay,
  login-form detection (reported as auth surfaces)
- API discovery: probes /openapi.json, /swagger.json, /api-docs, /.well-known/,
  extracts REST paths from JS (fetch/axios), discovers versioned APIs (/v1/, /v2/)
- Parameter mining: from JS (URLSearchParams, query strings), HTML data-*
  attributes, sitemap.xml + robots.txt
- Stateful crawling: session maintained via client cookies; CSRF tokens
  extracted and replayed in subsequent form submissions
- Content-type awareness: records content-type per endpoint so modules can
  send JSON/XML payloads appropriately
- Smart scope: priority queue — high-value URLs (admin, api, upload, search,
  login, redirect, download) scanned first
"""

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
    params: dict = field(default_factory=dict)
    source: str = "crawl"           # crawl | form | js | robots | sitemap | api-spec | spa-route
    content_type: str = ""          # observed response content-type
    is_login: bool = False          # detected login form
    has_file_upload: bool = False   # form has file input
    csrf_token: str = ""            # extracted CSRF token name=value if found
    priority: int = 0               # higher = scan first

    def key(self) -> str:
        u = urlsplit(self.url)
        base = urlunsplit((u.scheme, u.netloc, u.path.rstrip("/") or "/", "", ""))
        return f"{self.method}|{base}|{','.join(sorted(self.params))}"


# ---------------------------------------------------------------------------
# Priority scoring: interesting paths get scanned first
# ---------------------------------------------------------------------------
PRIORITY_PATTERNS = [
    (re.compile(r"/(admin|administrator|wp-admin|dashboard)", re.I), 100),
    (re.compile(r"/api/|/rest/|/graphql|/v\d+/", re.I), 90),
    (re.compile(r"/(upload|uploads|files?|media)", re.I), 85),
    (re.compile(r"/(login|signin|auth|oauth|register|signup)", re.I), 80),
    (re.compile(r"/(search|query|find|filter)", re.I), 70),
    (re.compile(r"/(redirect|redir|goto|url|return|next|continue)", re.I), 70),
    (re.compile(r"/(download|export|backup)", re.I), 65),
    (re.compile(r"/(user|users|account|profile)", re.I), 60),
    (re.compile(r"/(cart|checkout|order|payment|price)", re.I), 60),
    (re.compile(r"\.(xml|json)$", re.I), 50),
]


def score_priority(url: str) -> int:
    score = 0
    for rx, pts in PRIORITY_PATTERNS:
        if rx.search(url):
            score = max(score, pts)
    return score


# ---------------------------------------------------------------------------
# HTML parsing: links, deep forms, data-* URLs, framework markers
# ---------------------------------------------------------------------------
class _DeepParser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__()
        self.base = base_url
        self.links: set[str] = set()
        self.forms: list[dict] = []
        self.data_urls: set[str] = set()
        self._form = None
        self._select_name = None
        self._select_options: list[str] = []
        self.scripts: list[str] = []       # inline script bodies
        self.framework_hints: set[str] = set()
        self.comment_urls: set[str] = set()  # paths/URLs mined from HTML comments
        self._script_depth = 0

    @property
    def _in_script(self) -> bool:
        return self._script_depth > 0

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            self._script_depth += 1
        a = dict(attrs)
        # links
        if tag == "a" and a.get("href"):
            self.links.add(urljoin(self.base, a["href"]))
        elif tag in ("script", "iframe", "embed") and a.get("src"):
            src = a["src"]
            self.links.add(urljoin(self.base, src))
            self._check_framework_src(src)
        elif tag == "link" and a.get("href"):
            self.links.add(urljoin(self.base, a["href"]))
        elif tag in ("img", "source", "video", "audio") and a.get("src"):
            self.links.add(urljoin(self.base, a["src"]))
        elif tag == "object" and a.get("data"):
            self.links.add(urljoin(self.base, a["data"]))
        # data-* attributes that look like URLs
        for k, v in a.items():
            if k.startswith("data-") and v and isinstance(v, str):
                if v.startswith("/") or v.startswith("http"):
                    self.data_urls.add(urljoin(self.base, v))
        # meta refresh
        if tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            content = a.get("content", "")
            m = re.search(r"url=(.+)", content, re.I)
            if m:
                self.links.add(urljoin(self.base, m.group(1).strip("'\" ")))
        # framework markers in markup
        if a.get("data-reactroot") is not None or a.get("data-reactid") is not None:
            self.framework_hints.add("React")
        if a.get("ng-version") or a.get("ng-app") or any(k.startswith("ng-") for k in a):
            self.framework_hints.add("Angular")
        if a.get("data-v-") is not None or any(k.startswith("v-") for k in a if k != "value"):
            # v- directives suggest Vue (careful: 'value' excluded above)
            if any(k.startswith(("v-bind", "v-on", "v-model", "v-if", "v-for")) for k in a):
                self.framework_hints.add("Vue")
        # forms — deep analysis
        if tag == "form":
            self._form = {
                "action": urljoin(self.base, a.get("action", self.base)),
                "method": (a.get("method") or "GET").upper(),
                "enctype": a.get("enctype", "application/x-www-form-urlencoded"),
                "inputs": {},
                "input_types": {},
                "has_file": False,
            }
        elif tag == "input" and self._form is not None:
            name = a.get("name")
            itype = (a.get("type") or "text").lower()
            if name:
                self._form["inputs"][name] = a.get("value", _sample_value(itype, name))
                self._form["input_types"][name] = itype
                if itype == "file":
                    self._form["has_file"] = True
        elif tag == "textarea" and self._form is not None:
            name = a.get("name")
            if name:
                self._form["inputs"][name] = "test"
                self._form["input_types"][name] = "textarea"
        elif tag == "select" and self._form is not None:
            self._select_name = a.get("name")
            self._select_options = []
        elif tag == "option" and self._select_name and self._form is not None:
            val = a.get("value")
            # use option value or text; collect for param values
            self._select_options.append(val if val is not None else "")
        elif tag == "button" and self._form is not None:
            name = a.get("name")
            if name:
                self._form["inputs"][name] = a.get("value", "test")

    def handle_endtag(self, tag):
        if tag == "script":
            self._script_depth = max(0, self._script_depth - 1)
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None
        elif tag == "select" and self._select_name and self._form is not None:
            # use first non-empty option as sample value
            vals = [o for o in self._select_options if o]
            self._form["inputs"][self._select_name] = vals[0] if vals else "test"
            self._form["input_types"][self._select_name] = "select"
            self._form["select_options"] = self._form.get("select_options", {})
            self._form["select_options"][self._select_name] = self._select_options
            self._select_name = None

    def handle_data(self, data):
        # inline scripts: collect for JS analysis + framework detection
        if self._in_script:
            self.scripts.append(data)
            self._check_framework_js(data)

    def handle_comment(self, data):
        # Mine paths/URLs from HTML comments, e.g.
        # <!-- backup: /backup.zip -->, <!-- TODO: remove /api/v2/internal -->
        # These are DISCOVERED (present in the response), not guessed.
        for m in re.finditer(r"""["']?((?:/|\./)[A-Za-z0-9_\-./?=&%#]{2,})["']?""", data):
            path = m.group(1).rstrip(".,;:'\"")
            # skip obvious non-paths (file extensions of assets handled by should_skip later)
            if len(path) < 3 or path.startswith("//"):
                continue
            self.comment_urls.add(urljoin(self.base, path))

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def _check_framework_src(self, src: str):
        s = src.lower()
        if "react" in s:
            self.framework_hints.add("React")
        if "vue" in s:
            self.framework_hints.add("Vue")
        if "angular" in s:
            self.framework_hints.add("Angular")

    def _check_framework_js(self, js: str):
        if "__REACT" in js or "react-dom" in js.lower() or "React.createElement" in js:
            self.framework_hints.add("React")
        if "__VUE__" in js or "Vue.createApp" in js:
            self.framework_hints.add("Vue")
        if "ng-version" in js or "platformBrowserDynamic" in js:
            self.framework_hints.add("Angular")


def _sample_value(itype: str, name: str) -> str:
    """Smart sample values per input type/name."""
    if itype == "hidden":
        return "1"
    if itype in ("checkbox", "radio"):
        return "on"
    if itype == "number":
        return "1"
    if itype == "email":
        return "test@example.com"
    if itype == "password":
        return "password123"
    if itype == "tel":
        return "1234567890"
    if itype == "url":
        return "http://example.com/"
    if itype == "date":
        return "2024-01-01"
    nl = name.lower()
    if "email" in nl or "mail" in nl:
        return "test@example.com"
    if "pass" in nl:
        return "password123"
    if "user" in nl or "login" in nl:
        return "testuser"
    if "search" in nl or "query" in nl or "q" == nl:
        return "test"
    if "id" in nl:
        return "1"
    return "test"


# login form heuristics
LOGIN_INDICATORS = re.compile(
    r"password|passwd|pwd|login|signin|sign-in|log-in|auth", re.I)


def is_login_form(form: dict) -> bool:
    types = form.get("input_types", {})
    has_password = any(t == "password" for t in types.values())
    names = " ".join(form.get("inputs", {}).keys())
    if has_password:
        return True
    return bool(LOGIN_INDICATORS.search(names) and
                LOGIN_INDICATORS.search(form.get("action", "")))


# CSRF token heuristics
CSRF_NAMES = re.compile(
    r"csrf|xsrf|_token|authenticity_token|__requestverificationtoken", re.I)


def extract_csrf(form: dict) -> str:
    for name, val in form.get("inputs", {}).items():
        if CSRF_NAMES.search(name) and val and val not in ("test", "1", "on"):
            return f"{name}={val}"
    return ""


# ---------------------------------------------------------------------------
# JS analysis: SPA routes, API base URLs, param mining
# ---------------------------------------------------------------------------
JS_ENDPOINT_RE = re.compile(r"""(?:"|')((?:/|\./|https?://)[a-zA-Z0-9_\-./?=&%#]+)(?:"|')""")
FETCH_RE = re.compile(
    r"""(?:fetch|axios\.(?:get|post|put|delete|patch)|\$\.ajax|\.get|\.post)\s*\(\s*["']([^"']+)["']""")
API_PATH_RE = re.compile(r"""["']((?:/api/|/v\d+/|/rest/)[a-zA-Z0-9_\-./?=&%{}:]+)["']""")

# SPA route patterns
REACT_ROUTER_RE = re.compile(r"""(?:path|route)\s*[:=]\s*["'](/[a-zA-Z0-9_\-./:{}*]+)["']""")
VUE_ROUTER_RE = re.compile(r"""path\s*:\s*["'](/[a-zA-Z0-9_\-./:{}*]+)["']""")
ANGULAR_ROUTE_RE = re.compile(r"""path\s*:\s*["']([a-zA-Z0-9_\-./:{}*]+)["']""")
# API base URL patterns
API_BASE_RE = re.compile(
    r"""(?:baseURL|API_URL|apiUrl|API_BASE)\s*[:=]\s*["']([^"']+)["']""")
# param mining: URLSearchParams, query strings in code
URLSEARCHPARAMS_RE = re.compile(r"""URLSearchParams\(\s*["']([^"']+)["']""")
QUERY_IN_CODE_RE = re.compile(r"""[?&]([a-zA-Z_][a-zA-Z0-9_]*)=["']?\{?[^&"'}\s]*""")
# WebSocket endpoints referenced in JS
WS_URL_RE = re.compile(r"""["'](wss?://[A-Za-z0-9_\-./?=&%#:]+)["']""")
# browser storage keys used by the app (useful intel, mined not guessed)
STORAGE_KEY_RE = re.compile(
    r"""(?:localStorage|sessionStorage)\.(?:getItem|setItem|removeItem)\s*\(\s*["']([^"']{1,64})["']""")
# custom header names set by JS (e.g. setRequestHeader("X-Api-Key", ...))
HEADER_NAME_RE = re.compile(
    r"""setRequestHeader\s*\(\s*["']([^"']{1,64})["']""")
# headers object literals: headers: { "X-Foo": ... } or {"X-Foo": "..."}
HEADERS_OBJ_RE = re.compile(
    r"""["'](X-[A-Za-z0-9_\-]{1,48})["']\s*:""")


def extract_js_endpoints(js_text: str, base_url: str) -> set[str]:
    out = set()
    for m in JS_ENDPOINT_RE.finditer(js_text):
        out.add(urljoin(base_url, m.group(1)))
    for m in FETCH_RE.finditer(js_text):
        out.add(urljoin(base_url, m.group(1)))
    for m in API_PATH_RE.finditer(js_text):
        out.add(urljoin(base_url, m.group(1)))
    base_host = urlsplit(base_url).netloc
    return {u for u in out
            if urlsplit(u).netloc in ("", base_host)
            and not should_skip(u)
            and not re.search(r"\.(js|css|map|woff2?|ttf|eot)(\?|$)",
                              urlsplit(u).path, re.I)}


def extract_spa_routes(js_text: str, base_url: str) -> set[str]:
    """Extract client-side routes from SPA router definitions."""
    out = set()
    for rx in (REACT_ROUTER_RE, VUE_ROUTER_RE, ANGULAR_ROUTE_RE):
        for m in rx.finditer(js_text):
            path = m.group(1)
            # skip wildcards and param placeholders for crawling
            if "*" in path:
                continue
            path = re.sub(r"[:{][a-zA-Z_]+[}]?", "1", path)
            out.add(urljoin(base_url, path))
    base_host = urlsplit(base_url).netloc
    return {u for u in out
            if urlsplit(u).netloc in ("", base_host) and not should_skip(u)}


def extract_api_bases(js_text: str, base_url: str) -> set[str]:
    out = set()
    for m in API_BASE_RE.finditer(js_text):
        out.add(urljoin(base_url, m.group(1)))
    return out


def mine_params_from_js(js_text: str) -> dict[str, str]:
    """Mine parameter names from JS code."""
    params: dict[str, str] = {}
    for m in URLSEARCHPARAMS_RE.finditer(js_text):
        for pair in m.group(1).split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                params[k.strip()] = v.strip() or "test"
    for m in QUERY_IN_CODE_RE.finditer(js_text):
        k = m.group(1)
        if k not in params and len(k) < 40:
            params[k] = "test"
    return params


def extract_ws_endpoints(js_text: str) -> set[str]:
    """WebSocket URLs referenced in JS (wss://host/path). Returned as-is;
    the caller may map them to https:// for HTTP probing."""
    return {m.group(1) for m in WS_URL_RE.finditer(js_text)}


def mine_storage_keys(js_text: str) -> set[str]:
    """Browser storage keys the app actually uses (mined, not guessed)."""
    return {m.group(1) for m in STORAGE_KEY_RE.finditer(js_text)}


def mine_header_names(js_text: str) -> set[str]:
    """Custom header names the app's JS actually sets (mined, not guessed)."""
    out = {m.group(1) for m in HEADER_NAME_RE.finditer(js_text)}
    out.update(m.group(1) for m in HEADERS_OBJ_RE.finditer(js_text))
    return out


# ---------------------------------------------------------------------------
# Scope helpers
# ---------------------------------------------------------------------------
SKIP_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico",
    ".css", ".map", ".woff", ".woff2", ".ttf", ".eot",
    ".mp4", ".webm", ".mp3", ".wav", ".pdf", ".zip",
}
SKIP_PATTERNS = [
    re.compile(r"/logout|/signout|/logoff", re.I),
    re.compile(r"\.(jpg|jpeg|png|gif|webp|svg|ico|css|woff2?|ttf|eot|mp4|webm|mp3|wav|pdf|zip)(\?|$)", re.I),
]


def should_skip(url: str) -> bool:
    # only inspect the PATH — query values like ?file=doc.pdf are attack
    # surface, not static assets (regression: /download?file=x.pdf was skipped)
    path = urlsplit(url).path
    for pat in SKIP_PATTERNS:
        if pat.search(path):
            return True
    return False


def split_params(url: str) -> tuple[str, dict]:
    u = urlsplit(url)
    params = dict(parse_qsl(u.query, keep_blank_values=True))
    clean = urlunsplit((u.scheme, u.netloc, u.path, "", u.fragment))
    return clean, params


# API spec well-known paths
API_SPEC_PATHS = [
    "/openapi.json", "/swagger.json", "/swagger/v1/swagger.json",
    "/api-docs", "/api/docs", "/docs/openapi.json",
    "/.well-known/openapi.json", "/v1/openapi.json", "/v2/openapi.json",
    "/api/openapi.json", "/swagger-ui/swagger.json",
]


class Crawler:
    def __init__(self, client: ScanClient, config: ScanConfig):
        self.client = client
        self.config = config
        self.target_host = urlsplit(config.target).netloc
        self.target_scheme = urlsplit(config.target).scheme
        self.visited: set[str] = set()
        self.endpoints: dict[str, Endpoint] = {}
        self.frameworks: set[str] = set()
        self.auth_surfaces: list[dict] = []   # detected login forms
        self.csrf_tokens: dict[str, str] = {}  # url -> token name=value
        self.storage_keys: set[str] = set()   # browser storage keys mined from JS
        self.header_names: set[str] = set()   # custom header names mined from JS
        self.ws_urls: set[str] = set()         # websocket URLs mined from JS
        self.js_urls: set[str] = set()          # JS bundle URLs actually downloaded

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
        ep.priority = max(ep.priority, score_priority(ep.url))
        k = ep.key()
        if k not in self.endpoints:
            self.endpoints[k] = ep
        elif ep.priority > self.endpoints[k].priority:
            self.endpoints[k].priority = ep.priority

    async def fetch_robots(self):
        if self.config.ignore_robots:
            return
        base = f"{self.target_scheme}://{self.target_host}"
        # robots.txt
        resp = await self.client.get(base + "/robots.txt")
        if resp and resp.status_code == 200:
            for line in resp.text.splitlines():
                m = re.match(r"(?i)disallow:\s*(\S+)", line.strip())
                if m:
                    full = urljoin(base + "/", m.group(1))
                    clean, params = split_params(full)
                    self.add_endpoint(Endpoint(url=clean, params=params, source="robots"))
                s = re.match(r"(?i)sitemap:\s*(\S+)", line.strip())
                if s:
                    await self.fetch_sitemap(s.group(1))
        # sitemap.xml directly (even without robots mention)
        await self.fetch_sitemap(base + "/sitemap.xml")

    async def fetch_sitemap(self, url: str):
        if not self.in_scope(url):
            return
        resp = await self.client.get(url)
        if not resp or resp.status_code != 200:
            return
        # sitemap index or urlset
        for m in re.finditer(r"<loc>\s*([^<\s]+)\s*</loc>", resp.text):
            loc = m.group(1).strip()
            if "sitemap" in loc.lower() and loc != url:
                await self.fetch_sitemap(loc)  # nested sitemap
                continue
            if self.in_scope(loc) and not should_skip(loc):
                clean, params = split_params(loc)
                self.add_endpoint(Endpoint(url=clean, params=params, source="sitemap"))

    async def probe_api_specs(self):
        """Probe well-known API spec locations; parse paths into endpoints."""
        base = f"{self.target_scheme}://{self.target_host}"
        for path in API_SPEC_PATHS:
            url = base + path
            resp = await self.client.get(url)
            if not resp or resp.status_code != 200:
                continue
            ctype = resp.headers.get("content-type", "")
            if "json" not in ctype and not resp.text.strip().startswith("{"):
                continue
            try:
                import json as _json
                spec = _json.loads(resp.text)
            except Exception:
                continue
            paths = spec.get("paths", {})
            for api_path, methods in paths.items():
                if not isinstance(methods, dict):
                    continue
                # resolve path params {id} -> 1
                clean_path = re.sub(r"\{[^}]+\}", "1", api_path)
                full = urljoin(base + "/", clean_path.lstrip("/"))
                if not self.in_scope(full) or should_skip(full):
                    continue
                for method, details in methods.items():
                    method = method.upper()
                    if method not in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                        continue
                    params: dict[str, str] = {}
                    for p in (details.get("parameters") or []):
                        name = p.get("name")
                        if name:
                            params[name] = "test"
                    self.add_endpoint(Endpoint(
                        url=full, method=method, params=params,
                        source="api-spec",
                        content_type="application/json",
                    ))

    async def crawl_page(self, url: str, depth: int) -> list[str]:
        clean, params = split_params(url)
        if params:
            self.add_endpoint(Endpoint(url=clean, params=params, source="crawl"))
        resp = await self.client.get(url, dedupe=False)
        if not resp or resp.status_code >= 400:
            return []
        ctype = resp.headers.get("content-type", "")
        new_links: list[str] = []

        # JS files: download + extract endpoints + SPA routes + API bases + mined params
        if "javascript" in ctype or url.endswith(".js"):
            self.js_urls.add(clean)
            self._process_js(resp.text, url)
            return []

        if "html" not in ctype and "text" not in ctype:
            # record content-type for non-HTML endpoints (JSON/XML APIs)
            if params or "json" in ctype or "xml" in ctype:
                self.add_endpoint(Endpoint(url=clean, params=params,
                                           source="crawl", content_type=ctype))
            return []

        # HTML page: ensure it's a testable endpoint even WITHOUT params.
        # Page-level modules (domxss: NEEDS_PARAMS=False) analyze page content,
        # not query strings. Param-testing modules skip param-less endpoints.
        if not params:
            self.add_endpoint(Endpoint(url=clean, params={}, source="crawl-page",
                                       content_type=ctype))

        parser = _DeepParser(url)
        try:
            parser.feed(resp.text[:500_000])
        except Exception:
            pass

        self.frameworks.update(parser.framework_hints)

        for link in parser.links:
            if self.in_scope(link):
                new_links.append(link)
        # data-* URLs become endpoints
        for durl in parser.data_urls:
            if self.in_scope(durl) and not should_skip(durl):
                c, p = split_params(durl)
                self.add_endpoint(Endpoint(url=c, params=p, source="crawl"))
        # HTML-comment URLs become endpoints (discovered, not guessed).
        # No should_skip here: if a human referenced it in a comment it is
        # worth one probe (e.g. <!-- backup: /backup.zip -->). The crawler
        # never recurses into these (only modules test them).
        for curl in parser.comment_urls:
            if self.in_scope(curl):
                c, p = split_params(curl)
                self.add_endpoint(Endpoint(url=c, params=p, source="comment"))

        # deep form analysis
        for form in parser.forms:
            c, _ = split_params(form["action"])
            login = is_login_form(form)
            csrf = extract_csrf(form)
            if csrf:
                self.csrf_tokens[c] = csrf
            if login:
                self.auth_surfaces.append({
                    "url": c, "method": form["method"],
                    "fields": list(form["inputs"].keys()),
                })
            # file upload endpoints get priority + flag
            ep = Endpoint(
                url=c, method=form["method"], params=dict(form["inputs"]),
                source="form", content_type=(
                    "multipart/form-data" if form["enctype"].startswith("multipart")
                    else "application/x-www-form-urlencoded"),
                is_login=login,
                has_file_upload=form["has_file"],
                csrf_token=csrf,
            )
            # replay CSRF token automatically (already in inputs)
            self.add_endpoint(ep)

        # JS analysis on inline scripts ONLY. HTML links/forms already carry
        # their own query strings (via split_params); mining the full HTML
        # causes param pollution (e.g. ?next= from the nav landing on /about).
        for script in parser.scripts:
            self._process_js(script, url)

        # JS execution in the virtual browser (pure Python, no headless
        # browser): for SPA pages or scripts with sink/source patterns,
        # execute and harvest API calls + routes the static pass misses.
        if parser.framework_hints or self._js_worth_executing(parser.scripts):
            await self._process_js_execution(parser.scripts, url)

        return new_links

    def _js_worth_executing(self, scripts: list[str]) -> bool:
        """Cheap gate: execute only if a script shows sink/source interest."""
        try:
            from sentinelx.jsenv.static import score_js_interest
        except ImportError:
            return False
        for js in scripts:
            if len(js) > 60000:
                continue
            try:
                score, _, _ = score_js_interest(js)
            except Exception:
                continue
            if score >= 10:
                return True
        return False

    async def _process_js_execution(self, scripts: list[str], page_url: str):
        """Execute inline scripts in the virtual browser; harvest the
        network calls and routes observed during execution."""
        interesting = [s for s in scripts if s.strip() and len(s) < 60000][:8]
        if not interesting:
            return
        try:
            from sentinelx.jsenv.executor import execute_scripts
        except ImportError:
            return
        try:
            result = await asyncio.to_thread(execute_scripts, interesting, page_url)
        except Exception:
            return
        if not result.executed:
            return
        for call in result.api_calls:
            u = call.get("url", "")
            if not u or not self.in_scope(u):
                continue
            c, p = split_params(u.split("#")[0])
            if should_skip(c):
                continue
            self.add_endpoint(Endpoint(
                url=c, method=call.get("method", "GET"), params=p,
                source="js-exec",
                content_type="application/json" if "/api/" in c else "",
            ))
        base = f"{self.target_scheme}://{self.target_host}"
        for route in result.routes:
            r = route.split(":", 1)[-1].strip()
            if not r.startswith("/"):
                continue
            full = urljoin(base, r)
            if self.in_scope(full) and not should_skip(full):
                c, p = split_params(full)
                self.add_endpoint(Endpoint(url=c, params=p, source="js-exec-route"))

    def _process_js(self, js_text: str, base_url: str):
        for m in JS_ENDPOINT_RE.finditer(js_text):
            ep_url = urljoin(base_url, m.group(1))
            # skip asset files: they're downloaded via the crawl queue, not tested
            if re.search(r"\.(js|css|map|woff2?|ttf|eot)(\?|$)", urlsplit(ep_url).path, re.I):
                continue
            if not self.in_scope(ep_url) or should_skip(ep_url):
                continue
            c, p = split_params(ep_url)
            # proximity param mining: only attach params that appear NEAR this
            # URL in the source (±600 chars), not every param in the whole file
            window = js_text[max(0, m.start() - 600):m.end() + 600]
            for k, v in mine_params_from_js(window).items():
                p.setdefault(k, v)
            self.add_endpoint(Endpoint(url=c, params=p, source="js"))
        for m in FETCH_RE.finditer(js_text):
            ep_url = urljoin(base_url, m.group(1))
            if re.search(r"\.(js|css|map|woff2?|ttf|eot)(\?|$)", urlsplit(ep_url).path, re.I):
                continue
            if not self.in_scope(ep_url) or should_skip(ep_url):
                continue
            c, p = split_params(ep_url)
            window = js_text[max(0, m.start() - 600):m.end() + 600]
            for k, v in mine_params_from_js(window).items():
                p.setdefault(k, v)
            self.add_endpoint(Endpoint(url=c, params=p, source="js"))
        for m in API_PATH_RE.finditer(js_text):
            ep_url = urljoin(base_url, m.group(1))
            if not self.in_scope(ep_url) or should_skip(ep_url):
                continue
            c, p = split_params(ep_url)
            self.add_endpoint(Endpoint(url=c, params=p, source="js"))
        for route_url in extract_spa_routes(js_text, base_url):
            c, p = split_params(route_url)
            self.add_endpoint(Endpoint(url=c, params=p, source="spa-route"))
        for api_base in extract_api_bases(js_text, base_url):
            # probe the base itself as an endpoint
            c, p = split_params(api_base)
            if self.in_scope(c):
                self.add_endpoint(Endpoint(url=c, params=p, source="js"))
        # WebSocket URLs: record as seen, and also queue the https://
        # counterpart as a discovered endpoint (same host usually serves it)
        for ws_url in extract_ws_endpoints(js_text):
            self.ws_urls.add(ws_url)
            http_url = re.sub(r"^wss?://", "https://", ws_url)
            if self.in_scope(http_url) and not should_skip(http_url):
                c, p = split_params(http_url)
                self.add_endpoint(Endpoint(url=c, params=p, source="js-ws"))
        # storage keys + custom header names: mined intel for modules
        self.storage_keys.update(mine_storage_keys(js_text))
        self.header_names.update(mine_header_names(js_text))

    async def run(self) -> list[Endpoint]:
        max_pages = getattr(self.config, "max_pages", 50)
        await self.fetch_robots()
        await self.probe_api_specs()

        # priority queue: (priority, depth, url)
        import heapq
        queue: list[tuple[int, int, str]] = []
        heapq.heappush(queue, (0, 0, self.config.target))
        sem = asyncio.Semaphore(10)

        async def process(url: str, depth: int) -> list[str]:
            async with sem:
                try:
                    return await self.crawl_page(url, depth)
                except Exception:
                    return []

        while queue and len(self.visited) < max_pages:
            batch = []
            while queue and len(batch) < 10 and len(self.visited) + len(batch) < max_pages:
                neg_prio, depth, url = heapq.heappop(queue)
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
                            heapq.heappush(queue,
                                           (-score_priority(n), d + 1, n))
        # sort endpoints by priority (highest first) for smart scanning order
        eps = sorted(self.endpoints.values(),
                     key=lambda e: e.priority, reverse=True)
        return eps
