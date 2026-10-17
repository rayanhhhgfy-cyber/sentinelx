"""SentinelX jsenv: virtual browser environment (pure Python mocks).

These mocks are the *technique* — findings still come from REAL JavaScript
execution reaching REAL sinks (tainted data into innerHTML/document.write/
eval is observed during actual interpretation, not regex guessing).

Recorded signals:
- api_calls: every fetch()/XHR URL + method + body (hidden API discovery)
- dom_writes: every document.write/writeln/innerHTML/outerHTML/insertAdjacentHTML
  with the value AND its taint label (DOM XSS sink detection)
- eval_calls: every eval()/Function()/setTimeout(string) payload (code injection)
- routes: client-side route registrations (history.pushState, router.push, ...)
- storage: localStorage/sessionStorage/cookie writes (info)
- events: addEventListener registrations (info)
"""

from __future__ import annotations

from urllib.parse import urljoin

from .jsinterp import TaintedStr, taint, is_tainted, UNDEFINED


class ExecutionResult:
    """Everything observed during one mock-execution."""

    def __init__(self, page_url: str = ""):
        self.page_url = page_url
        self.api_calls: list[dict] = []     # {method, url, body, source}
        self.dom_writes: list[dict] = []   # {sink, value, taint, element}
        self.eval_calls: list[dict] = []   # {sink, code, taint}
        self.routes: list[str] = []
        self.storage_writes: list[dict] = []
        self.event_listeners: list[dict] = []
        self.console: list[str] = []
        self.errors: list[str] = []
        self.executed = False

    def to_dict(self):
        return {
            "page_url": self.page_url,
            "api_calls": self.api_calls,
            "dom_writes": self.dom_writes,
            "eval_calls": self.eval_calls,
            "routes": self.routes,
            "errors": self.errors[:10],
            "executed": self.executed,
        }


# ---------------------------------------------------------------------------
# Location (tainted sources)
# ---------------------------------------------------------------------------
class MockLocation:
    def __init__(self, result: ExecutionResult, page_url: str,
                 hash_canary: str, search_canary: str):
        self._result = result
        self._page_url = page_url
        self.href = page_url
        self.protocol = page_url.split("://")[0] + ":" if "://" in page_url else "http:"
        self.host = page_url.split("://", 1)[1].split("/")[0] if "://" in page_url else ""
        self.hostname = self.host.split(":")[0]
        self.pathname = "/" + page_url.split("://", 1)[1].split("/", 1)[1].split("?")[0] \
            if "://" in page_url and "/" in page_url.split("://", 1)[1] else "/"
        # attacker-controlled sources -> TAINTED
        self.hash = taint(hash_canary, "location.hash")
        self.search = taint(search_canary, "location.search")
        self._hash_raw = hash_canary

    def js_get(self, name):
        return getattr(self, name, UNDEFINED)

    def js_set(self, name, value):
        if name == "hash":
            self._result.routes.append("hash-nav:" + str(value)[:120])
        setattr(self, name, value)

    def assign(self, url):
        self._result.routes.append("assign:" + str(url)[:200])

    def replace(self, url):
        self._result.routes.append("replace:" + str(url)[:200])

    def reload(self):
        pass


# ---------------------------------------------------------------------------
# DOM elements
# ---------------------------------------------------------------------------
class MockElement:
    def __init__(self, result: ExecutionResult, tag="div", elem_id=""):
        self._result = result
        self.tagName = tag.upper()
        self.id = elem_id
        self.children = []
        self.attributes = {}
        self._inner_html = ""
        self._text = ""
        self.value = ""
        self.style = {}

    def js_get(self, name):
        if name == "innerHTML":
            return self._inner_html
        if name == "outerHTML":
            return self._outer()
        if name == "textContent":
            return self._text
        if name == "innerText":
            return self._text
        return getattr(self, name, UNDEFINED)

    def js_set(self, name, value):
        if name in ("innerHTML", "outerHTML"):
            self._result.dom_writes.append({
                "sink": f"{name}#{self.id or self.tagName}",
                "value": str(value)[:2000],
                "taint": is_tainted(value),
                "element": self.id or self.tagName,
            })
            self._inner_html = str(value)
        elif name in ("textContent", "innerText"):
            self._text = str(value)  # text sink — safe, but record taint flow
            if is_tainted(value):
                self._result.dom_writes.append({
                    "sink": f"{name}#{self.id or self.tagName} (text-safe)",
                    "value": str(value)[:500],
                    "taint": is_tainted(value),
                    "element": self.id or self.tagName,
                })
        else:
            setattr(self, name, value)

    def _outer(self):
        return f"<{self.tagName.lower()} id=\"{self.id}\">{self._inner_html}</{self.tagName.lower()}>"

    # DOM API
    def appendChild(self, child):
        self.children.append(child)
        return child

    def setAttribute(self, name, value):
        self.attributes[str(name)] = str(value)
        # event-handler attributes are code sinks
        if str(name).lower().startswith("on"):
            self._result.eval_calls.append({
                "sink": f"on{str(name)[2:]}-attribute",
                "code": str(value)[:1000],
                "taint": is_tainted(value),
            })

    def getAttribute(self, name):
        return self.attributes.get(str(name))

    def addEventListener(self, ev, fn):
        self._result.event_listeners.append({"element": self.id, "event": str(ev)})

    def querySelector(self, sel):
        return MockElement(self._result, "div", elem_id=str(sel)[:40])

    def querySelectorAll(self, sel):
        return [MockElement(self._result, "div", elem_id=str(sel)[:40])]


class MockDocument:
    def __init__(self, result: ExecutionResult, location):
        self._result = result
        self._location = location
        self._elements = {}
        self.cookie = ""
        self.title = ""
        self.referrer = ""
        self.domain = location.hostname if hasattr(location, "hostname") else ""

    def js_get(self, name):
        if name == "location":
            return self._location
        return getattr(self, name, UNDEFINED)

    def js_set(self, name, value):
        if name == "cookie":
            self._result.storage_writes.append({"store": "cookie", "value": str(value)[:300]})
        setattr(self, name, value)

    def _el(self, elem_id):
        if elem_id not in self._elements:
            self._elements[elem_id] = MockElement(self._result, "div", elem_id)
        return self._elements[elem_id]

    # sinks
    def write(self, *args):
        val = "".join(str(a) for a in args)
        self._result.dom_writes.append({
            "sink": "document.write", "value": val[:2000],
            "taint": _any_taint(args), "element": "#document",
        })

    def writeln(self, *args):
        val = "".join(str(a) for a in args)
        self._result.dom_writes.append({
            "sink": "document.writeln", "value": val[:2000],
            "taint": _any_taint(args), "element": "#document",
        })

    def getElementById(self, elem_id):
        return self._el(str(elem_id))

    def createElement(self, tag):
        return MockElement(self._result, str(tag))

    def querySelector(self, sel):
        return MockElement(self._result, "div", elem_id=str(sel)[:40])

    def querySelectorAll(self, sel):
        return [MockElement(self._result, "div", elem_id=str(sel)[:40])]

    def getElementsByTagName(self, tag):
        return [MockElement(self._result, str(tag))]

    def addEventListener(self, ev, fn):
        self._result.event_listeners.append({"element": "#document", "event": str(ev)})


def _any_taint(args) -> str:
    for a in args:
        t = is_tainted(a)
        if t:
            return t
    return ""


# ---------------------------------------------------------------------------
# Network recording (fetch / XHR)
# ---------------------------------------------------------------------------
class MockResponse:
    def __init__(self):
        pass

    def then(self, fn):
        return MockResponse()

    def catch(self, fn):
        return MockResponse()

    def json(self):
        r = MockResponse()
        return r

    def text(self):
        r = MockResponse()
        return r


class MockXHR:
    def __init__(self, result: ExecutionResult, page_url: str):
        self._result = result
        self._page_url = page_url
        self._method = "GET"
        self._url = ""
        self.readyState = 0
        self.status = 0
        self.responseText = ""

    def open(self, method, url, *args):
        self._method = str(method).upper()
        self._url = urljoin(self._page_url, str(url))

    def send(self, body=None):
        self._result.api_calls.append({
            "method": self._method,
            "url": self._url,
            "body": str(body)[:500] if body else "",
            "source": "XMLHttpRequest",
        })

    def setRequestHeader(self, k, v):
        pass

    def addEventListener(self, ev, fn):
        pass


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------
class MockStorage:
    def __init__(self, result: ExecutionResult, name: str):
        self._result = result
        self._name = name
        self._data = {}

    def setItem(self, k, v):
        self._data[str(k)] = str(v)
        self._result.storage_writes.append(
            {"store": self._name, "key": str(k), "value": str(v)[:300]})

    def getItem(self, k):
        return self._data.get(str(k))

    def removeItem(self, k):
        self._data.pop(str(k), None)


# ---------------------------------------------------------------------------
# Build the global scope for execution
# ---------------------------------------------------------------------------
def build_globals(page_url: str, hash_canary: str = "#SX_CANARY",
                  search_canary: str = "?sx=SX_CANARY") -> tuple[dict, ExecutionResult]:
    """Return (globals_dict, result). Execute page JS with these globals."""
    result = ExecutionResult(page_url)
    location = MockLocation(result, page_url, hash_canary, search_canary)
    document = MockDocument(result, location)
    storage_local = MockStorage(result, "localStorage")
    storage_session = MockStorage(result, "sessionStorage")

    def _fetch(url, opts=None):
        method = "GET"
        body = ""
        if isinstance(opts, dict):
            m = opts.get("method")
            if m:
                method = str(m).upper()
            b = opts.get("body")
            if b:
                body = str(b)[:500]
        result.api_calls.append({
            "method": method,
            "url": urljoin(page_url, str(url)),
            "body": body,
            "source": "fetch",
        })
        return MockResponse()

    def _eval(code):
        result.eval_calls.append({
            "sink": "eval", "code": str(code)[:2000],
            "taint": is_tainted(code),
        })
        return UNDEFINED

    def _Function(*args):
        code = str(args[-1]) if args else ""
        result.eval_calls.append({
            "sink": "Function", "code": code[:2000],
            "taint": is_tainted(code),
        })

        def _fn(*a, **k):
            return UNDEFINED
        return _fn

    def _setTimeout(fn, ms=None):
        if isinstance(fn, str):
            result.eval_calls.append({
                "sink": "setTimeout(string)", "code": fn[:1000],
                "taint": is_tainted(fn),
            })
        return 1

    def _setInterval(fn, ms=None):
        return _setTimeout(fn, ms)

    # window object: attribute access falls back to globals
    class MockWindow:
        def __init__(self, g):
            object.__setattr__(self, "_g", g)

        def js_get(self, name):
            g = object.__getattribute__(self, "_g")
            return g.get(name, UNDEFINED)

        def js_set(self, name, value):
            g = object.__getattribute__(self, "_g")
            g[name] = value

        def addEventListener(self, ev, fn):
            result.event_listeners.append({"element": "#window", "event": str(ev)})

    g: dict = {}
    window = MockWindow(g)

    g.update({
        "window": window,
        "self": window,
        "globalThis": window,
        "document": document,
        "location": location,
        "navigator": {"userAgent": "SentinelX-jsenv/1.0", "language": "en-US",
                      "platform": "Linux", "onLine": True},
        "fetch": _fetch,
        "XMLHttpRequest": lambda: MockXHR(result, page_url),
        "eval": _eval,
        "Function": _Function,
        "setTimeout": _setTimeout,
        "setInterval": _setInterval,
        "alert": lambda *a: result.console.append("alert:" + str(a[0])[:200] if a else "alert"),
        "console": {
            "log": lambda *a: result.console.append(" ".join(str(x)[:200] for x in a)),
            "warn": lambda *a: None, "error": lambda *a: None,
        },
        "localStorage": storage_local,
        "sessionStorage": storage_session,
        "history": {
            "pushState": lambda *a: result.routes.append(
                "pushState:" + str(a[-1])[:200] if a else "pushState"),
            "replaceState": lambda *a: result.routes.append(
                "replaceState:" + str(a[-1])[:200] if a else "replaceState"),
        },
        "WebSocket": _ws_factory(result, page_url),
        "EventSource": _es_factory(result, page_url),
        "JSON": _json_mock(),
        "Math": _math_mock(),
        "Object": _object_mock(),
        "parseInt": _parse_int,
        "parseFloat": _parse_float,
        "isNaN": lambda v: v != v,
        "encodeURIComponent": _encode_uri_component,
        "decodeURIComponent": _decode_uri_component,
        "encodeURI": lambda s: str(s),
        "decodeURI": lambda s: str(s),
        "btoa": _btoa,
        "atob": _atob,
    })
    # common router globals — method calls record routes
    g["router"] = _router_mock(result)
    return g, result


def _router_mock(result: ExecutionResult):
    class Router:
        def push(self, r):
            result.routes.append("router.push:" + str(r)[:200])

        def replace(self, r):
            result.routes.append("router.replace:" + str(r)[:200])

        def addRoute(self, r):
            result.routes.append("router.addRoute:" + str(r)[:200])
    return Router()


def _ws_factory(result, page_url):
    def _ws(url, *a):
        result.api_calls.append({
            "method": "WS", "url": urljoin(page_url, str(url)),
            "body": "", "source": "WebSocket",
        })

        class WS:
            def send(self, d): pass

            def addEventListener(self, e, f): pass
        return WS()
    return _ws


def _es_factory(result, page_url):
    def _es(url, *a):
        result.api_calls.append({
            "method": "SSE", "url": urljoin(page_url, str(url)),
            "body": "", "source": "EventSource",
        })

        class ES:
            def addEventListener(self, e, f): pass
        return ES()
    return _es


# ---------------------------------------------------------------------------
# Standard library mocks (JSON, Math, Object, URI codecs, base64)
# ---------------------------------------------------------------------------
def _json_mock():
    import json as _json

    class JSON:
        @staticmethod
        def stringify(v):
            try:
                return _json.dumps(_plain(v))
            except Exception:
                return "{}"

        @staticmethod
        def parse(s):
            try:
                return _json.loads(str(s))
            except Exception:
                return None
    return JSON()


def _plain(v):
    if isinstance(v, dict):
        return {str(k): _plain(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_plain(x) for x in v]
    if v is UNDEFINED:
        return None
    return v


def _math_mock():
    import math as _math

    class Math:
        PI = _math.pi
        E = _math.e

        @staticmethod
        def floor(x): return _math.floor(float(x or 0))

        @staticmethod
        def ceil(x): return _math.ceil(float(x or 0))

        @staticmethod
        def round(x): return round(float(x or 0))

        @staticmethod
        def random(): return 0.5

        @staticmethod
        def max(*a): return max([float(x or 0) for x in a]) if a else 0

        @staticmethod
        def min(*a): return min([float(x or 0) for x in a]) if a else 0

        @staticmethod
        def abs(x): return abs(float(x or 0))

        @staticmethod
        def pow(x, y): return float(x or 0) ** float(y or 0)
    return Math()


def _object_mock():
    class Object:
        @staticmethod
        def keys(o):
            return list(o.keys()) if isinstance(o, dict) else []

        @staticmethod
        def values(o):
            return list(o.values()) if isinstance(o, dict) else []

        @staticmethod
        def assign(tgt, *srcs):
            if isinstance(tgt, dict):
                for s in srcs:
                    if isinstance(s, dict):
                        tgt.update(s)
            return tgt
    return Object()


def _parse_int(s, radix=10):
    import re as _re
    m = _re.match(r"\s*[+-]?\d+", str(s))
    try:
        return int(m.group(0), int(radix or 10)) if m else float("nan")
    except ValueError:
        return float("nan")


def _parse_float(s):
    import re as _re
    m = _re.match(r"\s*[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?", str(s))
    try:
        return float(m.group(0)) if m else float("nan")
    except ValueError:
        return float("nan")


def _encode_uri_component(s):
    from urllib.parse import quote as _q
    return _q(str(s), safe="A-Za-z0-9_.!~*'()-")


def _decode_uri_component(s):
    from urllib.parse import unquote as _uq
    try:
        return _uq(str(s))
    except Exception:
        return str(s)


def _btoa(s):
    import base64 as _b64
    return _b64.b64encode(str(s).encode("latin-1", "replace")).decode()


def _atob(s):
    import base64 as _b64
    try:
        return _b64.b64decode(str(s)).decode("latin-1", "replace")
    except Exception:
        return ""
