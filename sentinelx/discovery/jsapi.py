"""SentinelX discovery: deep JS/HTML API extraction.

Reconstructs COMPLETE API calls from JavaScript + HTML — not just URLs,
but method, headers, query params, body fields, and content type.

Everything here is DISCOVERED (parsed from the target's own code), never
guessed. Results are cached by content hash so a bundle is parsed once.

Output: ApiCall {method, url, path_params, query_params, headers,
body_fields, body_raw, content_type, source_file, source_line}
"""

from __future__ import annotations

import hashlib
import json as _json
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, parse_qsl


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------

@dataclass
class ApiCall:
    method: str = "GET"
    url: str = ""                        # raw URL as found (may be relative)
    path_params: list = field(default_factory=list)   # ["id"] for /api/u/{id}
    query_params: dict = field(default_factory=dict)  # {name: example}
    headers: dict = field(default_factory=dict)       # {name: value|<redacted>}
    body_fields: dict = field(default_factory=dict)   # {name: example}
    body_raw: str = ""                   # raw body example (truncated)
    content_type: str = ""               # application/json etc.
    source_file: str = ""
    source_line: int = 0
    validated: bool = False              # set True after a live replay succeeds

    def resolved_url(self, base_url: str) -> str:
        """Absolute URL with {param} placeholders substituted by '1'."""
        u = self.url
        u = re.sub(r"\{[^}]*\}", "1", u)
        return urljoin(base_url, u)

    def secret_headers(self) -> list[str]:
        return [k for k, v in self.headers.items() if v == "<redacted>"]


# ---------------------------------------------------------------------------
# Value redaction (keep structure, hide secrets)
# ---------------------------------------------------------------------------

_SECRET_NAME_RE = re.compile(
    r"authorization|api[-_ ]?key|x-api-key|token|secret|password|passwd|"
    r"auth[-_ ]?token|bearer|private[-_ ]?key", re.I)


def redact_value(name: str, value: str) -> str:
    if _SECRET_NAME_RE.search(name or ""):
        return "<redacted>"
    return value


# ---------------------------------------------------------------------------
# Tiny JS-aware helpers: balanced delimiters, string unquoting, var resolve
# ---------------------------------------------------------------------------

def _balanced(text: str, start: int) -> tuple[str, int]:
    """Return (inner_text, index_after_closer) for the bracket at `start`.

    Handles '...' "..." `...` (with ${} nesting), regex-safe enough for
    API-call extraction. Never raises.
    """
    if start >= len(text):
        return "", start
    pairs = {"{": "}", "(": ")", "[": "]"}
    opener = text[start]
    closer = pairs.get(opener)
    if not closer:
        return "", start
    depth = 0
    i = start
    n = len(text)
    while i < n:
        c = text[i]
        if c in ("'", '"'):
            i += 1
            while i < n:
                if text[i] == "\\" and i + 1 < n:
                    i += 2
                    continue
                if text[i] == c:
                    i += 1
                    break
                i += 1
            continue
        if c == "`":
            i += 1
            while i < n:
                if text[i] == "\\" and i + 1 < n:
                    i += 2
                    continue
                if text[i] == "$" and i + 1 < n and text[i + 1] == "{":
                    inner, i = _balanced(text, i + 1)
                    continue
                if text[i] == "`":
                    i += 1
                    break
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            # line comment: skip to EOL (avoid treating / as bracket noise)
            while i < n and text[i] != "\n":
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2
            continue
        if c == opener:
            depth += 1
        elif c == closer:
            depth -= 1
            if depth == 0:
                return text[start + 1:i], i + 1
        i += 1
    return text[start + 1:], n


def _unquote(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
        try:
            return s[1:-1].encode().decode("unicode_escape")
        except Exception:
            return s[1:-1]
    return s


def _split_top_commas(text: str) -> list[str]:
    """Split on commas at depth 0 (strings/template literals respected)."""
    parts, depth, cur = [], 0, []
    i, n = 0, len(text)
    quote = None
    while i < n:
        c = text[i]
        if quote:
            cur.append(c)
            if c == "\\" and i + 1 < n:
                cur.append(text[i + 1]); i += 2; continue
            if c == quote:
                quote = None
            i += 1
            continue
        if c in ("'", '"'):
            quote = c; cur.append(c); i += 1; continue
        if c == "`":
            # template literal: consume whole thing
            j = i + 1
            while j < n:
                if text[j] == "\\" and j + 1 < n:
                    j += 2; continue
                if text[j] == "$" and j + 1 < n and text[j + 1] == "{":
                    inner, j = _balanced(text, j + 1)
                    continue
                if text[j] == "`":
                    j += 1; break
                j += 1
            cur.append(text[i:j]); i = j; continue
        if c in "({[":
            depth += 1
        elif c in ")}]":
            depth = max(0, depth - 1)
        if c == "," and depth == 0:
            parts.append("".join(cur)); cur = []
        else:
            cur.append(c)
        i += 1
    parts.append("".join(cur))
    return parts


def _parse_js_object_literal(text: str) -> dict:
    """Parse a flat-ish JS object literal into {key: value}.

    Values become Python values for literals, or markers:
      <var:name>      identifier reference
      <template:...>  template literal with substitutions
      <call:...>      call expression (e.g. JSON.stringify result unknown)
    Nested objects/arrays are parsed recursively when simple.
    """
    out: dict = {}
    text = text.strip()
    if text.startswith("{"):
        text, _ = _balanced(text, 0)
    for part in _split_top_commas(text):
        part = part.strip()
        if not part or ":" not in part:
            continue
        # split on first top-level colon
        ki = part.find(":")
        # ensure the colon isn't inside a nested structure before depth 0
        # (cheap check: recompute via split_top on ':' is overkill; the
        # first colon at depth 0 is what we want)
        depth, quote, ki = 0, None, -1
        j = 0
        while j < len(part):
            c = part[j]
            if quote:
                if c == "\\" and j + 1 < len(part):
                    j += 2; continue
                if c == quote:
                    quote = None
                j += 1; continue
            if c in ("'", '"', "`"):
                quote = c; j += 1; continue
            if c in "({[":
                depth += 1
            elif c in ")}]":
                depth = max(0, depth - 1)
            elif c == ":" and depth == 0:
                ki = j; break
            j += 1
        if ki < 0:
            continue
        raw_key, raw_val = part[:ki].strip(), part[ki + 1:].strip()
        key = _unquote(raw_key)
        if not key or not re.match(r"^[A-Za-z_$][\w$-]*$", key):
            continue
        out[key] = _parse_js_value(raw_val)
    return out


def _parse_js_value(raw: str):
    raw = raw.strip()
    if not raw:
        return ""
    if raw[0] in ("'", '"'):
        return _unquote(raw)
    if raw.startswith("`"):
        return _parse_template(raw)
    if raw in ("true", "false"):
        return raw == "true"
    if raw in ("null", "undefined"):
        return None
    if re.match(r"^-?\d+(\.\d+)?$", raw):
        try:
            return int(raw) if "." not in raw else float(raw)
        except ValueError:
            return raw
    if raw.startswith("{"):
        inner, _ = _balanced(raw, 0)
        return _parse_js_object_literal(inner)
    if raw.startswith("["):
        inner, _ = _balanced(raw, 0)
        return [_parse_js_value(p) for p in _split_top_commas(inner) if p.strip()]
    m = re.match(r"^JSON\.stringify\s*\(", raw)
    if m:
        inner, _ = _balanced(raw, m.end() - 1)
        if inner.strip().startswith("{"):
            return _parse_js_object_literal(inner)
        return f"<json:{inner.strip()[:80]}>"
    if re.match(r"^[A-Za-z_$][\w$]*$", raw):
        return f"<var:{raw}>"
    if re.match(r"^[A-Za-z_$][\w$]*\s*\(", raw):
        return f"<call:{raw[:60]}>"
    return raw[:120]


def _parse_template(raw: str):
    """Template literal -> string with ${expr} kept as {expr} markers."""
    raw = raw.strip()
    if not (raw.startswith("`") and raw.endswith("`") and len(raw) >= 2):
        return raw
    inner = raw[1:-1]
    out = []
    i = 0
    while i < len(inner):
        if inner[i] == "$" and i + 1 < len(inner) and inner[i + 1] == "{":
            expr, i = _balanced(inner, i + 1)
            out.append("{" + expr.strip() + "}")
            continue
        out.append(inner[i])
        i += 1
    return "<template:" + "".join(out) + ">"


def _resolve_var(js_text: str, name: str, limit: int = 20000) -> str | None:
    """Try to resolve `name` to a literal assigned nearby in the file."""
    name = name.strip()
    if not re.match(r"^[A-Za-z_$][\w$]*$", name):
        return None
    scope = js_text[:limit]
    for m in re.finditer(
            r"(?:var|let|const)\s+" + re.escape(name) + r"\s*=\s*('[^']*'|\"[^\"]*\"|\d+)",
            scope):
        return _unquote(m.group(1))
    return None


def _resolve_object_var(js_text: str, name: str, limit: int = 40000) -> dict | None:
    """Resolve `var name = { ... }` to a parsed object (values may be markers)."""
    name = name.strip()
    if not re.match(r"^[A-Za-z_$][\w$]*$", name):
        return None
    scope = js_text[:limit]
    for m in re.finditer(
            r"(?:var|let|const)\s+" + re.escape(name) + r"\s*=\s*\{", scope):
        try:
            inner, _ = _balanced(scope, m.end() - 1)
            return _parse_js_object_literal(inner)
        except Exception:
            continue
    return None


def _split_concat(expr: str) -> list[str]:
    """Split a JS expression on top-level '+' (string/template aware)."""
    parts, depth, cur = [], 0, []
    i, n = 0, len(expr)
    quote = None
    while i < n:
        c = expr[i]
        if quote:
            cur.append(c)
            if c == "\\" and i + 1 < n:
                cur.append(expr[i + 1]); i += 2; continue
            if c == quote:
                quote = None
            i += 1
            continue
        if c in ("'", '"'):
            quote = c; cur.append(c); i += 1; continue
        if c == "`":
            j = i + 1
            while j < n:
                if expr[j] == "\\" and j + 1 < n:
                    j += 2; continue
                if expr[j] == "$" and j + 1 < n and expr[j + 1] == "{":
                    _, j = _balanced(expr, j + 1)
                    continue
                if expr[j] == "`":
                    j += 1; break
                j += 1
            cur.append(expr[i:j]); i = j; continue
        if c in "({[":
            depth += 1
        elif c in ")}]":
            depth = max(0, depth - 1)
        if c == "+" and depth == 0:
            parts.append("".join(cur)); cur = []
        else:
            cur.append(c)
        i += 1
    parts.append("".join(cur))
    return parts


def _resolve_template_part(part: str, js_text: str,
                           path_params: list[str]) -> str:
    """Resolve one template literal part, substituting ${expr}."""
    parsed = _parse_template(part)
    if not parsed.startswith("<template:"):
        return part
    body = parsed[len("<template:"):-1]

    def _repl(m):
        expr = m.group(1).strip()
        resolved = _resolve_var(js_text, expr)
        if resolved is not None:
            return resolved
        if expr not in path_params:
            path_params.append(expr)
        return "{" + expr + "}"

    return re.sub(r"\{([^{}]+)\}", _repl, body)


def _resolve_url_expr(js_text: str, expr: str) -> tuple[str, list[str]]:
    """Resolve a JS URL expression to a URL string with {param} placeholders.

    Returns (url, path_params). Handles string literals, template literals,
    and + concatenation with best-effort variable resolution.
    """
    expr = expr.strip()
    path_params: list[str] = []

    def _sub_var(name: str) -> str:
        name = name.strip()
        resolved = _resolve_var(js_text, name)
        if resolved is not None:
            return resolved
        if name not in path_params:
            path_params.append(name)
        return "{" + name + "}"

    def _is_single_literal(s: str) -> str | None:
        """If s is exactly one string/template literal, return its kind."""
        s = s.strip()
        if len(s) < 2:
            return None
        q = s[0]
        if q in ("'", '"'):
            i = 1
            while i < len(s):
                if s[i] == "\\" and i + 1 < len(s):
                    i += 2
                    continue
                if s[i] == q:
                    return q if s[i + 1:].strip() == "" else None
                i += 1
            return None
        if q == "`":
            j = 1
            while j < len(s):
                if s[j] == "\\" and j + 1 < len(s):
                    j += 2
                    continue
                if s[j] == "$" and j + 1 < len(s) and s[j + 1] == "{":
                    _, j = _balanced(s, j + 1)
                    continue
                if s[j] == "`":
                    return q if s[j + 1:].strip() == "" else None
                j += 1
        return None

    # pure string literal
    if _is_single_literal(expr) in ("'", '"'):
        return _unquote(expr), path_params
    # pure template literal
    if _is_single_literal(expr) == "`":
        return _resolve_template_part(expr, js_text, path_params), path_params
    # concatenation / mixed expression
    parts = _split_concat(expr)
    if len(parts) == 1:
        p = parts[0].strip()
        if re.match(r"^[A-Za-z_$][\w$]*$", p):
            return _sub_var(p), path_params
        return p[:200], path_params
    out = []
    for p in parts:
        p = p.strip()
        if not p:
            continue
        kind = _is_single_literal(p)
        if kind in ("'", '"'):
            out.append(_unquote(p))
        elif kind == "`":
            out.append(_resolve_template_part(p, js_text, path_params))
        elif re.match(r"^[A-Za-z_$][\w$]*$", p):
            out.append(_sub_var(p))
        elif p:
            out.append(p[:60])
    return "".join(out), path_params


# ---------------------------------------------------------------------------
# Call-site regexes
# ---------------------------------------------------------------------------

_FETCH_RE = re.compile(r"(?<![\w$.])fetch\s*\(")
_AXIOS_RE = re.compile(r"axios\.(get|post|put|delete|patch|head|options)\s*\(")
_AXIOS_CFG_RE = re.compile(r"(?<![\w$.])axios\s*\(")
_AJAX_RE = re.compile(r"\$\.ajax\s*\(")
_XHR_NEW_RE = re.compile(r"(\w+)\s*=\s*new\s+XMLHttpRequest\s*\(")
_FORMDATA_APPEND_RE = re.compile(
    r"(\w+)\.append\s*\(\s*([\"'])(.*?)\2\s*,\s*([^)]+?)\)")


def _line_no(js_text: str, idx: int) -> int:
    return js_text.count("\n", 0, idx) + 1


def _call_args(js_text: str, open_paren_idx: int) -> tuple[list[str], int]:
    """Split call args at open_paren_idx. Returns (args, index_after_close)."""
    inner, end = _balanced(js_text, open_paren_idx)
    return _split_top_commas(inner), end


# ---------------------------------------------------------------------------
# Body / headers extraction from parsed option objects
# ---------------------------------------------------------------------------

def _extract_headers_dict(obj: dict) -> dict:
    headers = {}
    for k, v in obj.items():
        if isinstance(v, str) and not v.startswith("<"):
            headers[k] = redact_value(k, v)
        elif isinstance(v, str) and v.startswith("<var:"):
            headers[k] = "<redacted>" if _SECRET_NAME_RE.search(k) else v
        else:
            headers[k] = redact_value(k, str(v)[:120])
    return headers


def _extract_body_fields(value) -> tuple[dict, str]:
    """Return (fields, raw_example) from a body value."""
    fields: dict = {}

    def _example(v):
        if isinstance(v, str):
            # code expressions / markers are not usable examples
            if v.startswith("<") or "(" in v or ")" in v:
                return "test"
            return v
        if isinstance(v, bool):
            return v
        if isinstance(v, (int, float)):
            return v
        if v is None:
            return ""
        if isinstance(v, (dict, list)):
            return _json.dumps(v)[:120]
        return str(v)[:120]

    raw = ""
    if isinstance(value, dict):
        for k, v in value.items():
            fields[k] = _example(v)
        raw = _json.dumps({k: v for k, v in fields.items()})[:500]
    elif isinstance(value, str):
        if value.startswith("<var:"):
            raw = value
        elif value.startswith("<json:"):
            raw = value
        else:
            raw = value[:500]
            # url-encoded body?
            if "=" in raw and "&" in raw:
                for pair in raw.split("&"):
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        fields[k.strip()] = v.strip() or "test"
    return fields, raw


def _flatten_query(url: str) -> tuple[str, dict]:
    """Split query string off a URL -> (clean_url, {param: example})."""
    from urllib.parse import urlunsplit as _uu
    u = urlsplit(url)
    q = dict(parse_qsl(u.query, keep_blank_values=True))
    clean = _uu((u.scheme, u.netloc, u.path, "", u.fragment))
    return clean, {k: (v or "test") for k, v in q.items()}


# ---------------------------------------------------------------------------
# Main static extractor
# ---------------------------------------------------------------------------

def _finalize(call: ApiCall, base_url: str) -> ApiCall | None:
    if not call.url:
        return None
    call.url, qs = _flatten_query(call.url)
    for k, v in qs.items():
        call.query_params.setdefault(k, v)
    # placeholders that landed in the query string are query params, not path params
    call.path_params = [p for p in call.path_params if p not in call.query_params]
    # content-type inference
    hdrs_lower = {k.lower(): v for k, v in call.headers.items()}
    if "content-type" in hdrs_lower:
        call.content_type = hdrs_lower["content-type"]
    elif call.body_fields:
        call.content_type = "application/json"
    # absolutize for sanity (keep raw too — resolved at use time)
    if base_url and not urlsplit(call.url).netloc \
            and not call.url.startswith(("http", "//")):
        call.url = urljoin(base_url, call.url)
    return call


def extract_api_calls(js_text: str, base_url: str = "",
                      source_file: str = "") -> list[ApiCall]:
    """Deep-extract complete API calls from JS source. Never raises."""
    calls: list[ApiCall] = []
    if not js_text or len(js_text) > 1_000_000:
        return calls
    try:
        calls.extend(_extract_fetch(js_text, base_url, source_file))
        calls.extend(_extract_axios(js_text, base_url, source_file))
        calls.extend(_extract_ajax(js_text, base_url, source_file))
        calls.extend(_extract_xhr(js_text, base_url, source_file))
    except Exception:
        pass
    # dedupe by (method, url)
    seen, out = set(), []
    for c in calls:
        key = (c.method, c.url)
        if key not in seen:
            seen.add(key)
            out.append(c)
    return out


def _extract_fetch(js_text, base_url, source_file):
    out = []
    for m in _FETCH_RE.finditer(js_text):
        try:
            paren = js_text.index("(", m.end() - 1)
            args, _ = _call_args(js_text, paren)
            if not args:
                continue
            url, path_params = _resolve_url_expr(js_text, args[0])
            call = ApiCall(method="GET", url=url, path_params=path_params,
                           source_file=source_file,
                           source_line=_line_no(js_text, m.start()))
            if len(args) > 1 and args[1].strip().startswith("{"):
                opts = _parse_js_object_literal(args[1])
                if isinstance(opts.get("method"), str):
                    call.method = opts["method"].upper()
                if isinstance(opts.get("headers"), dict):
                    call.headers.update(_extract_headers_dict(opts["headers"]))
                if "body" in opts:
                    fields, raw = _extract_body_fields(opts["body"])
                    if not fields and isinstance(opts["body"], str):
                        # body: someVar -> resolve `var someVar = {...}`
                        vm = re.match(r"^<var:([A-Za-z_$][\w$]*)>$", opts["body"])
                        if vm:
                            _obj = _resolve_object_var(js_text, vm.group(1))
                            if _obj:
                                fields, raw = _extract_body_fields(_obj)
                    call.body_fields.update(fields)
                    call.body_raw = raw
            fin = _finalize(call, base_url)
            if fin:
                out.append(fin)
        except Exception:
            continue
    return out


def _extract_axios(js_text, base_url, source_file):
    out = []
    # axios.get/post/...(url, data?, config?)
    for m in _AXIOS_RE.finditer(js_text):
        try:
            method = m.group(1).upper()
            paren = js_text.index("(", m.end() - 1)
            args, _ = _call_args(js_text, paren)
            if not args:
                continue
            url, path_params = _resolve_url_expr(js_text, args[0])
            call = ApiCall(method=method, url=url, path_params=path_params,
                           source_file=source_file,
                           source_line=_line_no(js_text, m.start()))
            # data arg
            if len(args) > 1:
                data = args[1].strip()
                if data.startswith("{"):
                    fields, raw = _extract_body_fields(
                        _parse_js_object_literal(data))
                    call.body_fields.update(fields)
                    call.body_raw = raw
                elif data.startswith("JSON.stringify"):
                    inner_m = re.match(r"JSON\.stringify\s*\(", data)
                    if inner_m:
                        inner, _ = _balanced(data, inner_m.end() - 1)
                        if inner.strip().startswith("{"):
                            fields, raw = _extract_body_fields(
                                _parse_js_object_literal(inner))
                            call.body_fields.update(fields)
                            call.body_raw = raw
            # config arg
            if len(args) > 2 and args[2].strip().startswith("{"):
                cfg = _parse_js_object_literal(args[2])
                if isinstance(cfg.get("headers"), dict):
                    call.headers.update(_extract_headers_dict(cfg["headers"]))
                if isinstance(cfg.get("params"), dict):
                    for k, v in cfg["params"].items():
                        call.query_params[k] = v if isinstance(v, str) and not v.startswith("<") else "test"
            fin = _finalize(call, base_url)
            if fin:
                out.append(fin)
        except Exception:
            continue
    # axios({method, url, headers, data, params})
    for m in _AXIOS_CFG_RE.finditer(js_text):
        try:
            paren = js_text.index("(", m.end() - 1)
            args, _ = _call_args(js_text, paren)
            if not args or not args[0].strip().startswith("{"):
                continue
            cfg = _parse_js_object_literal(args[0])
            raw_url = cfg.get("url")
            if not isinstance(raw_url, str):
                continue
            url, path_params = _resolve_url_expr(js_text, raw_url)
            call = ApiCall(
                method=str(cfg.get("method", "GET")).upper(), url=url,
                path_params=path_params, source_file=source_file,
                source_line=_line_no(js_text, m.start()))
            if isinstance(cfg.get("headers"), dict):
                call.headers.update(_extract_headers_dict(cfg["headers"]))
            if isinstance(cfg.get("params"), dict):
                for k, v in cfg["params"].items():
                    call.query_params[k] = v if isinstance(v, str) and not v.startswith("<") else "test"
            if "data" in cfg:
                fields, raw = _extract_body_fields(cfg["data"])
                call.body_fields.update(fields)
                call.body_raw = raw
            fin = _finalize(call, base_url)
            if fin:
                out.append(fin)
        except Exception:
            continue
    return out


def _extract_ajax(js_text, base_url, source_file):
    out = []
    for m in _AJAX_RE.finditer(js_text):
        try:
            paren = js_text.index("(", m.end() - 1)
            args, _ = _call_args(js_text, paren)
            if not args or not args[0].strip().startswith("{"):
                continue
            cfg = _parse_js_object_literal(args[0])
            raw_url = cfg.get("url")
            if not isinstance(raw_url, str):
                continue
            url, path_params = _resolve_url_expr(js_text, raw_url)
            method = str(cfg.get("type", cfg.get("method", "GET"))).upper()
            call = ApiCall(method=method, url=url, path_params=path_params,
                           source_file=source_file,
                           source_line=_line_no(js_text, m.start()))
            if isinstance(cfg.get("headers"), dict):
                call.headers.update(_extract_headers_dict(cfg["headers"]))
            ct = cfg.get("contentType") or cfg.get("content-type")
            if isinstance(ct, str):
                call.content_type = ct
            if "data" in cfg:
                fields, raw = _extract_body_fields(cfg["data"])
                call.body_fields.update(fields)
                call.body_raw = raw
            fin = _finalize(call, base_url)
            if fin:
                out.append(fin)
        except Exception:
            continue
    return out


def _extract_xhr(js_text, base_url, source_file):
    """Track `x = new XMLHttpRequest()` then x.open/setRequestHeader/send."""
    out = []
    for vm in _XHR_NEW_RE.finditer(js_text):
        var = vm.group(1)
        try:
            method, url, path_params = "GET", "", []
            headers: dict = {}
            body_fields: dict = {}
            body_raw = ""
            line = _line_no(js_text, vm.start())
            # open(
            for om in re.finditer(re.escape(var) + r"\.open\s*\(", js_text[vm.end():]):
                abs_pos = vm.end() + om.start()
                paren = abs_pos + om.group(0).index("(")
                args, _ = _call_args(js_text, paren)
                if len(args) >= 2:
                    method = _unquote(args[0]).upper() or "GET"
                    url, path_params = _resolve_url_expr(js_text, args[1])
                break
            if not url:
                continue
            # setRequestHeader(...)
            for hm in re.finditer(
                    re.escape(var) + r"\.setRequestHeader\s*\(", js_text[vm.end():]):
                abs_pos = vm.end() + hm.start()
                paren = abs_pos + hm.group(0).index("(")
                args, _ = _call_args(js_text, paren)
                if len(args) >= 2:
                    hn = _unquote(args[0])
                    hv = _unquote(args[1]) if args[1].strip()[0] in ("'", '"') \
                        else args[1].strip()[:80]
                    if hn:
                        headers[hn] = redact_value(hn, hv)
            # send(
            for sm in re.finditer(re.escape(var) + r"\.send\s*\(", js_text[vm.end():]):
                abs_pos = vm.end() + sm.start()
                paren = abs_pos + sm.group(0).index("(")
                args, _ = _call_args(js_text, paren)
                if args and args[0].strip():
                    body_expr = args[0].strip()
                    jm = re.match(r"JSON\.stringify\s*\(", body_expr)
                    if jm:
                        inner, _ = _balanced(body_expr, jm.end() - 1)
                        _parsed = None
                        if inner.strip().startswith("{"):
                            _parsed = _parse_js_object_literal(inner)
                        else:
                            # JSON.stringify(someVar) -> resolve the variable
                            vm = re.match(r"^([A-Za-z_$][\w$]*)$", inner.strip())
                            if vm:
                                _parsed = _resolve_object_var(js_text, vm.group(1))
                        if _parsed:
                            fields, raw = _extract_body_fields(_parsed)
                            body_fields.update(fields)
                            body_raw = raw
                        else:
                            body_raw = inner[:200]
                    elif body_expr[0] in ("'", '"'):
                        fields, raw = _extract_body_fields(_unquote(body_expr))
                        body_fields.update(fields)
                        body_raw = raw or _unquote(body_expr)[:200]
                    else:
                        # maybe a FormData variable: look for .append calls
                        vm2 = re.match(r"^(\w+)$", body_expr)
                        if vm2:
                            for am in _FORMDATA_APPEND_RE.finditer(js_text):
                                if am.group(1) == vm2.group(1):
                                    fkey = am.group(3)
                                    fval_expr = am.group(4).strip()
                                    if fval_expr[:1] in ("'", '"'):
                                        fval = _unquote(fval_expr)
                                    else:
                                        fval = "test"
                                    body_fields[fkey] = fval
                            if body_fields:
                                body_raw = _json.dumps(body_fields)[:300]
                break
            call = ApiCall(method=method, url=url, path_params=path_params,
                           headers=headers, body_fields=body_fields,
                           body_raw=body_raw, source_file=source_file,
                           source_line=line)
            fin = _finalize(call, base_url)
            if fin:
                out.append(fin)
        except Exception:
            continue
    return out


# ---------------------------------------------------------------------------
# Content-hash cache — never parse the same bundle twice
# ---------------------------------------------------------------------------

_PARSE_CACHE: dict[str, list[ApiCall]] = {}


def extract_api_calls_cached(js_text: str, base_url: str = "",
                             source_file: str = "") -> list[ApiCall]:
    """Cached wrapper. URLs stay as-found; resolve per base_url at use time.

    Note: base_url is baked into cached results via urljoin for relative
    URLs. Bundles are per-site so this is correct in practice; the cache
    key includes the base host to be safe.
    """
    host = urlsplit(base_url).netloc if base_url else ""
    key = hashlib.sha256((host + "\x00" + js_text).encode(
        "utf-8", "replace")).hexdigest()
    hit = _PARSE_CACHE.get(key)
    if hit is not None:
        return hit
    calls = extract_api_calls(js_text, base_url, source_file)
    # bound cache
    if len(_PARSE_CACHE) > 500:
        _PARSE_CACHE.clear()
    _PARSE_CACHE[key] = calls
    return calls


def cache_stats() -> dict:
    return {"entries": len(_PARSE_CACHE)}


# ---------------------------------------------------------------------------
# HTML API extraction: data-* attrs, embedded JSON, window.__DATA__, meta
# ---------------------------------------------------------------------------

class _ApiHtmlParser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__()
        self.base = base_url
        self.data_api_urls: list[str] = []
        self.embedded_json: list[str] = []
        self.meta_apis: list[str] = []
        self._in_json_script = False
        self._script_depth = 0

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "script":
            self._script_depth += 1
            if (a.get("type") or "").lower() == "application/json":
                self._in_json_script = True
        for k in ("data-api", "data-endpoint", "data-url", "data-action"):
            v = a.get(k)
            if v and isinstance(v, str) and (
                    v.startswith("/") or v.startswith("http")):
                self.data_api_urls.append(urljoin(self.base, v))
        if tag == "meta":
            name = (a.get("name") or a.get("property") or "").lower()
            content = a.get("content", "")
            if content and ("api" in name or "endpoint" in name):
                if content.startswith("/") or content.startswith("http"):
                    self.meta_apis.append(urljoin(self.base, content))

    def handle_endtag(self, tag):
        if tag == "script":
            self._script_depth = max(0, self._script_depth - 1)
            self._in_json_script = False

    def handle_data(self, data):
        if self._in_json_script and data.strip().startswith(("{", "[")):
            self.embedded_json.append(data.strip()[:20000])


_DATA_VAR_RE = re.compile(
    r"window\.__(?:DATA|INITIAL_STATE|APP_DATA|CONFIG)__\s*=\s*(\{)")


def extract_html_apis(html: str, base_url: str) -> list[ApiCall]:
    """Extract API references from HTML: data-* attrs, embedded JSON blobs,
    window.__DATA__ assignments, meta tags. Never raises."""
    calls: list[ApiCall] = []
    if not html:
        return calls
    try:
        p = _ApiHtmlParser(base_url)
        p.feed(html[:300_000])
        for u in p.data_api_urls:
            c, q = _flatten_query(u)
            calls.append(ApiCall(method="GET", url=c, query_params=q,
                                 source_file=base_url, source_line=0))
        for u in p.meta_apis:
            c, q = _flatten_query(u)
            calls.append(ApiCall(method="GET", url=c, query_params=q,
                                 source_file=base_url, source_line=0))
        # embedded JSON: mine URLs + treat JSON objects as body-shape intel
        for blob in p.embedded_json:
            try:
                data = _json.loads(blob)
            except Exception:
                continue
            for u in _mine_urls_in_obj(data):
                c, q = _flatten_query(urljoin(base_url, u))
                calls.append(ApiCall(method="GET", url=c, query_params=q,
                                     source_file=base_url, source_line=0))
        # window.__DATA__ = {...}
        for m in _DATA_VAR_RE.finditer(html):
            inner, _ = _balanced(html, m.end() - 1)
            try:
                data = _json.loads(inner)
            except Exception:
                continue
            for u in _mine_urls_in_obj(data):
                c, q = _flatten_query(urljoin(base_url, u))
                calls.append(ApiCall(method="GET", url=c, query_params=q,
                                     source_file=base_url, source_line=0))
    except Exception:
        pass
    return calls


def _mine_urls_in_obj(data, _depth=0) -> list[str]:
    out = []
    if _depth > 4:
        return out
    if isinstance(data, str):
        if re.match(r"^(/|https?://)[\w\-./?=&%#]+$", data) and len(data) > 2:
            # only API-ish paths, not asset links
            if re.search(r"/api/|/v\d+/|/rest/|endpoint|graphql", data, re.I):
                out.append(data)
    elif isinstance(data, dict):
        for v in data.values():
            out.extend(_mine_urls_in_obj(v, _depth + 1))
    elif isinstance(data, list):
        for v in data:
            out.extend(_mine_urls_in_obj(v, _depth + 1))
    return out
