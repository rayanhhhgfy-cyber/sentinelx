"""SentinelX jsruntime.executor: run page JavaScript in node.

``execute()`` runs JS against the mock browser environment and returns a
structured ``ExecutionResult``. It NEVER raises — a broken script, a hung
script, or an unsupported API cannot crash the scan.

Safety controls:
- per-script byte size limit (skip pathological bundles)
- wall-clock timeout via subprocess (node is SIGKILLed on timeout)
- node-only globals shadowed in the preamble (process/require/Buffer...)
- all node errors captured into result.errors
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from . import node_exec as _node


@dataclass
class ExecutionResult:
    executed: bool = False
    trace: list = field(default_factory=list)      # raw __sx_trace entries
    api_calls: list = field(default_factory=list)  # net:fetch / net:xhr
    dom_writes: list = field(default_factory=list)  # sink:innerHTML etc.
    eval_calls: list = field(default_factory=list)  # sink:eval / Function
    routes: list = field(default_factory=list)     # nav:* route changes
    websockets: list = field(default_factory=list)
    storage_access: list = field(default_factory=list)
    unsupported: list = field(default_factory=list)  # unsupported API hits
    errors: list = field(default_factory=list)
    elapsed: float = 0.0


# trace kind -> result bucket
_BUCKET = (
    ("net:fetch", "api_calls"), ("net:xhr-open", "api_calls"),
    ("net:xhr-send", "api_calls"),
    ("sink:innerHTML", "dom_writes"), ("sink:outerHTML", "dom_writes"),
    ("sink:document.write", "dom_writes"), ("sink:js-url-attr", "dom_writes"),
    ("sink:eval", "eval_calls"), ("sink:Function", "eval_calls"),
    ("sink:setTimeout-string", "eval_calls"), ("sink:setInterval-string", "eval_calls"),
    ("nav:pushState", "routes"), ("nav:replaceState", "routes"),
    ("nav:assign", "routes"), ("nav:replace", "routes"),
    ("net:websocket", "websockets"), ("net:websocket-send", "websockets"),
    ("storage:", "storage_access"),
    ("unsupported", "unsupported"),
)


def _bucket_for(kind: str) -> str | None:
    for prefix, bucket in _BUCKET:
        if kind.startswith(prefix):
            return bucket
    return None


def _rewrite_dangerous_calls(js: str) -> str:
    """Rewrite bare eval(/Function( calls to interceptable __sx_* versions.

    The preamble defines __sx_eval/__sx_Function (record-only, never
    execute). We rewrite them in the page source instead of relying on
    global overrides. String literals and comments are left untouched
    via a small state-machine tokenizer.
    """
    out: list[str] = []
    i, n = 0, len(js)
    while i < n:
        c = js[i]
        # string literals
        if c in ("'", '"'):
            quote = c
            out.append(c)
            i += 1
            while i < n:
                if js[i] == "\\" and i + 1 < n:
                    out.append(js[i:i + 2])
                    i += 2
                    continue
                out.append(js[i])
                if js[i] == quote:
                    i += 1
                    break
                i += 1
            continue
        # template literals (node supports ES6; treat like strings)
        if c == "`":
            out.append(c)
            i += 1
            while i < n:
                if js[i] == "\\" and i + 1 < n:
                    out.append(js[i:i + 2])
                    i += 2
                    continue
                if js[i] == "$" and i + 1 < n and js[i + 1] == "{":
                    # ${...} interpolation — copy balanced braces verbatim
                    # but still rewrite eval/ inside via recursion
                    out.append("${")
                    i += 2
                    depth = 1
                    start = i
                    while i < n and depth > 0:
                        if js[i] == "{":
                            depth += 1
                        elif js[i] == "}":
                            depth -= 1
                        i += 1
                    inner = js[start:i - 1]
                    out.append(_rewrite_dangerous_calls(inner))
                    out.append("}")
                    continue
                out.append(js[i])
                if js[i] == "`":
                    i += 1
                    break
                i += 1
            continue
        # comments
        if c == "/" and i + 1 < n and js[i + 1] == "/":
            j = js.find("\n", i)
            j = n if j == -1 else j
            out.append(js[i:j])
            i = j
            continue
        if c == "/" and i + 1 < n and js[i + 1] == "*":
            j = js.find("*/", i + 2)
            j = n if j == -1 else j + 2
            out.append(js[i:j])
            i = j
            continue
        # identifier check
        if c.isalpha() or c in ("_", "$"):
            j = i + 1
            while j < n and (js[j].isalnum() or js[j] in ("_", "$")):
                j += 1
            word = js[i:j]
            # lookahead for '(' skipping whitespace
            k = j
            while k < n and js[k] in (" \t\r\n"):
                k += 1
            if word == "eval" and k < n and js[k] == "(":
                # make sure it's not obj.eval (property access)
                p = i - 1
                while p >= 0 and js[p] in (" \t\r\n"):
                    p -= 1
                if p < 0 or js[p] != ".":
                    out.append("__sx_eval")
                    i = j
                    continue
            if word == "Function" and k < n and js[k] == "(":
                p = i - 1
                while p >= 0 and js[p] in (" \t\r\n"):
                    p -= 1
                if p < 0 or js[p] not in (".",):
                    out.append("__sx_Function")
                    i = j
                    continue
            out.append(word)
            i = j
            continue
        out.append(c)
        i += 1
    return "".join(out)


def execute(js_code: str, page_url: str = "",
            hash_canary: str = "SX_CANARY",
            search_canary: str = "SX_CANARY",
            timeout: float = 10.0,
            max_script_bytes: int = 200_000) -> ExecutionResult:
    """Execute JS in the virtual browser (node). Never raises.

    Returns ExecutionResult with categorized observations.
    """
    result = ExecutionResult()
    start = time.monotonic()

    if not js_code or not js_code.strip():
        return result
    if len(js_code.encode("utf-8", "replace")) > max_script_bytes:
        result.errors.append(
            f"script too large ({len(js_code)} chars > {max_script_bytes}); skipped")
        return result

    rewritten = _rewrite_dangerous_calls(js_code)
    trace, errors = _node.execute_js_node(
        rewritten, page_url=page_url,
        hash_canary=hash_canary, search_canary=search_canary,
        timeout=timeout,
    )

    result.trace = trace if isinstance(trace, list) else []
    result.errors = errors
    # executed=True when node ran and dumped a trace (even an empty one).
    # A timeout or spawn failure leaves executed=False.
    result.executed = not any(
        e.startswith("timeout after") or e.startswith("node not found")
        or e.startswith("node spawn") or e.startswith("temp file")
        for e in errors
    ) or bool(trace)
    for entry in result.trace:
        if not isinstance(entry, dict):
            continue
        bucket = _bucket_for(str(entry.get("kind", "")))
        if bucket:
            getattr(result, bucket).append(entry)
    result.elapsed = time.monotonic() - start
    return result


def execute_scripts(scripts: list[str], page_url: str = "",
                    hash_canary: str = "SX_CANARY",
                    search_canary: str = "SX_CANARY",
                    timeout: float = 15.0,
                    max_script_bytes: int = 200_000) -> ExecutionResult:
    """Execute multiple <script> blocks sharing one virtual browser session.

    Later scripts see globals set by earlier ones, like a real page.
    Joined with a safe separator; per-script size cap still applies to the
    total. Never raises.
    """
    kept: list[str] = []
    total = 0
    for js in scripts:
        if not js or not js.strip():
            continue
        stripped = js.strip()
        # skip obvious JSON blobs / non-code script types
        if (stripped.startswith("{") and stripped.endswith("}")
                and "function" not in stripped):
            continue
        b = len(js.encode("utf-8", "replace"))
        if total + b > max_script_bytes:
            break
        kept.append(js)
        total += b
    if not kept:
        return ExecutionResult()
    combined = "\n;\n".join(kept)
    return execute(combined, page_url, hash_canary, search_canary,
                   timeout=timeout, max_script_bytes=max_script_bytes)
