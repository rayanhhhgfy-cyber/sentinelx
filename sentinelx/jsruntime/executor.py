"""SentinelX jsruntime.executor: run page JavaScript in js2py.

``execute()`` runs JS against the mock browser environment and returns a
structured ``ExecutionResult``. It NEVER raises — a broken script, a hung
script, or an unsupported API cannot crash the scan.

Safety controls:
- per-script byte size limit (skip pathological bundles)
- wall-clock timeout via worker thread (abandoned, never joined-killed)
- recursion limit inside the worker
- all js2py exceptions captured into result.errors
"""

from __future__ import annotations

import concurrent.futures
import sys
import time
from dataclasses import dataclass, field

from . import mock as _mock


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


def _to_python(value, _depth: int = 0):
    """Convert js2py values to plain Python (dicts/lists/strs).

    js2py wraps both arrays and objects as JsObjectWrapper with both
    to_list() and to_dict(). Arrays are detected via to_list(); plain
    objects fall back to to_dict().
    """
    if _depth > 8:
        return str(value)[:500]
    try:
        if hasattr(value, "to_list") and hasattr(value, "to_dict"):
            try:
                l = value.to_list()
            except Exception:
                l = None
            # to_list() on a plain object returns []; on an array returns items.
            # Disambiguate via to_dict(): dense numeric keys => array.
            if l:
                return [_to_python(v, _depth + 1) for v in l]
            try:
                d = value.to_dict()
            except Exception:
                return str(value)[:500]
            if d and all(str(k).isdigit() for k in d.keys()):
                # array-like (possibly empty)
                return [_to_python(d[k], _depth + 1)
                        for k in sorted(d.keys(), key=int)]
            return {str(k): _to_python(v, _depth + 1) for k, v in d.items()}
        if hasattr(value, "to_dict"):
            try:
                d = value.to_dict()
            except Exception:
                return str(value)[:500]
            return {str(k): _to_python(v, _depth + 1) for k, v in d.items()}
        if hasattr(value, "to_list"):
            try:
                l = value.to_list()
            except Exception:
                return str(value)[:500]
            return [_to_python(v, _depth + 1) for v in l]
    except Exception:
        pass
    if isinstance(value, (dict, list, str, int, float, bool)) or value is None:
        if isinstance(value, dict):
            return {str(k): _to_python(v, _depth + 1) for k, v in value.items()}
        if isinstance(value, list):
            return [_to_python(v, _depth + 1) for v in value]
        return value
    try:
        return str(value)[:2000]
    except Exception:
        return "<unprintable>"


def _rewrite_dangerous_calls(js: str) -> str:
    """Rewrite bare eval(/Function( calls to interceptable __sx_* versions.

    js2py treats ``eval`` and the ``Function`` constructor as special
    forms, so preamble overrides are bypassed. We rewrite them in the
    page source instead. String literals and comments are left untouched
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
        # regex literal heuristic: /.../  (skip; rare in our context, and
        # rewriting inside regex is harmless as we only match eval(/Function()
        # identifier patterns which cannot validly appear bare in regex)
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
                if p >= 0 and js[p:p + 3] == "new":
                    # 'new Function(' -> 'new __sx_Function('
                    out.append("__sx_Function")
                else:
                    out.append("__sx_Function")
                i = j
                continue
            out.append(word)
            i = j
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _run_in_worker(preamble: str, js_code: str) -> tuple[list, list]:
    """Execute JS in this thread. Returns (trace, errors)."""
    import js2py

    errors: list[str] = []
    # Bound Python recursion: page JS recursion becomes Python recursion.
    old_limit = sys.getrecursionlimit()
    try:
        sys.setrecursionlimit(5000)
    except Exception:
        pass
    try:
        ctx = js2py.EvalJs({})
        ctx.execute(preamble)
        try:
            ctx.execute(_rewrite_dangerous_calls(js_code))
        except Exception as e:  # noqa: BLE001 — capture, never propagate
            errors.append(f"{type(e).__name__}: {str(e)[:300]}")
        # Extract the trace
        trace: list = []
        try:
            raw = ctx.__sx_trace
            trace = _to_python(raw) or []
            if not isinstance(trace, list):
                trace = []
        except Exception as e:  # noqa: BLE001
            errors.append(f"trace-extract: {type(e).__name__}: {str(e)[:200]}")
        return trace, errors
    finally:
        try:
            sys.setrecursionlimit(old_limit)
        except Exception:
            pass


def execute(js_code: str, page_url: str = "",
            hash_canary: str = "SX_CANARY",
            search_canary: str = "SX_CANARY",
            timeout: float = 10.0,
            max_script_bytes: int = 200_000) -> ExecutionResult:
    """Execute JS in the virtual browser. Never raises.

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

    preamble = _mock.build_preamble(page_url, hash_canary, search_canary)

    trace: list = []
    errors: list[str] = []
    # NOTE: not a context manager — on timeout we shutdown(wait=False) so an
    # abandoned infinite-loop worker never blocks the scan.
    pool = concurrent.futures.ThreadPoolExecutor(
        max_workers=1, thread_name_prefix="sx-js")
    try:
        fut = pool.submit(_run_in_worker, preamble, js_code)
        try:
            trace, errors = fut.result(timeout=timeout)
            result.executed = True
        except concurrent.futures.TimeoutError:
            fut.cancel()
            errors.append(f"timeout after {timeout:.1f}s; worker abandoned")
            result.executed = False
        except Exception as e:  # noqa: BLE001
            errors.append(f"worker: {type(e).__name__}: {str(e)[:200]}")
    finally:
        try:
            pool.shutdown(wait=False, cancel_futures=True)
        except Exception:
            pass

    result.trace = trace if isinstance(trace, list) else []
    result.errors = errors
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
