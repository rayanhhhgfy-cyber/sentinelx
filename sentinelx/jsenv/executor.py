"""SentinelX jsenv: high-level JS execution API.

execute_js() runs page JavaScript inside the virtual browser and returns
everything observed: API calls, DOM writes (with taint), eval calls, routes.
Never raises — worst case returns an empty ExecutionResult with errors logged.
"""

from __future__ import annotations

import time

from .jsinterp import Interpreter
from .mock import build_globals, ExecutionResult


# js2py intentionally NOT used (broken on Python 3.11+). The built-in
# jsinterp interpreter is the execution engine — pure Python, no deps.
_JS2PY_AVAILABLE = False


def execute_js(js_code: str, page_url: str = "",
               hash_canary: str = "#SX_CANARY_DOMXSS",
               search_canary: str = "?sx=SX_CANARY_DOMXSS",
               timeout: float = 10.0,
               max_steps: int = 200000) -> ExecutionResult:
    """Execute JS against the virtual browser. Never raises."""
    g, result = build_globals(page_url, hash_canary, search_canary)
    if not js_code or not js_code.strip():
        return result
    interp = Interpreter(g, max_steps=max_steps)
    start = time.monotonic()
    try:
        # wall-clock guard via step budget (interpreter ticks per op);
        # the timeout here is a soft outer bound for pathological regex etc.
        interp.run(js_code)
        result.executed = True
    except Exception as e:  # noqa: BLE001 — never crash the scan
        result.errors.append(f"{type(e).__name__}: {e}"[:300])
        result.executed = True  # partial execution still yields signals
    elapsed = time.monotonic() - start
    if elapsed > timeout:
        result.errors.append(f"soft-timeout after {elapsed:.1f}s")
    return result


def execute_scripts(scripts: list[str], page_url: str = "",
                    **kwargs) -> ExecutionResult:
    """Execute multiple <script> blocks sharing one virtual browser session
    (later scripts see globals set by earlier ones — like a real page)."""
    g, result = build_globals(
        page_url,
        kwargs.get("hash_canary", "#SX_CANARY_DOMXSS"),
        kwargs.get("search_canary", "?sx=SX_CANARY_DOMXSS"),
    )
    interp = Interpreter(g, max_steps=kwargs.get("max_steps", 200000))
    for js in scripts:
        if not js or not js.strip():
            continue
        # skip JSON blobs / non-code script types by cheap heuristic
        stripped = js.strip()
        if stripped.startswith("{") and stripped.endswith("}") and "function" not in stripped:
            continue
        try:
            interp.run(js)
            result.executed = True
        except Exception as e:  # noqa: BLE001
            result.errors.append(f"{type(e).__name__}: {e}"[:200])
    return result


def is_js2py_available() -> bool:
    return _JS2PY_AVAILABLE
