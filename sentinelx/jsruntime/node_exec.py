"""SentinelX jsruntime.node_exec: JavaScript execution via node subprocess.

Replaces the js2py backend (js2py is abandoned and broken on Python 3.13+).
Page JavaScript runs in real Node.js (V8) against the mock browser
environment (mock_preamble.js). No Playwright, no Selenium, no headless
browser — plain ``node`` subprocess, Termux compatible.

Design:
- node is a HARD dependency: ensure_node() raises RuntimeError with install
  instructions if node is missing or cannot run a trivial script.
- execute_js_node() NEVER raises: timeouts kill the child, broken scripts
  return errors, missing node returns an explanatory error result.
- The page script is wrapped so the trace ALWAYS dumps (even on throw or
  top-level return), via try/catch/finally.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time

PREAMBLE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "mock_preamble.js")

#: marker line the dumper prints; the trace JSON follows on the same line
TRACE_MARKER = "__SX_TRACE_JSON__"

_node_path: str | None = None
_node_checked: bool = False


def _find_node() -> str | None:
    global _node_path
    if _node_path is None:
        _node_path = shutil.which("node")
    return _node_path


def node_available() -> bool:
    """True if `node` exists and runs a trivial script."""
    node = _find_node()
    if not node:
        return False
    try:
        p = subprocess.run([node, "--version"], capture_output=True,
                           timeout=10)
        if p.returncode != 0:
            return False
        p2 = subprocess.run([node, "-e", "console.log(40+2)"],
                            capture_output=True, timeout=10, text=True)
        return p2.returncode == 0 and p2.stdout.strip() == "42"
    except Exception:
        return False


def ensure_node() -> None:
    """Raise RuntimeError with install instructions if node is unusable."""
    if not _find_node():
        raise RuntimeError(
            "Node.js is required for JavaScript analysis but `node` was not "
            "found on PATH.\n"
            "Install it with:  pkg install nodejs   (Termux)\n"
            "or download from https://nodejs.org/"
        )
    if not node_available():
        raise RuntimeError(
            "Node.js was found but cannot execute JavaScript "
            "(`node -e` smoke test failed).\n"
            "Reinstall it with:  pkg install nodejs   (Termux)\n"
            "or download from https://nodejs.org/"
        )


def _load_preamble() -> str:
    with open(PREAMBLE_PATH, "r", encoding="utf-8") as f:
        return f.read()


def _js_str(s: str) -> str:
    """Encode a Python string as a JS string literal."""
    return json.dumps(s)


def build_script(page_js: str, page_url: str = "",
                 hash_canary: str = "SX_CANARY",
                 search_canary: str = "SX_CANARY") -> str:
    """Assemble the full node script: config + preamble + page + dumper."""
    config = (
        "var __SX_PAGE_URL = %s;\n"
        "var __SX_SEARCH = %s;\n"
        "var __SX_HASH = %s;\n"
    ) % (
        _js_str(page_url),
        _js_str("?" + search_canary.lstrip("?")),
        _js_str("#" + hash_canary.lstrip("#")),
    )
    dumper = (
        "\ntry {\n"
        "  try {\n"
        "%s\n"
        "  } catch (__sx_e) {\n"
        "    __sx_log('js-error', String((__sx_e && __sx_e.message) || __sx_e).slice(0, 300));\n"
        "  }\n"
        "} finally {\n"
        "  try { console.log('%s' + JSON.stringify(__sx_trace)); }\n"
        "  catch (__sx_e2) { console.log('%s[]'); }\n"
        "}\n"
    ) % (page_js, TRACE_MARKER, TRACE_MARKER)
    return config + _load_preamble() + dumper


def execute_js_node(js_code: str, page_url: str = "",
                    hash_canary: str = "SX_CANARY",
                    search_canary: str = "SX_CANARY",
                    timeout: float = 10.0) -> tuple[list, list]:
    """Run JS in node. Returns (trace, errors). Never raises.

    trace: list of {"kind":..., "data":...} dicts from __sx_trace.
    errors: list of human-readable error strings.
    """
    errors: list[str] = []
    node = _find_node()
    if not node:
        return [], ["node not found on PATH — install with: pkg install nodejs"]

    full_js = build_script(js_code, page_url, hash_canary, search_canary)

    tmp_path = ""
    try:
        fd, tmp_path = tempfile.mkstemp(prefix="sx_js_", suffix=".js",
                                        dir=tempfile.gettempdir())
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(full_js)
    except Exception as e:  # noqa: BLE001
        return [], [f"temp file: {type(e).__name__}: {str(e)[:200]}"]

    start = time.monotonic()
    try:
        # Minimal env: node needs nothing but PATH.
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
               "NODE_NO_WARNINGS": "1"}
        try:
            p = subprocess.run([node, tmp_path], capture_output=True,
                               text=True, timeout=timeout, env=env)
        except subprocess.TimeoutExpired:
            return [], [f"timeout after {timeout:.1f}s; node process killed"]
        except Exception as e:  # noqa: BLE001
            return [], [f"node spawn: {type(e).__name__}: {str(e)[:200]}"]

        trace: list = []
        marker_line = ""
        for line in p.stdout.splitlines():
            if line.startswith(TRACE_MARKER):
                marker_line = line  # last one wins (dumper runs last)
        if marker_line:
            raw = marker_line[len(TRACE_MARKER):]
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, list):
                    trace = [e for e in parsed if isinstance(e, dict)]
                else:
                    errors.append("trace JSON was not a list")
            except Exception as e:  # noqa: BLE001
                errors.append(f"trace parse: {type(e).__name__}: {str(e)[:200]}")
        else:
            errors.append("node produced no trace (script may have exited early)")

        if p.returncode != 0 and not marker_line:
            err = (p.stderr or "").strip().splitlines()
            # node prints the stack; keep the first meaningful line
            first = next((l.strip() for l in err
                          if l.strip() and "at " not in l[:4]), "")
            if first:
                errors.append(f"node exit {p.returncode}: {first[:300]}")
        elif p.stderr:
            # warnings on stderr with a good trace are not fatal; note briefly
            first = p.stderr.strip().splitlines()
            if first and "Warning" not in first[0]:
                errors.append(f"node stderr: {first[0][:200]}")
        _ = time.monotonic() - start
        return trace, errors
    finally:
        try:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)
        except Exception:
            pass
