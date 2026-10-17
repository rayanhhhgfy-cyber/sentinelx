"""Tests for sentinelx.jsruntime — node-powered JS execution.

Covers: node initialization, mock browser environment, executor safety,
taint tracking, instrumentation/correlation, and false-positive discipline.

Run: .venv/bin/python tests/test_jsruntime.py
"""

from __future__ import annotations

import sys

from sentinelx.jsruntime import (
    ensure_node, node_available, execute, execute_scripts,
    instrument, taint as taint_mod, assists,
)
from sentinelx.jsruntime import mock as mock_mod


def test_node_initializes():
    ensure_node()  # must not raise
    assert node_available(), "node_available() false after ensure_node()"
    import subprocess, shutil
    node = shutil.which("node")
    p = subprocess.run([node, "-e", "console.log(40+2)"],
                       capture_output=True, timeout=10, text=True)
    assert p.stdout.strip() == "42", "node basic execution broken"


def test_mock_location_canaries():
    r = execute("var h = location.hash; var s = location.search;",
                page_url="http://t/", hash_canary="HASH123",
                search_canary="SEARCH456", timeout=10)
    assert r.executed, f"not executed: {r.errors}"
    # canaries must be observable via JS
    r2 = execute("__sx_log('probe', location.hash + '|' + location.search);",
                 page_url="http://t/", hash_canary="HASH123",
                 search_canary="SEARCH456", timeout=10)
    assert r2.executed
    assert any("HASH123" in str(e.get("data", "")) for e in r2.trace), \
        "hash canary not visible to JS"


def test_mock_fetch_recorded():
    r = execute('fetch("/api/a"); fetch("http://x/y", {method: "POST", body: "z=1"});',
                timeout=10)
    assert r.executed, r.errors
    assert len(r.api_calls) == 2, f"expected 2 api_calls, got {len(r.api_calls)}"
    urls = [e["data"]["url"] for e in r.api_calls]
    assert "/api/a" in urls and "http://x/y" in urls


def test_mock_xhr_recorded():
    r = execute('var x = new XMLHttpRequest(); x.open("POST", "/api/xhr"); x.send("a=1");',
                timeout=10)
    assert r.executed, r.errors
    assert r.api_calls, "XHR not recorded"
    assert any("/api/xhr" in str(e["data"].get("url", "")) for e in r.api_calls)


def test_mock_websocket_recorded():
    r = execute('var w = new WebSocket("ws://t:9999/live"); w.send("hello");',
                timeout=10)
    assert r.executed, r.errors
    assert r.websockets, "WebSocket not recorded"


def test_mock_innerhtml_sink():
    r = execute('document.getElementById("o").innerHTML = "<b>" + location.hash.slice(1) + "</b>";',
                hash_canary="CANK", timeout=10)
    assert r.executed, r.errors
    assert r.dom_writes, "innerHTML write not recorded"
    assert any("CANK" in str(e["data"].get("value", "")) for e in r.dom_writes)


def test_mock_document_write_sink():
    r = execute('document.write("x" + location.search);',
                search_canary="CANS", timeout=10)
    assert r.executed, r.errors
    assert any("sink:document.write" in e["kind"] for e in r.trace)


def test_mock_eval_intercepted():
    r = execute('eval("alert(1)");', timeout=10)
    assert r.executed, r.errors
    assert any("sink:eval" in e["kind"] for e in r.trace), \
        "eval not intercepted"
    # eval must NOT actually execute (no exception from undefined alert)
    assert not any("alert" in str(e) for e in r.errors)


def test_mock_eval_in_string_preserved():
    # "eval(" inside a string literal must NOT be rewritten
    r = execute('var s = "call eval(x)"; __sx_log("s", s);', timeout=10)
    assert r.executed, r.errors
    assert not any("sink:eval" in e["kind"] for e in r.trace), \
        "string literal was incorrectly rewritten"


def test_mock_settimeout_string_sink():
    r = execute('setTimeout("alert(1)", 100);', timeout=10)
    assert r.executed, r.errors
    assert any("sink:setTimeout-string" in e["kind"] for e in r.trace)


def test_mock_storage():
    r = execute('localStorage.setItem("k", "v"); sessionStorage.setItem("a", "b");',
                timeout=10)
    assert r.executed, r.errors
    assert len(r.storage_access) >= 2


def test_mock_unsupported_logged():
    r = execute('var w = new Worker("x.js");', timeout=10)
    assert r.executed, r.errors
    assert any(e["kind"] == "unsupported" for e in r.trace), \
        "unsupported API not logged"


def test_executor_timeout():
    # infinite loop must not hang the scanner
    r = execute("while (true) {}", timeout=2)
    assert any("timeout" in e.lower() for e in r.errors), \
        f"infinite loop not timed out: {r.errors}"


def test_executor_syntax_error_isolated():
    r = execute("var x = {{{;", timeout=10)
    assert r.errors, "syntax error not captured"
    # must not raise, must return a result
    assert isinstance(r.trace, list)


def test_executor_size_limit():
    big = "var x = 1;" * 100000  # ~1MB
    r = execute(big, timeout=10, max_script_bytes=1000)
    assert any("too large" in e for e in r.errors)


def test_taint_flow_confirmed():
    tracker = taint_mod.TaintTracker()
    mark = tracker.new_mark(taint_mod.Source.FRAGMENT, "location.hash")
    r = execute('document.getElementById("o").innerHTML = location.hash;',
                hash_canary=mark.canary, timeout=10)
    assert r.executed
    flows = tracker.flows_from_trace(r.trace)
    assert flows, "taint flow not detected"
    assert flows[0].sink == "sink:innerHTML"
    assert flows[0].source == taint_mod.Source.FRAGMENT


def test_taint_no_flow_clean():
    tracker = taint_mod.TaintTracker()
    mark = tracker.new_mark(taint_mod.Source.FRAGMENT, "location.hash")
    r = execute('document.getElementById("o").innerHTML = "static text";',
                hash_canary=mark.canary, timeout=10)
    assert r.executed
    flows = tracker.flows_from_trace(r.trace)
    assert not flows, f"false taint flow: {flows}"


def test_tainted_str_propagation():
    t = taint_mod.taint("user", taint_mod.Source.QUERY, "q")
    assert taint_mod.is_tainted(t)
    combined = "hello " + t + "!"
    assert taint_mod.is_tainted(combined)
    assert taint_mod.taint_sources(combined)[0][0] == taint_mod.Source.QUERY
    # untainted stays untainted
    assert not taint_mod.is_tainted("plain")
    # replace propagates
    r2 = t.replace("user", "admin")
    assert taint_mod.is_tainted(r2)


def test_correlate_confirmed():
    tracker = taint_mod.TaintTracker()
    mark = tracker.new_mark(taint_mod.Source.FRAGMENT, "location.hash")
    r = execute('document.write(location.hash);',
                hash_canary=mark.canary, timeout=10)
    cf = instrument.correlate_dom_xss(["document.write"], r, tracker)
    assert cf.confidence == instrument.CONFIRMED, f"got {cf.confidence}"
    assert not cf.static_only


def test_correlate_static_only_is_low():
    # sink pattern in JS but never executed at runtime → LOW, static_only
    tracker = taint_mod.TaintTracker()
    r = execute('var x = 1;', timeout=10)  # no sinks at all
    cf = instrument.correlate_dom_xss(["innerHTML"], r, tracker)
    assert cf.confidence == instrument.LOW, f"got {cf.confidence}"
    assert cf.static_only, "static-only indicator must be labeled"


def test_assists_extract_scripts():
    html = '<html><script>var a = 1;</script><script src="x.js"></script></html>'
    scripts = assists.extract_scripts(html)
    assert len(scripts) == 1 and "var a" in scripts[0]


def test_assists_analyze_html():
    html = ('<html><body><script>'
            'fetch("/api/hidden");'
            'document.getElementById("o").innerHTML = location.hash;'
            '</script></body></html>')
    pr = assists.analyze_html("http://t/page", html, timeout=10)
    assert pr is not None and pr.executed
    assert any("/api/hidden" in e["url"] for e in pr.api_endpoints)
    assert pr.flows, "expected taint flow to innerHTML"


def run_all():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    passed, failed = 0, []
    for t in tests:
        try:
            t()
            passed += 1
            print(f"  PASS {t.__name__}")
        except Exception as e:  # noqa: BLE001
            failed.append((t.__name__, e))
            print(f"  FAIL {t.__name__}: {type(e).__name__}: {e}")
    print(f"\n{passed} passed, {len(failed)} failed")
    return failed


if __name__ == "__main__":
    fails = run_all()
    sys.exit(1 if fails else 0)
