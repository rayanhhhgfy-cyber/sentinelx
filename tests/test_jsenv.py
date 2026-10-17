"""Tests for sentinelx.jsenv — pure-Python JS execution + analysis.

Run: .venv/bin/python tests/test_jsenv.py
"""

from __future__ import annotations

from sentinelx.jsenv.executor import execute_js, execute_scripts
from sentinelx.jsenv.static import extract_api_calls, analyze_js, score_js_interest


def test_taint_propagation():
    r = execute_js(
        "var h = location.hash.slice(1); var x = 'a' + h + 'b'; "
        "document.getElementById('e').innerHTML = x;",
        "http://t/",
        hash_canary="#CANARY1",
    )
    assert r.executed
    writes = [w for w in r.dom_writes if "innerHTML" in w["sink"]]
    assert writes, "innerHTML write not recorded"
    assert "CANARY1" in writes[0]["value"]
    assert "location.hash" in writes[0]["taint"]


def test_fetch_recording():
    r = execute_js(
        'fetch("/api/a"); fetch("/api/b", {method: "POST"});',
        "http://t/",
    )
    urls = {c["url"] for c in r.api_calls}
    assert "http://t/api/a" in urls
    assert "http://t/api/b" in urls
    methods = {c["method"] for c in r.api_calls}
    assert "POST" in methods


def test_variable_concatenation_url():
    # static regex misses this; execution must catch it
    r = execute_js(
        'var BASE = "/api"; fetch(BASE + "/hidden");',
        "http://t/",
    )
    assert any("hidden" in c["url"] for c in r.api_calls)


def test_document_write_taint():
    r = execute_js(
        'document.write("<p>" + location.search + "</p>");',
        "http://t/",
        search_canary="?q=CANARY2",
    )
    writes = [w for w in r.dom_writes if w["sink"] == "document.write"]
    assert writes
    assert "CANARY2" in writes[0]["value"]
    assert "location.search" in writes[0]["taint"]


def test_eval_recording():
    r = execute_js('eval("alert(" + location.hash + ")");', "http://t/")
    assert r.eval_calls
    assert r.eval_calls[0]["sink"] == "eval"


def test_bad_js_never_crashes():
    r = execute_js("this is not valid js {{{{", "http://t/")
    assert isinstance(r.errors, list)  # no raise


def test_infinite_loop_bounded():
    import time
    t0 = time.monotonic()
    r = execute_js("while(true) { var x = 1; }", "http://t/")
    assert r.executed  # step limit stops it, no hang
    assert time.monotonic() - t0 < 10, "interpreter hung on infinite loop"


def test_static_api_extraction():
    calls = extract_api_calls('fetch("/api/x"); $.ajax({url: "/api/y"});',
                              "http://t/")
    urls = {c["url"] for c in calls}
    assert "http://t/api/x" in urls
    assert "http://t/api/y" in urls


def test_static_interest_scoring():
    score, sinks, sources = score_js_interest(
        'document.getElementById("a").innerHTML = location.hash;')
    assert score > 0
    assert "innerHTML" in sinks
    assert "location.hash" in sources


def test_analyze_js_combined():
    res = analyze_js('fetch("/api/z"); var k = "x";', "http://t/")
    assert any("api/z" in c["url"] for c in res["api_calls"])
    assert isinstance(res["interest_score"], int)


def test_execute_scripts_shared_scope():
    r = execute_scripts(
        ['var BASE = "/api";', 'fetch(BASE + "/shared");'],
        "http://t/",
    )
    assert any("shared" in c["url"] for c in r.api_calls)


TESTS = [
    test_taint_propagation,
    test_fetch_recording,
    test_variable_concatenation_url,
    test_document_write_taint,
    test_eval_recording,
    test_bad_js_never_crashes,
    test_infinite_loop_bounded,
    test_static_api_extraction,
    test_static_interest_scoring,
    test_analyze_js_combined,
    test_execute_scripts_shared_scope,
]


if __name__ == "__main__":
    passed = 0
    for t in TESTS:
        try:
            t()
            print(f"PASS {t.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"FAIL {t.__name__}: {e}")
        except Exception as e:
            print(f"ERROR {t.__name__}: {type(e).__name__}: {e}")
    print(f"\n{passed}/{len(TESTS)} passed")
    raise SystemExit(0 if passed == len(TESTS) else 1)
