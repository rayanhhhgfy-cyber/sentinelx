"""Tests for sentinelx/discovery/jsapi.py — deep API reconstruction."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sentinelx.discovery import jsapi


def _calls(js, base="http://127.0.0.1:5056"):
    jsapi._PARSE_CACHE.clear()
    return jsapi.extract_api_calls(js, base)


def test_fetch_full_shape():
    calls = _calls('''fetch("/api/newsletter", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: email })
    });''')
    assert len(calls) == 1
    c = calls[0]
    assert c.method == "POST" and c.url.endswith("/api/newsletter")
    assert c.headers.get("Content-Type") == "application/json"
    assert c.body_fields.get("email") == "test"
    assert c.content_type == "application/json"


def test_secret_redaction():
    calls = _calls('''fetch("/api/internal/stats", {
      headers: { "X-Api-Key": "nx_live_SECRET123", "X-Plain": "v" }});''')
    c = calls[0]
    assert c.headers["X-Api-Key"] == "<redacted>"
    assert c.headers["X-Plain"] == "v"


def test_axios_config():
    calls = _calls('''axios.post("/api/v1/lookup", {code: code, verbose: true},
      {headers: {"Authorization": "Bearer tok", "X-Req": "1"},
       params: {debug: "1"}});''')
    c = calls[0]
    assert c.method == "POST"
    assert c.body_fields["code"] == "test" and c.body_fields["verbose"] is True
    assert c.headers["Authorization"] == "<redacted>"
    assert c.query_params["debug"] == "1"


def test_xhr_tracking():
    calls = _calls('''var xhr = new XMLHttpRequest();
      xhr.open("POST", "/api/contact", true);
      xhr.setRequestHeader("Content-Type", "application/json");
      xhr.setRequestHeader("X-Custom", "abc");
      xhr.send(JSON.stringify({name: name}));''')
    c = calls[0]
    assert c.method == "POST" and c.url.endswith("/api/contact")
    assert c.headers["Content-Type"] == "application/json"
    assert "X-Custom" in c.headers
    assert c.body_fields.get("name") == "test"


def test_xhr_payload_var_resolution():
    calls = _calls('''var payload = { name: n, email: e };
      var xhr = new XMLHttpRequest();
      xhr.open("POST", "/api/contact");
      xhr.send(JSON.stringify(payload));''')
    c = calls[0]
    assert set(c.body_fields) == {"name", "email"}


def test_template_literal_path_param():
    calls = _calls('fetch(`/api/users/${userId}/posts`);', base="http://h/")
    c = calls[0]
    assert "{userId}" in c.url
    assert "userId" in c.path_params
    assert c.resolved_url("http://h/") == "http://h/api/users/1/posts"


def test_template_literal_resolved_var():
    calls = _calls('var userId = 42; fetch(`/api/users/${userId}`);')
    c = calls[0]
    assert c.url.endswith("/api/users/42")
    assert c.path_params == []


def test_concat_resolution():
    calls = _calls('fetch("/api/users/" + userId + "?active=1");')
    c = calls[0]
    assert "{userId}" in c.url
    assert c.query_params.get("active") == "1"


def test_ajax_full():
    calls = _calls('''$.ajax({url: "/api/search", type: "POST",
      headers: {"X-Req": "a"},
      data: JSON.stringify({q: q, limit: 10}),
      contentType: "application/json"});''')
    c = calls[0]
    assert c.method == "POST"
    assert c.body_fields == {"q": "test", "limit": 10}
    assert c.content_type == "application/json"


def test_query_in_url():
    calls = _calls('fetch("/api/search?q=test&page=2");')
    c = calls[0]
    assert c.query_params == {"q": "test", "page": "2"}
    assert "?" not in c.url


def test_cache():
    js = 'fetch("/api/a");'
    jsapi._PARSE_CACHE.clear()
    r1 = jsapi.extract_api_calls_cached(js, "http://h/")
    assert jsapi.cache_stats()["entries"] == 1
    r2 = jsapi.extract_api_calls_cached(js, "http://h/")
    assert r1 == r2 and jsapi.cache_stats()["entries"] == 1


def test_html_data_api():
    html = '<div data-api="/api/widget/stats" data-endpoint="/api/v2/ping"></div>'
    calls = jsapi.extract_html_apis(html, "http://h/")
    urls = [c.url for c in calls]
    assert "http://h/api/widget/stats" in urls
    assert "http://h/api/v2/ping" in urls


def test_html_embedded_json():
    html = '''<script type="application/json">{"apiUrl": "/api/config", "x": 1}</script>'''
    calls = jsapi.extract_html_apis(html, "http://h/")
    assert any(c.url == "http://h/api/config" for c in calls)


def test_no_crash_on_garbage():
    for bad in ["", "fetch(", "{{{{", "var x = ;;;", "`unterminated",
                "fetch(`/api/${a + `nested`}`);"]:
        jsapi.extract_api_calls(bad, "http://h/")
    jsapi.extract_html_apis("<div><span", "http://h/")


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except Exception:
            failed += 1
            print(f"FAIL {fn.__name__}")
            traceback.print_exc()
    print(f"{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
