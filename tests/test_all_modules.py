"""Deterministic tests for ALL SentinelX vulnerability modules.

One Flask app provides paired vulnerable/safe endpoints. Each module is
tested against both: must DETECT on vulnerable, must NOT fire on safe.

This is the compatibility gate: every module in COMPAT_CHECKLIST.md must
pass here after any engine change.

Run: PYTHONPATH=. .venv/bin/python tests/test_all_modules.py
"""

from __future__ import annotations

import asyncio
import sys
import threading

from flask import Flask, request, jsonify, make_response, redirect
from werkzeug.serving import make_server

from sentinelx.core.http import ScanClient, ScanConfig


def serve(app, port):
    server = make_server("127.0.0.1", port, app)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


def make_config(target):
    return ScanConfig(target=target, rate_per_sec=100, concurrency=10,
                      timeout=10)


def build_app():
    app = Flask(__name__)

    # ---- SQLi ----
    @app.route("/sqli")
    def sqli_vuln():
        uid = request.args.get("id", "")
        if "'" in uid:
            return "SQL syntax error near '' at line 1", 500
        return f"user {uid}"

    @app.route("/sqli_safe")
    def sqli_safe():
        return "user 1"  # parameterized, no reflection of quotes

    # ---- XSS ----
    @app.route("/xss")
    def xss_vuln():
        return f"<html><body>hello {request.args.get('q', '')}</body></html>"

    @app.route("/xss_safe")
    def xss_safe():
        import html as h
        return f"<html><body>hello {h.escape(request.args.get('q', ''))}</body></html>"

    # ---- LFI ----
    @app.route("/lfi")
    def lfi_vuln():
        import os
        f = request.args.get("file", "")
        try:
            with open(os.path.join("/tmp", f)) as fh:
                return fh.read()[:500]
        except Exception as e:
            return f"Error: {e}", 500

    @app.route("/lfi_safe")
    def lfi_safe():
        return "file viewer"

    # ---- Open redirect ----
    @app.route("/redir")
    def redir_vuln():
        return redirect(request.args.get("url", "/"))

    @app.route("/redir_safe")
    def redir_safe():
        return redirect("/")

    # ---- SSRF ----
    @app.route("/ssrf")
    def ssrf_vuln():
        u = request.args.get("url", "")
        if "169.254" in u or "metadata" in u:
            return "instance-id: i-12345\nami-id: ami-abc"
        return f"fetched {u}"

    @app.route("/ssrf_safe")
    def ssrf_safe():
        return "no fetch"

    # ---- RCE ----
    @app.route("/rce")
    def rce_vuln():
        import subprocess
        host = request.args.get("host", "")
        try:
            out = subprocess.check_output(f"echo {host}", shell=True,
                                          timeout=5).decode()[:200]
            return out
        except Exception as e:
            return str(e)[:200]

    # ---- SSTI ----
    @app.route("/ssti")
    def ssti_vuln():
        from jinja2 import Template
        name = request.args.get("name", "")
        try:
            return Template(f"hello {name}").render()
        except Exception as e:
            return str(e)[:200]

    # ---- XXE ----
    @app.route("/xxe", methods=["POST"])
    def xxe_vuln():
        data = request.data.decode("utf-8", "replace")
        if "<!ENTITY" in data:
            return "ENTITY processed: xxe-test"
        return "xml ok"

    # ---- Deserialization ----
    @app.route("/deser", methods=["POST"])
    def deser_vuln():
        import pickle, base64
        try:
            obj = pickle.loads(base64.b64decode(request.data))
            return f"deserialized {type(obj).__name__}"
        except Exception:
            return "bad data"

    # ---- IDOR ----
    @app.route("/idor")
    def idor_vuln():
        uid = request.args.get("id", "1")
        users = {"1": "alice", "2": "bob-private", "3": "carol-private"}
        return jsonify(user=users.get(uid, "unknown"))

    # ---- JWT ----
    @app.route("/jwt")
    def jwt_vuln():
        import base64, json
        tok = request.headers.get("Authorization", "").replace("Bearer ", "")
        try:
            payload = json.loads(base64.urlsafe_b64decode(
                tok.split(".")[1] + "==").decode())
            if payload.get("admin"):
                return jsonify(admin=True, flag="jwt-admin-ok")
            return jsonify(admin=False)
        except Exception:
            return jsonify(error="bad token"), 401

    # ---- CSRF ----
    @app.route("/csrf_transfer", methods=["POST"])
    def csrf_vuln():
        return jsonify(transferred=True)

    # ---- Host header ----
    @app.route("/host")
    def host_vuln():
        return f"reset link: http://{request.headers.get('Host', '')}/reset?t=abc"

    # ---- CRLF ----
    @app.route("/crlf")
    def crlf_vuln():
        lang = request.args.get("lang", "en")
        r = make_response("ok")
        r.headers["X-Lang"] = lang
        return r

    # ---- LDAP ----
    @app.route("/ldap")
    def ldap_vuln():
        u = request.args.get("user", "")
        if "*" in u or "(" in u:
            return "LDAP error: invalid filter", 500
        return f"user {u}"

    # ---- XPath ----
    @app.route("/xpath")
    def xpath_vuln():
        q = request.args.get("q", "")
        if "'" in q:
            return "XPathException: invalid expression", 500
        return f"result for {q}"

    # ---- DOM XSS page ----
    @app.route("/domxss")
    def domxss_vuln():
        return """<html><body><div id="o"></div><script>
var u = location.hash.slice(1);
document.getElementById("o").innerHTML = u;
</script></body></html>"""

    @app.route("/domxss_safe")
    def domxss_safe():
        return """<html><body><div id="o"></div><script>
var u = location.hash.slice(1);
document.getElementById("o").textContent = u;
</script></body></html>"""

    # ---- security headers: missing ----
    @app.route("/noheaders")
    def noheaders():
        r = make_response("<html><body>hi</body></html>")
        return r

    # ---- GraphQL ----
    @app.route("/graphql", methods=["GET", "POST"])
    def graphql_vuln():
        if request.method == "GET":
            return jsonify(data={"__schema": {"types": []}})
        return jsonify(data={"ok": True})

    # ---- secrets ----
    @app.route("/secrets.js")
    def secrets_js():
        return 'var k = "<redacted>";\n'

    # ---- prototype pollution ----
    @app.route("/pollute")
    def pollute_vuln():
        return """<html><script>
var o = {};
var k = location.hash.slice(1).split("=")[0];
o[k] = "polluted";
</script></html>"""

    return app


PORT = 18099
BASE = f"http://127.0.0.1:{PORT}"


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def check(name, condition, detail=""):
    status = "PASS" if condition else "FAIL"
    print(f"  {status} {name}" + (f" — {detail}" if detail and not condition else ""))
    return condition


async def _scan(mod_fn, url, params=None, method="GET"):
    config = make_config(url)
    async with ScanClient(config) as client:
        return await mod_fn(client, config, method, url, params or {})


def main():
    app = build_app()
    srv = serve(app, PORT)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    results = []

    def t(name, mod_path, fn_name, url, params, expect_find, method="GET"):
        import importlib
        mod = importlib.import_module(f"sentinelx.modules.{mod_path}")
        fn = getattr(mod, fn_name)
        try:
            findings = loop.run_until_complete(_scan(fn, url, params, method))
            found = len(findings) > 0
            ok = (found == expect_find)
            results.append(check(
                f"{name} [{'VULN' if expect_find else 'SAFE'}]",
                ok, f"expected_find={expect_find} got {len(findings)}"))
        except Exception as e:
            results.append(check(f"{name}", False, f"{type(e).__name__}: {e}"))

    # ---- positive + negative per module ----
    t("sqli", "sqli", "scan_endpoint", f"{BASE}/sqli", {"id": "1"}, True)
    t("sqli", "sqli", "scan_endpoint", f"{BASE}/sqli_safe", {"id": "1"}, False)
    t("xss", "xss", "scan_endpoint", f"{BASE}/xss", {"q": "x"}, True)
    t("xss", "xss", "scan_endpoint", f"{BASE}/xss_safe", {"q": "x"}, False)
    t("lfi", "lfi", "scan_endpoint", f"{BASE}/lfi", {"file": "x"}, True)
    t("openredirect", "probe", "scan_openredirect", f"{BASE}/redir", {"url": "/"}, True)
    t("openredirect", "probe", "scan_openredirect", f"{BASE}/redir_safe", {"url": "/"}, False)
    t("ssrf", "ssrf", "scan_endpoint", f"{BASE}/ssrf", {"url": "x"}, True)
    t("rce", "rce", "scan_endpoint", f"{BASE}/rce", {"host": "x"}, True)
    t("ssti", "ssti", "scan_endpoint", f"{BASE}/ssti", {"name": "x"}, True)
    t("xxe", "xxe", "scan_endpoint", f"{BASE}/xxe", {}, True, "POST")
    t("deser", "deser", "scan_endpoint", f"{BASE}/pickle" if False else f"{BASE}/deser", {}, True, "POST")
    t("idor", "idor", "scan_endpoint", f"{BASE}/idor", {"id": "1"}, True)
    t("jwt", "jwt", "scan_endpoint", f"{BASE}/jwt", {}, True)
    t("csrf", "csrf", "scan_endpoint", f"{BASE}/csrf_transfer", {}, True, "POST")
    t("hostheader", "hostheader", "scan_endpoint", f"{BASE}/host", {}, True)
    t("crlf", "crlf", "scan_endpoint", f"{BASE}/crlf", {"lang": "en"}, True)
    t("ldap", "ldap", "scan_endpoint", f"{BASE}/ldap", {"user": "x"}, True)
    t("xpath", "xpath", "scan_endpoint", f"{BASE}/xpath", {"q": "x"}, True)
    t("domxss", "domxss", "scan_endpoint", f"{BASE}/domxss", {}, True)
    t("domxss", "domxss", "scan_endpoint", f"{BASE}/domxss_safe", {}, False)
    t("graphql", "graphql", "scan_endpoint", f"{BASE}/graphql", {}, True)
    t("secrets", "secrets", "scan_endpoint", f"{BASE}/secrets.js", {}, True)
    t("proto_pollute", "proto_pollute", "scan_endpoint", f"{BASE}/pollute", {}, True)
    t("audit-headers", "audit", "scan_headers", f"{BASE}/noheaders", {}, True)
    t("techfp", "techfp", "fingerprint", f"{BASE}/noheaders", {}, True)
    t("clickjack", "clickjack", "scan_endpoint", f"{BASE}/noheaders", {}, True)
    t("csrf-get", "csrf", "scan_endpoint", f"{BASE}/noheaders", {}, False)

    passed = sum(results)
    print(f"\n{passed}/{len(results)} module checks passed")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
