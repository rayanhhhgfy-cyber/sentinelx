"""Integration tests for SentinelX new modules: secrets, techfp, graphql.

Each test spins up a tiny Flask app (vulnerable variant + hardened variant),
runs the module against it with a real ScanClient, and asserts detection.
Run: .venv/bin/python tests/test_new_modules.py
"""

from __future__ import annotations

import asyncio
import threading

from flask import Flask, request, jsonify, make_response
from werkzeug.serving import make_server

from sentinelx.core.http import ScanClient, ScanConfig


def serve(app, port):
    from werkzeug.serving import WSGIRequestHandler
    WSGIRequestHandler.server_version = "web"
    WSGIRequestHandler.sys_version = ""
    server = make_server("127.0.0.1", port, app)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


def new_client(target):
    config = ScanConfig(target=target, rate_per_sec=50, concurrency=10)
    return config, ScanClient(config)


# ── secrets: vulnerable app leaks an AWS key + private key in JS ──────────

def vuln_secrets_app():
    app = Flask(__name__)

    @app.route("/")
    def index():
        return "<html><body><script src='/app.js'></script></body></html>"

    @app.route("/app.js")
    def js():
        return ('var cfg = {awsKey: "AKIAIOSFODNN7EXAMPLE", '
                'db: "postgres://admin:s3cret-pw@db.internal:5432/app"};\n'
                "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n")

    return app


def clean_secrets_app():
    app = Flask(__name__)

    @app.route("/")
    def index():
        return "<html><body><script src='/app.js'></script></body></html>"

    @app.route("/app.js")
    def js():
        return "var cfg = {env: 'prod'};\nconsole.log('hello');"

    return app


async def finalize_all(fs):
    out = []
    for i, f in enumerate(fs, 1):
        out.append(f.finalize(i))
    return out


async def test_secrets():
    from sentinelx.modules import secrets
    # vulnerable
    srv = serve(vuln_secrets_app(), 5171)
    config, client = new_client("http://127.0.0.1:5171")
    async with client:
        f1 = await finalize_all(await secrets.scan_page(client, config, "http://127.0.0.1:5171/app.js"))
        f2 = await finalize_all(await secrets.scan_endpoint(client, config, "GET", "http://127.0.0.1:5171/", {}))
    kinds = {f.subtype for f in f1 + f2}
    assert any("AWS access key" in k for k in kinds), f"AWS key not found: {kinds}"
    assert any("private key" in k.lower() for k in kinds), f"private key not found: {kinds}"
    assert any("Postgres" in k for k in kinds), f"postgres URI not found: {kinds}"
    # redaction check — no full secret in proof
    for f in f1 + f2:
        assert "AKIAIOSFODNN7EXAMPLE" not in f.evidence.proof, "secret leaked unredacted!"
        assert "***REDACTED***" in f.evidence.proof
    assert any(f.severity == "high" for f in f1 + f2), "AWS key should be HIGH"
    srv.shutdown()
    # hardened
    srv = serve(clean_secrets_app(), 5172)
    config, client = new_client("http://127.0.0.1:5172")
    async with client:
        f3 = await secrets.scan_page(client, config, "http://127.0.0.1:5172/app.js")
        f4 = await secrets.scan_endpoint(client, config, "GET", "http://127.0.0.1:5172/", {})
    assert f3 == [] and f4 == [], f"false positives: {f3 + f4}"
    srv.shutdown()
    print("PASS secrets: detected AWS key + RSA key + Postgres URI (redacted, HIGH sev); clean app -> []")


# ── techfp: vulnerable app reveals stack ───────────────────────────────────

def vuln_tech_app():
    app = Flask(__name__)

    @app.route("/")
    def index():
        r = make_response(
            "<html><body><div id='react-root'></div>"
            "<script>window.__NEXT_DATA__={};</script>"
            "<script src='https://cdn.jsdelivr.net/npm/jquery-3.7.1.min.js'></script>"
            "</body></html>")
        r.headers["Server"] = "nginx/1.24.0"
        r.headers["X-Powered-By"] = "Express"
        return r

    return app


def clean_tech_app():
    app = Flask(__name__)

    @app.route("/")
    def index():
        r = make_response("<html><body><h1>Hi</h1></body></html>")
        r.headers["Server"] = "web"
        return r

    @app.after_request
    def strip_werkzeug(resp):
        resp.headers["Server"] = "web"
        return resp

    return app


async def test_techfp():
    from sentinelx.modules import techfp
    srv = serve(vuln_tech_app(), 5173)
    config, client = new_client("http://127.0.0.1:5173")
    async with client:
        f1 = await finalize_all(await techfp.fingerprint(client, config, "http://127.0.0.1:5173/"))
    names = {f.payload for f in f1}
    assert "Nginx" in names, f"nginx not detected: {names}"
    assert "Express" in names, f"express not detected: {names}"
    assert "React" in names, f"react not detected: {names}"
    assert "Next.js" in names, f"next.js not detected: {names}"
    assert "jQuery" in names, f"jquery not detected: {names}"
    assert all(f.severity == "info" for f in f1)
    srv.shutdown()
    srv = serve(clean_tech_app(), 5174)
    srv.server_version = "web"
    srv.sys_version = ""
    config, client = new_client("http://127.0.0.1:5174")
    async with client:
        f2 = await techfp.fingerprint(client, config, "http://127.0.0.1:5174/")
    assert f2 == [], f"false positives: {[f.payload for f in f2]}"
    srv.shutdown()
    print(f"PASS techfp: detected {sorted(names)} (INFO); clean app -> []")


# ── graphql: vulnerable app exposes introspection ─────────────────────────

def vuln_graphql_app():
    app = Flask(__name__)

    @app.route("/graphql", methods=["GET", "POST"])
    def gql():
        if request.method == "GET":
            return "<html><body>GraphiQL IDE</body></html>"
        data = request.get_json(silent=True) or {}
        if "__schema" in data.get("query", ""):
            return jsonify({"data": {"__schema": {"queryType": {"name": "Query"}}}})
        return jsonify({"data": {}})

    @app.route("/api/graphql", methods=["POST"])
    def gql_api():
        # no playground UI here — introspection only
        data = request.get_json(silent=True) or {}
        if "__schema" in data.get("query", ""):
            return jsonify({"data": {"__schema": {"queryType": {"name": "Mutation"}}}})
        return jsonify({"data": {}})

    return app


def clean_graphql_app():
    app = Flask(__name__)

    @app.route("/graphql", methods=["GET", "POST"])
    def gql():
        data = request.get_json(silent=True) or {}
        if "__schema" in data.get("query", ""):
            return jsonify({"errors": [{"message": "introspection disabled"}]}), 400
        return jsonify({"data": {}})

    return app


async def test_graphql():
    from sentinelx.modules import graphql
    srv = serve(vuln_graphql_app(), 5175)
    config, client = new_client("http://127.0.0.1:5175")
    async with client:
        f1 = await finalize_all(await graphql.scan_endpoint(client, config, "GET", "http://127.0.0.1:5175/", {}))
    subs = {f.subtype for f in f1}
    assert "graphql-playground" in subs, f"playground not found: {subs}"
    assert "graphql-introspection" in subs, f"introspection not found: {subs}"
    srv.shutdown()
    srv = serve(clean_graphql_app(), 5176)
    config, client = new_client("http://127.0.0.1:5176")
    async with client:
        f2 = await graphql.scan_endpoint(client, config, "GET", "http://127.0.0.1:5176/", {})
    assert f2 == [], f"false positives: {[f.subtype for f in f2]}"
    srv.shutdown()
    print(f"PASS graphql: detected {sorted(subs)}; introspection-disabled app -> []")


async def main():
    await test_secrets()
    await test_techfp()
    await test_graphql()
    print("\nALL NEW-MODULE TESTS PASSED")


if __name__ == "__main__":
    asyncio.run(main())
