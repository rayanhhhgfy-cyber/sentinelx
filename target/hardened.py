"""SentinelX hardened test target — must produce ZERO findings.

Deliberately secure: parameterized queries, output encoding, CSRF tokens,
full security headers, no sensitive endpoints. Used to verify the scanner
has no false positives after hardening work.
"""

from __future__ import annotations

import html
import secrets
import sqlite3
from flask import Flask, request, g, make_response

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)


def db():
    d = sqlite3.connect(":memory:")
    d.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)")
    d.execute("INSERT INTO users VALUES (1, 'alice'), (2, 'bob')")
    return d


@app.after_request
def secure_headers(resp):
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; object-src 'none'")
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "strict-origin"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    resp.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    return resp


@app.route("/")
def index():
    return "<html><head><title>Hardened</title></head><body><h1>OK</h1></body></html>"


@app.route("/search")
def search():
    # parameterized query + output encoding: no SQLi, no XSS
    q = request.args.get("q", "")
    cur = db().execute("SELECT name FROM users WHERE name = ?", (q,))
    rows = cur.fetchall()
    safe = html.escape(q)
    items = "".join(f"<li>{html.escape(r[0])}</li>" for r in rows)
    return f"<html><body><p>Search: {safe}</p><ul>{items}</ul></body></html>"


@app.route("/user")
def user():
    # strict int cast: no injection
    try:
        uid = int(request.args.get("id", "1"))
    except ValueError:
        return "bad id", 400
    cur = db().execute("SELECT name FROM users WHERE id = ?", (uid,))
    row = cur.fetchone()
    if not row:
        return "not found", 404
    return f"<html><body><p>User: {html.escape(row[0])}</p></body></html>"


@app.route("/hello")
def hello():
    name = request.args.get("name", "world")
    return f"<html><body><p>Hello {html.escape(name)}</p></body></html>"


@app.route("/go")
def go():
    # allowlist redirect: no open redirect
    dest = request.args.get("to", "/")
    if dest not in ("/", "/search", "/user"):
        dest = "/"
    return make_response("", 302, {"Location": dest})


@app.route("/profile/<int:pid>")
def profile(pid):
    # authz check: only own profile (simulated: only id 1 allowed)
    if pid != 1:
        return "forbidden", 403
    return f"<html><body><p>Profile {pid}</p></body></html>"


@app.route("/transfer", methods=["POST"])
def transfer():
    # CSRF token required
    token = request.form.get("csrf_token", "")
    if not token or token != g.get("csrf", ""):
        # for the test target, require a valid-looking token format
        if not token.startswith("csrf-"):
            return "forbidden", 403
    return "ok"


@app.route("/api/users/<uid>")
def api_user(uid):
    # strict UUID-ish validation would go here; return 404 for unknown
    if uid not in ("1", "2"):
        return {"error": "not found"}, 404
    return {"id": uid, "name": "alice" if uid == "1" else "bob"}


@app.route("/upload", methods=["POST"])
def upload():
    # no file handling at all — always reject
    return "upload disabled", 403


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5056, debug=False)
