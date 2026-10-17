"""SentinelX test target v2 — DELIBERATELY VULNERABLE demo app.

Run: python target/app.py   (listens on 127.0.0.1:5055)
Only for testing the scanner. Never expose publicly.
"""

import base64
import hmac
import json
import os
import sqlite3
import subprocess
import time
from flask import Flask, request, redirect, make_response

app = Flask(__name__)

# ---------- helpers ----------
def db():
    c = sqlite3.connect(":memory:")
    c.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)")
    c.execute("INSERT INTO users VALUES (1, 'alice', 'alice@x.com'), (2, 'bob', 'bob@x.com'), (3, 'carol', 'carol@x.com')")
    return c

JWT_SECRET = "testsecret"

def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def make_jwt(payload: dict, secret: str = JWT_SECRET, alg: str = "HS256") -> str:
    header = b64u(json.dumps({"alg": alg, "typ": "JWT"}).encode())
    body = b64u(json.dumps(payload).encode())
    if alg == "none":
        return f"{header}.{body}."
    sig = b64u(hmac.new(secret.encode(), f"{header}.{body}".encode(), "sha256").digest())
    return f"{header}.{body}.{sig}"

def check_jwt(token: str):
    # VULN: accepts alg=none
    try:
        h, p, s = token.split(".")
        header = json.loads(base64.urlsafe_b64decode(h + "=="))
        payload = json.loads(base64.urlsafe_b64decode(p + "=="))
        if header.get("alg") == "none":
            return payload  # VULN!
        expect = b64u(hmac.new(JWT_SECRET.encode(), f"{h}.{p}".encode(), "sha256").digest())
        if hmac.compare_digest(expect, s):
            return payload
    except Exception:
        pass
    return None

# ---------- original vulns ----------
@app.route("/")
def index():
    return """<html><body><h1>VulnDemo v2</h1>
    <a href="/search?q=test">search</a> <a href="/user?id=1">user</a>
    <a href="/hello?name=guest">hello</a> <a href="/go?url=/">go</a>
    <a href="/view?file=welcome.txt">view</a> <a href="/ping?host=127.0.0.1">ping</a>
    <a href="/fetch?url=http://example.com">fetch</a> <a href="/profile/2">profile</a>
    <a href="/account?id=1">account</a>
    <form action="/search" method="GET"><input name="q" value="x"><input type="submit"></form>
    <form action="/transfer" method="POST"><input type="hidden" name="amount" value="10"><input type="submit" value="send"></form>
    <script>var API="/api/users";</script>
    </body></html>"""

@app.route("/search")
def search():
    q = request.args.get("q", "")
    con = db()
    try:
        cur = con.execute(f"SELECT name FROM users WHERE name LIKE '%{q}%'")
        rows = cur.fetchall()
        return f"<html><body>Results for {q}: " + ", ".join(r[0] for r in rows) + "</body></html>"
    except Exception as e:
        return f"<html><body>SQLite.Exception: {e}</body></html>", 500

@app.route("/user")
def user():
    uid = request.args.get("id", "1")
    con = db()
    try:
        cur = con.execute(f"SELECT name FROM users WHERE id = {uid}")
        row = cur.fetchone()
        if row:
            return f"<html><body><h1>User: {row[0]}</h1><p>Profile page</p></body></html>"
        return "<html><body><h1>Not found</h1></body></html>"
    except Exception as e:
        return f"<html><body>SQLite.Exception: {e}</body></html>", 500

@app.route("/hello")
def hello():
    name = request.args.get("name", "guest")
    resp = make_response(f"<html><body><h1>Hello {name}</h1></body></html>")
    resp.set_cookie("session", "abc123")
    return resp

@app.route("/go")
def go():
    return redirect(request.args.get("url", "/"))

# ---------- NEW: LFI ----------
@app.route("/view")
def view():
    # VULN: path traversal
    f = request.args.get("file", "welcome.txt")
    base = os.path.join(os.path.dirname(__file__), "files")
    try:
        with open(os.path.join(base, f), errors="replace") as fh:
            content = fh.read(4000)
    except Exception as e:
        return f"<html><body>Error: {e}</body></html>", 500
    return f"<html><body><pre>{content}</pre></body></html>"

# ---------- NEW: RCE ----------
@app.route("/ping")
def ping():
    # VULN: command injection
    host = request.args.get("host", "127.0.0.1")
    try:
        out = subprocess.run(f"echo PING {host}", shell=True, capture_output=True,
                             text=True, timeout=12).stdout
    except subprocess.TimeoutExpired:
        out = "TIMEOUT"
    return f"<html><body><pre>{out}</pre></body></html>"

# ---------- NEW: SSRF ----------
@app.route("/fetch")
def fetch():
    # VULN: SSRF — fetches arbitrary URL server-side
    import urllib.request
    target = request.args.get("url", "http://example.com")
    try:
        with urllib.request.urlopen(target, timeout=4) as r:
            data = r.read(3000).decode("utf-8", "replace")
    except Exception as e:
        data = f"fetch error: {e}"
    return f"<html><body><h1>Fetched</h1><pre>{data}</pre></body></html>"

# ---------- NEW: IDOR ----------
@app.route("/account")
def account():
    aid = request.args.get("id", "1")
    con = db()
    cur = con.execute(f"SELECT name, email FROM users WHERE id = {aid}")
    row = cur.fetchone()
    if not row:
        return "<html><body>not found</body></html>", 404
    return f"<html><body><h1>Account {aid}</h1><p>Name: {row[0]}</p><p>Email: {row[1]}</p></body></html>"

@app.route("/profile/<pid>")
def profile(pid):
    con = db()
    cur = con.execute(f"SELECT name FROM users WHERE id = {pid}")
    row = cur.fetchone()
    if not row:
        return "nope", 404
    return f"<html><body>Profile of {row[0]} (id {pid})</body></html>"

# ---------- NEW: JWT ----------
@app.route("/login")
def login():
    token = make_jwt({"sub": "guest", "role": "user", "exp": int(time.time()) + 3600})
    resp = make_response("<html><body>logged in</body></html>")
    resp.set_cookie("token", token)
    return resp

@app.route("/api/me")
def api_me():
    token = request.cookies.get("token", "") or request.headers.get("Authorization", "").replace("Bearer ", "")
    payload = check_jwt(token)
    if not payload:
        return "unauthorized", 401
    return f"<html><body><h1>me: {payload.get('sub')}</h1><p>role: {payload.get('role')}</p></body></html>"

# ---------- NEW: CSRF ----------
@app.route("/transfer", methods=["POST"])
def transfer():
    # VULN: state-changing POST with no CSRF token
    amount = request.form.get("amount", "0")
    return f"<html><body>Transferred ${amount}. No CSRF token required!</body></html>"

# ---------- secret leak for testing ----------
@app.route("/debug")
def debug():
    return "<html><body><!-- AWS_KEY=AKIAIOSFODNN7EXAMPLE --><p>debug page</p></body></html>"

# ---------- graphql for testing ----------
@app.route("/graphql", methods=["GET", "POST"])
def graphql():
    q = (request.get_json(silent=True) or {}).get("query", "")
    if "__schema" in q:
        return {"data": {"__schema": {"queryType": {"name": "Query"}}}}
    return {"data": {}}


if __name__ == "__main__":
    os.makedirs(os.path.join(os.path.dirname(__file__), "files"), exist_ok=True)
    with open(os.path.join(os.path.dirname(__file__), "files", "welcome.txt"), "w") as f:
        f.write("welcome to vulndemo")
    app.run(host="127.0.0.1", port=5055)
