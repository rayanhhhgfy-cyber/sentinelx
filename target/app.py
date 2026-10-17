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
    <a href="/account?id=1">account</a> <a href="/xml">xml</a>
    <a href="/template?name=guest">template</a> <a href="/reset?email=a@x.com">reset</a>
    <a href="/ldap?user=admin">ldap</a> <a href="/xpath?q=test">xpath</a>
    <a href="/agent">agent</a> <a href="/redirect?next=/">redirect</a>
    <a href="/jsgo?url=/">jsgo</a> <a href="/api/users/1">api user</a>
    <a href="/pollute?a=b">pollute</a> <a href="/crlftest?next=/">crlftest</a>
    <form action="/search" method="GET"><input name="q" value="x"><input type="submit"></form>
    <form action="/transfer" method="POST"><input type="hidden" name="amount" value="10"><input type="submit" value="send"></form>
    <form action="/pickle" method="POST"><input name="data" value="x"><input type="submit"></form>
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

# ---------- NEW: XXE test endpoint ----------
@app.route("/xml", methods=["POST"])
def xml_parse():
    # VULN: parses XML with external entities enabled
    import xml.etree.ElementTree as ET
    data = request.data.decode("utf-8", "replace")
    try:
        # Simulate vulnerable parser: resolve file:// entities naively
        import re
        m = re.search(r'SYSTEM\s+"file://([^"]+)"', data)
        content = ""
        if m:
            try:
                with open(m.group(1), errors="replace") as fh:
                    content = fh.read(2000)
            except Exception as e:
                content = f"failed to load external entity {m.group(1)}: {e}"
        m2 = re.search(r"&(\w+);", data)
        return f"<html><body><r>{content or 'parsed'}</r></body></html>"
    except Exception as e:
        return f"<html><body>xml parse error: {e}</body></html>", 400

# ---------- NEW: SSTI test endpoint ----------
@app.route("/template")
def template():
    # VULN: renders user input as Jinja2 template
    from jinja2 import Template
    name = request.args.get("name", "guest")
    try:
        t = Template(f"<html><body><h1>Hello {name}</h1></body></html>")
        return t.render()
    except Exception as e:
        return f"<html><body>jinja2 UndefinedError: {e}</body></html>", 500

# ---------- NEW: Host header password reset ----------
@app.route("/reset")
def reset():
    # VULN: reset link built from Host header
    email = request.args.get("email", "user@x.com")
    host = request.headers.get("Host", "127.0.0.1:5055")
    return (f'<html><body><p>Reset link sent to {email}:</p>'
            f'<a href="http://{host}/reset/confirm?token=abc123">'
            f"http://{host}/reset/confirm?token=abc123</a></body></html>")

# ---------- NEW: LDAP injection test endpoint ----------
@app.route("/ldap")
def ldap_search():
    # VULN: LDAP filter injection (simulated with error messages)
    user = request.args.get("user", "")
    # Simulate LDAP error on metacharacters
    if any(c in user for c in ("*", "(", ")", "\\", "\x00")):
        if "*)" in user or "*(" in user:
            return ("<html><body>LDAPException: Invalid filter: "
                    "unbalanced parentheses near '*'</body></html>", 500)
        return "<html><body>LDAP: 3 users found</body></html>"
    if user == "admin":
        return "<html><body>LDAP: 1 user found: admin</body></html>"
    return "<html><body>LDAP: 0 users found</body></html>"

# ---------- NEW: XPath injection test endpoint ----------
@app.route("/xpath")
def xpath_query():
    # VULN: XPath injection (simulated)
    q = request.args.get("q", "")
    if "'" in q and "or" in q.lower():
        return ("<html><body>XPathException: Invalid expression: "
                "unexpected token 'or' — 5 nodes matched</body></html>", 500)
    if "'" in q:
        return ("<html><body>XPathException: Invalid predicate: "
                "unclosed string literal</body></html>", 500)
    return f"<html><body>XPath: 1 node for '{q}'</body></html>"

# ---------- NEW: Header-based RCE ----------
@app.route("/agent")
def agent():
    # VULN: User-Agent passed to shell
    ua = request.headers.get("User-Agent", "")
    try:
        out = subprocess.run(f"echo AGENT {ua}", shell=True, capture_output=True,
                             text=True, timeout=12).stdout
    except subprocess.TimeoutExpired:
        out = "TIMEOUT"
    return f"<html><body><pre>{out}</pre></body></html>"

# ---------- NEW: CRLF injection ----------
@app.route("/redirect")
def crlf_redirect():
    # VULN: user input in header without sanitization
    nxt = request.args.get("next", "/")
    resp = make_response("<html><body>redirecting</body></html>")
    # Simulate vulnerable header injection (Flask blocks real CRLF, so we
    # reflect it in a custom header value for the scanner to detect)
    resp.headers["X-Redirect-To"] = nxt
    return resp

@app.route("/crlftest")
def crlf_test():
    # VULN: simulates a server with no CRLF sanitization (old PHP/Node)
    import urllib.parse
    nxt = request.args.get("next", "/")
    resp = make_response("<html><body>crlf test</body></html>")
    decoded = urllib.parse.unquote(nxt)
    # vulnerable: splits on CRLF and treats each line as a header
    for line in decoded.replace("\r", "\n").split("\n"):
        if ":" in line:
            k, v = line.split(":", 1)
            k = k.strip()
            if k and k.lower() not in ("content-length", "host"):
                try:
                    resp.headers[k] = v.strip()
                except Exception:
                    pass
    return resp

# ---------- NEW: JS-based open redirect ----------
@app.route("/jsgo")
def js_go():
    # VULN: URL reflected into JavaScript context
    url = request.args.get("url", "/")
    return (f"<html><body><script>var target = '{url}'; "
            f"if (target) window.location = target;</script></body></html>")

# ---------- NEW: IDOR API ----------
@app.route("/api/users/<uid>")
def api_user(uid):
    # VULN: no auth check on API IDOR
    con = db()
    try:
        cur = con.execute(f"SELECT name, email FROM users WHERE id = {uid}")
        row = cur.fetchone()
    except Exception:
        return {"error": "invalid"}, 400
    if not row:
        return {"error": "not found"}, 404
    return {"id": uid, "name": row[0], "email": row[1]}

# ---------- NEW: JWT advanced (jwk/kid) ----------
@app.route("/api/admin")
def api_admin():
    # VULN: accepts kid path traversal and jwk confusion (simulated)
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    try:
        h, p, s = token.split(".")
        header = json.loads(base64.urlsafe_b64decode(h + "=="))
        # VULN: kid used as file path
        kid = header.get("kid", "")
        if kid and ("../" in kid or "..\\" in kid):
            return "<html><body>JWT: kid path traversal accepted</body></html>"
        # VULN: jwk embedded key trusted
        if "jwk" in header:
            return "<html><body>JWT: embedded jwk trusted</body></html>"
    except Exception:
        pass
    return "unauthorized", 401

# ---------- NEW: Prototype pollution ----------
@app.route("/pollute")
def pollute():
    # VULN: query params merged into JS object without sanitization
    params = dict(request.args)
    js_obj = "{"
    for k, v in params.items():
        js_obj += f'"{k}": "{v}",'
    js_obj += "}"
    return (f"<html><body><script>var config = {js_obj}; "
            f"var polluted = config.__proto__.polluted;</script>"
            f"<p>config loaded</p></body></html>")

# ---------- NEW: Deserialization ----------
@app.route("/pickle", methods=["POST"])
def pickle_load():
    # VULN: unpickles user-supplied base64
    import pickle
    data = request.data
    try:
        raw = base64.b64decode(data)
        obj = pickle.loads(raw)
        return f"<html><body>unpickled: {type(obj).__name__}</body></html>"
    except Exception as e:
        return f"<html><body>pickle.UnpicklingError: {e}</body></html>", 400


if __name__ == "__main__":
    os.makedirs(os.path.join(os.path.dirname(__file__), "files"), exist_ok=True)
    with open(os.path.join(os.path.dirname(__file__), "files", "welcome.txt"), "w") as f:
        f.write("welcome to vulndemo")
    app.run(host="127.0.0.1", port=5055)
