"""SentinelX Academy Lab — one Flask app with a planted vuln per PortSwigger
Academy category, plus safe equivalents. Deterministic: no CSRF tokens,
no timestamps in responses (stable baselines).

Run: .venv/bin/python target/academy_lab.py  (port 5070)
"""
from __future__ import annotations

import base64
import json
import re
import time
from flask import Flask, request, Response, jsonify, make_response

app = Flask(__name__)

PRODUCTS = {1: "Red Widget", 2: "Blue Widget", 3: "Green Widget"}
USERS = {
    1: {"id": 1, "name": "alice", "email": "alice@example.com"},
    2: {"id": 2, "name": "bob", "email": "bob@example.com"},
    3: {"id": 3, "name": "carol", "email": "carol@example.com"},
}
COMMENTS: list[str] = []


# ---------- 1. SQLi: error-based ----------
@app.get("/lab/sqli_error")
def sqli_error():
    cat = request.args.get("category", "")
    if "'" in cat or '"' in cat:
        return ("sqlite3.OperationalError: near \"'\": syntax error", 500)
    return f"<html><body>Products in {cat}: widget1, widget2</body></html>"


@app.get("/lab/sqli_error_safe")
def sqli_error_safe():
    cat = request.args.get("category", "")
    if not re.fullmatch(r"[a-z]+", cat or "all"):
        return "Invalid category", 400
    return f"<html><body>Products in {cat}: widget1, widget2</body></html>"


# ---------- 2. SQLi: UNION-based ----------
@app.get("/lab/sqli_union")
def sqli_union():
    cat = request.args.get("category", "")
    if re.search(r"UNION\s+SELECT", cat, re.I):
        # simulate: version extracted via marker
        return "<html><body>Products: SXV5.7.33SXV, widget1</body></html>"
    if "'" in cat:
        return "SQL syntax error", 500
    return f"<html><body>Products in {cat}: widget1, widget2</body></html>"


# ---------- 3. SQLi: boolean-blind ----------
@app.get("/lab/sqli_blind")
def sqli_blind():
    cat = request.args.get("category", "")
    if "' AND '1'='2" in cat or "' AND 1=2" in cat:
        return "<html><body>No products found.</body></html>"
    return "<html><body>Products: widget1, widget2, widget3</body></html>"


# ---------- 4. SQLi: time-blind ----------
@app.get("/lab/sqli_time")
def sqli_time():
    cat = request.args.get("category", "")
    m = re.search(r"(?:SLEEP|pg_sleep)\((\d+)\)", cat, re.I)
    if m:
        time.sleep(int(m.group(1)))
        return "<html><body>Products: widget1</body></html>"
    if "WAITFOR" in cat.upper():
        m2 = re.search(r"0:0:(\d+)", cat)
        time.sleep(int(m2.group(1)) if m2 else 3)
        return "<html><body>Products: widget1</body></html>"
    return "<html><body>Products: widget1, widget2</body></html>"


# ---------- 5. SQLi: cookie-based (TrackingId) ----------
@app.get("/lab/sqli_cookie")
def sqli_cookie():
    tid = request.cookies.get("TrackingId", "")
    if "'" in tid:
        return ("sqlite3.OperationalError: unrecognized token: \"'\"", 500)
    if "' AND '1'='2" in tid:
        body = "<html><body>Welcome back.</body></html>"  # false: no products
    elif tid:
        body = "<html><body>Welcome back! Products: widget1, widget2</body></html>"
    else:
        body = "<html><body>Welcome! Products: widget1</body></html>"
    resp = make_response(body)
    if "TrackingId" not in request.cookies:
        resp.set_cookie("TrackingId", "abc123")
    return resp


# ---------- 6. XSS: reflected ----------
@app.get("/lab/xss_ref")
def xss_ref():
    q = request.args.get("q", "")
    return f"<html><body><h1>Search results for: {q}</h1></body></html>"


@app.get("/lab/xss_ref_safe")
def xss_ref_safe():
    import html as _h
    q = request.args.get("q", "")
    return f"<html><body><h1>Search results for: {_h.escape(q)}</h1></body></html>"


# ---------- 7. XSS: stored ----------
@app.post("/lab/xss_stored")
def xss_stored_post():
    c = request.form.get("comment", "")
    COMMENTS.append(c)
    return "Comment saved", 200


@app.get("/lab/xss_stored/view")
def xss_stored_view():
    items = "".join(f"<p>{c}</p>" for c in COMMENTS)
    return f"<html><body><h1>Comments</h1>{items}</body></html>"


# ---------- 8. CSRF: no token ----------
@app.get("/lab/csrf/form")
def csrf_form():
    return ('<html><body><form method="POST" action="/lab/csrf/email">'
            '<input name="email"><button>Change</button></form></body></html>')


@app.post("/lab/csrf/email")
def csrf_email():
    email = request.form.get("email", "")
    return f"<html><body>Email changed to {email}</body></html>"


# ---------- 9. Clickjacking: no frame headers ----------
@app.get("/lab/clickjack")
def clickjack():
    return "<html><body><h1>Account settings</h1></body></html>"


# ---------- 10. CORS: reflects arbitrary origin + credentials ----------
@app.get("/lab/cors")
def cors_lab():
    origin = request.headers.get("Origin", "")
    resp = make_response(jsonify({"data": "secret"}))
    if origin:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp


@app.get("/lab/cors_safe")
def cors_safe():
    resp = make_response(jsonify({"data": "public"}))
    resp.headers["Access-Control-Allow-Origin"] = "https://trusted.example.com"
    return resp


# ---------- 11. XXE ----------
@app.post("/lab/xxe")
def xxe_lab():
    data = request.data.decode(errors="replace")
    if "<!ENTITY" in data or "<!DOCTYPE" in data:
        return "<html><body>Parsed: root:x:0:0:root</body></html>"
    return "<html><body>XML parsed OK</body></html>"


# ---------- 12. SSRF ----------
@app.get("/lab/ssrf")
def ssrf_lab():
    target = request.args.get("url", "")
    # naive blocklist like PortSwigger's first SSRF lab
    if "127.0.0.1" in target or "localhost" in target:
        return "Blocked: host not allowed", 403
    if "169.254.169.254" in target:
        return "instance-id: i-12345", 200
    return f"<html><body>Fetched {target}: no content</body></html>", 200


# ---------- 13. OS command injection ----------
@app.get("/lab/rce")
def rce_lab():
    ip = request.args.get("ip", "")
    if any(s in ip for s in (";", "|", "&&", "`", "$(")):
        return "<html><body>uid=0(root) gid=0(root) groups=0(root)</body></html>"
    return f"<html><body>ping {ip}: 64 bytes</body></html>"


# ---------- 14. SSTI ----------
@app.get("/lab/ssti")
def ssti_lab():
    name = request.args.get("name", "")
    # simulate Jinja2 rendering
    out = name.replace("{{7*7}}", "49").replace("{{7*'7'}}", "7777777")
    return f"<html><body>Hello {out}</body></html>"


# ---------- 15. Path traversal ----------
@app.get("/lab/lfi")
def lfi_lab():
    f = request.args.get("file", "")
    if ".." in f or "%2e" in f.lower():
        return "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon", 200
    return f"<html><body>File: {f}</body></html>"


# ---------- 16. IDOR: real (user objects with emails) ----------
@app.get("/lab/api/users/<int:uid>")
def idor_users(uid):
    u = USERS.get(uid)
    if not u:
        return "Not found", 404
    return jsonify(u)


# ---------- 17. IDOR safe: public product catalog (must NOT flag) ----------
@app.get("/lab/product")
def product_catalog():
    pid = request.args.get("productId", "1")
    name = PRODUCTS.get(int(pid) if pid.isdigit() else 0, "Unknown product")
    return f"<html><body><h1>{name}</h1><p>Price: $10. In stock.</p></body></html>"


# ---------- 18. Auth: username enumeration ----------
@app.post("/lab/login")
def login_lab():
    u = request.form.get("username", "")
    p = request.form.get("password", "")
    if u != "admin":
        return "Invalid username", 200
    if p != "secret123":
        return "Invalid password", 200
    return "Welcome admin", 200


# ---------- 19. JWT: accepts alg=none ----------
# Exposes a real JWT in the page; the endpoint accepts Bearer tokens.
SAMPLE_JWT = ("eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYm9iIiwiYWRtaW4iOmZhbHNlfQ."
              "dGVzdHNpZ25hdHVyZXNpZ25hdHVyZXNpZ25hdHVyZQ")


@app.get("/lab/jwt")
def jwt_lab():
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:]
        # vulnerable: accept alg=none
        try:
            header = token.split(".")[0]
            h = json.loads(base64.urlsafe_b64decode(header + "==").decode())
            if h.get("alg") == "none":
                return jsonify({"user": "admin", "admin": True})
        except Exception:
            pass
        if token == SAMPLE_JWT:
            return jsonify({"user": "bob", "admin": False})
        return "Invalid token", 401
    return (f"<html><body><h1>Dashboard</h1>"
            f"<script>var token='{SAMPLE_JWT}';</script></body></html>")


# ---------- 20. Cache poisoning: unkeyed header reflection ----------
# Simulates a naive cache: keyed by URL only, NOT by X-Forwarded-Host.
_CACHE: dict[str, str] = {}


@app.get("/lab/cache")
def cache_lab():
    buster = request.args.get("cb", "")
    cache_key = request.path + ("?cb=" + buster if buster else "")
    if cache_key in _CACHE:
        resp = make_response(_CACHE[cache_key])
        resp.headers["X-Cache"] = "HIT"
        resp.headers["Age"] = "42"
        return resp
    host = request.headers.get("X-Forwarded-Host", "example.com")
    body = (f"<html><head><script src=\"https://{host}/app.js\"></script></head>"
            f"<body>Welcome</body></html>")
    _CACHE[cache_key] = body
    resp = make_response(body)
    resp.headers["X-Cache"] = "MISS"
    return resp


# ---------- 21. Deserialization ----------
@app.post("/lab/deser")
def deser_lab():
    data = request.form.get("data", "") or (request.data.decode(errors="replace"))
    # check raw (pickle protocol 0 is ASCII, not base64)
    if "cos" in data and "system" in data:
        return ("<html><body><h1>500</h1><pre>_pickle.UnpicklingError: "
                "os.system blocked by policy</pre></body></html>", 500)
    try:
        raw = base64.b64decode(data)
        if b"cos\nsystem" in raw or b"subprocess" in raw or b"os" in raw:
            return ("<html><body>pickle.UnpicklingError</body></html>", 500)
    except Exception:
        pass
    return "<html><body>Object loaded</body></html>"


# ---------- 22. Info disclosure ----------
@app.get("/lab/debug")
def debug_lab():
    return ("<html><body><h1>Traceback</h1><pre>File \"/app/main.py\", line 42\n"
            "DEBUG = True\nDB_PASSWORD='hunter2'\n"
            "AWS_SECRET_ACCESS_KEY='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'\n"
            "</pre></body></html>", 500)


@app.get("/lab/backup.bak")
def backup_lab():
    return "DB_PASSWORD='hunter2'\nAPI_KEY='sk-live-abc123def456'", 200


# ---------- 23. Host header: reset poisoning ----------
@app.route("/lab/reset", methods=["GET", "POST"])
def reset_lab():
    host = request.headers.get("Host", "example.com")
    # also honor X-Forwarded-Host override
    host = request.headers.get("X-Forwarded-Host", host)
    return f"<html><body>Reset link: https://{host}/reset?token=abc</body></html>"


# ---------- 24. File upload: unrestricted ----------
@app.get("/lab/upload")
def upload_form():
    return ('<html><body><form method="POST" enctype="multipart/form-data" '
            'action="/lab/upload"><input type="file" name="f"></form></body></html>')


@app.post("/lab/upload")
def upload_lab():
    f = request.files.get("f")
    if not f:
        return "No file", 400
    # vulnerable: no type check, no rename
    return f"<html><body>Uploaded to /uploads/{f.filename}</body></html>"


# ---------- 25. NoSQLi ----------
@app.post("/lab/nosql/login")
def nosql_lab():
    try:
        body = request.get_json(force=True)
    except Exception:
        return "Invalid JSON", 400
    user = body.get("username", "")
    pw = body.get("password", "")
    # vulnerable: Mongo-style operator injection
    if isinstance(pw, dict) and ("$gt" in pw or "$ne" in pw):
        return jsonify({"ok": True, "user": "admin"})
    if user == "admin" and pw == "secret123":
        return jsonify({"ok": True, "user": "admin"})
    return jsonify({"ok": False}), 401


# ---------- 26. LDAP ----------
@app.get("/lab/ldap")
def ldap_lab():
    u = request.args.get("user", "")
    if "*" in u or "(" in u:
        return "LDAP: error code 32 - No such object (dc=example)", 500
    return f"<html><body>User {u} found</body></html>"


# ---------- 27. XPath ----------
@app.get("/lab/xpath")
def xpath_lab():
    q = request.args.get("q", "")
    if "'" in q:
        return "XPathException: Invalid expression", 500
    return f"<html><body>Results for {q}</body></html>"


# ================= Juice Shop class representatives =================

# --- SQLi login bypass (Juice Shop: login admin with ' OR 1=1--) ---
@app.get("/lab/login_sqli")
def login_sqli_form():
    return ('<html><body><form method="POST" action="/lab/login_sqli">'
            '<input name="username"><input name="password" type="password">'
            '<button>Login</button></form></body></html>')


@app.post("/lab/login_sqli")
def login_sqli():
    u = request.form.get("username", "")
    p = request.form.get("password", "")
    # simulate vulnerable: SELECT * FROM users WHERE username='<u>' AND password='<p>'
    if "' OR '1'='1" in u or "' OR 1=1" in u or "'--" in u or "' #" in u:
        return "<html><body>Welcome admin! <a href='/lab/admin'>Admin panel</a></body></html>"
    if "'" in u or "'" in p:
        return ("sqlite3.OperationalError: near \"'\": syntax error", 500)
    if u == "admin" and p == "secret123":
        return "<html><body>Welcome admin</body></html>"
    return "<html><body>Invalid credentials</body></html>"


# --- DOM XSS: location.hash sink (Juice Shop: multiple DOM challenges) ---
@app.get("/lab/domxss")
def domxss_lab():
    return ("""<html><body><div id="out"></div><script>
var h = location.hash.slice(1);
document.getElementById('out').innerHTML = h;
</script></body></html>""")


# --- Forced browsing: admin panel with no auth check ---
@app.get("/lab/admin")
def admin_lab():
    return "<html><body><h1>Admin panel</h1><p>Users: alice, bob</p></body></html>"


# --- Basket IDOR: user baskets with emails (Juice Shop: basket challenges) ---
BASKETS = {
    1: {"id": 1, "user": "alice@example.com", "items": ["widget"]},
    2: {"id": 2, "user": "bob@example.com", "items": ["gadget"]},
}


@app.get("/lab/api/baskets/<int:bid>")
def basket_idor(bid):
    b = BASKETS.get(bid)
    if not b:
        return "Not found", 404
    return jsonify(b)


# --- Exposed config/credentials in JS bundle (Juice Shop: sensitive data) ---
@app.get("/lab/app.js")
def app_js():
    return ("""// app bundle
var API_KEY = 'sk-live-abc123def456ghi789';
var STRIPE_KEY = 'pk_live_51H7xYzAbCdEfGhIjKlMn';
fetch('/lab/api/products');
""", 200, {"Content-Type": "application/javascript"})


# --- Weak credentials: admin:admin works (Juice Shop: weak password) ---
@app.post("/lab/login_weak")
def login_weak():
    u = request.form.get("username", "")
    p = request.form.get("password", "")
    if (u, p) in (("admin", "admin"), ("admin", "password123")):
        return "<html><body>Welcome admin</body></html>"
    return "<html><body>Invalid credentials</body></html>"


@app.get("/")
def index():
    return "<html><body><h1>Academy Lab</h1></body></html>"


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5070, threaded=True)
