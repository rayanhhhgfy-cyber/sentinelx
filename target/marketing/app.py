"""Nexora — fake digital agency marketing site (deliberately vulnerable).

Test target for SentinelX dynamic-discovery proof. Run:
    python3 target/marketing/app.py
Then scan:
    python3 -m sentinelx.cli --target http://127.0.0.1:5056 --confirm-own --no-wordlist
"""

import os
import sqlite3
from flask import Flask, request, jsonify, make_response, redirect, send_file

app = Flask(__name__, static_folder="static", static_url_path="/static")
BASE = os.path.dirname(os.path.abspath(__file__))

# --------------------------------------------------------------------------
# Blog DB (SQLi via string-concatenated query, errors reflected)
# --------------------------------------------------------------------------
DB = os.path.join(BASE, "blog.db")


def init_db():
    if os.path.exists(DB):
        os.remove(DB)
    con = sqlite3.connect(DB)
    con.execute("CREATE TABLE posts (id INTEGER PRIMARY KEY, title TEXT, body TEXT)")
    posts = [
        ("Why your brand needs a redesign", "A fresh look converts visitors into customers..."),
        ("SEO in 2026: what still works", "Content quality beats keyword stuffing every time..."),
        ("Our cloud migration playbook", "We moved 40 clients to the cloud last year..."),
        ("Design systems that scale", "Tokens, components, and governance..."),
    ]
    con.executemany("INSERT INTO posts (title, body) VALUES (?, ?)", posts)
    con.commit()
    con.close()


# --------------------------------------------------------------------------
# Fake client data (IDOR: /api/clients/<id> exposes other clients)
# --------------------------------------------------------------------------
CLIENTS = {
    1: {"id": 1, "name": "Acme Corp", "contact": "alice@acme.example",
        "contract_value": 120000, "internal_notes": "Late payer. Escalate to legal if 60d overdue."},
    2: {"id": 2, "name": "Globex Inc", "contact": "bob@globex.example",
        "contract_value": 85000, "internal_notes": "CEO wants weekly reports. Do NOT share roadmap."},
    3: {"id": 3, "name": "Initech LLC", "contact": "carol@initech.example",
        "contract_value": 210000, "internal_notes": "Renewal at risk — competitor undercut by 15%."},
}

NAV = """
<nav>
  <a href="/">Home</a> | <a href="/about">About</a> | <a href="/services">Services</a> |
  <a href="/pricing">Pricing</a> | <a href="/blog">Blog</a> | <a href="/contact">Contact</a> |
  <a href="/go?next=https://portal.nexora.example">Client portal</a>
</nav>
"""

FOOTER = """
<footer><p>&copy; 2026 Nexora Digital. All rights reserved.</p>
<p><a href="/go?next=/pricing">See plans</a></p></footer>
"""

# NOTE: the HTML comment below is intentional — it is how a scanner doing
# DYNAMIC discovery (comment mining) finds /backup.zip without wordlists.
BACKUP_COMMENT = "<!-- deploy backup: /backup.zip — TODO: remove before launch -->\n"


def page(title, body, scripts=()):
    tags = "\n".join(f'<script src="/static/js/{s}"></script>' for s in scripts)
    html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>{title} — Nexora Digital</title>
<link rel="stylesheet" href="/static/css/style.css"></head>
<body>
{BACKUP_COMMENT}
<header><h1>Nexora Digital</h1>{NAV}</header>
<main>{body}</main>
{FOOTER}
{tags}
</body></html>"""
    resp = make_response(html)
    # cookie WITHOUT HttpOnly / Secure (intentional)
    resp.set_cookie("nx_session", "guest-abc123")
    return resp


@app.route("/")
def home():
    body = """
<h2>We build brands that convert.</h2>
<p>Nexora is a full-service digital agency. Strategy, design, engineering.</p>
<div id="nx-spotlight"><h3>Client spotlight</h3><div id="spotlight-body">Loading…</div></div>
<section id="newsletter">
  <h3>Get our newsletter</h3>
  <div id="nx-promo"></div>
  <form id="nx-newsletter" method="post" action="/api/newsletter">
    <input type="email" name="email" placeholder="you@example.com" required>
    <button type="submit">Subscribe</button>
  </form>
  <div id="nx-news-msg"></div>
</section>
"""
    return page("Home", body, scripts=("main.js", "newsletter.js", "analytics.js"))


@app.route("/about")
def about():
    return page("About", "<h2>About Nexora</h2><p>Founded 2019. 40+ specialists.</p>",
                scripts=("main.js", "analytics.js"))


@app.route("/services")
def services():
    body = """
<h2>Services</h2>
<ul><li>Brand identity</li><li>Web engineering</li><li>Cloud migration</li></ul>
<p><a href="/download?file=cloud-migration-playbook.pdf">Download our cloud migration whitepaper</a></p>
<p><a href="/download?file=brand-guidelines.pdf">Brand guidelines (PDF)</a></p>
"""
    return page("Services", body, scripts=("main.js", "analytics.js"))


@app.route("/pricing")
def pricing():
    return page("Pricing", "<h2>Pricing</h2><p>Starter $2k · Growth $8k · Enterprise custom.</p>",
                scripts=("main.js", "analytics.js"))


@app.route("/blog")
def blog():
    con = sqlite3.connect(DB)
    posts = con.execute("SELECT id, title FROM posts").fetchall()
    con.close()
    items = "".join(f'<li><a href="/blog/post/{pid}">{t}</a></li>' for pid, t in posts)
    body = f"""
<h2>Blog</h2>
<form method="get" action="/blog/search">
  <input type="text" name="q" placeholder="Search articles…">
  <button type="submit">Search</button>
</form>
<ul>{items}</ul>
"""
    return page("Blog", body, scripts=("main.js", "analytics.js"))


@app.route("/blog/search")
def blog_search():
    q = request.args.get("q", "")
    # INTENTIONAL SQLi: string-concatenated query, DB errors reflected
    con = sqlite3.connect(DB)
    try:
        rows = con.execute(
            f"SELECT id, title FROM posts WHERE title LIKE '%{q}%' OR body LIKE '%{q}%'"
        ).fetchall()
        err = ""
    except Exception as e:
        rows, err = [], f"Database error: {e}"
    con.close()
    items = "".join(f'<li><a href="/blog/post/{pid}">{t}</a></li>' for pid, t in rows)
    # INTENTIONAL reflected XSS: q echoed without encoding
    body = f"<h2>Search results for: {q}</h2>"
    if err:
        body += f"<p class='error'>{err}</p>"
    body += f"<ul>{items}</ul>" if items else "<p>No results.</p>"
    return page("Search", body, scripts=("main.js",))


@app.route("/blog/post/<int:pid>")
def blog_post(pid):
    con = sqlite3.connect(DB)
    row = con.execute("SELECT title, body FROM posts WHERE id=?", (pid,)).fetchone()
    con.close()
    if not row:
        return "Not found", 404
    return page(row[0], f"<h2>{row[0]}</h2><p>{row[1]}</p>", scripts=("main.js",))


@app.route("/contact", methods=["GET"])
def contact():
    # INTENTIONAL: no CSRF token on this form
    body = """
<h2>Contact us</h2>
<form id="nx-contact" method="post" action="/api/contact">
  <input type="text" name="name" placeholder="Your name" required><br>
  <input type="email" name="email" placeholder="Email" required><br>
  <textarea name="message" placeholder="How can we help?"></textarea><br>
  <button type="submit">Send</button>
</form>
<div id="nx-contact-msg"></div>
"""
    return page("Contact", body, scripts=("contact-form.js", "analytics.js"))


@app.route("/go")
def go():
    # INTENTIONAL open redirect
    nxt = request.args.get("next", "/")
    return redirect(nxt)


@app.route("/download")
def download():
    # INTENTIONAL LFI: whitepaper downloads, naive path join
    fname = request.args.get("file", "")
    path = os.path.join(BASE, "whitepapers", fname)
    if not os.path.isfile(path):
        return "Whitepaper not found", 404
    return send_file(path)


# --------------------------------------------------------------------------
# APIs
# --------------------------------------------------------------------------
@app.route("/api/newsletter", methods=["POST"])
def api_newsletter():
    data = request.get_json(silent=True) or request.form
    email = data.get("email", "")
    return jsonify({"ok": True, "message": f"Subscribed {email}!"})


@app.route("/api/contact", methods=["POST"])
def api_contact():
    # INTENTIONAL: state-changing POST with no CSRF protection
    data = request.get_json(silent=True) or request.form
    return jsonify({"ok": True, "message": f"Thanks {data.get('name', 'friend')}, we'll reply soon."})


@app.route("/api/clients/<int:cid>")
def api_client(cid):
    # INTENTIONAL IDOR: no auth, sequential IDs, sensitive fields exposed
    c = CLIENTS.get(cid)
    if not c:
        return jsonify({"error": "not found"}), 404
    return jsonify(c)


@app.route("/api/internal/stats")
def api_internal_stats():
    # INTENTIONAL: internal API with zero auth, called by analytics.js
    return jsonify({
        "visitors_today": 1234,
        "revenue_mtd": 48210,
        "server": "prod-web-03",
        "db_host": "db-internal.nexora.local",
    })


# --------------------------------------------------------------------------
# Info disclosure
# --------------------------------------------------------------------------
@app.route("/.git/HEAD")
def git_head():
    return "ref: refs/heads/main\n", 200, {"Content-Type": "text/plain"}


@app.route("/backup.zip")
def backup():
    # fake backup file — reachable, referenced from an HTML comment
    return "PK\x03\x04FAKE-ZIP-BACKUP-NEXORA-DB-DUMP", 200, {"Content-Type": "application/zip"}


if __name__ == "__main__":
    init_db()
    # whitepaper fixtures
    wp = os.path.join(BASE, "whitepapers")
    os.makedirs(wp, exist_ok=True)
    for name, text in [
        ("cloud-migration-playbook.pdf", "NEXORA CLOUD MIGRATION PLAYBOOK (sample)\nStep 1: assess..."),
        ("brand-guidelines.pdf", "NEXORA BRAND GUIDELINES (sample)\nLogo clearspace..."),
    ]:
        with open(os.path.join(wp, name), "w") as f:
            f.write(text)
    print("Nexora marketing site on http://127.0.0.1:5056")
    # threaded: the scanner fires concurrent requests; single-threaded dev
    # servers queue them and produce fake "time-blind" delays
    app.run(host="127.0.0.1", port=5056, threaded=True)
