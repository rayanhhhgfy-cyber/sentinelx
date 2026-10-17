"""SentinelX test target: realistic SSRF lab (PortSwigger-style).

- GET /product?stockApi=<url>  — fetches the URL server-side, returns stock info.
  Naive blocklist rejects the literal string "127.0.0.1" (bypass needed).
- GET /admin — internal only (127.0.0.1); reachable via SSRF bypass payloads.
- Other params are NOT vulnerable (FP check for the scanner).

Run:  python3 target/ssrf_lab.py   (listens on 127.0.0.1:5060)
"""

from __future__ import annotations

import re
import urllib.request
import urllib.error
from flask import Flask, request, Response

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Internal-only admin panel (simulates cloud-internal / admin interface)
# ---------------------------------------------------------------------------
@app.route("/admin")
def admin():
    # Only reachable from localhost — i.e. via SSRF, not directly... but
    # the scanner runs locally too, so we gate on a header the SSRF sets.
    # Realistic enough: direct browser hits get 403, SSRF-forwarded gets 200.
    if request.headers.get("X-Forwarded-For") == "127.0.0.1" or \
            request.remote_addr == "127.0.0.1" and request.args.get("via") == "ssrf":
        return Response(
            "<html><body><h1>Admin panel</h1>"
            "<p>users: admin, deploy, backup_svc</p>"
            "<p>SSRF-ADMIN-MARKER-9f3k2</p></body></html>",
            mimetype="text/html")
    # Direct external access denied — but SSRF from the same host passes
    # via the ?via=ssrf channel the product page sets (simulates the
    # server-side request carrying internal context).
    return Response("403 - internal only", status=403)


# ---------------------------------------------------------------------------
# Vulnerable product page: ?stockApi=<url>
# ---------------------------------------------------------------------------
BLOCKED_LITERAL = "127.0.0.1"  # naive blocklist: literal string match only


@app.route("/product")
def product():
    name = request.args.get("name", "Widget")
    color = request.args.get("color", "red")   # NOT vulnerable (FP check)
    stock_api = request.args.get("stockApi", "")
    # a second URL-ish param to prove param prioritization works
    thumb = request.args.get("thumb", "")      # NOT vulnerable (FP check)

    stock_info = "no stock API queried"
    if stock_api:
        # --- naive blocklist: rejects the literal string only ---
        if BLOCKED_LITERAL in stock_api:
            return Response(
                f"<html><body><h1>{name}</h1>"
                f"<p>color: {color}</p>"
                f"<p>Blocked: host not allowed</p></body></html>",
                mimetype="text/html")
        # --- vulnerable fetch ---
        try:
            # mark internal fetches so /admin treats them as server-side
            req = urllib.request.Request(
                stock_api, headers={"X-Forwarded-For": "127.0.0.1"})
            with urllib.request.urlopen(req, timeout=4) as r:
                data = r.read(4000).decode("utf-8", "replace")
            # reflect fetched content (like PortSwigger's stock API labs)
            stock_info = f"stock data: {data[:1500]}"
        except urllib.error.URLError as e:
            # error oracle: reason leaks that a fetch was attempted
            stock_info = f"stock check failed: {e.reason}"
        except Exception as e:  # noqa: BLE001 - lab realism
            stock_info = f"stock check failed: {type(e).__name__}: {e}"

    # escape name/color for HTML (not vulnerable), stock_info is server-fetched
    import html as _html
    return Response(
        f"<html><head><title>Shop</title></head><body>"
        f"<h1>{_html.escape(name)}</h1>"
        f"<p>color: {_html.escape(color)}</p>"
        f"<p>{stock_info}</p>"
        f'<form method="get" action="/product">'
        f'<input type="hidden" name="name" value="{_html.escape(name)}">'
        f'<input type="text" name="stockApi" placeholder="stock API URL">'
        f'<input type="submit" value="check stock"></form>'
        f'<img src="/static/logo.png" srcset="/static/logo-2x.png 2x" '
        f'data-src="/static/logo-lazy.png">'
        f'<a href="/about">About</a>'
        f"</body></html>",
        mimetype="text/html")


@app.route("/about")
def about():
    return Response(
        "<html><body><h1>About our shop</h1>"
        "<p>We sell widgets.</p>"
        '<meta property="og:image" content="/static/og.png">'
        "<!-- internal docs: /docs/internal.html -->"
        "</body></html>", mimetype="text/html")


@app.route("/docs/internal.html")
def internal_docs():
    return Response(
        "<html><body><p>Internal docs. Stock API: /api/stock?item=1</p></body></html>",
        mimetype="text/html")


@app.route("/api/stock")
def api_stock():
    item = request.args.get("item", "?")
    return {"item": item, "stock": 42}


if __name__ == "__main__":
    # threaded=True: the lab must handle the scanner's concurrent probes
    # without serializing them (else time-based detection breaks).
    app.run(host="127.0.0.1", port=5060, threaded=True)
