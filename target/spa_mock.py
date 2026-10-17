"""SentinelX jsenv test target — DELIBERATELY VULNERABLE mock SPA.

Serves a page whose JavaScript:
  1. calls fetch('/api/hidden/users') — an API invisible to static HTML
  2. does document.getElementById('x').innerHTML = location.hash.slice(1)
     — a REAL DOM XSS (hash -> innerHTML dataflow)
  3. registers client-side routes (/app/dashboard, /app/admin)

Run: python target/spa_mock.py   (listens on 127.0.0.1:5056)
Only for testing the scanner. Never expose publicly.
"""

from flask import Flask, request, jsonify

app = Flask(__name__)

SPA_PAGE = """<!DOCTYPE html>
<html>
<head><title>MockApp SPA</title></head>
<body>
<div id="root"></div>
<div id="x"></div>
<script>
// mock SPA bootstrap
var API_BASE = "/api";
function loadUsers() {
    fetch(API_BASE + "/hidden/users")
        .then(function(r) { return r.json(); });
    fetch("/api/v2/orders", {method: "POST", body: JSON.stringify({all: true})});
}
function render() {
    // DOM XSS: location.hash flows into innerHTML
    var h = location.hash.slice(1);
    document.getElementById("x").innerHTML = h;
    // second sink: document.write with search
    document.write("<p>search was: " + location.search + "</p>");
}
// client-side routes
var routes = {
    "/app/dashboard": "dash",
    "/app/admin": "admin"
};
history.pushState({}, "", "/app/dashboard");
loadUsers();
render();
</script>
</body>
</html>
"""


@app.route("/")
def index():
    return SPA_PAGE, 200, {"Content-Type": "text/html"}


@app.route("/api/hidden/users")
def hidden_users():
    return jsonify([{"id": 1, "name": "alice"}, {"id": 2, "name": "bob"}])


@app.route("/api/v2/orders", methods=["POST"])
def orders():
    return jsonify({"orders": []})


@app.route("/app/<path:p>")
def spa_route(p):
    # SPA fallback — same page for all client routes
    return SPA_PAGE, 200, {"Content-Type": "text/html"}


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5057, debug=False)
