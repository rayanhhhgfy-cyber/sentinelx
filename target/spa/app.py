"""Minimal Angular-style SPA test target: empty HTML shell + JS bundles with API calls.
Simulates Juice Shop: <app-root> + main.js bundle that calls REST APIs."""
from flask import Flask, request, Response, jsonify
import html as _h

app = Flask(__name__)

INDEX_HTML = """<!doctype html><html><head><title>Shop SPA</title>
<link rel="stylesheet" href="/styles.css"></head>
<body><app-root></app-root>
<script src="/runtime.js"></script>
<script src="/main.js"></script>
</body></html>"""

# Minified webpack-style bundle (one huge line) with API calls + a vuln
MAIN_JS = """!function(){var e={api:"/api"};function t(u){return fetch(e.api+u).then(r=>r.json())}
t("/products").then(p=>{document.querySelector("app-root").innerHTML=p.map(x=>"<div>"+x.name+"</div>").join("")});
document.addEventListener("click",function(ev){var q=new URLSearchParams(location.search).get("q");if(q){document.body.innerHTML="<h1>Results for "+q+"</h1>"}});
var cfg={apiKey:"sk_test_51HxYzAbCdEfGhIjKlMnOp"};
function getProduct(id){return fetch(e.api+"/products/"+id).then(r=>r.json())}
function searchProducts(q){return fetch(e.api+"/search?q="+encodeURIComponent(q)).then(r=>r.text())}function login(u,pw){return fetch("/api/login",{method:"POST",headers:{"Content-Type":"application/json","X-Client-Version":"2.1"},body:JSON.stringify({username:u,password:pw})})}window.__shop={login:login,ver:"2.1"};}();"""

RUNTIME_JS = """window.webpackChunk={push:function(m){for(var k in m){try{m[k]()}catch(e){}}}};"""

@app.route("/")
def index():
    return Response(INDEX_HTML, mimetype="text/html")

@app.route("/main.js")
def main_js():
    return Response(MAIN_JS, mimetype="application/javascript")

@app.route("/runtime.js")
def runtime_js():
    return Response(RUNTIME_JS, mimetype="application/javascript")

@app.route("/styles.css")
def css():
    return Response("body{margin:0}", mimetype="text/css")

# --- APIs ---
PRODUCTS = [{"id": 1, "name": "Apple"}, {"id": 2, "name": "Orange"}]

@app.route("/api/products")
def api_products():
    return jsonify(PRODUCTS)

@app.route("/api/products/<pid>")
def api_product(pid):
    # IDOR: no auth check
    p = next((x for x in PRODUCTS if str(x["id"]) == pid), None)
    return jsonify(p or {"error": "not found"})

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(force=True, silent=True) or {}
    # SQLi simulation: string-concat query
    q = data.get("username", "")
    if "'" in q:
        return Response("SQL syntax error near '%s'" % _h.escape(q[:30]), status=500)
    if q == "admin" and data.get("password") == "admin123":
        return jsonify({"token": "fake-jwt-token"})
    return Response("Invalid credentials", status=401)

@app.route("/api/search")
def api_search():
    q = request.args.get("q", "")
    # reflected XSS
    return Response("<html><body><h1>Results for %s</h1></body></html>" % q, mimetype="text/html")

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5061, threaded=True)
