"""API-only backend: NO HTML at all, just JSON endpoints.
Tests: OpenAPI probing, response mining for URLs, JSON content-type handling."""
from flask import Flask, request, jsonify, Response
import html as _h

app = Flask(__name__)

USERS = [{"id": 1, "name": "alice", "email": "alice@example.com"},
         {"id": 2, "name": "bob", "email": "bob@example.com"}]

@app.route("/openapi.json")
def openapi():
    return jsonify({
        "openapi": "3.0.0",
        "paths": {
            "/api/v1/users": {"get": {"parameters": [{"name": "q"}]}},
            "/api/v1/users/{id}": {"get": {"parameters": [{"name": "id"}]}},
            "/api/v1/search": {"get": {"parameters": [{"name": "term"}]}},
        }
    })

@app.route("/api/v1/users")
def users():
    q = request.args.get("q", "")
    if "'" in q:  # SQLi simulation
        return Response("SQL syntax error near '%s'" % _h.escape(q[:30]), status=500)
    # response mining: contains links to other endpoints
    return jsonify({"users": USERS, "next": "/api/v1/users?page=2",
                    "related": "/api/v1/search?term=test"})

@app.route("/api/v1/users/<uid>")
def user(uid):
    # IDOR: no auth
    u = next((x for x in USERS if str(x["id"]) == uid), None)
    return jsonify(u or {"error": "not found"})

@app.route("/api/v1/search")
def search():
    term = request.args.get("term", "")
    return jsonify({"results": ["x"], "echo": term})

@app.route("/")
def root():
    # no HTML — just a JSON pointer
    return jsonify({"api": "/openapi.json", "version": "1.0"})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5062, threaded=True)
