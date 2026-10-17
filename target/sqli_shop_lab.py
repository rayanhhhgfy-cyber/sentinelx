"""Test shop mimicking the classic PortSwigger SQLi lab pattern.
- / : homepage with category filter links
- /filter?category=Pets : VULNERABLE to SQLi (string concatenation into query)
- /product?productId=1 : safe product page
"""
from __future__ import annotations
import sqlite3
import html as _html
from flask import Flask, request, Response

app = Flask(__name__)

# In-memory DB with products
DB = sqlite3.connect(":memory:", check_same_thread=False)
DB.execute("CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, category TEXT, price REAL)")
DB.executemany(
    "INSERT INTO products VALUES (?,?,?,?)",
    [
        (1, "Furball", "Pets", 19.99),
        (2, " squeaky Toy", "Pets", 9.99),
        (3, "Coffee Mug", "Gifts", 12.50),
        (4, "Notebook", "Gifts", 7.25),
    ],
)
DB.commit()

CATEGORIES = ["Pets", "Gifts"]


@app.route("/")
def home():
    links = "".join(
        f'<li><a href="/filter?category={c}">{c}</a></li>' for c in CATEGORIES
    )
    products = "".join(
        f'<li><a href="/product?productId={r[0]}">{_html.escape(r[1])}</a></li>'
        for r in DB.execute("SELECT id, name FROM products")
    )
    return f"""<html><head><title>Shop</title></head><body>
<h1>Welcome to the shop</h1>
<h2>Categories</h2><ul>{links}</ul>
<h2>Products</h2><ul>{products}</ul>
</body></html>"""


@app.route("/filter")
def filter_cat():
    category = request.args.get("category", "")
    # VULNERABLE: direct string concatenation (classic lab pattern)
    query = f"SELECT name, price FROM products WHERE category = '{category}'"
    try:
        rows = DB.execute(query).fetchall()
    except Exception:
        # SUPPRESSED error like PortSwigger labs (generic 500, no DB details)
        return Response("<html><body><h1>Internal Server Error</h1></body></html>", status=500)
    items = "".join(f"<li>{_html.escape(r[0])} — ${r[1]}</li>" for r in rows)
    return f"<html><body><h1>Category: {_html.escape(category)}</h1><ul>{items}</ul></body></html>"


@app.route("/product")
def product():
    pid = request.args.get("productId", "")
    try:
        pid_int = int(pid)
    except ValueError:
        return Response("Invalid product id", status=400)
    row = DB.execute("SELECT name, price FROM products WHERE id = ?", (pid_int,)).fetchone()
    if not row:
        return Response("Not found", status=404)
    return f"<html><body><h1>{_html.escape(row[0])}</h1><p>${row[1]}</p></body></html>"


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5071, threaded=True)
