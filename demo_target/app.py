"""
demo_target/app.py — Intentionally Vulnerable API for Safe Testing.
⚠️  FOR EDUCATIONAL & TESTING PURPOSES ONLY — DO NOT DEPLOY ON PUBLIC SERVERS ⚠️

Runs on port 5001. Exposes intentional vulnerabilities for APIAST to detect.
"""

import json
import time
from flask import Flask, request, jsonify, make_response

app = Flask(__name__)

# "Database" in memory
USERS = {
    1: {"id": 1, "username": "alice",   "email": "alice@example.com", "role": "user",  "balance": 1000},
    2: {"id": 2, "username": "bob",     "email": "bob@example.com",   "role": "user",  "balance": 500},
    3: {"id": 3, "username": "admin",   "email": "admin@example.com", "role": "admin", "balance": 9999},
}

PRODUCTS = [
    {"id": 1, "name": "Widget A", "price": 9.99,  "stock": 100},
    {"id": 2, "name": "Widget B", "price": 19.99, "stock": 50},
    {"id": 3, "name": "Secret Product", "price": 999.99, "stock": 1, "hidden": True},
]

VALID_TOKENS = {
    "token_alice_123": 1,   # user
    "token_bob_456":   2,   # user
    "token_admin_789": 3,   # admin
}

# Track request counts (no actual rate limiting)
_request_log = []


def no_security_headers(response):
    """Intentionally strip security headers."""
    response.headers.pop("X-Content-Type-Options", None)
    response.headers.pop("X-Frame-Options", None)
    response.headers.pop("Strict-Transport-Security", None)
    response.headers.pop("Content-Security-Policy", None)
    response.headers["Server"] = "Apache/2.4.1 (Vulnerable Demo)"
    response.headers["X-Powered-By"] = "PHP/7.2.0"
    return response

app.after_request(no_security_headers)


# ── OpenAPI Spec (for discovery testing) ─────────────────────────────────────

@app.route("/openapi.json")
def openapi_spec():
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "Vulnerable Demo API", "version": "1.0.0"},
        "servers": [{"url": "http://localhost:5001"}],
        "paths": {
            "/api/v1/login":        {"post": {"summary": "Login", "security": []}},
            "/api/v1/users":        {"get":  {"summary": "List users", "security": [{"bearerAuth": []}]}},
            "/api/v1/users/{id}":   {"get":  {"summary": "Get user",  "security": [{"bearerAuth": []}]}},
            "/api/v1/admin":        {"get":  {"summary": "Admin panel","security": [{"bearerAuth": []}]}},
            "/api/v1/search":       {"get":  {"summary": "Search",    "security": []}},
            "/api/v1/products":     {"get":  {"summary": "Products",  "security": []}},
            "/api/v1/data":         {"get":  {"summary": "Data dump", "security": []}},
            "/api/v1/register":     {"post": {"summary": "Register",  "security": []}},
            "/health":              {"get":  {"summary": "Health check","security": []}},
        },
        "components": {
            "securitySchemes": {
                "bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}
            }
        },
    }
    return jsonify(spec)


@app.route("/health")
def health():
    return jsonify({"status": "ok", "version": "1.0.0", "db": "sqlite3://demo.db"})


# ── Auth Endpoints ────────────────────────────────────────────────────────────

@app.route("/api/v1/login", methods=["POST"])
def login():
    """VULN: SQL injection in username field, default credentials accepted."""
    data = request.get_json() or {}
    username = data.get("username", "")
    password = data.get("password", "")

    # Simulate SQL error on injection payloads
    sqli_chars = ["'", '"', "--", "OR", "UNION", "DROP"]
    if any(c.upper() in username.upper() or c.upper() in password.upper() for c in sqli_chars):
        return jsonify({
            "error": "You have an error in your SQL syntax near ''' at line 1: SELECT * FROM users WHERE username='" + username + "'"
        }), 500

    # Accept default credentials
    defaults = [("admin", "admin"), ("admin", "password"), ("admin", "123456"),
                ("test", "test"), ("user", "user")]
    if (username, password) in defaults:
        return jsonify({
            "access_token": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VySWQiOjMsInJvbGUiOiJhZG1pbiJ9.",
            "token_type": "bearer",
            "user": USERS[3],
        })

    # Normal auth
    user = next((u for u in USERS.values() if u["username"] == username), None)
    if user:
        token = f"token_{username}_123"
        return jsonify({"access_token": token, "token_type": "bearer", "user": user})

    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/api/v1/register", methods=["POST"])
def register():
    """VULN: Mass assignment — accepts is_admin field."""
    data = request.get_json() or {}
    # Blind copy all fields including privileged ones
    new_user = {
        "id": max(USERS.keys()) + 1,
        "username": data.get("username", ""),
        "email": data.get("email", ""),
        "role": data.get("role", "user"),          # VULN: should not allow
        "is_admin": data.get("is_admin", False),   # VULN: mass assignment
        "admin": data.get("admin", False),          # VULN
        "isAdmin": data.get("isAdmin", False),      # VULN
        "balance": data.get("balance", 0),
    }
    USERS[new_user["id"]] = new_user
    return jsonify(new_user), 201


# ── User Endpoints ────────────────────────────────────────────────────────────

@app.route("/api/v1/users")
def list_users():
    """VULN: No auth required, returns all users including admin."""
    return jsonify(list(USERS.values()))


@app.route("/api/v1/users/<int:user_id>")
def get_user(user_id: int):
    """VULN: BOLA — no ownership check, any user ID is accessible."""
    user = USERS.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify(user)


# ── Admin Endpoint ────────────────────────────────────────────────────────────

@app.route("/api/v1/admin")
def admin_panel():
    """VULN: Accepts alg:none JWT, no proper role check."""
    auth = request.headers.get("Authorization", "")
    if not auth:
        # VULN: accessible without auth sometimes
        return jsonify({"admin": True, "secret_key": "SUPER_SECRET_KEY_12345",
                         "users": list(USERS.values()), "config": {"debug": True}})

    token = auth.replace("Bearer ", "").replace("bearer ", "")
    # Accept alg:none tokens (VULN)
    if token.endswith("."):
        return jsonify({"admin": True, "message": "alg:none token accepted",
                         "users": list(USERS.values()), "secret_key": "SUPER_SECRET_KEY_12345"})

    # Look up token
    user_id = VALID_TOKENS.get(token)
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"admin": True, "user_id": user_id, "users": list(USERS.values())})


# ── Search (XSS) ──────────────────────────────────────────────────────────────

@app.route("/api/v1/search")
def search():
    """VULN: Reflects search query without sanitization (XSS)."""
    q = request.args.get("q", "")
    results = [p for p in PRODUCTS if q.lower() in p["name"].lower()]
    # VULN: reflect raw input in HTML-like text/html response
    resp = make_response(
        f"<html><body><h1>Search results for: {q}</h1>"
        f"<p>{len(results)} results found.</p>"
        f"<pre>{json.dumps(results, indent=2)}</pre></body></html>",
        200,
    )
    resp.content_type = "text/html"
    return resp


# ── Products (No auth) ────────────────────────────────────────────────────────

@app.route("/api/v1/products")
def products():
    """VULN: Returns hidden products without auth."""
    return jsonify(PRODUCTS)


# ── Data (No rate limiting) ───────────────────────────────────────────────────

@app.route("/api/v1/data")
def data_dump():
    """VULN: No rate limiting, returns sensitive data."""
    _request_log.append(time.time())
    # Never return 429
    return jsonify({
        "records": [{"id": i, "data": f"sensitive_record_{i}"} for i in range(10)],
        "total": 1000,
        "page": 1,
    })


if __name__ == "__main__":
    print("\n" + "="*60)
    print("  [!] VULNERABLE DEMO API -- FOR TESTING ONLY  [!]")
    print("="*60)
    print("  Running on http://localhost:5001")
    print("  Point APIAST at: http://localhost:5001")
    print("="*60 + "\n")
    app.run(host="0.0.0.0", port=5001, debug=False)
