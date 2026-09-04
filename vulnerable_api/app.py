"""
vulnerable_api/app.py
Intentionally Vulnerable REST API — Public Demo Target for APIAST
Exposes OWASP API Top 10 vulnerabilities for testing.
Deploy to Railway / Render / any cloud platform.
"""
import json, time, os
from flask import Blueprint, Flask, request, jsonify, make_response

vuln_target_bp = Blueprint("vuln_target", __name__)
app = Flask(__name__)

# ── In-memory "database" ──────────────────────────────────────────────────────
USERS = {
    1: {"id": 1, "username": "alice",  "email": "alice@example.com",  "role": "user",  "password": "alice123",  "balance": 1000},
    2: {"id": 2, "username": "bob",    "email": "bob@example.com",    "role": "user",  "password": "bob456",    "balance": 500},
    3: {"id": 3, "username": "admin",  "email": "admin@example.com",  "role": "admin", "password": "admin",     "balance": 9999},
    4: {"id": 4, "username": "charlie","email": "charlie@example.com","role": "user",  "password": "charlie789","balance": 250},
}
PRODUCTS = [
    {"id": 1, "name": "Widget A",       "price": 9.99,   "stock": 100},
    {"id": 2, "name": "Widget B",       "price": 19.99,  "stock": 50},
    {"id": 3, "name": "Secret Product", "price": 999.99, "stock": 1, "hidden": True},
]
VALID_TOKENS = {
    "token_alice_123":  1,
    "token_bob_456":    2,
    "token_admin_789":  3,
    "token_charlie_000":4,
}
_request_log = []

# ── Strip security headers (intentional) ─────────────────────────────────────
@vuln_target_bp.after_request
def strip_security_headers(response):
    response.headers.pop("X-Content-Type-Options", None)
    response.headers.pop("X-Frame-Options", None)
    response.headers.pop("Strict-Transport-Security", None)
    response.headers.pop("Content-Security-Policy", None)
    response.headers["Server"]       = "Apache/2.4.1 (VulnTarget)"
    response.headers["X-Powered-By"] = "PHP/7.2.0"
    return response

# ── OpenAPI spec (enables Module 1 Swagger parsing) ──────────────────────────
@vuln_target_bp.route("/openapi.json")
def openapi_spec():
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "APIAST Vulnerable Demo API", "version": "1.0.0",
                 "description": "Intentionally vulnerable API for APIAST capstone testing."},
        "servers": [{"url": os.environ.get("PUBLIC_URL", "https://vulnerable-api.example.com")}],
        "paths": {
            "/api/v1/login":          {"post": {"summary": "Login (SQLi + default creds)",  "security": []}},
            "/api/v1/register":       {"post": {"summary": "Register (Mass Assignment)",     "security": []}},
            "/api/v1/users":          {"get":  {"summary": "List users (No auth required)",  "security": [{"bearerAuth": []}]}},
            "/api/v1/users/{id}":     {"get":  {"summary": "Get user (BOLA/IDOR)",           "security": [{"bearerAuth": []}]}},
            "/api/v1/admin":          {"get":  {"summary": "Admin panel (Broken Auth)",      "security": [{"bearerAuth": []}]}},
            "/api/v1/search":         {"get":  {"summary": "Search (Reflected XSS)",         "security": []}},
            "/api/v1/products":       {"get":  {"summary": "Products (No rate limiting)",    "security": []}},
            "/api/v1/data":           {"get":  {"summary": "Data dump (No rate limiting)",   "security": []}},
            "/health":                {"get":  {"summary": "Health check (Info disclosure)", "security": []}},
            "/api/v1/profile":        {"get":  {"summary": "Profile (Excessive exposure)",   "security": [{"bearerAuth": []}]}},
            "/api/v1/token_check":    {"get":  {"summary": "Token in URL (Insecure API key)","security": []}},
        },
        "components": {
            "securitySchemes": {
                "bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}
            }
        }
    }
    return jsonify(spec)

# ── Health (info disclosure) ──────────────────────────────────────────────────
@vuln_target_bp.route("/health")
def health():
    """VULN: Exposes DB path, version, debug flag."""
    return jsonify({
        "status": "ok", "version": "1.0.0",
        "db": "sqlite3:///app/data/users.db",
        "debug": True, "env": "production",
        "server": "Apache/2.4.1",
    })

# ── Login (SQLi + default creds + alg:none) ───────────────────────────────────
@vuln_target_bp.route("/api/v1/login", methods=["POST"])
def login():
    """VULN: SQLi in username, accepts default credentials, returns alg:none JWT."""
    data = request.get_json() or {}
    username = data.get("username", "")
    password = data.get("password", "")

    sqli_chars = ["'", '"', "--", "OR", "UNION", "DROP", ";"]
    if any(c.upper() in username.upper() or c.upper() in password.upper() for c in sqli_chars):
        return jsonify({
            "error": "You have an error in your SQL syntax near ''' at line 1: "
                     "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
        }), 500

    defaults = [("admin", "admin"), ("admin", "password"), ("admin", "123456"),
                ("test", "test"), ("user", "user"), ("admin", "admin123")]
    if (username, password) in defaults:
        # Return alg:none JWT (CRITICAL vuln)
        return jsonify({
            "access_token": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VySWQiOjMsInJvbGUiOiJhZG1pbiIsImV4cCI6OTk5OTk5OTk5OX0.",
            "token_type": "bearer",
            "user": USERS[3],
            "note": "alg:none JWT issued",
        })

    user = next((u for u in USERS.values() if u["username"] == username), None)
    if user and user["password"] == password:
        return jsonify({
            "access_token": f"token_{username}_123",
            "token_type": "bearer",
            "user": {k: v for k, v in user.items() if k != "password"},
        })

    return jsonify({"error": "Invalid credentials"}), 401

# ── Register (mass assignment) ────────────────────────────────────────────────
@vuln_target_bp.route("/api/v1/register", methods=["POST"])
def register():
    """VULN: Mass assignment — accepts is_admin, role, balance."""
    data = request.get_json() or {}
    new_user = {
        "id":       max(USERS.keys()) + 1,
        "username": data.get("username", ""),
        "email":    data.get("email", ""),
        "role":     data.get("role", "user"),          # VULN
        "is_admin": data.get("is_admin", False),        # VULN
        "admin":    data.get("admin", False),           # VULN
        "isAdmin":  data.get("isAdmin", False),         # VULN
        "balance":  data.get("balance", 0),             # VULN
        "password": data.get("password", ""),
    }
    USERS[new_user["id"]] = new_user
    return jsonify(new_user), 201

# ── Users (no auth — BOLA) ────────────────────────────────────────────────────
@vuln_target_bp.route("/api/v1/users")
def list_users():
    """VULN: No authentication required, returns all users including passwords."""
    return jsonify([u for u in USERS.values()])   # includes password field!

@vuln_target_bp.route("/api/v1/users/<int:user_id>")
def get_user(user_id):
    """VULN: BOLA — no ownership check. Any user ID accessible without auth."""
    user = USERS.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify(user)  # includes password!

# ── Admin (broken auth + alg:none accepted) ───────────────────────────────────
@vuln_target_bp.route("/api/v1/admin")
def admin_panel():
    """VULN: Accessible without auth. Accepts alg:none JWT."""
    auth = request.headers.get("Authorization", "")
    if not auth:
        # VULN: No auth needed at all
        return jsonify({
            "admin": True,
            "secret_key": "SUPER_SECRET_KEY_12345",
            "jwt_secret": "random_weak_secret",
            "users": list(USERS.values()),
            "config": {"debug": True, "db_password": "admin123"},
        })
    token = auth.replace("Bearer ", "").replace("bearer ", "")
    if token.endswith("."):           # alg:none — VULN
        return jsonify({"admin": True, "message": "alg:none accepted", "users": list(USERS.values())})
    user_id = VALID_TOKENS.get(token)
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"admin": True, "user_id": user_id, "users": list(USERS.values())})

# ── Profile (excessive data exposure) ────────────────────────────────────────
@vuln_target_bp.route("/api/v1/profile")
def profile():
    """VULN: Returns sensitive fields — password, SSN, credit_card."""
    auth = request.headers.get("Authorization", "")
    token = auth.replace("Bearer ", "").replace("bearer ", "")
    user_id = VALID_TOKENS.get(token, 1)
    user = USERS.get(user_id, USERS[1]).copy()
    # VULN: returns sensitive data that should never be in API response
    user["ssn"]         = "123-45-6789"
    user["credit_card"] = "4111-1111-1111-1111"
    user["cvv"]         = "123"
    user["pin"]         = "4321"
    user["secret"]      = "private_api_key_abc123"
    return jsonify(user)

# ── Search (reflected XSS) ────────────────────────────────────────────────────
@vuln_target_bp.route("/api/v1/search")
def search():
    """VULN: Reflects raw input — XSS."""
    q = request.args.get("q", "")
    results = [p for p in PRODUCTS if q.lower() in p["name"].lower()]
    resp = make_response(
        f"<html><body><h1>Results for: {q}</h1>"
        f"<pre>{json.dumps(results, indent=2)}</pre></body></html>", 200
    )
    resp.content_type = "text/html"
    return resp

# ── Products (no rate limiting + hidden data) ─────────────────────────────────
@vuln_target_bp.route("/api/v1/products")
def products():
    """VULN: Returns hidden products, no rate limiting."""
    return jsonify(PRODUCTS)

# ── Data dump (no rate limiting) ──────────────────────────────────────────────
@vuln_target_bp.route("/api/v1/data")
def data_dump():
    """VULN: No rate limiting, returns sensitive data."""
    _request_log.append(time.time())
    return jsonify({
        "records": [{"id": i, "ssn": f"SSN-{i:04d}", "data": f"sensitive_record_{i}"} for i in range(20)],
        "total": 1000, "page": 1,
    })

# ── Token in URL (insecure API key) ──────────────────────────────────────────
@vuln_target_bp.route("/api/v1/token_check")
def token_check():
    """VULN: Accepts API key in URL query parameter."""
    api_key = request.args.get("api_key") or request.args.get("token") or request.args.get("key")
    if api_key:
        return jsonify({"authenticated": True, "note": "API key exposed in URL — visible in logs"})
    return jsonify({"authenticated": False}), 401

# Register blueprint for standalone execution
app.register_blueprint(vuln_target_bp)

# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    print(f"[*] Starting Vulnerable Demo API on port {port}...")
    app.run(host="0.0.0.0", port=port, debug=False)

