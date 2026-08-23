"""
config.py — Central configuration for the Intelligent API Security Testing Platform.
"""

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ──────────────────────────────────────────────────────────────────────────────
# Flask / Application Settings
# ──────────────────────────────────────────────────────────────────────────────
SECRET_KEY = os.environ.get("SECRET_KEY", "apiast-dev-secret-change-in-prod-2025")
DEBUG = os.environ.get("DEBUG", "false").lower() == "true"
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", 5000))
DEMO_TARGET_PORT = int(os.environ.get("DEMO_TARGET_PORT", 5001))

# ──────────────────────────────────────────────────────────────────────────────
# Database
# ──────────────────────────────────────────────────────────────────────────────
DB_PATH = os.path.join(BASE_DIR, "apiast.db")
SQLALCHEMY_DATABASE_URI = f"sqlite:///{DB_PATH}"
SQLALCHEMY_TRACK_MODIFICATIONS = False

# ──────────────────────────────────────────────────────────────────────────────
# Scanner Settings
# ──────────────────────────────────────────────────────────────────────────────
REQUEST_TIMEOUT = 10          # seconds per HTTP request
MAX_CRAWL_DEPTH = 3           # max link-follow depth for endpoint discovery
RATE_LIMIT_TEST_COUNT = 30    # requests to fire for rate-limit testing
BRUTE_FORCE_DELAY = 0.05      # seconds between brute-force requests

# ──────────────────────────────────────────────────────────────────────────────
# Authentication Testing
# ──────────────────────────────────────────────────────────────────────────────
JWT_WEAK_SECRETS = [
    "secret", "password", "123456", "admin", "test",
    "jwt_secret", "change_me", "supersecret", "token", "key",
    "qwerty", "letmein", "welcome", "monkey", "dragon",
]

COMMON_PATHS = [
    "/api/v1/users", "/api/v1/user", "/api/v1/admin", "/api/v1/login",
    "/api/v1/register", "/api/v1/health", "/api/v2/users", "/api/users",
    "/api/login", "/api/admin", "/api/health", "/api/me", "/api/profile",
    "/auth/login", "/auth/token", "/auth/refresh", "/v1/users", "/v1/health",
    "/users", "/admin", "/login", "/health", "/status", "/ping",
    "/api/v1/products", "/api/v1/orders", "/api/v1/payments",
    "/api/v1/search", "/api/v1/data", "/api/v1/config", "/api/v1/settings",
    "/api/v1/token", "/api/v1/refresh", "/api/v1/logout",
    "/swagger.json", "/openapi.json", "/api-docs", "/api/swagger.json",
    "/api/openapi.json", "/docs", "/redoc", "/.well-known/openapi.json",
]

SWAGGER_PATHS = [
    "/swagger.json", "/openapi.json", "/api-docs", "/api/swagger.json",
    "/api/openapi.json", "/swagger/v1/swagger.json",
    "/.well-known/openapi.json", "/v1/swagger.json", "/v2/swagger.json",
]

# ──────────────────────────────────────────────────────────────────────────────
# Vulnerability Payloads
# ──────────────────────────────────────────────────────────────────────────────
SQLI_PAYLOADS = [
    "'", "\"", "' OR '1'='1", "' OR 1=1--", "\" OR \"1\"=\"1",
    "'; DROP TABLE users;--", "' UNION SELECT NULL--",
    "1' AND 1=2 UNION SELECT NULL, NULL--",
    "admin'--", "' OR 'x'='x", "') OR ('1'='1",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<svg onload=alert(1)>",
    "\"><script>alert(document.cookie)</script>",
    "'><script>alert(1)</script>",
    "<body onload=alert(1)>",
]

SQLI_ERROR_PATTERNS = [
    "sql syntax", "mysql_fetch", "ora-", "sqlite_",
    "postgresql", "warning: mysql", "unterminated string",
    "quoted string not properly terminated", "sqlstate",
    "syntax error", "unclosed quotation", "microsoft sql server",
    "you have an error in your sql syntax",
]

# ──────────────────────────────────────────────────────────────────────────────
# OWASP API Top 10 (2023)
# ──────────────────────────────────────────────────────────────────────────────
OWASP_API_TOP10 = {
    "API1": "Broken Object Level Authorization (BOLA)",
    "API2": "Broken Authentication",
    "API3": "Broken Object Property Level Authorization",
    "API4": "Unrestricted Resource Consumption",
    "API5": "Broken Function Level Authorization (BFLA)",
    "API6": "Unrestricted Access to Sensitive Business Flows",
    "API7": "Server Side Request Forgery (SSRF)",
    "API8": "Security Misconfiguration",
    "API9": "Improper Inventory Management",
    "API10": "Unsafe Consumption of APIs",
}

# ──────────────────────────────────────────────────────────────────────────────
# Risk Scoring
# ──────────────────────────────────────────────────────────────────────────────
SEVERITY_WEIGHTS = {
    "CRITICAL": 10.0,
    "HIGH": 7.5,
    "MEDIUM": 5.0,
    "LOW": 2.5,
    "INFO": 0.5,
}

SEVERITY_COLORS = {
    "CRITICAL": "#ff4757",
    "HIGH": "#ff6b35",
    "MEDIUM": "#ffa502",
    "LOW": "#2ed573",
    "INFO": "#70a1ff",
}

# ──────────────────────────────────────────────────────────────────────────────
# AI / Recommendations
# ──────────────────────────────────────────────────────────────────────────────
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")  # Leave empty for rule-based mode
USE_AI_RECOMMENDATIONS = bool(OPENAI_API_KEY)

# ──────────────────────────────────────────────────────────────────────────────
# Monitoring
# ──────────────────────────────────────────────────────────────────────────────
DEFAULT_MONITOR_INTERVAL = 60   # minutes
REPORTS_DIR = os.path.join(BASE_DIR, "output_reports")
os.makedirs(REPORTS_DIR, exist_ok=True)
