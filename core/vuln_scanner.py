"""
core/vuln_scanner.py — Module 2: API Vulnerability Assessment
Tests for OWASP API Top 10: SQLi, XSS, Broken Auth, BOLA, BFLA, Rate Limiting,
Mass Assignment, Excessive Data Exposure, SSRF, Command Injection, Improper Inventory.
"""

import time
import json
import re
import requests
from config import (
    SQLI_PAYLOADS, XSS_PAYLOADS, SQLI_ERROR_PATTERNS,
    REQUEST_TIMEOUT, RATE_LIMIT_TEST_COUNT, BRUTE_FORCE_DELAY,
)


def _safe_request(method: str, url: str, **kwargs) -> requests.Response | None:
    try:
        kwargs.setdefault("timeout", REQUEST_TIMEOUT)
        kwargs.setdefault("verify", False)
        resp = getattr(requests, method.lower())(url, **kwargs)
        return resp
    except Exception:
        return None


def _contains_sqli_error(text: str) -> bool:
    text = text.lower()
    return any(pattern in text for pattern in SQLI_ERROR_PATTERNS)


# ── SQL Injection Testing ─────────────────────────────────────────────────────

def test_sqli(base_url: str, endpoint: dict, callback=None) -> list[dict]:
    """Test an endpoint for SQL Injection vulnerabilities."""
    findings = []
    path = endpoint.get("path", "/")
    url = base_url.rstrip("/") + path

    for payload in SQLI_PAYLOADS:
        # Test via query parameter
        test_url = url + ("?" if "?" not in url else "&") + f"id={requests.utils.quote(payload)}"
        resp = _safe_request("GET", test_url)
        if resp:
            if _contains_sqli_error(resp.text) or resp.status_code == 500:
                findings.append({
                    "vuln_type": "SQL Injection",
                    "owasp_category": "API8",
                    "severity": "CRITICAL",
                    "cvss_score": 9.8,
                    "description": f"SQL Injection detected in query parameter at {path}",
                    "payload": payload,
                    "evidence": resp.text[:300] if resp else "",
                    "remediation": "Use parameterized queries / prepared statements. Never concatenate user input into SQL strings.",
                    "path": path,
                })
                if callback:
                    callback(f"[CRITICAL] SQLi found at {path} with payload: {payload[:30]}")
                break

        # Test via POST body
        resp_post = _safe_request("POST", url,
                                   json={"username": payload, "password": payload},
                                   headers={"Content-Type": "application/json"})
        if resp_post:
            if _contains_sqli_error(resp_post.text) or resp_post.status_code == 500:
                if not any(f["path"] == path and f["vuln_type"] == "SQL Injection" for f in findings):
                    findings.append({
                        "vuln_type": "SQL Injection",
                        "owasp_category": "API8",
                        "severity": "CRITICAL",
                        "cvss_score": 9.8,
                        "description": f"SQL Injection detected in POST body at {path}",
                        "payload": payload,
                        "evidence": resp_post.text[:300],
                        "remediation": "Use parameterized queries. Validate and sanitize all input fields.",
                        "path": path,
                    })
                    if callback:
                        callback(f"[CRITICAL] SQLi (POST body) found at {path}")
                    break

    return findings


# ── XSS Testing ───────────────────────────────────────────────────────────────

def test_xss(base_url: str, endpoint: dict, callback=None) -> list[dict]:
    """Test an endpoint for reflected XSS."""
    findings = []
    path = endpoint.get("path", "/")
    url = base_url.rstrip("/") + path

    for payload in XSS_PAYLOADS:
        encoded = requests.utils.quote(payload)
        test_url = url + ("?" if "?" not in url else "&") + f"q={encoded}&search={encoded}"
        resp = _safe_request("GET", test_url)
        if resp and payload in resp.text:
            ct = resp.headers.get("Content-Type", "")
            if "html" in ct or "text" in ct:
                findings.append({
                    "vuln_type": "Cross-Site Scripting (XSS)",
                    "owasp_category": "API8",
                    "severity": "HIGH",
                    "cvss_score": 7.2,
                    "description": f"Reflected XSS detected at {path} — user input echoed without sanitization",
                    "payload": payload,
                    "evidence": f"Payload reflected in response body (Content-Type: {ct})",
                    "remediation": "Encode all output. Use Content-Security-Policy headers. Sanitize input with a library like bleach.",
                    "path": path,
                })
                if callback:
                    callback(f"[HIGH] XSS found at {path}")
                break

    return findings


# ── Broken Authentication Testing ─────────────────────────────────────────────

def test_broken_auth(base_url: str, endpoints: list[dict], callback=None) -> list[dict]:
    """Test for broken authentication: missing auth, expired tokens, default creds."""
    findings = []
    protected_paths = [ep for ep in endpoints if ep.get("auth_required")]

    for ep in protected_paths[:5]:
        path = ep.get("path", "/")
        url = base_url.rstrip("/") + path

        resp = _safe_request("GET", url)
        if resp and resp.status_code in (200, 201):
            findings.append({
                "vuln_type": "Broken Authentication",
                "owasp_category": "API2",
                "severity": "CRITICAL",
                "cvss_score": 9.1,
                "description": f"Protected endpoint {path} accessible without credentials",
                "payload": "No Authorization header",
                "evidence": f"HTTP {resp.status_code} — response returned without auth",
                "remediation": "Enforce authentication middleware on all protected routes. Use decorator-based auth guards.",
                "path": path,
            })
            if callback:
                callback(f"[CRITICAL] Broken Auth: {path} accessible without token")

        fake_token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ."
        resp_forged = _safe_request("GET", url, headers={"Authorization": f"Bearer {fake_token}"})
        if resp_forged and resp_forged.status_code in (200, 201):
            findings.append({
                "vuln_type": "Broken Authentication (alg:none token accepted)",
                "owasp_category": "API2",
                "severity": "CRITICAL",
                "cvss_score": 9.8,
                "description": f"Endpoint {path} accepts unsigned (alg:none) JWT tokens",
                "payload": fake_token,
                "evidence": f"HTTP {resp_forged.status_code} returned with forged token",
                "remediation": "Validate JWT signature with a verified library. Reject alg:none tokens explicitly.",
                "path": path,
            })
            if callback:
                callback(f"[CRITICAL] alg:none token accepted at {path}")

    login_paths = ["/api/v1/login", "/login", "/auth/login", "/api/login"]
    default_creds = [
        {"username": "admin", "password": "admin"},
        {"username": "admin", "password": "password"},
        {"username": "test",  "password": "test"},
        {"username": "admin", "password": "123456"},
    ]
    for lpath in login_paths:
        ep_found = next((ep for ep in endpoints if ep.get("path") == lpath), None)
        if ep_found:
            for creds in default_creds:
                resp = _safe_request("POST", base_url.rstrip("/") + lpath,
                                      json=creds, headers={"Content-Type": "application/json"})
                if resp and resp.status_code in (200, 201):
                    try:
                        data = resp.json()
                        if "token" in str(data).lower() or "access" in str(data).lower():
                            findings.append({
                                "vuln_type": "Default Credentials Accepted",
                                "owasp_category": "API2",
                                "severity": "CRITICAL",
                                "cvss_score": 9.8,
                                "description": f"Login endpoint accepts default credentials at {lpath}",
                                "payload": json.dumps(creds),
                                "evidence": f"Login succeeded with {creds['username']}:{creds['password']}",
                                "remediation": "Enforce strong password policy. Remove default credentials. Implement account lockout.",
                                "path": lpath,
                            })
                            if callback:
                                callback(f"[CRITICAL] Default creds accepted: {creds['username']}:{creds['password']}")
                            break
                    except Exception:
                        pass

    return findings


# ── BOLA / IDOR Testing (API1) ────────────────────────────────────────────────

def test_bola(base_url: str, endpoints: list[dict], callback=None) -> list[dict]:
    """Test for Broken Object Level Authorization — access resources by guessing IDs."""
    findings = []
    # Endpoints with path parameters that look like IDs
    id_pattern = re.compile(r"(\{[^}]+\}|/\d+)")
    candidate_paths = [
        ep for ep in endpoints
        if id_pattern.search(ep.get("path", ""))
    ]

    # Also probe common ID-based paths not in spec
    common_id_paths = [
        "/api/v1/users/2", "/api/v1/users/3", "/api/v1/orders/1",
        "/api/v1/accounts/1", "/api/v1/profile/2",
    ]
    for cpath in common_id_paths:
        candidate_paths.append({"path": cpath, "method": "GET", "auth_required": True})

    checked = set()
    for ep in candidate_paths[:8]:
        path = ep.get("path", "/")
        # Substitute template parameter with IDs 1, 2, 3
        test_paths = [re.sub(r"\{[^}]+\}", str(i), path) for i in range(1, 4)]
        test_paths.append(path)

        for tp in set(test_paths):
            if tp in checked:
                continue
            checked.add(tp)
            url = base_url.rstrip("/") + tp
            resp = _safe_request("GET", url)
            if resp and resp.status_code == 200:
                try:
                    body = resp.json()
                    # Heuristic: response contains user/account-like data without auth
                    body_str = json.dumps(body).lower()
                    if any(k in body_str for k in ("email", "username", "password", "balance", "role", "account")):
                        if tp not in [f.get("path") for f in findings]:
                            findings.append({
                                "vuln_type": "Broken Object Level Authorization (BOLA/IDOR)",
                                "owasp_category": "API1",
                                "severity": "HIGH",
                                "cvss_score": 8.1,
                                "description": f"Resource at {tp} returned sensitive data without ownership validation",
                                "payload": f"GET {tp} (no auth)",
                                "evidence": body_str[:200],
                                "remediation": "Validate that the authenticated user owns the requested resource on every request. Use UUIDs instead of sequential IDs.",
                                "path": tp,
                            })
                            if callback:
                                callback(f"[HIGH] BOLA detected at {tp}")
                except Exception:
                    pass

    return findings


# ── BFLA Testing (API5) ───────────────────────────────────────────────────────

def test_bfla(base_url: str, endpoints: list[dict], callback=None) -> list[dict]:
    """Test for Broken Function Level Authorization — regular users accessing admin functions."""
    findings = []
    admin_paths = [
        "/api/v1/admin", "/admin", "/api/admin", "/api/v1/users",
        "/api/v1/config", "/api/v1/settings", "/api/v1/data",
    ]
    # Use a fake regular-user token
    regular_token = "token_regular_user_99999"
    headers = {"Authorization": f"Bearer {regular_token}"}

    for path in admin_paths:
        ep = next((e for e in endpoints if e.get("path") == path), None)
        if not ep:
            continue
        url = base_url.rstrip("/") + path
        resp = _safe_request("GET", url, headers=headers)
        if resp and resp.status_code == 200:
            try:
                body_str = json.dumps(resp.json()).lower()
                if any(k in body_str for k in ("admin", "users", "config", "secret", "key")):
                    findings.append({
                        "vuln_type": "Broken Function Level Authorization (BFLA)",
                        "owasp_category": "API5",
                        "severity": "HIGH",
                        "cvss_score": 8.0,
                        "description": f"Admin-level endpoint {path} accessible with a regular user token",
                        "payload": f"Authorization: Bearer {regular_token}",
                        "evidence": body_str[:200],
                        "remediation": "Enforce role-based access control (RBAC) on all administrative endpoints. Check the caller's role on every request, not just at login.",
                        "path": path,
                    })
                    if callback:
                        callback(f"[HIGH] BFLA: admin endpoint {path} accessible with regular token")
            except Exception:
                pass

    return findings


# ── Excessive Data Exposure Testing (API3) ────────────────────────────────────

SENSITIVE_FIELD_PATTERNS = re.compile(
    r"(password|passwd|secret|api_key|apikey|private_key|access_token|credit_card|"
    r"card_number|ssn|social_security|pin|cvv|dob|date_of_birth|bank_account)",
    re.IGNORECASE,
)


def test_excessive_exposure(base_url: str, endpoints: list[dict], callback=None) -> list[dict]:
    """Scan API responses for sensitive fields that should not be exposed."""
    findings = []

    for ep in endpoints[:15]:
        path = ep.get("path", "/")
        url = base_url.rstrip("/") + path
        resp = _safe_request("GET", url)
        if not resp or resp.status_code not in (200, 201):
            continue

        try:
            body_str = json.dumps(resp.json())
        except Exception:
            body_str = resp.text

        matches = SENSITIVE_FIELD_PATTERNS.findall(body_str)
        if matches:
            unique_fields = list(set(m.lower() for m in matches))
            findings.append({
                "vuln_type": "Excessive Data Exposure",
                "owasp_category": "API3",
                "severity": "HIGH",
                "cvss_score": 7.5,
                "description": f"Endpoint {path} returns sensitive fields: {', '.join(unique_fields[:5])}",
                "payload": f"GET {path}",
                "evidence": f"Sensitive fields detected in response: {', '.join(unique_fields[:5])}",
                "remediation": "Apply response field filtering. Only return fields that the client actually needs. Use DTOs/serializers with explicit allowlists.",
                "path": path,
            })
            if callback:
                callback(f"[HIGH] Excessive data exposure at {path}: {', '.join(unique_fields[:3])}")

    return findings


# ── SSRF Testing (API7) ───────────────────────────────────────────────────────

SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://169.254.169.254",          # AWS metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://0.0.0.0",
    "file:///etc/passwd",
]

SSRF_INDICATOR_PATTERNS = [
    "root:", "ec2", "ami-", "instance-id", "metadata", "/bin/bash",
    "127.0.0.1", "localhost", "internal",
]


def test_ssrf(base_url: str, endpoints: list[dict], callback=None) -> list[dict]:
    """Test for Server-Side Request Forgery by injecting internal URLs into params."""
    findings = []
    # Target endpoints that accept URL-like parameters
    url_param_paths = [ep for ep in endpoints if ep.get("method") in ("GET", "POST")]

    for ep in url_param_paths[:8]:
        path = ep.get("path", "/")
        url = base_url.rstrip("/") + path

        for ssrf_payload in SSRF_PAYLOADS[:3]:
            # Inject via query params
            test_url = url + ("?" if "?" not in url else "&") + f"url={requests.utils.quote(ssrf_payload)}&redirect={requests.utils.quote(ssrf_payload)}&path={requests.utils.quote(ssrf_payload)}"
            resp = _safe_request("GET", test_url)
            if resp and resp.status_code in (200, 201):
                body_lower = (resp.text or "").lower()
                if any(ind in body_lower for ind in SSRF_INDICATOR_PATTERNS):
                    if path not in [f.get("path") for f in findings]:
                        findings.append({
                            "vuln_type": "Server-Side Request Forgery (SSRF)",
                            "owasp_category": "API7",
                            "severity": "CRITICAL",
                            "cvss_score": 9.0,
                            "description": f"SSRF vulnerability detected at {path} — internal resource fetched",
                            "payload": ssrf_payload,
                            "evidence": resp.text[:200],
                            "remediation": "Validate and allowlist all user-supplied URLs. Disable unnecessary URL-fetching features. Use a DNS-based SSRF filter.",
                            "path": path,
                        })
                        if callback:
                            callback(f"[CRITICAL] SSRF detected at {path}")
                        break

    return findings


# ── Command Injection Testing (API8) ─────────────────────────────────────────

CMDI_PAYLOADS = [
    "; id", "| id", "& id", "`id`", "$(id)",
    "; whoami", "| whoami", "& whoami",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
]

CMDI_INDICATORS = [
    "uid=", "gid=", "root", "www-data", "daemon",
    "root:", "bin/bash", "bin/sh",
]


def test_command_injection(base_url: str, endpoints: list[dict], callback=None) -> list[dict]:
    """Test for Command Injection by injecting shell metacharacters into query params."""
    findings = []

    for ep in endpoints[:10]:
        path = ep.get("path", "/")
        url = base_url.rstrip("/") + path

        for payload in CMDI_PAYLOADS[:4]:
            encoded = requests.utils.quote(payload)
            test_url = url + ("?" if "?" not in url else "&") + f"cmd={encoded}&exec={encoded}&input={encoded}"
            resp = _safe_request("GET", test_url)
            if resp and resp.status_code in (200, 201):
                body = resp.text.lower()
                if any(ind in body for ind in CMDI_INDICATORS):
                    if path not in [f.get("path") for f in findings]:
                        findings.append({
                            "vuln_type": "Command Injection",
                            "owasp_category": "API8",
                            "severity": "CRITICAL",
                            "cvss_score": 9.8,
                            "description": f"Command injection detected at {path} — shell output returned",
                            "payload": payload,
                            "evidence": resp.text[:200],
                            "remediation": "Never pass user input to system shell commands. Use safe APIs. Validate and sanitize all inputs with strict allowlists.",
                            "path": path,
                        })
                        if callback:
                            callback(f"[CRITICAL] Command injection at {path}")
                        break

    return findings


# ── Improper Inventory Management (API9) ─────────────────────────────────────

DEPRECATED_VERSION_PATTERNS = [
    "/v0/", "/v-old/", "/old/", "/legacy/", "/deprecated/", "/beta/",
    "/api/v0", "/api/old", "/api/legacy",
]


def test_inventory_management(base_url: str, endpoints: list[dict], callback=None) -> list[dict]:
    """Detect old/deprecated API versions still accessible."""
    findings = []
    base = base_url.rstrip("/")

    # Check if deprecated version paths are accessible
    for dep_path in DEPRECATED_VERSION_PATTERNS:
        url = base + dep_path.rstrip("/") + "/"
        resp = _safe_request("GET", url)
        if resp and resp.status_code not in (404, 410, 301, 302):
            findings.append({
                "vuln_type": "Improper Inventory Management",
                "owasp_category": "API9",
                "severity": "MEDIUM",
                "cvss_score": 5.3,
                "description": f"Deprecated API version path accessible: {dep_path}",
                "payload": dep_path,
                "evidence": f"HTTP {resp.status_code} returned for deprecated path",
                "remediation": "Decommission old API versions. Use proper versioning strategy. Return 410 Gone for deprecated endpoints.",
                "path": dep_path,
            })
            if callback:
                callback(f"[MEDIUM] Deprecated API version accessible: {dep_path}")

    # Check for endpoints exposing version info that can guide enumeration
    info_paths = ["/health", "/status", "/version", "/api/v1/health", "/info"]
    for ipath in info_paths:
        ep = next((e for e in endpoints if e.get("path") == ipath), None)
        if ep:
            url = base + ipath
            resp = _safe_request("GET", url)
            if resp and resp.status_code == 200:
                try:
                    body = resp.json()
                    body_str = json.dumps(body).lower()
                    if "db" in body_str or "database" in body_str or "version" in body_str:
                        findings.append({
                            "vuln_type": "Information Disclosure via Health Endpoint",
                            "owasp_category": "API9",
                            "severity": "LOW",
                            "cvss_score": 3.1,
                            "description": f"Health/info endpoint {ipath} discloses infrastructure details",
                            "payload": f"GET {ipath}",
                            "evidence": body_str[:200],
                            "remediation": "Restrict health endpoints. Remove sensitive details (DB name, version numbers) from public status endpoints.",
                            "path": ipath,
                        })
                except Exception:
                    pass

    return findings


# ── Rate Limit Testing (API4) ─────────────────────────────────────────────────

def test_rate_limit(base_url: str, endpoint: dict, callback=None) -> list[dict]:
    """Test if the endpoint has rate limiting."""
    findings = []
    path = endpoint.get("path", "/")
    url = base_url.rstrip("/") + path
    status_codes = []

    if callback:
        callback(f"Rate-limit testing {path} ({RATE_LIMIT_TEST_COUNT} requests)...")

    for i in range(RATE_LIMIT_TEST_COUNT):
        resp = _safe_request("GET", url)
        if resp:
            status_codes.append(resp.status_code)
        time.sleep(BRUTE_FORCE_DELAY)

    if 429 not in status_codes and len(status_codes) >= RATE_LIMIT_TEST_COUNT * 0.8:
        findings.append({
            "vuln_type": "Missing Rate Limiting",
            "owasp_category": "API4",
            "severity": "MEDIUM",
            "cvss_score": 5.3,
            "description": f"No rate limiting detected on {path} — {RATE_LIMIT_TEST_COUNT} requests succeeded",
            "payload": f"{RATE_LIMIT_TEST_COUNT} rapid GET requests",
            "evidence": f"All {len(status_codes)} requests returned without 429 Too Many Requests",
            "remediation": "Implement rate limiting (e.g., Flask-Limiter). Add throttle rules per IP and per user.",
            "path": path,
        })
        if callback:
            callback(f"[MEDIUM] No rate limiting on {path}")

    return findings


# ── Mass Assignment Testing (API3) ────────────────────────────────────────────

def test_mass_assignment(base_url: str, endpoint: dict, callback=None) -> list[dict]:
    """Test if POST/PUT endpoints accept undeclared privileged fields."""
    findings = []
    if endpoint.get("method", "GET") not in ("POST", "PUT", "PATCH"):
        return findings

    path = endpoint.get("path", "/")
    url = base_url.rstrip("/") + path

    privileged_payload = {
        "username": "testuser",
        "password": "testpass",
        "is_admin": True,
        "role": "admin",
        "admin": True,
        "isAdmin": True,
    }

    resp = _safe_request("POST", url, json=privileged_payload,
                          headers={"Content-Type": "application/json"})
    if resp and resp.status_code in (200, 201):
        try:
            data = resp.json()
            body_str = json.dumps(data).lower()
            if "admin" in body_str or "is_admin" in body_str:
                findings.append({
                    "vuln_type": "Mass Assignment",
                    "owasp_category": "API3",
                    "severity": "HIGH",
                    "cvss_score": 7.5,
                    "description": f"Mass assignment vulnerability at {path} — privileged fields accepted",
                    "payload": json.dumps(privileged_payload),
                    "evidence": f"Response echoed privileged fields: {body_str[:200]}",
                    "remediation": "Use an allowlist (whitelist) approach for request body fields. Never auto-bind all incoming fields.",
                    "path": path,
                })
                if callback:
                    callback(f"[HIGH] Mass assignment vulnerability at {path}")
        except Exception:
            pass

    return findings


# ── Security Headers Check (API8) ─────────────────────────────────────────────

def test_security_headers(base_url: str, callback=None) -> list[dict]:
    """Check for missing security headers on the API."""
    findings = []
    resp = _safe_request("GET", base_url.rstrip("/") + "/")
    if not resp:
        resp = _safe_request("GET", base_url.rstrip("/") + "/api/v1/health")
    if not resp:
        return findings

    headers = {k.lower(): v for k, v in resp.headers.items()}
    checks = [
        ("x-content-type-options", "MEDIUM", "Missing X-Content-Type-Options header",
         "Add 'X-Content-Type-Options: nosniff' to all responses"),
        ("x-frame-options", "MEDIUM", "Missing X-Frame-Options header",
         "Add 'X-Frame-Options: DENY' to prevent clickjacking"),
        ("strict-transport-security", "HIGH", "Missing HSTS header",
         "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'"),
        ("content-security-policy", "MEDIUM", "Missing Content-Security-Policy header",
         "Implement a strict CSP policy to prevent XSS"),
        ("x-xss-protection", "LOW", "Missing X-XSS-Protection header",
         "Add 'X-XSS-Protection: 1; mode=block'"),
    ]

    for header_name, severity, desc, remediation in checks:
        if header_name not in headers:
            findings.append({
                "vuln_type": f"Missing Security Header: {header_name}",
                "owasp_category": "API8",
                "severity": severity,
                "cvss_score": {"HIGH": 6.1, "MEDIUM": 4.3, "LOW": 2.1}.get(severity, 3.0),
                "description": desc,
                "payload": f"HTTP Response to {base_url}",
                "evidence": f"Header '{header_name}' absent from response",
                "remediation": remediation,
                "path": "/",
            })
            if callback:
                callback(f"[{severity}] {desc}")

    # Check for sensitive info in response headers
    sensitive_headers = ["server", "x-powered-by", "x-aspnet-version"]
    for h in sensitive_headers:
        if h in headers:
            findings.append({
                "vuln_type": "Information Disclosure via Headers",
                "owasp_category": "API8",
                "severity": "LOW",
                "cvss_score": 3.1,
                "description": f"Server technology disclosed in header '{h}': {headers[h]}",
                "payload": "",
                "evidence": f"{h}: {headers[h]}",
                "remediation": f"Remove or obscure the '{h}' header to reduce fingerprinting surface.",
                "path": "/",
            })

    return findings


# ── Error Message Analysis (API8) ─────────────────────────────────────────────

ERROR_DISCLOSURE_PATTERNS = re.compile(
    r"(traceback|stack trace|exception in|line \d+|file \"[^\"]+\"|"
    r"syntaxerror|typeerror|nameerror|attributeerror|at com\.|"
    r"java\.lang\.|php warning|php error|notice: undefined|"
    r"warning: include|fatal error|parse error)",
    re.IGNORECASE,
)


def test_error_disclosure(base_url: str, endpoints: list[dict], callback=None) -> list[dict]:
    """Detect endpoints that return stack traces or verbose error messages."""
    findings = []
    for ep in endpoints[:10]:
        path = ep.get("path", "/")
        url = base_url.rstrip("/") + path
        # Send a deliberately malformed request
        malformed_url = url + ("?" if "?" not in url else "&") + "id=INVALID_TYPE_STRING&debug=true"
        resp = _safe_request("GET", malformed_url)
        if resp and resp.status_code in (400, 500):
            if ERROR_DISCLOSURE_PATTERNS.search(resp.text):
                findings.append({
                    "vuln_type": "Verbose Error Message / Stack Trace Disclosure",
                    "owasp_category": "API8",
                    "severity": "MEDIUM",
                    "cvss_score": 5.0,
                    "description": f"Endpoint {path} returns verbose error messages with implementation details",
                    "payload": "Invalid type parameter",
                    "evidence": resp.text[:300],
                    "remediation": "Suppress detailed error messages in production. Return generic 400/500 responses to clients. Log full stack traces server-side only.",
                    "path": path,
                })
                if callback:
                    callback(f"[MEDIUM] Error disclosure at {path}")
    return findings


# ── Main Vulnerability Scan Pipeline ─────────────────────────────────────────

def run_vuln_scan(base_url: str, endpoints: list[dict], callback=None) -> list[dict]:
    """Run all vulnerability checks against discovered endpoints."""
    all_findings = []

    if callback:
        callback(f"Starting vulnerability scan on {len(endpoints)} endpoints...")

    # 1. Security headers (once per target)
    if callback:
        callback("Checking security headers...")
    all_findings.extend(test_security_headers(base_url, callback))

    # 2. Per-endpoint checks
    for ep in endpoints[:20]:
        path = ep.get("path", "/")
        method = ep.get("method", "GET")
        if callback:
            callback(f"Scanning {method} {path}...")

        all_findings.extend(test_sqli(base_url, ep, callback))
        all_findings.extend(test_xss(base_url, ep, callback))
        if method in ("POST", "PUT", "PATCH"):
            all_findings.extend(test_mass_assignment(base_url, ep, callback))

    # 3. Auth checks across all endpoints
    if callback:
        callback("Testing broken authentication patterns...")
    all_findings.extend(test_broken_auth(base_url, endpoints, callback))

    # 4. BOLA/IDOR checks
    if callback:
        callback("Testing for BOLA / IDOR vulnerabilities...")
    all_findings.extend(test_bola(base_url, endpoints, callback))

    # 5. BFLA checks
    if callback:
        callback("Testing for Broken Function Level Authorization...")
    all_findings.extend(test_bfla(base_url, endpoints, callback))

    # 6. Excessive data exposure
    if callback:
        callback("Scanning for excessive data exposure...")
    all_findings.extend(test_excessive_exposure(base_url, endpoints, callback))

    # 7. SSRF
    if callback:
        callback("Testing for Server-Side Request Forgery (SSRF)...")
    all_findings.extend(test_ssrf(base_url, endpoints, callback))

    # 8. Command injection
    if callback:
        callback("Testing for command injection...")
    all_findings.extend(test_command_injection(base_url, endpoints, callback))

    # 9. Improper inventory management
    if callback:
        callback("Checking for improper inventory management...")
    all_findings.extend(test_inventory_management(base_url, endpoints, callback))

    # 10. Error disclosure
    if callback:
        callback("Checking for verbose error message disclosure...")
    all_findings.extend(test_error_disclosure(base_url, endpoints, callback))

    # 11. Rate limiting on first available endpoint
    if endpoints:
        all_findings.extend(test_rate_limit(base_url, endpoints[0], callback))

    if callback:
        callback(f"Vulnerability scan complete: {len(all_findings)} findings")

    return all_findings
