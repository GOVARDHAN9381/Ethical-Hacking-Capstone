"""
core/auth_tester.py — Module 1: JWT, API Key, and Authentication Testing.
"""

import base64
import hmac
import hashlib
import json
import time
import requests
from config import JWT_WEAK_SECRETS, REQUEST_TIMEOUT


# ── JWT Utilities ─────────────────────────────────────────────────────────────

def _b64_decode(data: str) -> bytes:
    """Base64url decode with padding fix."""
    data += "=" * (4 - len(data) % 4)
    return base64.urlsafe_b64decode(data)


def decode_jwt_unsafe(token: str) -> dict:
    """Decode JWT header and payload without verification."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {"error": "Not a valid JWT (wrong number of segments)"}
        header  = json.loads(_b64_decode(parts[0]))
        payload = json.loads(_b64_decode(parts[1]))
        return {"header": header, "payload": payload, "raw_parts": parts}
    except Exception as e:
        return {"error": str(e)}


def check_jwt_none_alg(token: str) -> dict:
    """Test for alg:none vulnerability."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {"vulnerable": False, "detail": "Invalid JWT format"}
        header = json.loads(_b64_decode(parts[0]))
        payload = json.loads(_b64_decode(parts[1]))

        # If the token itself already uses alg:none — confirmed vulnerable
        if header.get("alg", "").lower() == "none":
            return {
                "vulnerable": True,
                "detail": "Token already uses alg:none — server accepts unsigned tokens",
                "original_alg": "none",
            }

        # Craft an alg:none token for manual testing (not confirmed until server tested)
        none_header = base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "typ": "JWT"}).encode()
        ).rstrip(b"=").decode()
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).rstrip(b"=").decode()
        none_token = f"{none_header}.{payload_b64}."

        return {
            "vulnerable": False,
            "potential": True,
            "crafted_token": none_token,
            "detail": "alg:none token crafted for testing — submit manually to verify if server accepts it",
            "original_alg": header.get("alg", "unknown"),
        }
    except Exception as e:
        return {"vulnerable": False, "detail": str(e)}


def brute_force_jwt_secret(token: str, callback=None) -> dict:
    """Try weak secrets to forge JWT."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {"cracked": False, "secret": None}
        header  = json.loads(_b64_decode(parts[0]))
        alg     = header.get("alg", "HS256")
        if not alg.startswith("HS"):
            return {"cracked": False, "secret": None, "detail": f"Non-HMAC algorithm: {alg}"}

        signing_input = f"{parts[0]}.{parts[1]}".encode()
        sig_bytes = _b64_decode(parts[2])

        hash_fn = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }.get(alg, hashlib.sha256)

        for secret in JWT_WEAK_SECRETS:
            computed = hmac.new(secret.encode(), signing_input, hash_fn).digest()
            if hmac.compare_digest(computed, sig_bytes):
                if callback:
                    callback(f"[CRITICAL] JWT secret cracked: '{secret}'")
                return {"cracked": True, "secret": secret, "alg": alg}

        return {"cracked": False, "secret": None}
    except Exception as e:
        return {"cracked": False, "secret": None, "error": str(e)}


def analyze_jwt_claims(token: str) -> list[dict]:
    """Analyze JWT claims for security issues."""
    decoded = decode_jwt_unsafe(token)
    issues = []

    if "error" in decoded:
        return [{"issue": "Invalid JWT", "severity": "HIGH", "detail": decoded["error"]}]

    payload = decoded.get("payload", {})
    header  = decoded.get("header", {})

    # Check expiry
    exp = payload.get("exp")
    if exp is None:
        issues.append({"issue": "No expiration claim (exp)", "severity": "MEDIUM",
                       "detail": "JWT has no expiry — tokens never expire"})
    elif exp < time.time():
        issues.append({"issue": "Token is expired", "severity": "LOW",
                       "detail": f"Token expired at {exp}"})

    # Check algorithm
    alg = header.get("alg", "")
    if alg.lower() == "none":
        issues.append({"issue": "Algorithm: none", "severity": "CRITICAL",
                       "detail": "Unsigned JWT — anyone can forge tokens"})
    elif alg in ("HS256",):
        issues.append({"issue": f"Weak algorithm: {alg}", "severity": "LOW",
                       "detail": "Consider upgrading to RS256 or ES256"})

    # Check sensitive data in payload
    sensitive_keys = ["password", "passwd", "secret", "ssn", "credit_card", "cvv", "pin"]
    for key in payload.keys():
        if any(s in key.lower() for s in sensitive_keys):
            issues.append({"issue": f"Sensitive field in payload: {key}", "severity": "HIGH",
                           "detail": "JWT payload is base64-encoded, not encrypted"})

    return issues


# ── API Key Testing ───────────────────────────────────────────────────────────

def test_api_key_in_url(url: str) -> dict:
    """Check if API key appears as a query parameter (insecure)."""
    insecure_param_names = ["api_key", "apikey", "api-key", "key", "token", "access_token", "secret"]
    from urllib.parse import urlparse, parse_qs
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    found = []
    for name in insecure_param_names:
        if name in params:
            found.append(name)
    if found:
        return {"vulnerable": True, "params": found,
                "detail": f"API key in URL query params ({', '.join(found)}) — exposed in logs/history"}
    return {"vulnerable": False}


def test_missing_auth(base_url: str, endpoint_path: str, callback=None) -> dict:
    """Test if an authenticated endpoint can be accessed without credentials."""
    url = base_url.rstrip("/") + endpoint_path
    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT, verify=False)
        if resp.status_code in (200, 201, 202):
            return {
                "vulnerable": True,
                "status_code": resp.status_code,
                "detail": f"Endpoint accessible without authentication (HTTP {resp.status_code})",
            }
        return {
            "vulnerable": False,
            "status_code": resp.status_code,
            "detail": f"Endpoint correctly rejected unauthenticated request (HTTP {resp.status_code})",
        }
    except Exception as e:
        return {"vulnerable": False, "error": str(e)}


def test_bola(base_url: str, endpoint_template: str, user_id: int = 1, callback=None) -> dict:
    """Test for Broken Object Level Authorization by accessing another user's data."""
    target_id = user_id + 1  # Try to access next user's data
    path = endpoint_template.replace("{id}", str(target_id)).replace("{user_id}", str(target_id))
    url = base_url.rstrip("/") + path
    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT, verify=False)
        if resp.status_code == 200:
            return {
                "vulnerable": True,
                "tested_id": target_id,
                "status_code": 200,
                "detail": f"BOLA: Can access user {target_id} data without authorization",
            }
        return {"vulnerable": False, "tested_id": target_id, "status_code": resp.status_code}
    except Exception as e:
        return {"vulnerable": False, "error": str(e)}


# ── Main Auth Testing Pipeline ────────────────────────────────────────────────

def run_auth_tests(base_url: str, endpoints: list[dict], token: str | None = None,
                   callback=None) -> list[dict]:
    """Run all authentication tests against discovered endpoints."""
    results = []

    if callback:
        callback("Starting authentication tests...")

    # 1. JWT analysis if token provided
    if token:
        if callback:
            callback("Analyzing JWT token...")

        claims_issues = analyze_jwt_claims(token)
        for issue in claims_issues:
            results.append({
                "test_name": f"JWT Claim: {issue['issue']}",
                "category": "JWT",
                "passed": False,
                "severity": issue["severity"],
                "detail": issue["detail"],
            })
            if callback:
                callback(f"  [{issue['severity']}] {issue['issue']}")

        # alg:none check
        none_result = check_jwt_none_alg(token)
        results.append({
            "test_name": "JWT alg:none Attack",
            "category": "JWT",
            "passed": not none_result.get("vulnerable", False),
            "severity": "CRITICAL" if none_result.get("vulnerable") else None,
            "detail": none_result.get("detail"),
        })

        # Secret brute-force
        if callback:
            callback("Brute-forcing JWT secret against common weak secrets...")
        bf = brute_force_jwt_secret(token, callback)
        if bf.get("cracked"):
            results.append({
                "test_name": "JWT Weak Secret",
                "category": "JWT",
                "passed": False,
                "severity": "CRITICAL",
                "detail": f"JWT secret cracked: '{bf['secret']}' — tokens can be forged",
            })
        else:
            results.append({
                "test_name": "JWT Weak Secret Brute-Force",
                "category": "JWT",
                "passed": True,
                "severity": "INFO",
                "detail": "JWT secret not found in common weak secrets list",
            })

    # 2. Test missing auth on sensitive endpoints
    sensitive_paths = ["/api/v1/admin", "/api/v1/users", "/admin", "/api/admin",
                       "/api/v1/settings", "/api/v1/config"]
    for path in sensitive_paths:
        matching_ep = next((ep for ep in endpoints if ep.get("path") == path), None)
        if matching_ep and matching_ep.get("auth_required"):
            if callback:
                callback(f"Testing missing auth on {path}...")
            result = test_missing_auth(base_url, path, callback)
            results.append({
                "test_name": f"Missing Auth: {path}",
                "category": "BrokenAuth",
                "passed": not result.get("vulnerable", False),
                "severity": "CRITICAL" if result.get("vulnerable") else None,
                "detail": result.get("detail", ""),
                "endpoint_path": path,
            })

    # 3. Check for API keys in URLs
    for ep in endpoints:
        path = ep.get("path", "")
        if "?" in path:
            key_check = test_api_key_in_url(base_url + path)
            if key_check.get("vulnerable"):
                results.append({
                    "test_name": f"API Key in URL: {path}",
                    "category": "ApiKey",
                    "passed": False,
                    "severity": "HIGH",
                    "detail": key_check.get("detail"),
                })

    # 4. BOLA test on user endpoints
    user_paths = ["/api/v1/users/{id}", "/api/v1/user/{id}", "/users/{id}", "/api/users/{id}"]
    for path_template in user_paths:
        ep_match = next(
            (ep for ep in endpoints if "{id}" in ep.get("path", "") or
             ep.get("path", "").rstrip("/").split("/")[-1].isdigit()), None
        )
        if ep_match or any(p.replace("{id}", "1") in [e.get("path") for e in endpoints]
                           for p in user_paths):
            if callback:
                callback(f"Testing BOLA on user endpoints...")
            bola = test_bola(base_url, path_template.replace("{id}", "1"), callback=callback)
            if bola.get("vulnerable"):
                results.append({
                    "test_name": "BOLA: Unauthorized Object Access",
                    "category": "BOLA",
                    "passed": False,
                    "severity": "HIGH",
                    "detail": bola.get("detail"),
                })
            break

    if callback:
        callback(f"Auth testing complete: {len(results)} checks performed")

    return results
