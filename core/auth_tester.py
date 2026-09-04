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
    """Test if an endpoint can be accessed without credentials."""
    url = base_url.rstrip("/") + ("/" if not endpoint_path.startswith("/") else "") + endpoint_path
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
            "detail": f"Endpoint correctly rejected or restricted unauthenticated request (HTTP {resp.status_code})",
        }
    except Exception as e:
        return {"vulnerable": False, "error": str(e)}


def test_bola(base_url: str, endpoint_template: str, user_id: int = 1, callback=None) -> dict:
    """Test for Broken Object Level Authorization by accessing another user's/object's data."""
    target_id = user_id + 1
    # Replace various common parameter names
    path = endpoint_template
    for param in ["{id}", "{user_id}", "{userId}", "{petId}", "{orderId}", "{accountId}", "{book_id}"]:
        path = path.replace(param, str(target_id))
    # Also handle username substitution
    for u_param in ["{username}", "{user}", "{name}"]:
        path = path.replace(u_param, "admin")
    
    url = base_url.rstrip("/") + ("/" if not path.startswith("/") else "") + path
    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT, verify=False)
        if resp.status_code in (200, 201, 202):
            # Check if JSON payload was returned
            try:
                data = resp.json()
                if data:
                    return {
                        "vulnerable": True,
                        "tested_id": target_id,
                        "status_code": resp.status_code,
                        "detail": f"BOLA/IDOR: Object data accessed for ID/user '{target_id}' without authorization (HTTP {resp.status_code})",
                    }
            except Exception:
                pass
            return {
                "vulnerable": True,
                "tested_id": target_id,
                "status_code": resp.status_code,
                "detail": f"BOLA/IDOR: Endpoint accessible with modified object identifier '{target_id}' (HTTP {resp.status_code})",
            }
        return {"vulnerable": False, "tested_id": target_id, "status_code": resp.status_code,
                "detail": f"Object access restricted for ID '{target_id}' (HTTP {resp.status_code})"}
    except Exception as e:
        return {"vulnerable": False, "error": str(e)}


def test_fake_token_acceptance(base_url: str, endpoint_path: str, callback=None) -> dict:
    """Test if the server blindly accepts an invalid or alg:none forged Bearer token."""
    url = base_url.rstrip("/") + ("/" if not endpoint_path.startswith("/") else "") + endpoint_path
    # Forged alg:none token
    forged_token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwicm9sZSI6ImFkbWluIn0."
    try:
        headers = {"Authorization": f"Bearer {forged_token}"}
        resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT, verify=False)
        if resp.status_code in (200, 201, 202):
            return {
                "vulnerable": True,
                "status_code": resp.status_code,
                "detail": f"Server accepted unsigned alg:none forged JWT on {endpoint_path} (HTTP {resp.status_code})",
            }
        return {
            "vulnerable": False,
            "status_code": resp.status_code,
            "detail": f"Server correctly rejected unsigned alg:none token (HTTP {resp.status_code})",
        }
    except Exception as e:
        return {"vulnerable": False, "error": str(e)}


# ── Main Auth Testing Pipeline ────────────────────────────────────────────────

def run_auth_tests(base_url: str, endpoints: list[dict], token: str | None = None,
                   callback=None) -> list[dict]:
    """Run all authentication tests against discovered endpoints and target API."""
    results = []
    base_url = base_url.rstrip("/")

    if callback:
        callback("Starting authentication security assessment...")

    # 1. JWT analysis if token provided
    if token:
        if callback:
            callback("Analyzing supplied JWT token...")

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
            "severity": "CRITICAL" if none_result.get("vulnerable") else "INFO",
            "detail": none_result.get("detail"),
        })

        # Secret brute-force
        if callback:
            callback("Brute-forcing JWT secret against common weak dictionary...")
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

    # 2. Test missing auth on discovered endpoints & sensitive endpoints
    sensitive_keywords = ["admin", "user", "account", "profile", "setting", "config", "order", "billing", "payment", "secret", "private"]
    tested_paths = set()
    
    # Collect candidate endpoints to test
    candidates = []
    for ep in endpoints:
        p = ep.get("path", "")
        if not p or p in tested_paths:
            continue
        # High priority: marked auth_required or matches sensitive keywords or write methods
        is_sensitive = any(kw in p.lower() for kw in sensitive_keywords)
        if ep.get("auth_required") or is_sensitive or ep.get("method") in ("POST", "PUT", "DELETE"):
            candidates.append(p)
            tested_paths.add(p)
            if len(candidates) >= 5:
                break

    # If no candidate found from discovery, add standard sensitive probes
    common_sensitive = ["/api/v1/admin", "/api/v1/users", "/admin", "/api/admin", "/users", "/api/users", "/api/v1/settings"]
    for p in common_sensitive:
        if p not in tested_paths and len(candidates) < 6:
            candidates.append(p)
            tested_paths.add(p)

    for path in candidates:
        if callback:
            callback(f"Testing missing auth on {path}...")
        result = test_missing_auth(base_url, path, callback)
        status = result.get("status_code", 0)
        is_vuln = result.get("vulnerable", False)
        
        # If it returns 200 on an admin/sensitive path, it's CRITICAL; if it rejects (401/403), it's PASSED
        if is_vuln and any(kw in path.lower() for kw in ["admin", "setting", "config", "secret"]):
            results.append({
                "test_name": f"Broken Auth: Unauthenticated Access to {path}",
                "category": "BrokenAuth",
                "passed": False,
                "severity": "CRITICAL",
                "detail": f"Critical administrative endpoint accessible without authentication (HTTP {status})",
                "endpoint_path": path,
            })
        elif is_vuln:
            results.append({
                "test_name": f"Auth Check: Unauthenticated Access to {path}",
                "category": "BrokenAuth",
                "passed": False,
                "severity": "HIGH",
                "detail": f"Endpoint accessible without credentials (HTTP {status})",
                "endpoint_path": path,
            })
        else:
            results.append({
                "test_name": f"Auth Verification: Access Control on {path}",
                "category": "BrokenAuth",
                "passed": True,
                "severity": "INFO",
                "detail": result.get("detail", f"Endpoint restricted/protected (HTTP {status})"),
                "endpoint_path": path,
            })

    # 3. Forged / alg:none token acceptance test against API
    probe_target_path = candidates[0] if candidates else "/"
    if callback:
        callback(f"Testing forged alg:none JWT acceptance on {probe_target_path}...")
    fake_token_res = test_fake_token_acceptance(base_url, probe_target_path, callback)
    results.append({
        "test_name": "Forged alg:none JWT Acceptance Test",
        "category": "JWT",
        "passed": not fake_token_res.get("vulnerable", False),
        "severity": "CRITICAL" if fake_token_res.get("vulnerable") else "INFO",
        "detail": fake_token_res.get("detail", ""),
        "endpoint_path": probe_target_path,
    })

    # 4. Check for API keys in query parameters
    api_key_params = ["api_key", "apikey", "api-key", "token", "access_token", "key", "secret"]
    exposed_endpoints = []
    for ep in endpoints:
        path = ep.get("path", "")
        if any(f"{p}=" in path.lower() or f"?{p}" in path.lower() for p in api_key_params):
            exposed_endpoints.append(path)
    
    if exposed_endpoints:
        for ep_path in exposed_endpoints[:3]:
            results.append({
                "test_name": f"API Key in URL: {ep_path}",
                "category": "ApiKey",
                "passed": False,
                "severity": "HIGH",
                "detail": f"Sensitive credential/key exposed in URL query string on {ep_path}",
                "endpoint_path": ep_path,
            })
    else:
        results.append({
            "test_name": "API Key URL Parameter Check",
            "category": "ApiKey",
            "passed": True,
            "severity": "INFO",
            "detail": "No API keys or auth tokens discovered in URL query parameters",
        })

    # 5. BOLA / IDOR testing on parameterized endpoints
    param_templates = []
    for ep in endpoints:
        p = ep.get("path", "")
        if any(param in p for param in ["{id}", "{user_id}", "{userId}", "{petId}", "{orderId}", "{accountId}", "{username}"]):
            param_templates.append(p)
        elif p.rstrip("/").split("/")[-1].isdigit():
            # e.g. /api/users/1 -> replace last segment with {id}
            parts = p.rstrip("/").split("/")
            parts[-1] = "{id}"
            param_templates.append("/".join(parts))

    if not param_templates:
        param_templates = ["/api/v1/users/{id}", "/users/{id}"]

    for template in param_templates[:3]:
        if callback:
            callback(f"Testing BOLA / IDOR on {template}...")
        bola = test_bola(base_url, template, callback=callback)
        if bola.get("vulnerable"):
            results.append({
                "test_name": f"BOLA / IDOR: Unauthorized Object Access on {template}",
                "category": "BOLA",
                "passed": False,
                "severity": "HIGH",
                "detail": bola.get("detail", "Object accessible across authorization boundaries"),
                "endpoint_path": template,
            })
        else:
            results.append({
                "test_name": f"BOLA Protection: Object Access on {template}",
                "category": "BOLA",
                "passed": True,
                "severity": "INFO",
                "detail": bola.get("detail", f"Object ID tampering correctly restricted (HTTP {bola.get('status_code')})"),
                "endpoint_path": template,
            })

    if callback:
        callback(f"Authentication testing complete: {len(results)} checks performed")

    return results

