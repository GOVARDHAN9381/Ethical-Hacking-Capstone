"""
core/api_discovery.py — Module 1: API Endpoint Discovery & Swagger/OpenAPI scanning.
"""

import time
import json
import requests
import yaml
from urllib.parse import urljoin, urlparse
from config import COMMON_PATHS, SWAGGER_PATHS, REQUEST_TIMEOUT


def _safe_get(url: str, **kwargs) -> requests.Response | None:
    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT, verify=False,
                            allow_redirects=True, **kwargs)
        return resp
    except Exception:
        return None


def _detect_auth_type(response: requests.Response) -> tuple[bool, str | None]:
    """Detect if an endpoint requires authentication and what type."""
    auth_required = False
    auth_type = None

    if response is None:
        return False, None

    www_auth = response.headers.get("WWW-Authenticate", "")
    if "Bearer" in www_auth:
        auth_required = True
        auth_type = "JWT/Bearer"
    elif "Basic" in www_auth:
        auth_required = True
        auth_type = "Basic"
    elif "ApiKey" in www_auth or "Api-Key" in www_auth:
        auth_required = True
        auth_type = "ApiKey"

    if response.status_code in (401, 403):
        auth_required = True
        if not auth_type:
            auth_type = "Unknown"

    # Check response body for token hints
    if not auth_required:
        try:
            body = response.text.lower()
            if "unauthorized" in body or "forbidden" in body or "token" in body:
                if response.status_code in (401, 403):
                    auth_required = True
        except Exception:
            pass

    return auth_required, auth_type


def probe_common_paths(base_url: str, callback=None) -> list[dict]:
    """Probe a list of common API paths against the target."""
    base_url = base_url.rstrip("/")
    discovered = []

    for path in COMMON_PATHS:
        url = base_url + path
        t0 = time.time()
        resp = _safe_get(url)
        elapsed = round((time.time() - t0) * 1000, 2)

        if resp is None:
            continue

        # Consider anything that isn't a 404/410 as "found"
        if resp.status_code not in (404, 410):
            auth_required, auth_type = _detect_auth_type(resp)
            entry = {
                "path": path,
                "method": "GET",
                "status_code": resp.status_code,
                "auth_required": auth_required,
                "auth_type": auth_type,
                "response_time": elapsed,
                "content_type": resp.headers.get("Content-Type", ""),
                "source": "probe",
            }
            discovered.append(entry)
            if callback:
                callback(f"[FOUND] {resp.status_code} {path} ({elapsed}ms)")

    return discovered


def parse_swagger(base_url: str, callback=None) -> list[dict]:
    """Try to fetch and parse Swagger/OpenAPI spec to extract endpoints."""
    base_url = base_url.rstrip("/")
    endpoints = []
    spec = None

    for swagger_path in SWAGGER_PATHS:
        url = base_url + swagger_path
        resp = _safe_get(url)
        if resp and resp.status_code == 200:
            if callback:
                callback(f"[SWAGGER] Found spec at {swagger_path}")
            try:
                ct = resp.headers.get("Content-Type", "")
                if "yaml" in ct or swagger_path.endswith(".yaml"):
                    spec = yaml.safe_load(resp.text)
                else:
                    spec = resp.json()
                break
            except Exception:
                continue

    if not spec:
        return endpoints

    paths = spec.get("paths", {})
    servers = spec.get("servers", [])
    server_url = servers[0].get("url", "") if servers else ""

    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, operation in methods.items():
            if method.lower() in ("get", "post", "put", "patch", "delete", "options"):
                security = operation.get("security", spec.get("security", []))
                auth_required = bool(security)
                auth_type = None
                if auth_required:
                    # Try to determine auth type from security scheme names
                    try:
                        scheme_name = list(security[0].keys())[0] if security else ""
                        security_schemes = spec.get("components", {}).get("securitySchemes", {})
                        scheme_def = security_schemes.get(scheme_name, {})
                        s_type = scheme_def.get("type", "")
                        s_scheme = scheme_def.get("scheme", "")
                        if s_scheme.lower() == "bearer" or "jwt" in scheme_name.lower():
                            auth_type = "JWT/Bearer"
                        elif s_type == "apiKey":
                            auth_type = "ApiKey"
                        elif s_scheme.lower() == "basic":
                            auth_type = "Basic"
                        else:
                            auth_type = s_type or "Unknown"
                    except Exception:
                        auth_type = "Unknown"

                endpoints.append({
                    "path": path,
                    "method": method.upper(),
                    "status_code": None,
                    "auth_required": auth_required,
                    "auth_type": auth_type,
                    "response_time": None,
                    "content_type": "application/json",
                    "source": "swagger",
                })

    if callback:
        callback(f"[SWAGGER] Parsed {len(endpoints)} endpoints from spec")
    return endpoints


def discover_endpoints(base_url: str, callback=None) -> dict:
    """Main discovery entry point: probe + swagger parsing."""
    results = {
        "base_url": base_url,
        "probe_results": [],
        "swagger_results": [],
        "all_endpoints": [],
        "swagger_found": False,
    }

    if callback:
        callback(f"Starting endpoint discovery on {base_url}")

    # Step 1: Parse Swagger/OpenAPI
    if callback:
        callback("Checking for Swagger/OpenAPI documentation...")
    swagger_eps = parse_swagger(base_url, callback)
    results["swagger_results"] = swagger_eps
    results["swagger_found"] = len(swagger_eps) > 0

    # Step 2: Probe common paths
    if callback:
        callback(f"Probing {len(COMMON_PATHS)} common API paths...")
    probe_eps = probe_common_paths(base_url, callback)
    results["probe_results"] = probe_eps

    # Step 3: Merge and deduplicate
    seen = set()
    all_eps = []
    for ep in swagger_eps + probe_eps:
        key = (ep["path"].lower(), ep.get("method", "GET").upper())
        if key not in seen:
            seen.add(key)
            all_eps.append(ep)

    results["all_endpoints"] = all_eps

    if callback:
        callback(f"Discovery complete: {len(all_eps)} unique endpoints found")

    return results
