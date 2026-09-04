"""
test_modules.py — End-to-end test for Module 1 & Module 2 against the demo target.
Run AFTER starting demo_target/app.py on port 5001.
"""

import requests
import warnings
warnings.filterwarnings("ignore")

TARGET = "http://localhost:5001"

print("\n" + "="*60)
print("  APIAST Module 1 & 2 -- End-to-End Test")
print("  Target:", TARGET)
print("="*60 + "\n")

# ── Verify demo target is up ──────────────────────────────────────────────────
print("[STEP 0] Checking demo target health...")
try:
    r = requests.get(TARGET + "/health", timeout=5, verify=False)
    print("  [OK] Demo target is UP  status=%d" % r.status_code)
except Exception as e:
    print("  [FAIL] Demo target not reachable:", e)
    print("  --> Start it with: python demo_target/app.py")
    raise SystemExit(1)

# ── Module 1: API Discovery ───────────────────────────────────────────────────
print("\n[STEP 1] Module 1 -- API Endpoint Discovery & Swagger Scanning")
from core.api_discovery import discover_endpoints

result = discover_endpoints(TARGET)
eps = result["all_endpoints"]
swagger_found = result["swagger_found"]

print("  Endpoints discovered :", len(eps))
print("  Swagger/OpenAPI found:", swagger_found)
print("  Probe results        :", len(result["probe_results"]))
print("  Swagger results      :", len(result["swagger_results"]))
print()
for ep in eps:
    auth_str = "auth=" + (ep["auth_type"] or "?") if ep.get("auth_required") else "public"
    print("    %-6s %-35s  %-7s  %s" % (ep["method"], ep["path"], ep["source"], auth_str))

assert len(eps) > 0, "FAIL: No endpoints discovered"
assert swagger_found, "FAIL: Swagger spec not found at /openapi.json"
print("\n  [PASS] Module 1 Discovery OK")

# ── Module 1: Auth Testing ────────────────────────────────────────────────────
print("\n[STEP 2] Module 1 -- Authentication Tests (JWT alg:none token)")
from core.auth_tester import run_auth_tests

# The demo login returns an alg:none token for default creds
none_token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VySWQiOjMsInJvbGUiOiJhZG1pbiJ9."

auth_results = run_auth_tests(TARGET, eps, token=none_token)
failures = [r for r in auth_results if not r.get("passed")]

print("  Total auth checks  :", len(auth_results))
print("  Failed checks      :", len(failures))
print()
for r in auth_results:
    status = "[VULN]" if not r.get("passed") else "[PASS]"
    sev = r.get("severity") or "   "
    print("    %s [%-8s] %s" % (status, sev, r["test_name"]))

assert any("alg:none" in r["test_name"] for r in auth_results), "FAIL: alg:none check not present"
print("\n  [PASS] Module 1 Auth Tests OK")

# ── Module 2: Vulnerability Scan ─────────────────────────────────────────────
print("\n[STEP 3] Module 2 -- Vulnerability Assessment (this takes ~30s for rate-limit test)")
from core.vuln_scanner import run_vuln_scan

findings = run_vuln_scan(TARGET, eps)
by_sev = {}
for f in findings:
    sev = f.get("severity", "INFO")
    by_sev[sev] = by_sev.get(sev, 0) + 1

print("  Total findings:", len(findings))
for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
    count = by_sev.get(sev, 0)
    if count:
        print("    %-10s: %d" % (sev, count))

print()
for f in findings:
    sev  = f.get("severity", "?")
    vt   = f.get("vuln_type", "?")
    path = f.get("path", "?")
    print("    [%-8s] %-45s at %s" % (sev, vt, path))

assert len(findings) > 0, "FAIL: No vulnerabilities found (demo target should be full of them)"
assert any(f["vuln_type"] == "SQL Injection" for f in findings), "FAIL: SQLi not detected"
assert any(f["vuln_type"] == "Broken Authentication" for f in findings), "FAIL: Broken Auth not detected"
print("\n  [PASS] Module 2 Vulnerability Scan OK")

# ── Summary ───────────────────────────────────────────────────────────────────
print("\n" + "="*60)
print("  ALL TESTS PASSED")
print("  Module 1: %d endpoints, %d auth issues" % (len(eps), len(failures)))
print("  Module 2: %d vulnerabilities" % len(findings))
print("="*60 + "\n")
