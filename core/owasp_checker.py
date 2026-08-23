"""
core/owasp_checker.py — OWASP API Top 10 (2023) mapping and coverage analysis.
"""

from config import OWASP_API_TOP10

# Extended vuln type → OWASP category mapping
VULN_OWASP_MAP = {
    # API1 — Broken Object Level Authorization
    "bola":                               "API1",
    "broken object level authorization":  "API1",
    "idor":                               "API1",
    # API2 — Broken Authentication
    "broken authentication":              "API2",
    "default credentials":                "API2",
    "alg:none":                           "API2",
    "jwt":                                "API2",
    # API3 — Broken Object Property Level Authorization / Excessive Data Exposure
    "mass assignment":                    "API3",
    "excessive data exposure":            "API3",
    "broken object property":             "API3",
    # API4 — Unrestricted Resource Consumption
    "rate limiting":                      "API4",
    "unrestricted resource":              "API4",
    # API5 — Broken Function Level Authorization
    "bfla":                               "API5",
    "broken function level":              "API5",
    "privilege escalation":               "API5",
    # API6 — Unrestricted Access to Sensitive Business Flows
    "business logic":                     "API6",
    "sensitive business flow":            "API6",
    # API7 — Server Side Request Forgery
    "ssrf":                               "API7",
    "server-side request forgery":        "API7",
    "server side request forgery":        "API7",
    # API8 — Security Misconfiguration / Injection
    "sql injection":                      "API8",
    "xss":                                "API8",
    "cross-site scripting":               "API8",
    "command injection":                  "API8",
    "security header":                    "API8",
    "information disclosure":             "API8",
    "verbose error":                      "API8",
    "error message":                      "API8",
    "stack trace":                        "API8",
    "misconfiguration":                   "API8",
    # API9 — Improper Inventory Management
    "improper inventory":                 "API9",
    "deprecated":                         "API9",
    "inventory management":               "API9",
    # API10 — Unsafe Consumption of APIs
    "unsafe consumption":                 "API10",
    "third-party api":                    "API10",
}


def map_vuln_to_owasp(vuln_type: str) -> str:
    """Map a vulnerability type string to its OWASP API category."""
    vuln_lower = vuln_type.lower()
    for pattern, category in VULN_OWASP_MAP.items():
        if pattern in vuln_lower:
            return category
    return "API8"  # Default to Security Misconfiguration


def enrich_findings(findings: list[dict]) -> list[dict]:
    """Add OWASP category and name to each finding if not already set."""
    enriched = []
    for f in findings:
        fc = dict(f)
        if not fc.get("owasp_category"):
            fc["owasp_category"] = map_vuln_to_owasp(fc.get("vuln_type", ""))
        cat = fc.get("owasp_category", "")
        fc["owasp_name"] = OWASP_API_TOP10.get(cat, "Unknown")
        enriched.append(fc)
    return enriched


def generate_owasp_summary(findings: list[dict]) -> dict:
    """
    Generate a full OWASP API Top 10 coverage summary.

    Returns:
        {
          "categories": [{"category": "API1", "name": "...", "found": bool, "count": int, "severity": str}],
          "coverage_pct": float,  # % of categories that have findings
          "tested_count": int,
          "found_count": int,
        }
    """
    # Count findings per OWASP category
    category_data: dict[str, dict] = {}
    for f in findings:
        cat = f.get("owasp_category", "API8")
        if cat not in category_data:
            category_data[cat] = {"count": 0, "severities": []}
        category_data[cat]["count"] += 1
        category_data[cat]["severities"].append(f.get("severity", "INFO"))

    severity_rank = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

    categories = []
    for cat_id, cat_name in sorted(OWASP_API_TOP10.items()):
        data = category_data.get(cat_id)
        if data:
            best_sev = max(data["severities"], key=lambda s: severity_rank.get(s, 0))
            categories.append({
                "category": cat_id,
                "name": cat_name,
                "found": True,
                "count": data["count"],
                "severity": best_sev,
            })
        else:
            categories.append({
                "category": cat_id,
                "name": cat_name,
                "found": False,
                "count": 0,
                "severity": None,
            })

    found_count = sum(1 for c in categories if c["found"])
    total_count = len(categories)
    coverage_pct = round((found_count / total_count) * 100, 1) if total_count > 0 else 0.0

    return {
        "categories": categories,
        "coverage_pct": coverage_pct,
        "tested_count": total_count,
        "found_count": found_count,
    }
