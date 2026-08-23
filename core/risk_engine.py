"""
core/risk_engine.py — Module 3: CVSS-based Risk Scoring, Security Score & Compliance Analysis.
"""

from config import SEVERITY_WEIGHTS


# ── CVSS v3.1 Simplified Scoring ──────────────────────────────────────────────

CVSS_SEVERITY_RANGES = [
    (9.0, 10.0, "CRITICAL"),
    (7.0, 8.9,  "HIGH"),
    (4.0, 6.9,  "MEDIUM"),
    (0.1, 3.9,  "LOW"),
    (0.0, 0.0,  "INFO"),
]

VULN_TYPE_CVSS = {
    "SQL Injection":                              9.8,
    "Command Injection":                          9.8,
    "Default Credentials Accepted":              9.8,
    "Broken Authentication (alg:none":           9.8,
    "Server-Side Request Forgery (SSRF)":        9.0,
    "Broken Authentication":                     9.1,
    "BOLA":                                       8.1,
    "Broken Object Level Authorization":          8.1,
    "Broken Function Level Authorization":        8.0,
    "BFLA":                                       8.0,
    "Cross-Site Scripting (XSS)":               7.2,
    "Excessive Data Exposure":                   7.5,
    "Mass Assignment":                           7.5,
    "Missing Rate Limiting":                     5.3,
    "Unrestricted Resource":                     5.3,
    "Verbose Error Message":                     5.0,
    "Missing Security Header":                   4.3,
    "Improper Inventory Management":             5.3,
    "Information Disclosure via Health":         3.1,
    "Information Disclosure":                    3.1,
}


def get_cvss_score(vuln_type: str, provided_score: float | None = None) -> float:
    """Return CVSS score for a vulnerability type."""
    if provided_score is not None and provided_score > 0:
        return round(provided_score, 1)
    for pattern, score in VULN_TYPE_CVSS.items():
        if pattern.lower() in vuln_type.lower():
            return score
    return 5.0  # default medium


def cvss_to_severity(score: float) -> str:
    """Convert CVSS score to severity label."""
    for low, high, label in CVSS_SEVERITY_RANGES:
        if low <= score <= high:
            return label
    return "INFO"


def calculate_risk_score(findings: list[dict]) -> dict:
    """
    Calculate an aggregate risk score (0–10) from all vulnerability findings.
    Uses a weighted combination of CVSS scores with diminishing returns.
    """
    if not findings:
        return {
            "overall_score": 0.0,
            "security_score": 100.0,
            "risk_level": "INFO",
            "total_vulns": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "cvss_breakdown": [],
        }

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    cvss_scores = []
    breakdown = []

    for f in findings:
        cvss = get_cvss_score(f.get("vuln_type", ""), f.get("cvss_score"))
        sev = cvss_to_severity(cvss)
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        cvss_scores.append(cvss)
        breakdown.append({
            "vuln_type": f.get("vuln_type", "Unknown"),
            "cvss_score": cvss,
            "severity": sev,
            "owasp_category": f.get("owasp_category", "N/A"),
        })

    # Weighted aggregate: highest score anchors, others add diminishing weight
    sorted_scores = sorted(cvss_scores, reverse=True)
    if sorted_scores:
        base = sorted_scores[0]
        additional = sum(s * (0.1 ** (i + 1)) for i, s in enumerate(sorted_scores[1:]))
        raw_score = min(10.0, base + additional)
    else:
        raw_score = 0.0

    # Boost for multiple criticals
    crit = severity_counts["CRITICAL"]
    if crit >= 5:
        raw_score = min(10.0, raw_score + 1.0)
    elif crit >= 3:
        raw_score = min(10.0, raw_score + 0.5)

    overall_score  = round(raw_score, 1)
    security_score = calculate_security_score(overall_score)
    risk_level     = cvss_to_severity(overall_score)

    return {
        "overall_score": overall_score,
        "security_score": security_score,
        "risk_level": risk_level,
        "total_vulns": len(findings),
        "critical_count": severity_counts["CRITICAL"],
        "high_count": severity_counts["HIGH"],
        "medium_count": severity_counts["MEDIUM"],
        "low_count": severity_counts["LOW"],
        "cvss_breakdown": breakdown,
    }


def calculate_security_score(risk_score_0_to_10: float) -> float:
    """
    Convert a 0–10 risk score to a 0–100 Security Score (higher = safer).

    Mapping:
        0.0 risk → 100 security
        9.8 risk → ~0 security
        Uses an inverted, slightly exponential curve for realism.
    """
    risk = max(0.0, min(10.0, risk_score_0_to_10))
    # Linear inversion: security = 100 - (risk/10 * 100)
    # Then apply a slight curve to reward clean APIs more
    raw = 100.0 - (risk * 10.0)
    # Clamp between 0 and 100
    return round(max(0.0, min(100.0, raw)), 1)


def calculate_compliance_score(findings: list[dict], owasp_summary: dict) -> float:
    """
    Measure compliance with OWASP API Security guidance.

    Score = % of OWASP API Top 10 categories that have NO findings.
    A 100% compliance score means no findings in any OWASP category.
    """
    categories = owasp_summary.get("categories", [])
    if not categories:
        return 0.0

    clean_count = sum(1 for c in categories if not c.get("found"))
    total = len(categories)
    return round((clean_count / total) * 100.0, 1) if total > 0 else 0.0


def compare_scans(
    current_findings: list[dict],
    previous_findings: list[dict],
    current_endpoints: list[dict],
    previous_endpoints: list[dict],
    current_risk: dict,
    previous_risk: dict,
) -> dict:
    """
    Trend Analysis: compare current scan results with the previous scan.

    Returns:
        {
          new_issues: int,
          resolved_issues: int,
          increased_risk: bool,
          reduced_risk: bool,
          risk_delta: float,       # positive = worse
          new_endpoints: list[str],
          removed_endpoints: list[str],
          auth_changes: list[dict],
          version_changed: bool,
        }
    """
    curr_vuln_types  = {f.get("vuln_type", "") for f in current_findings}
    prev_vuln_types  = {f.get("vuln_type", "") for f in previous_findings}
    new_vuln_types   = curr_vuln_types - prev_vuln_types
    resolved_types   = prev_vuln_types - curr_vuln_types

    curr_paths = {ep.get("path", "") for ep in current_endpoints}
    prev_paths = {ep.get("path", "") for ep in previous_endpoints}
    new_eps    = sorted(curr_paths - prev_paths)
    removed_eps= sorted(prev_paths - curr_paths)

    # Auth changes: paths that exist in both but changed auth type
    auth_changes = []
    curr_auth_map = {ep.get("path"): ep.get("auth_type") for ep in current_endpoints}
    prev_auth_map = {ep.get("path"): ep.get("auth_type") for ep in previous_endpoints}
    for path in curr_paths & prev_paths:
        curr_auth = curr_auth_map.get(path)
        prev_auth = prev_auth_map.get(path)
        if curr_auth != prev_auth:
            auth_changes.append({
                "path": path,
                "was": prev_auth,
                "now": curr_auth,
            })

    curr_score = current_risk.get("overall_score", 0.0)
    prev_score = previous_risk.get("overall_score", 0.0)
    risk_delta = round(curr_score - prev_score, 1)

    return {
        "new_issues":       len(new_vuln_types),
        "resolved_issues":  len(resolved_types),
        "new_vuln_types":   sorted(new_vuln_types),
        "resolved_types":   sorted(resolved_types),
        "increased_risk":   risk_delta > 0,
        "reduced_risk":     risk_delta < 0,
        "risk_delta":       risk_delta,
        "new_endpoints":    new_eps,
        "removed_endpoints": removed_eps,
        "auth_changes":     auth_changes,
        "version_changed":  False,  # Can be set by caller if versions differ
    }


def prioritize_findings(findings: list[dict]) -> list[dict]:
    """Sort findings by CVSS score descending (highest risk first)."""
    def sort_key(f):
        return get_cvss_score(f.get("vuln_type", ""), f.get("cvss_score"))
    return sorted(findings, key=sort_key, reverse=True)
