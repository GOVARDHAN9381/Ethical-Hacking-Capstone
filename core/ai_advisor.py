"""
core/ai_advisor.py — Module 3: AI-Based (Rule-Based) Remediation Recommendations.
Optionally uses OpenAI GPT if OPENAI_API_KEY is configured.
Includes compliance report generation and priority ranking.
"""

import json
from config import USE_AI_RECOMMENDATIONS, OPENAI_API_KEY


# ── Rule-Based Recommendation Knowledge Base ──────────────────────────────────

REMEDIATION_KB = {
    "SQL Injection": {
        "title": "Eliminate SQL Injection",
        "priority": 1,
        "steps": [
            "Use parameterized queries or ORM (e.g., SQLAlchemy) instead of string concatenation",
            "Apply input validation and type checking on all user-supplied data",
            "Implement a Web Application Firewall (WAF) as a secondary defense layer",
            "Apply the principle of least privilege to database accounts",
            "Enable database-level logging and anomaly detection",
        ],
        "references": ["OWASP SQL Injection Prevention", "CWE-89"],
        "effort": "Medium",
        "impact": "Critical",
    },
    "Cross-Site Scripting (XSS)": {
        "title": "Prevent Cross-Site Scripting",
        "priority": 2,
        "steps": [
            "HTML-encode all user-supplied output before rendering",
            "Use a Content Security Policy (CSP) header to restrict script sources",
            "Sanitize input with a server-side library (e.g., bleach for Python)",
            "Set HttpOnly and Secure flags on all cookies",
            "Use the X-XSS-Protection header as a browser-level defense",
        ],
        "references": ["OWASP XSS Prevention Cheat Sheet", "CWE-79"],
        "effort": "Low",
        "impact": "High",
    },
    "Broken Authentication": {
        "title": "Fix Broken Authentication",
        "priority": 1,
        "steps": [
            "Enforce JWT signature validation — never accept alg:none tokens",
            "Implement token expiry (short-lived access tokens, long-lived refresh tokens)",
            "Add account lockout after N failed login attempts",
            "Use multi-factor authentication (MFA) for sensitive operations",
            "Rotate API keys and tokens regularly; invalidate on logout",
            "Log all authentication events and alert on anomalies",
        ],
        "references": ["OWASP Authentication Cheat Sheet", "CWE-287"],
        "effort": "Medium",
        "impact": "Critical",
    },
    "Default Credentials Accepted": {
        "title": "Remove Default Credentials",
        "priority": 1,
        "steps": [
            "Remove all default usernames and passwords before deployment",
            "Force password change on first login for any seeded accounts",
            "Implement a strong password policy (length, complexity, history)",
            "Use a secrets manager (e.g., HashiCorp Vault) for all credentials",
        ],
        "references": ["OWASP Authentication Cheat Sheet", "CWE-1392"],
        "effort": "Low",
        "impact": "Critical",
    },
    "BOLA": {
        "title": "Fix Broken Object Level Authorization (BOLA/IDOR)",
        "priority": 1,
        "steps": [
            "Validate that the authenticated user owns the requested resource on every request",
            "Never rely solely on object IDs in URLs — verify ownership server-side",
            "Use non-sequential, unpredictable IDs (e.g., UUIDs) to reduce guessability",
            "Implement row-level security in the database layer",
            "Write automated tests that verify cross-user access is denied",
        ],
        "references": ["OWASP BOLA", "CWE-639"],
        "effort": "Medium",
        "impact": "High",
    },
    "Broken Object Level Authorization": {
        "title": "Fix Broken Object Level Authorization (BOLA/IDOR)",
        "priority": 1,
        "steps": [
            "Validate that the authenticated user owns the requested resource on every request",
            "Never rely solely on object IDs in URLs — verify ownership server-side",
            "Use non-sequential, unpredictable IDs (e.g., UUIDs) to reduce guessability",
            "Implement row-level security in the database layer",
            "Write automated tests that verify cross-user access is denied",
        ],
        "references": ["OWASP BOLA", "CWE-639"],
        "effort": "Medium",
        "impact": "High",
    },
    "BFLA": {
        "title": "Fix Broken Function Level Authorization (BFLA)",
        "priority": 1,
        "steps": [
            "Enforce role-based access control (RBAC) on every administrative endpoint",
            "Check the caller's role on every request, not just at login time",
            "Deny by default — require explicit permission grants for all sensitive functions",
            "Audit all admin-level functions to ensure non-admin accounts cannot reach them",
            "Use middleware or decorators to enforce function-level authorization consistently",
        ],
        "references": ["OWASP BFLA", "CWE-285"],
        "effort": "Medium",
        "impact": "High",
    },
    "Broken Function Level Authorization": {
        "title": "Fix Broken Function Level Authorization (BFLA)",
        "priority": 1,
        "steps": [
            "Enforce role-based access control (RBAC) on every administrative endpoint",
            "Check the caller's role on every request, not just at login time",
            "Deny by default — require explicit permission grants for all sensitive functions",
            "Audit all admin-level functions to ensure non-admin accounts cannot reach them",
            "Use middleware or decorators to enforce function-level authorization consistently",
        ],
        "references": ["OWASP BFLA", "CWE-285"],
        "effort": "Medium",
        "impact": "High",
    },
    "Excessive Data Exposure": {
        "title": "Reduce Excessive Data Exposure",
        "priority": 1,
        "steps": [
            "Apply response field filtering — only return fields the client actually needs",
            "Define explicit response DTOs/serializers with allowlists, not blocklists",
            "Never expose password hashes, API keys, SSNs, or financial data in API responses",
            "Use field-level encryption for sensitive attributes stored in the database",
            "Audit all API responses and remove unnecessary sensitive fields",
        ],
        "references": ["OWASP Excessive Data Exposure", "CWE-200"],
        "effort": "Medium",
        "impact": "High",
    },
    "Server-Side Request Forgery": {
        "title": "Prevent Server-Side Request Forgery (SSRF)",
        "priority": 1,
        "steps": [
            "Validate and allowlist all user-supplied URLs before fetching",
            "Disable unnecessary URL-fetching features in your API",
            "Use a DNS-based SSRF filter to block internal/cloud metadata IPs",
            "Never allow user input to control the Host header or target URL",
            "Enforce strict network egress rules — APIs should not make arbitrary outbound requests",
        ],
        "references": ["OWASP SSRF Prevention", "CWE-918"],
        "effort": "Medium",
        "impact": "Critical",
    },
    "Command Injection": {
        "title": "Prevent Command Injection",
        "priority": 1,
        "steps": [
            "Never pass user input to system shell commands (os.system, subprocess with shell=True)",
            "Use safe APIs with arguments passed as lists, not strings",
            "Validate and sanitize all inputs with strict allowlists",
            "Run application processes with minimal OS privileges",
            "Implement a WAF with signature-based command injection detection",
        ],
        "references": ["OWASP Command Injection Prevention", "CWE-77"],
        "effort": "Low",
        "impact": "Critical",
    },
    "Improper Inventory": {
        "title": "Fix Improper API Inventory Management",
        "priority": 2,
        "steps": [
            "Decommission old API versions — return 410 Gone for deprecated endpoints",
            "Maintain an up-to-date API inventory with version, owner, and status fields",
            "Use a versioning strategy (URL versioning or header versioning) consistently",
            "Remove debug/beta endpoints from production deployments",
            "Automate API discovery scans to detect undocumented endpoints",
        ],
        "references": ["OWASP API9", "CWE-1059"],
        "effort": "Medium",
        "impact": "Medium",
    },
    "Mass Assignment": {
        "title": "Prevent Mass Assignment",
        "priority": 2,
        "steps": [
            "Use explicit allowlist serializers — never auto-bind all request fields",
            "Define separate DTOs/schemas for create, update, and response",
            "Mark sensitive fields (is_admin, role, balance) as read-only in your ORM",
            "Validate the shape and types of all incoming data strictly",
        ],
        "references": ["OWASP Mass Assignment", "CWE-915"],
        "effort": "Low",
        "impact": "High",
    },
    "Missing Rate Limiting": {
        "title": "Implement Rate Limiting",
        "priority": 2,
        "steps": [
            "Apply rate limits per IP and per authenticated user on all endpoints",
            "Use Flask-Limiter or API Gateway rate limiting rules",
            "Return proper 429 Too Many Requests responses with Retry-After headers",
            "Implement exponential back-off on repeated failures",
            "Monitor for unusual traffic spikes and set alerts",
        ],
        "references": ["OWASP API4", "RFC 6585"],
        "effort": "Low",
        "impact": "Medium",
    },
    "Missing Security Header": {
        "title": "Add Missing Security Headers",
        "priority": 3,
        "steps": [
            "Add X-Content-Type-Options: nosniff to all responses",
            "Add X-Frame-Options: DENY to prevent clickjacking",
            "Add Strict-Transport-Security with a long max-age (≥1 year)",
            "Implement a strict Content-Security-Policy",
            "Remove or obscure Server and X-Powered-By headers",
        ],
        "references": ["OWASP Secure Headers Project", "MDN Security Headers"],
        "effort": "Low",
        "impact": "Medium",
    },
    "Information Disclosure": {
        "title": "Reduce Information Disclosure",
        "priority": 3,
        "steps": [
            "Suppress detailed error messages in production (stack traces, SQL errors)",
            "Remove or obscure Server, X-Powered-By, X-AspNet-Version headers",
            "Avoid exposing internal paths, library versions, or infrastructure details",
            "Return generic error messages to clients; log full details server-side",
        ],
        "references": ["OWASP Information Exposure", "CWE-200"],
        "effort": "Low",
        "impact": "Low",
    },
    "Verbose Error Message": {
        "title": "Suppress Verbose Error Messages",
        "priority": 3,
        "steps": [
            "Configure production error handlers to return generic messages",
            "Never expose stack traces, line numbers, or file paths to API consumers",
            "Use structured logging (ELK, Datadog) to capture full errors server-side",
            "Implement a global exception handler that sanitizes all error responses",
        ],
        "references": ["OWASP Error Handling", "CWE-209"],
        "effort": "Low",
        "impact": "Medium",
    },
}

GENERAL_RECOMMENDATIONS = [
    {
        "title": "Implement API Authentication Centrally",
        "detail": "Use a single auth middleware or gateway to enforce authentication uniformly across all routes.",
        "priority": 1,
    },
    {
        "title": "Enable HTTPS Only",
        "detail": "Redirect all HTTP traffic to HTTPS. Use TLS 1.2+ with strong cipher suites.",
        "priority": 1,
    },
    {
        "title": "Adopt a Zero-Trust Architecture",
        "detail": "Treat every request as untrusted. Validate, authenticate, and authorize every API call.",
        "priority": 2,
    },
    {
        "title": "Maintain an API Inventory",
        "detail": "Keep an up-to-date registry of all API endpoints, their owners, versions, and exposure levels.",
        "priority": 3,
    },
    {
        "title": "Automate Security Testing in CI/CD",
        "detail": "Integrate DAST/SAST tools into your pipeline so vulnerabilities are caught before deployment.",
        "priority": 2,
    },
]


def generate_recommendations(findings: list[dict], risk_score: dict) -> dict:
    """Generate prioritized remediation recommendations from vulnerability findings."""
    seen_types = set()
    specific_recs = []

    for f in findings:
        vuln_type = f.get("vuln_type", "")
        matched_key = None
        for kb_key in REMEDIATION_KB:
            if kb_key.lower() in vuln_type.lower() or vuln_type.lower() in kb_key.lower():
                matched_key = kb_key
                break
        if matched_key and matched_key not in seen_types:
            seen_types.add(matched_key)
            rec = dict(REMEDIATION_KB[matched_key])
            rec["applies_to"] = vuln_type
            specific_recs.append(rec)

    specific_recs.sort(key=lambda x: x.get("priority", 99))

    risk_level = risk_score.get("risk_level", "INFO")
    score      = risk_score.get("overall_score", 0)
    crit       = risk_score.get("critical_count", 0)
    high       = risk_score.get("high_count", 0)
    total      = risk_score.get("total_vulns", 0)
    sec_score  = risk_score.get("security_score", 100.0)

    summary_parts = [
        f"Security Score: {sec_score}/100 | Risk Score: {score}/10 ({risk_level}).",
        f"Found {total} vulnerabilities: {crit} Critical, {high} High.",
    ]
    if risk_level == "CRITICAL":
        summary_parts.append("⚠️ Immediate remediation required before any production deployment.")
    elif risk_level == "HIGH":
        summary_parts.append("Urgent action recommended. Address Critical and High findings within 72 hours.")
    elif risk_level == "MEDIUM":
        summary_parts.append("Schedule remediation for all Medium and above findings within 30 days.")
    else:
        summary_parts.append("Good security posture. Review Low and Informational findings in next sprint.")

    return {
        "summary": " ".join(summary_parts),
        "specific_recommendations": specific_recs,
        "general_recommendations": GENERAL_RECOMMENDATIONS,
        "total_recommendations": len(specific_recs) + len(GENERAL_RECOMMENDATIONS),
        "priority_ranking": {
            "critical": crit,
            "high": high,
            "medium": risk_score.get("medium_count", 0),
            "low": risk_score.get("low_count", 0),
        },
    }


def generate_compliance_report(findings: list[dict], owasp_summary: dict) -> dict:
    """
    Generate a per-OWASP-category compliance report.

    Returns:
        {
          "categories": [{"category": "API1", "name": "...", "status": "PASS"|"FAIL", "severity": str, "count": int}],
          "compliance_score": float (0-100),
          "passed": int,
          "failed": int,
        }
    """
    from config import OWASP_API_TOP10
    categories = owasp_summary.get("categories", [])
    report_cats = []
    passed = 0
    failed = 0
    for cat in categories:
        status = "FAIL" if cat.get("found") else "PASS"
        if status == "PASS":
            passed += 1
        else:
            failed += 1
        report_cats.append({
            "category": cat["category"],
            "name": cat["name"],
            "status": status,
            "severity": cat.get("severity"),
            "count": cat.get("count", 0),
        })

    total = passed + failed
    score = round((passed / total) * 100.0, 1) if total > 0 else 0.0
    return {
        "categories": report_cats,
        "compliance_score": score,
        "passed": passed,
        "failed": failed,
    }


def generate_ai_recommendations(findings: list[dict], risk_score: dict) -> dict:
    """
    Use OpenAI GPT for recommendations if API key is set, else fall back to rule-based.
    """
    if not USE_AI_RECOMMENDATIONS or not OPENAI_API_KEY:
        return generate_recommendations(findings, risk_score)

    try:
        import requests as req
        vuln_summary = [
            {"type": f.get("vuln_type"), "severity": f.get("severity"), "path": f.get("path")}
            for f in findings[:10]
        ]
        prompt = (
            f"You are a cybersecurity expert. Analyze these API vulnerabilities and provide "
            f"specific, actionable remediation advice:\n{json.dumps(vuln_summary, indent=2)}\n"
            f"Risk Score: {risk_score.get('overall_score')}/10. "
            f"Security Score: {risk_score.get('security_score', 'N/A')}/100. "
            f"Provide 5 prioritized recommendations in JSON format with fields: "
            f"title, steps (list), effort (Low/Medium/High), impact (Low/Medium/High/Critical)."
        )

        response = req.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {OPENAI_API_KEY}", "Content-Type": "application/json"},
            json={"model": "gpt-3.5-turbo", "messages": [{"role": "user", "content": prompt}],
                  "temperature": 0.3, "max_tokens": 1000},
            timeout=30,
        )
        if response.status_code == 200:
            content = response.json()["choices"][0]["message"]["content"]
            try:
                start = content.find("[")
                end = content.rfind("]") + 1
                ai_recs = json.loads(content[start:end])
                base = generate_recommendations(findings, risk_score)
                base["ai_recommendations"] = ai_recs
                base["used_ai"] = True
                return base
            except Exception:
                pass
    except Exception:
        pass

    return generate_recommendations(findings, risk_score)
