"""
api/analysis_routes.py — Module 3: AI Risk Analysis & Recommendations Routes.
"""

from flask import Blueprint, request, jsonify
from db.manager import (
    get_findings, get_scan, save_risk_analysis, get_risk_analysis,
    get_auth_results, get_endpoints, get_scans_for_url, get_scan_comparison,
)

analysis_bp = Blueprint("analysis", __name__)


@analysis_bp.route("/<int:session_id>/analyze", methods=["POST"])
def run_analysis(session_id: int):
    """Run risk analysis on a completed scan session."""
    from core.risk_engine import calculate_risk_score, prioritize_findings, calculate_compliance_score, compare_scans
    from core.ai_advisor import generate_ai_recommendations, generate_compliance_report
    from core.owasp_checker import enrich_findings, generate_owasp_summary

    scan = get_scan(session_id)
    if not scan:
        return jsonify({"error": "Session not found"}), 404

    findings_records = get_findings(session_id)
    auth_records     = get_auth_results(session_id)

    all_findings = [f.to_dict() for f in findings_records]

    for ar in auth_records:
        if not ar.passed:
            all_findings.append({
                "vuln_type": ar.test_name,
                "severity": ar.severity or "MEDIUM",
                "cvss_score": None,
                "owasp_category": "API2",
                "path": "auth",
            })

    risk_data        = calculate_risk_score(all_findings)
    enriched         = enrich_findings(all_findings)
    owasp            = generate_owasp_summary(enriched)
    compliance_score = calculate_compliance_score(all_findings, owasp)
    recs             = generate_ai_recommendations(all_findings, risk_data)
    comp_report      = generate_compliance_report(all_findings, owasp)
    prioritized      = prioritize_findings(all_findings)

    # Trend analysis vs previous scan for same URL
    trend = {}
    try:
        prev_scans = get_scans_for_url(scan.target_url)
        prev_scan  = next(
            (s for s in prev_scans if s.id != session_id and s.status == "COMPLETED"),
            None,
        )
        if prev_scan:
            prev_findings  = [f.to_dict() for f in get_findings(prev_scan.id)]
            prev_endpoints = [e.to_dict() for e in get_endpoints(prev_scan.id)]
            curr_endpoints = [e.to_dict() for e in get_endpoints(session_id)]
            prev_risk      = calculate_risk_score(prev_findings)
            trend = compare_scans(
                all_findings, prev_findings,
                curr_endpoints, prev_endpoints,
                risk_data, prev_risk,
            )
            trend["previous_session_id"] = prev_scan.id
    except Exception:
        pass

    # Save enriched analysis to DB
    save_risk_analysis(session_id, {
        "overall_score":     risk_data["overall_score"],
        "security_score":    risk_data.get("security_score", 100.0),
        "compliance_score":  compliance_score,
        "risk_level":        risk_data["risk_level"],
        "total_vulns":       risk_data["total_vulns"],
        "critical_count":    risk_data["critical_count"],
        "high_count":        risk_data["high_count"],
        "medium_count":      risk_data["medium_count"],
        "low_count":         risk_data["low_count"],
        "summary":           recs.get("summary", ""),
        "recommendations":   (
            recs.get("specific_recommendations", []) +
            recs.get("general_recommendations", [])
        ),
        "trend":             trend,
        "owasp_coverage":    owasp.get("categories", []),
    })

    return jsonify({
        "session_id":         session_id,
        "risk":               {**risk_data, "security_score": risk_data.get("security_score", 100.0)},
        "recommendations":    recs,
        "owasp_summary":      owasp,
        "compliance_report":  comp_report,
        "compliance_score":   compliance_score,
        "trend":              trend,
        "prioritized_findings": prioritized[:20],
    })


@analysis_bp.route("/<int:session_id>/report", methods=["GET"])
def get_analysis_report(session_id: int):
    """Get the saved risk analysis for a session."""
    analysis = get_risk_analysis(session_id)
    if not analysis:
        return jsonify({"error": "No analysis found. Run /analyze first."}), 404
    return jsonify(analysis.to_dict())


@analysis_bp.route("/<int:session_id>/score", methods=["GET"])
def get_risk_score(session_id: int):
    """Quick risk score lookup for dashboard widgets."""
    analysis = get_risk_analysis(session_id)
    if not analysis:
        return jsonify({"score": 0, "level": "INFO"})
    return jsonify({
        "score": analysis.overall_score,
        "security_score": analysis.security_score,
        "compliance_score": analysis.compliance_score,
        "level": analysis.risk_level,
        "total_vulns": analysis.total_vulns,
    })


@analysis_bp.route("/<int:session_id>/compliance", methods=["GET"])
def get_compliance_report(session_id: int):
    """Return a per-OWASP-category compliance report for a session."""
    from core.ai_advisor import generate_compliance_report
    from core.owasp_checker import enrich_findings, generate_owasp_summary

    findings_records = get_findings(session_id)
    all_findings     = [f.to_dict() for f in findings_records]
    enriched         = enrich_findings(all_findings)
    owasp            = generate_owasp_summary(enriched)
    report           = generate_compliance_report(all_findings, owasp)
    return jsonify(report)


@analysis_bp.route("/<int:session_id>/trend", methods=["GET"])
def get_trend(session_id: int):
    """Return trend analysis comparing this session with the previous scan for the same URL."""
    scan = get_scan(session_id)
    if not scan:
        return jsonify({"error": "Session not found"}), 404

    comp = get_scan_comparison(session_id)
    if comp:
        return jsonify(comp.to_dict())

    return jsonify({
        "session_id": session_id,
        "message": "No previous scan found for comparison",
        "new_endpoints": [],
        "removed_endpoints": [],
        "auth_changes": [],
        "new_vulns": 0,
        "resolved_vulns": 0,
        "risk_delta": 0.0,
    })
