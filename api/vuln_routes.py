"""
api/vuln_routes.py — Module 2: Vulnerability Assessment Routes.
"""

import threading
from flask import Blueprint, request, jsonify, current_app
from db.manager import (
    create_scan, update_scan_status, add_log,
    save_endpoint, save_finding, get_findings, get_endpoints, get_scan
)

vuln_bp = Blueprint("vuln", __name__)


def _run_vuln_worker(app, session_id: int, target_url: str, endpoints: list[dict]):
    from core.vuln_scanner import run_vuln_scan
    from core.owasp_checker import enrich_findings, generate_owasp_summary

    def log(msg, level="INFO"):
        with app.app_context():
            add_log(session_id, msg, level)
        app.push_event(session_id, {"type": "log", "level": level, "message": msg})

    with app.app_context():
        try:
            update_scan_status(session_id, "RUNNING")
            app.push_event(session_id, {"type": "status", "status": "RUNNING"})

            log(f"Starting vulnerability scan on {target_url}")
            findings = run_vuln_scan(target_url, endpoints, callback=log)

            # Enrich with OWASP categories
            enriched = enrich_findings(findings)
            owasp_summary = generate_owasp_summary(enriched)

            # Save findings
            for f in enriched:
                save_finding(session_id, f)

            critical = sum(1 for f in enriched if f.get("severity") == "CRITICAL")
            high     = sum(1 for f in enriched if f.get("severity") == "HIGH")

            app.push_event(session_id, {
                "type": "vuln_complete",
                "total_findings": len(enriched),
                "critical": critical,
                "high": high,
                "owasp_coverage": owasp_summary.get("coverage_pct", 0),
            })
            log(f"Scan complete: {len(enriched)} findings ({critical} Critical, {high} High)", "SUCCESS")

            update_scan_status(session_id, "COMPLETED")
            app.push_event(session_id, {"type": "status", "status": "COMPLETED"})

        except Exception as exc:
            import traceback
            log(f"Scan failed: {exc}", "ERROR")
            log(traceback.format_exc(), "ERROR")
            update_scan_status(session_id, "FAILED", error_msg=str(exc))
            app.push_event(session_id, {"type": "status", "status": "FAILED", "error": str(exc)})


@vuln_bp.route("/start", methods=["POST"])
def start_vuln_scan():
    data = request.get_json() or {}
    target_url   = (data.get("target_url") or "").strip()
    session_id   = data.get("session_id")   # reuse discovery session
    endpoint_list = data.get("endpoints", [])

    if not target_url:
        return jsonify({"error": "target_url is required"}), 400

    if session_id:
        # Fetch endpoints from existing discovery session
        existing = get_endpoints(session_id)
        endpoints = [ep.to_dict() for ep in existing]
        scan_session = get_scan(session_id)
        if scan_session:
            update_scan_status(session_id, "PENDING")
    else:
        scan_session = create_scan(target_url, scan_type="vuln")
        session_id = scan_session.id
        endpoints = endpoint_list

    app = current_app._get_current_object()
    t = threading.Thread(
        target=_run_vuln_worker,
        args=(app, session_id, target_url, endpoints),
        daemon=True,
    )
    t.start()

    return jsonify({"session_id": session_id, "status": "STARTED"}), 202


@vuln_bp.route("/<int:session_id>/findings", methods=["GET"])
def get_session_findings(session_id: int):
    findings = get_findings(session_id)
    return jsonify([f.to_dict() for f in findings])


@vuln_bp.route("/<int:session_id>/owasp", methods=["GET"])
def get_owasp_summary(session_id: int):
    from core.owasp_checker import generate_owasp_summary
    findings = get_findings(session_id)
    f_dicts = [f.to_dict() for f in findings]
    return jsonify(generate_owasp_summary(f_dicts))


@vuln_bp.route("/<int:session_id>/status", methods=["GET"])
def get_vuln_status(session_id: int):
    scan = get_scan(session_id)
    if not scan:
        return jsonify({"error": "Session not found"}), 404
    return jsonify(scan.to_dict())
