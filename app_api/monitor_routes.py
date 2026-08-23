"""
api/monitor_routes.py — Module 4: Continuous Monitoring & Reporting Routes.
"""

from flask import Blueprint, request, jsonify, current_app, send_file
from db.manager import (
    create_schedule, get_all_schedules, toggle_schedule, delete_schedule,
    get_recent_alerts, acknowledge_alert, get_dashboard_stats, get_all_scans,
    get_findings, get_risk_analysis, get_endpoints, get_auth_results,
    get_scan_comparison,
)

monitor_bp = Blueprint("monitor", __name__)


@monitor_bp.route("/schedules", methods=["GET"])
def list_schedules():
    schedules = get_all_schedules()
    return jsonify([s.to_dict() for s in schedules])


@monitor_bp.route("/schedules", methods=["POST"])
def add_schedule():
    from core.monitor import add_monitor_job, SCHEDULE_PRESETS
    data = request.get_json() or {}
    target_url = data.get("target_url", "").strip()
    scan_type  = data.get("scan_type", "full")
    preset     = data.get("schedule_preset", None)

    # Resolve preset to interval
    if preset and preset in SCHEDULE_PRESETS:
        interval = SCHEDULE_PRESETS[preset]
    else:
        interval = int(data.get("interval_minutes", 60))
        preset   = None

    if not target_url:
        return jsonify({"error": "target_url is required"}), 400

    schedule = create_schedule(target_url, scan_type, interval, schedule_preset=preset)
    app = current_app._get_current_object()

    try:
        from app import run_scan_worker, push_event
        add_monitor_job(schedule.id, app, run_scan_worker, push_event)
    except Exception:
        pass

    return jsonify(schedule.to_dict()), 201


@monitor_bp.route("/schedules/<int:schedule_id>", methods=["DELETE"])
def remove_schedule(schedule_id: int):
    from core.monitor import remove_monitor_job
    remove_monitor_job(schedule_id)
    delete_schedule(schedule_id)
    return jsonify({"deleted": True})


@monitor_bp.route("/schedules/<int:schedule_id>/toggle", methods=["POST"])
def toggle_schedule_active(schedule_id: int):
    from core.monitor import add_monitor_job, remove_monitor_job
    data = request.get_json() or {}
    active = data.get("active", True)
    toggle_schedule(schedule_id, active)
    app = current_app._get_current_object()
    if active:
        try:
            from app import run_scan_worker, push_event
            add_monitor_job(schedule_id, app, run_scan_worker, push_event)
        except Exception:
            pass
    else:
        remove_monitor_job(schedule_id)
    return jsonify({"schedule_id": schedule_id, "active": active})


@monitor_bp.route("/alerts", methods=["GET"])
def get_alerts():
    alerts = get_recent_alerts(limit=50)
    return jsonify([a.to_dict() for a in alerts])


@monitor_bp.route("/alerts/<int:alert_id>/acknowledge", methods=["POST"])
def ack_alert(alert_id: int):
    acknowledge_alert(alert_id)
    return jsonify({"acknowledged": True})


@monitor_bp.route("/stats", methods=["GET"])
def dashboard_stats():
    stats = get_dashboard_stats()
    return jsonify(stats)


@monitor_bp.route("/scans", methods=["GET"])
def list_scans():
    scans = get_all_scans(limit=50)
    # Enrich with finding counts and risk scores
    from db.models import VulnFinding, RiskAnalysis
    result = []
    for s in scans:
        d = s.to_dict()
        finding_count = VulnFinding.query.filter_by(session_id=s.id).count()
        analysis = RiskAnalysis.query.filter_by(session_id=s.id)\
                                     .order_by(RiskAnalysis.created_at.desc()).first()
        d["finding_count"]    = finding_count
        d["security_score"]   = analysis.security_score if analysis else None
        d["compliance_score"] = analysis.compliance_score if analysis else None
        d["risk_level"]       = analysis.risk_level if analysis else None
        result.append(d)
    return jsonify(result)


@monitor_bp.route("/changes/<int:session_id>", methods=["GET"])
def get_changes(session_id: int):
    """Return change detection results for a given scan session."""
    comp = get_scan_comparison(session_id)
    if not comp:
        return jsonify({
            "session_id": session_id,
            "message": "No previous scan to compare against",
            "new_endpoints": [],
            "removed_endpoints": [],
            "auth_changes": [],
            "new_vulns": 0,
            "resolved_vulns": 0,
            "risk_delta": 0.0,
        })
    return jsonify(comp.to_dict())


# ── Report Downloads ──────────────────────────────────────────────────────────

def _load_report_data(session_id: int):
    from db.manager import get_scan
    scan     = get_scan(session_id)
    if not scan:
        return None, None, None, None, None
    findings     = get_findings(session_id)
    endpoints    = get_endpoints(session_id)
    analysis     = get_risk_analysis(session_id)
    auth_results = get_auth_results(session_id)
    return (
        scan.to_dict(),
        [ep.to_dict() for ep in endpoints],
        [f.to_dict() for f in findings],
        analysis.to_dict() if analysis else None,
        [a.to_dict() for a in auth_results],
    )


@monitor_bp.route("/report/<int:session_id>/pdf", methods=["GET"])
def download_pdf_report(session_id: int):
    """Generate and download a PDF security report."""
    from reports.pdf_generator import generate_pdf_report
    scan, endpoints, findings, analysis, auth_results = _load_report_data(session_id)
    if not scan:
        return jsonify({"error": "Session not found"}), 404

    pdf_path = generate_pdf_report(
        scan=scan,
        endpoints=endpoints,
        findings=findings,
        auth_results=auth_results,
        analysis=analysis,
    )
    return send_file(
        pdf_path,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"security_report_session_{session_id}.pdf",
    )


@monitor_bp.route("/report/<int:session_id>/html", methods=["GET"])
def download_html_report(session_id: int):
    """Generate and download an HTML security report."""
    from reports.export_generator import generate_html_report
    scan, endpoints, findings, analysis, auth_results = _load_report_data(session_id)
    if not scan:
        return jsonify({"error": "Session not found"}), 404

    html_path = generate_html_report(
        scan=scan,
        endpoints=endpoints,
        findings=findings,
        analysis=analysis,
        auth_results=auth_results,
    )
    return send_file(
        html_path,
        mimetype="text/html",
        as_attachment=True,
        download_name=f"security_report_session_{session_id}.html",
    )


@monitor_bp.route("/report/<int:session_id>/csv", methods=["GET"])
def download_csv_report(session_id: int):
    """Generate and download a CSV findings report."""
    from reports.export_generator import generate_csv_report
    scan, _, findings, _, _ = _load_report_data(session_id)
    if not scan:
        return jsonify({"error": "Session not found"}), 404

    csv_path = generate_csv_report(scan=scan, findings=findings)
    return send_file(
        csv_path,
        mimetype="text/csv",
        as_attachment=True,
        download_name=f"security_report_session_{session_id}.csv",
    )


@monitor_bp.route("/report/<int:session_id>/json", methods=["GET"])
def download_json_report(session_id: int):
    """Generate and download a JSON security report."""
    from reports.export_generator import generate_json_report
    scan, endpoints, findings, analysis, auth_results = _load_report_data(session_id)
    if not scan:
        return jsonify({"error": "Session not found"}), 404

    json_path = generate_json_report(
        scan=scan,
        endpoints=endpoints,
        findings=findings,
        analysis=analysis,
        auth_results=auth_results,
    )
    return send_file(
        json_path,
        mimetype="application/json",
        as_attachment=True,
        download_name=f"security_report_session_{session_id}.json",
    )
