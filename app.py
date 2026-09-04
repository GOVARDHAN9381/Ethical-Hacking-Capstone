"""
app.py — Flask application factory for the Intelligent API Security Testing Platform (APIAST).
Provides REST API, SSE scan streaming, and the web dashboard.
"""

import threading
import time
import queue
import json
from datetime import datetime
from flask import Flask, Response, stream_with_context, render_template

import config
from db.models import db
from db.manager import init_db, create_scan, update_scan_status, add_log


# ── Global SSE event queues (session_id → list of Queue objects) ────────────
_sse_listeners: dict[int, list[queue.Queue]] = {}
_sse_lock = threading.Lock()


def push_event(session_id: int, data: dict):
    """Broadcast a JSON event to all SSE listeners for a given session."""
    with _sse_lock:
        queues = _sse_listeners.get(session_id, [])
        for q in queues:
            try:
                q.put_nowait(data)
            except queue.Full:
                pass


def subscribe(session_id: int) -> queue.Queue:
    q: queue.Queue = queue.Queue(maxsize=500)
    with _sse_lock:
        _sse_listeners.setdefault(session_id, []).append(q)
    return q


def unsubscribe(session_id: int, q: queue.Queue):
    with _sse_lock:
        lst = _sse_listeners.get(session_id, [])
        if q in lst:
            lst.remove(q)


# ── Full Scan Worker (all 4 modules) ──────────────────────────────────────────

def run_scan_worker(app, session_id: int, target_url: str, scan_type: str = "full"):
    """Full 4-module scan pipeline executed in a background thread."""
    from core.api_discovery import discover_endpoints
    from core.auth_tester import run_auth_tests
    from core.vuln_scanner import run_vuln_scan
    from core.owasp_checker import enrich_findings, generate_owasp_summary
    from core.risk_engine import calculate_risk_score, prioritize_findings, calculate_compliance_score
    from core.ai_advisor import generate_ai_recommendations, generate_compliance_report
    from core.endpoint_classifier import classify_endpoints, build_api_inventory
    from db.manager import (
        save_endpoint, save_auth_result, save_finding,
        save_risk_analysis, get_endpoints, save_api_inventory,
    )

    def log(msg, level="INFO"):
        with app.app_context():
            add_log(session_id, msg, level)
        push_event(session_id, {"type": "log", "level": level, "message": msg,
                                  "ts": datetime.utcnow().isoformat()})

    with app.app_context():
        try:
            update_scan_status(session_id, "RUNNING")
            push_event(session_id, {"type": "status", "status": "RUNNING"})

            # ── Module 1: API Discovery ────────────────────────────────────
            log(f"[Module 1] Starting API discovery on {target_url}")
            discovery = discover_endpoints(target_url, callback=log)
            raw_endpoints = discovery.get("all_endpoints", [])

            # Classify endpoints
            log("[Module 1] Classifying endpoints...")
            endpoints = classify_endpoints(raw_endpoints)

            endpoint_records = []
            for ep_data in endpoints:
                rec = save_endpoint(session_id, ep_data)
                endpoint_records.append(rec)

            # Build API inventory
            spec_info = None
            if discovery.get("swagger_found"):
                # Try to extract spec info for inventory
                spec_info = {"title": None, "version": None}

            inventory_data = build_api_inventory(target_url, endpoints, spec_info)
            inventory_data["swagger_url"] = (
                target_url.rstrip("/") + "/openapi.json"
                if discovery.get("swagger_found") else None
            )
            save_api_inventory(session_id, inventory_data)

            # Compute classification breakdown
            from core.endpoint_classifier import get_classification_summary
            class_summary = get_classification_summary(endpoints)

            push_event(session_id, {
                "type": "discovery_complete",
                "endpoint_count": len(endpoints),
                "swagger_found": discovery.get("swagger_found", False),
                "classification": class_summary,
                "api_name": inventory_data.get("api_name"),
                "api_version": inventory_data.get("version"),
            })
            log(f"[Module 1] Discovery complete: {len(endpoints)} endpoints found", "SUCCESS")

            # Auth testing
            log("[Module 1] Running authentication tests...")
            auth_results = run_auth_tests(target_url, endpoints, callback=log)
            for result in auth_results:
                save_auth_result(session_id, result)
            auth_vulns = sum(1 for r in auth_results if not r.get("passed"))
            push_event(session_id, {
                "type": "auth_complete",
                "total_checks": len(auth_results),
                "vulnerabilities": auth_vulns,
            })
            log(f"[Module 1] Auth tests complete: {auth_vulns} issues", "SUCCESS")

            # ── Module 2: Vulnerability Assessment ────────────────────────
            if scan_type in ("full", "vuln"):
                log("[Module 2] Starting vulnerability assessment...")
                findings = run_vuln_scan(target_url, endpoints, callback=log)
                enriched = enrich_findings(findings)
                owasp_summary = generate_owasp_summary(enriched)

                for f in enriched:
                    save_finding(session_id, f)

                crit = sum(1 for f in enriched if f.get("severity") == "CRITICAL")
                high = sum(1 for f in enriched if f.get("severity") == "HIGH")
                push_event(session_id, {
                    "type": "vuln_complete",
                    "total_findings": len(enriched),
                    "critical": crit,
                    "high": high,
                    "owasp_coverage": owasp_summary.get("coverage_pct", 0),
                    "owasp_categories": owasp_summary.get("categories", []),
                })
                log(f"[Module 2] Scan complete: {len(enriched)} findings ({crit} Critical, {high} High)", "SUCCESS")

                # ── Module 3: Risk Analysis ────────────────────────────────
                log("[Module 3] Running AI risk analysis...")
                all_findings_for_risk = list(enriched)
                for ar in auth_results:
                    if not ar.get("passed"):
                        all_findings_for_risk.append({
                            "vuln_type": ar.get("test_name", "Auth Issue"),
                            "severity": ar.get("severity", "MEDIUM"),
                            "cvss_score": None,
                            "owasp_category": "API2",
                        })

                risk_data       = calculate_risk_score(all_findings_for_risk)
                compliance_score= calculate_compliance_score(all_findings_for_risk, owasp_summary)
                recs            = generate_ai_recommendations(all_findings_for_risk, risk_data)
                comp_report     = generate_compliance_report(all_findings_for_risk, owasp_summary)

                save_risk_analysis(session_id, {
                    **risk_data,
                    "compliance_score": compliance_score,
                    "summary": recs.get("summary", ""),
                    "recommendations": (
                        recs.get("specific_recommendations", []) +
                        recs.get("general_recommendations", [])
                    ),
                    "owasp_coverage": owasp_summary.get("categories", []),
                })

                push_event(session_id, {
                    "type": "analysis_complete",
                    "overall_score": risk_data["overall_score"],
                    "security_score": risk_data["security_score"],
                    "compliance_score": compliance_score,
                    "risk_level": risk_data["risk_level"],
                    "priority_ranking": recs.get("priority_ranking", {}),
                })
                log(
                    f"[Module 3] Security Score: {risk_data['security_score']}/100 | "
                    f"Risk: {risk_data['overall_score']}/10 ({risk_data['risk_level']}) | "
                    f"Compliance: {compliance_score}%",
                    "SUCCESS",
                )

            update_scan_status(session_id, "COMPLETED")
            log("Scan pipeline completed successfully. ✔", "SUCCESS")
            push_event(session_id, {"type": "status", "status": "COMPLETED"})

            # ── Module 4: Change Detection ────────────────────────────────
            try:
                from core.monitor import run_change_detection
                run_change_detection(app, session_id, target_url)
            except Exception:
                pass  # Change detection is best-effort

        except Exception as exc:
            import traceback
            tb = traceback.format_exc()
            log(f"Scan failed: {exc}", "ERROR")
            log(tb, "ERROR")
            update_scan_status(session_id, "FAILED", error_msg=str(exc))
            push_event(session_id, {"type": "status", "status": "FAILED", "error": str(exc)})


# ── Application Factory ────────────────────────────────────────────────────────

def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")

    # Configuration
    app.config["SECRET_KEY"]                = config.SECRET_KEY
    app.config["SQLALCHEMY_DATABASE_URI"]   = config.SQLALCHEMY_DATABASE_URI
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = config.SQLALCHEMY_TRACK_MODIFICATIONS

    # Initialize DB
    init_db(app)

    # Expose helpers on app object for blueprints
    app.push_event = push_event
    app.run_scan_worker = run_scan_worker

    # Register Blueprints
    from app_api.discovery_routes import discovery_bp
    from app_api.vuln_routes       import vuln_bp
    from app_api.analysis_routes   import analysis_bp
    from app_api.monitor_routes    import monitor_bp
    from app_api.dashboard_routes  import dashboard_bp
    from vulnerable_api.app        import vuln_target_bp

    app.register_blueprint(discovery_bp,  url_prefix="/api/discovery")
    app.register_blueprint(vuln_bp,        url_prefix="/api/vuln")
    app.register_blueprint(analysis_bp,    url_prefix="/api/analysis")
    app.register_blueprint(monitor_bp,     url_prefix="/api/monitor")
    app.register_blueprint(dashboard_bp,   url_prefix="/api/dashboard")
    app.register_blueprint(vuln_target_bp, url_prefix="/vuln-api")

    # ── SSE Stream Endpoint ─────────────────────────────────────────────────
    @app.route("/api/scan/<int:session_id>/stream")
    def scan_stream(session_id: int):
        """Server-Sent Events stream for live scan output."""
        q = subscribe(session_id)

        def generate():
            try:
                import os
                from db.models import ScanLog
                from db.manager import get_scan
                
                is_vercel = os.environ.get("VERCEL") == "1"
                scan_record = None
                with app.app_context():
                    scan_record = get_scan(session_id)
                
                # On Vercel, the actual scan execution is initiated in the SSE stream
                # to prevent Vercel from killing the background worker thread.
                if is_vercel and scan_record and scan_record.status == "PENDING":
                    if scan_record.scan_type == "discovery":
                        from app_api.discovery_routes import _run_discovery_worker
                        t = threading.Thread(
                            target=_run_discovery_worker,
                            args=(app, session_id, scan_record.target_url, None),
                            daemon=True,
                        )
                    elif scan_record.scan_type == "vuln":
                        from db.manager import get_endpoints
                        with app.app_context():
                            existing_eps = get_endpoints(session_id)
                        if existing_eps:
                            from app_api.vuln_routes import _run_vuln_worker
                            endpoints_list = [ep.to_dict() for ep in existing_eps]
                            t = threading.Thread(
                                target=_run_vuln_worker,
                                args=(app, session_id, scan_record.target_url, endpoints_list),
                                daemon=True,
                            )
                        else:
                            t = threading.Thread(
                                target=run_scan_worker,
                                args=(app, session_id, scan_record.target_url, "vuln"),
                                daemon=True,
                            )
                    else:
                        t = threading.Thread(
                            target=run_scan_worker,
                            args=(app, session_id, scan_record.target_url, scan_record.scan_type),
                            daemon=True,
                        )
                    t.start()


                with app.app_context():
                    logs = ScanLog.query.filter_by(session_id=session_id)\
                                        .order_by(ScanLog.timestamp).all()
                    for log_entry in logs:
                        payload = json.dumps({
                            "type": "log",
                            "message": log_entry.message,
                            "level": log_entry.level,
                            "ts": log_entry.timestamp.isoformat(),
                        })
                        yield f"data: {payload}\n\n"

                while True:
                    try:
                        event = q.get(timeout=30)
                        yield f"data: {json.dumps(event)}\n\n"
                        if event.get("type") == "status" and \
                           event.get("status") in ("COMPLETED", "FAILED"):
                            break
                    except queue.Empty:
                        yield 'data: {"type":"ping"}\n\n'
            finally:
                unsubscribe(session_id, q)

        return Response(
            stream_with_context(generate()),
            mimetype="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    # ── Full Scan Trigger (all 4 modules) ───────────────────────────────────
    @app.route("/api/scan/start", methods=["POST"])
    def start_full_scan():
        import os
        from flask import request, jsonify
        data = request.get_json() or {}
        target_url = (data.get("target_url") or "").strip()
        scan_type  = data.get("scan_type", "full")
        if not target_url:
            return jsonify({"error": "target_url is required"}), 400
        scan = create_scan(target_url, scan_type=scan_type)
        
        is_vercel = os.environ.get("VERCEL") == "1"
        if is_vercel:
            # On Vercel, the actual scan execution is initiated in the SSE stream
            # to prevent Vercel from killing the background worker thread.
            return jsonify({"session_id": scan.id, "status": "STARTED"}), 202

        t = threading.Thread(
            target=run_scan_worker,
            args=(app, scan.id, target_url, scan_type),
            daemon=True,
        )
        t.start()
        return jsonify({"session_id": scan.id, "status": "STARTED"}), 202

    # ── Web Routes ──────────────────────────────────────────────────────────
    @app.route("/")
    def index():
        return render_template("dashboard.html")

    @app.route("/discovery")
    def discovery_page():
        return render_template("discovery.html")

    @app.route("/vuln-scan")
    def vuln_scan_page():
        return render_template("vuln_scan.html")

    @app.route("/analysis")
    def analysis_page():
        return render_template("analysis.html")

    @app.route("/monitor")
    def monitor_page():
        return render_template("monitor.html")

    @app.route("/report")
    def report_page():
        return render_template("report.html")

    @app.route("/inventory")
    def inventory_page():
        return render_template("inventory.html")

    # Restore monitoring schedules
    import os
    if os.environ.get("VERCEL") != "1":
        with app.app_context():
            try:
                from core.monitor import restore_schedules
                restore_schedules(app, run_scan_worker, push_event)
            except Exception:
                pass

    return app


if __name__ == "__main__":
    application = create_app()
    application.run(host=config.HOST, port=config.PORT, debug=config.DEBUG)
