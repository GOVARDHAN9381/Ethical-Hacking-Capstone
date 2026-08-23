"""
api/discovery_routes.py — Module 1: API Discovery & Auth Testing Routes.
"""

import threading
import json
from flask import Blueprint, request, jsonify, current_app
from db.manager import (
    create_scan, update_scan_status, add_log,
    save_endpoint, save_auth_result, get_endpoints, get_auth_results, get_scan,
    save_api_inventory, get_all_inventories, get_api_inventory,
)

discovery_bp = Blueprint("discovery", __name__)


def _run_discovery_worker(app, session_id: int, target_url: str, token: str | None):
    from core.api_discovery import discover_endpoints
    from core.auth_tester import run_auth_tests

    def log(msg, level="INFO"):
        with app.app_context():
            add_log(session_id, msg, level)
        app.push_event(session_id, {"type": "log", "level": level, "message": msg})

    with app.app_context():
        try:
            update_scan_status(session_id, "RUNNING")
            app.push_event(session_id, {"type": "status", "status": "RUNNING"})

            # Step 1: Discover endpoints
            log(f"Starting API discovery on {target_url}")
            discovery = discover_endpoints(target_url, callback=log)
            raw_endpoints = discovery.get("all_endpoints", [])

            # Classify endpoints
            from core.endpoint_classifier import classify_endpoints, build_api_inventory, get_classification_summary
            endpoints = classify_endpoints(raw_endpoints)

            # Save to DB
            endpoint_records = []
            for ep_data in endpoints:
                rec = save_endpoint(session_id, ep_data)
                endpoint_records.append(rec)

            # Build and save API inventory
            inventory_data = build_api_inventory(target_url, endpoints)
            inventory_data["swagger_url"] = (
                target_url.rstrip("/") + "/openapi.json"
                if discovery.get("swagger_found") else None
            )
            save_api_inventory(session_id, inventory_data)
            class_summary = get_classification_summary(endpoints)

            app.push_event(session_id, {
                "type": "discovery_complete",
                "endpoint_count": len(endpoints),
                "swagger_found": discovery.get("swagger_found", False),
                "classification": class_summary,
                "api_name": inventory_data.get("api_name"),
                "api_version": inventory_data.get("version"),
            })
            log(f"Discovery complete: {len(endpoints)} endpoints found", "SUCCESS")

            # Step 2: Auth testing
            log("Starting authentication tests...")
            auth_results = run_auth_tests(target_url, endpoints, token=token, callback=log)
            for result in auth_results:
                save_auth_result(session_id, result)

            vulnerable_count = sum(1 for r in auth_results if not r.get("passed"))
            app.push_event(session_id, {
                "type": "auth_complete",
                "total_checks": len(auth_results),
                "vulnerabilities": vulnerable_count,
            })
            log(f"Auth testing complete: {vulnerable_count} issues found", "SUCCESS")

            update_scan_status(session_id, "COMPLETED")
            app.push_event(session_id, {"type": "status", "status": "COMPLETED"})

        except Exception as exc:
            import traceback
            log(f"Scan failed: {exc}", "ERROR")
            log(traceback.format_exc(), "ERROR")
            update_scan_status(session_id, "FAILED", error_msg=str(exc))
            app.push_event(session_id, {"type": "status", "status": "FAILED", "error": str(exc)})


@discovery_bp.route("/start", methods=["POST"])
def start_discovery():
    data = request.get_json() or {}
    target_url = (data.get("target_url") or "").strip()
    token = (data.get("jwt_token") or "").strip() or None

    if not target_url:
        return jsonify({"error": "target_url is required"}), 400

    scan = create_scan(target_url, scan_type="discovery")
    app = current_app._get_current_object()

    t = threading.Thread(
        target=_run_discovery_worker,
        args=(app, scan.id, target_url, token),
        daemon=True,
    )
    t.start()

    return jsonify({"session_id": scan.id, "status": "STARTED"}), 202


@discovery_bp.route("/<int:session_id>/endpoints", methods=["GET"])
def get_session_endpoints(session_id: int):
    endpoints = get_endpoints(session_id)
    return jsonify([ep.to_dict() for ep in endpoints])


@discovery_bp.route("/<int:session_id>/auth", methods=["GET"])
def get_session_auth(session_id: int):
    results = get_auth_results(session_id)
    return jsonify([r.to_dict() for r in results])


@discovery_bp.route("/<int:session_id>/status", methods=["GET"])
def get_discovery_status(session_id: int):
    scan = get_scan(session_id)
    if not scan:
        return jsonify({"error": "Session not found"}), 404
    return jsonify(scan.to_dict())


@discovery_bp.route("/analyze-jwt", methods=["POST"])
def analyze_jwt():
    """Standalone JWT analysis endpoint."""
    from core.auth_tester import decode_jwt_unsafe, analyze_jwt_claims, brute_force_jwt_secret, check_jwt_none_alg
    data = request.get_json() or {}
    token = data.get("token", "").strip()
    if not token:
        return jsonify({"error": "token is required"}), 400

    decoded = decode_jwt_unsafe(token)
    claims_issues = analyze_jwt_claims(token)
    none_result = check_jwt_none_alg(token)
    bf_result = brute_force_jwt_secret(token)

    return jsonify({
        "decoded": decoded,
        "claims_issues": claims_issues,
        "alg_none_vulnerable": none_result.get("vulnerable", False),
        "weak_secret_cracked": bf_result.get("cracked", False),
        "cracked_secret": bf_result.get("secret"),
    })


@discovery_bp.route("/inventory", methods=["GET"])
def list_inventory():
    """Return the full API asset inventory."""
    inventories = get_all_inventories()
    return jsonify([inv.to_dict() for inv in inventories])


@discovery_bp.route("/<int:session_id>/inventory", methods=["GET"])
def get_session_inventory(session_id: int):
    """Return inventory for a specific scan session."""
    inv = get_api_inventory(session_id)
    if not inv:
        return jsonify({"error": "No inventory found for this session"}), 404
    return jsonify(inv.to_dict())


@discovery_bp.route("/<int:session_id>/classify", methods=["GET"])
def get_endpoint_classification(session_id: int):
    """Return endpoint classification breakdown for a session."""
    from core.endpoint_classifier import get_classification_summary
    endpoints = get_endpoints(session_id)
    ep_dicts = [ep.to_dict() for ep in endpoints]
    summary = get_classification_summary(ep_dicts)
    return jsonify({
        "session_id": session_id,
        "total": len(ep_dicts),
        "breakdown": summary,
        "endpoints": ep_dicts,
    })
