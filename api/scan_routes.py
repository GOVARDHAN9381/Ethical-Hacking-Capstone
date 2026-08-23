"""
api/scan_routes.py — REST endpoints for scan management.
"""

import threading
from flask import Blueprint, request, jsonify, current_app
from db.models import db, Scan
from db.manager import create_scan, get_scan_full

scan_bp = Blueprint("scan", __name__)


@scan_bp.route("/start", methods=["POST"])
def start_scan():
    """
    POST /api/scan/start
    Body: { "target": "192.168.1.0/24", "scan_type": "connect|syn|full", "notes": "" }
    Returns: { "scan_id": <int>, "status": "PENDING" }
    """
    data = request.get_json(silent=True) or {}
    target = data.get("target", "").strip()
    scan_type = data.get("scan_type", "connect").strip()
    notes = data.get("notes", "").strip()

    if not target:
        return jsonify({"error": "target is required"}), 400

    if scan_type not in ("connect", "syn", "full", "udp"):
        scan_type = "connect"

    scan = create_scan(target=target, scan_type=scan_type, notes=notes)

    # Kick off background scan thread
    app = current_app._get_current_object()
    t = threading.Thread(
        target=app.run_scan_worker,
        args=(app, scan.id, target, scan_type),
        daemon=True,
        name=f"scan-{scan.id}",
    )
    t.start()

    return jsonify({"scan_id": scan.id, "status": "PENDING", "target": target}), 202


@scan_bp.route("/list", methods=["GET"])
def list_scans():
    """GET /api/scan/list — Return all scans ordered newest-first."""
    scans = Scan.query.order_by(Scan.started_at.desc()).all()
    return jsonify([s.to_dict() for s in scans])


@scan_bp.route("/<int:scan_id>/status", methods=["GET"])
def scan_status(scan_id: int):
    """GET /api/scan/<id>/status — Current scan state."""
    scan = Scan.query.get_or_404(scan_id)
    return jsonify(scan.to_dict())


@scan_bp.route("/<int:scan_id>/detail", methods=["GET"])
def scan_detail_api(scan_id: int):
    """GET /api/scan/<id>/detail — Full scan with hosts, ports, vulns."""
    result = get_scan_full(scan_id)
    if result is None:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(result)


@scan_bp.route("/<int:scan_id>/logs", methods=["GET"])
def scan_logs(scan_id: int):
    """GET /api/scan/<id>/logs — All log entries for a scan."""
    from db.models import ScanLog
    logs = ScanLog.query.filter_by(scan_id=scan_id)\
                        .order_by(ScanLog.timestamp).all()
    return jsonify([l.to_dict() for l in logs])


@scan_bp.route("/<int:scan_id>", methods=["DELETE"])
def delete_scan(scan_id: int):
    """DELETE /api/scan/<id> — Remove a scan and all related data."""
    scan = Scan.query.get_or_404(scan_id)
    if scan.status == "RUNNING":
        return jsonify({"error": "Cannot delete a running scan"}), 409
    db.session.delete(scan)
    db.session.commit()
    return jsonify({"deleted": scan_id})
