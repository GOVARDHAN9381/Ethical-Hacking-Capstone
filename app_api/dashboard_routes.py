"""
api/dashboard_routes.py — Dashboard statistics API.
"""

from flask import Blueprint, jsonify
from db.manager import get_dashboard_stats, get_all_scans

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/stats", methods=["GET"])
def stats():
    """Extended dashboard statistics including security & compliance scores."""
    data = get_dashboard_stats()
    return jsonify(data)


@dashboard_bp.route("/trend", methods=["GET"])
def trend():
    """Return last 10 completed scans with their risk/security scores for trend chart."""
    from db.models import ScanSession, RiskAnalysis
    from db.manager import db
    results = (
        ScanSession.query
        .filter_by(status="COMPLETED")
        .order_by(ScanSession.created_at.desc())
        .limit(10)
        .all()
    )
    trend_data = []
    for s in reversed(results):
        analysis = RiskAnalysis.query.filter_by(session_id=s.id)\
                                     .order_by(RiskAnalysis.created_at.desc()).first()
        trend_data.append({
            "session_id":      s.id,
            "target_url":      s.target_url,
            "created_at":      s.created_at.isoformat() if s.created_at else None,
            "security_score":  analysis.security_score if analysis else None,
            "compliance_score":analysis.compliance_score if analysis else None,
            "overall_score":   analysis.overall_score if analysis else None,
            "risk_level":      analysis.risk_level if analysis else None,
        })
    return jsonify(trend_data)
