"""
db/manager.py — Database helper functions for the API Security Testing Platform.
"""

import json
from datetime import datetime
from db.models import (
    db, ScanSession, DiscoveredEndpoint, AuthTestResult,
    VulnFinding, RiskAnalysis, MonitorSchedule, Alert, ScanLog,
    ApiInventory, ScanComparison,
)


def init_db(app):
    db.init_app(app)
    with app.app_context():
        db.create_all()


# ── Scan Sessions ─────────────────────────────────────────────────────────────

def create_scan(target_url: str, scan_type: str = "full") -> ScanSession:
    session = ScanSession(target_url=target_url, scan_type=scan_type, status="PENDING")
    db.session.add(session)
    db.session.commit()
    return session


def update_scan_status(session_id: int, status: str, error_msg: str = None):
    session = ScanSession.query.get(session_id)
    if session:
        session.status = status
        if error_msg:
            session.error_msg = error_msg
        if status in ("COMPLETED", "FAILED"):
            session.completed_at = datetime.utcnow()
        db.session.commit()


def get_scan(session_id: int) -> ScanSession:
    return ScanSession.query.get(session_id)


def get_all_scans(limit: int = 50):
    return ScanSession.query.order_by(ScanSession.created_at.desc()).limit(limit).all()


def get_scans_for_url(base_url: str, limit: int = 20):
    """Return scans for a specific target URL, newest first."""
    # Match both exact URL and with/without trailing slash
    url_clean = base_url.rstrip("/")
    return (
        ScanSession.query
        .filter(
            (ScanSession.target_url == url_clean) |
            (ScanSession.target_url == url_clean + "/")
        )
        .order_by(ScanSession.created_at.desc())
        .limit(limit)
        .all()
    )


# ── Endpoints ─────────────────────────────────────────────────────────────────

def save_endpoint(session_id: int, data: dict) -> DiscoveredEndpoint:
    ep = DiscoveredEndpoint(
        session_id=session_id,
        path=data.get("path", "/"),
        method=data.get("method", "GET"),
        status_code=data.get("status_code"),
        auth_required=data.get("auth_required", False),
        auth_type=data.get("auth_type"),
        response_time=data.get("response_time"),
        content_type=data.get("content_type"),
        source=data.get("source", "probe"),
        category=data.get("category"),
    )
    db.session.add(ep)
    db.session.commit()
    return ep


def get_endpoints(session_id: int):
    return DiscoveredEndpoint.query.filter_by(session_id=session_id).all()


# ── Auth Results ──────────────────────────────────────────────────────────────

def save_auth_result(session_id: int, data: dict) -> AuthTestResult:
    result = AuthTestResult(
        session_id=session_id,
        endpoint_id=data.get("endpoint_id"),
        test_name=data.get("test_name", "Unknown"),
        category=data.get("category"),
        passed=data.get("passed", True),
        severity=data.get("severity"),
        detail=data.get("detail"),
    )
    db.session.add(result)
    db.session.commit()
    return result


def get_auth_results(session_id: int):
    return AuthTestResult.query.filter_by(session_id=session_id).all()


# ── Vulnerability Findings ────────────────────────────────────────────────────

def save_finding(session_id: int, data: dict) -> VulnFinding:
    finding = VulnFinding(
        session_id=session_id,
        endpoint_id=data.get("endpoint_id"),
        vuln_type=data.get("vuln_type", "Unknown"),
        owasp_category=data.get("owasp_category"),
        severity=data.get("severity", "INFO"),
        cvss_score=data.get("cvss_score"),
        description=data.get("description"),
        payload=data.get("payload"),
        evidence=data.get("evidence"),
        remediation=data.get("remediation"),
    )
    db.session.add(finding)
    db.session.commit()

    # Auto-create alert for HIGH/CRITICAL
    if finding.severity in ("CRITICAL", "HIGH"):
        alert = Alert(
            session_id=session_id,
            finding_id=finding.id,
            message=f"[{finding.severity}] {finding.vuln_type} detected at {data.get('path', 'unknown path')}",
            severity=finding.severity,
            is_new=True,
        )
        db.session.add(alert)
        db.session.commit()

    return finding


def get_findings(session_id: int):
    return VulnFinding.query.filter_by(session_id=session_id).all()


# ── Risk Analysis ─────────────────────────────────────────────────────────────

def save_risk_analysis(session_id: int, data: dict) -> RiskAnalysis:
    analysis = RiskAnalysis(
        session_id=session_id,
        overall_score=data.get("overall_score", 0.0),
        security_score=data.get("security_score", 100.0),
        compliance_score=data.get("compliance_score", 0.0),
        risk_level=data.get("risk_level", "INFO"),
        total_vulns=data.get("total_vulns", 0),
        critical_count=data.get("critical_count", 0),
        high_count=data.get("high_count", 0),
        medium_count=data.get("medium_count", 0),
        low_count=data.get("low_count", 0),
        summary=data.get("summary"),
        recommendations_json=json.dumps(data.get("recommendations", [])),
        trend_json=json.dumps(data.get("trend", {})),
        owasp_coverage_json=json.dumps(data.get("owasp_coverage", [])),
    )
    db.session.add(analysis)
    db.session.commit()
    return analysis


def get_risk_analysis(session_id: int) -> RiskAnalysis:
    return RiskAnalysis.query.filter_by(session_id=session_id).order_by(RiskAnalysis.created_at.desc()).first()


# ── API Inventory ─────────────────────────────────────────────────────────────

def save_api_inventory(session_id: int, data: dict) -> ApiInventory:
    # Upsert by base_url (update if already exists for this base URL)
    existing = ApiInventory.query.filter_by(base_url=data.get("base_url", "")).first()
    if existing:
        existing.session_id      = session_id
        existing.api_name        = data.get("api_name", existing.api_name)
        existing.version         = data.get("version", existing.version)
        existing.auth_type       = data.get("auth_type", existing.auth_type)
        existing.total_endpoints = data.get("total_endpoints", existing.total_endpoints)
        existing.public_count    = data.get("public_count", existing.public_count)
        existing.auth_count      = data.get("auth_count", existing.auth_count)
        existing.admin_count     = data.get("admin_count", existing.admin_count)
        existing.swagger_url     = data.get("swagger_url", existing.swagger_url)
        existing.last_scan       = datetime.utcnow()
        db.session.commit()
        return existing

    inv = ApiInventory(
        session_id=session_id,
        api_name=data.get("api_name"),
        base_url=data.get("base_url", ""),
        version=data.get("version"),
        auth_type=data.get("auth_type"),
        total_endpoints=data.get("total_endpoints", 0),
        public_count=data.get("public_count", 0),
        auth_count=data.get("auth_count", 0),
        admin_count=data.get("admin_count", 0),
        owner=data.get("owner"),
        swagger_url=data.get("swagger_url"),
    )
    db.session.add(inv)
    db.session.commit()
    return inv


def get_api_inventory(session_id: int) -> ApiInventory:
    return ApiInventory.query.filter_by(session_id=session_id).first()


def get_all_inventories(limit: int = 50):
    return ApiInventory.query.order_by(ApiInventory.last_scan.desc()).limit(limit).all()


# ── Scan Comparisons (Change Detection) ──────────────────────────────────────

def save_scan_comparison(session_id: int, data: dict) -> ScanComparison:
    comp = ScanComparison(
        session_id=session_id,
        previous_session_id=data.get("previous_session_id"),
        new_endpoints=json.dumps(data.get("new_endpoints", [])),
        removed_endpoints=json.dumps(data.get("removed_endpoints", [])),
        auth_changes=json.dumps(data.get("auth_changes", [])),
        new_vulns=data.get("new_vulns", 0),
        resolved_vulns=data.get("resolved_vulns", 0),
        risk_delta=data.get("risk_delta", 0.0),
        version_changed=data.get("version_changed", False),
    )
    db.session.add(comp)
    db.session.commit()
    return comp


def get_scan_comparison(session_id: int) -> ScanComparison:
    return ScanComparison.query.filter_by(session_id=session_id).first()


# ── Monitor Schedules ─────────────────────────────────────────────────────────

def create_schedule(
    target_url: str,
    scan_type: str = "full",
    interval_minutes: int = 60,
    schedule_preset: str = None,
) -> MonitorSchedule:
    from datetime import timedelta
    now = datetime.utcnow()
    schedule = MonitorSchedule(
        target_url=target_url,
        scan_type=scan_type,
        interval_minutes=interval_minutes,
        schedule_preset=schedule_preset,
        next_run=now + timedelta(minutes=interval_minutes),
        active=True,
    )
    db.session.add(schedule)
    db.session.commit()
    return schedule


def get_active_schedules():
    return MonitorSchedule.query.filter_by(active=True).all()


def update_schedule_run(schedule_id: int):
    from datetime import timedelta
    schedule = MonitorSchedule.query.get(schedule_id)
    if schedule:
        schedule.last_run = datetime.utcnow()
        schedule.next_run = datetime.utcnow() + timedelta(minutes=schedule.interval_minutes)
        db.session.commit()


def toggle_schedule(schedule_id: int, active: bool):
    schedule = MonitorSchedule.query.get(schedule_id)
    if schedule:
        schedule.active = active
        db.session.commit()


def delete_schedule(schedule_id: int):
    schedule = MonitorSchedule.query.get(schedule_id)
    if schedule:
        db.session.delete(schedule)
        db.session.commit()


def get_all_schedules():
    return MonitorSchedule.query.order_by(MonitorSchedule.created_at.desc()).all()


# ── Alerts ────────────────────────────────────────────────────────────────────

def get_recent_alerts(limit: int = 20):
    return Alert.query.order_by(Alert.created_at.desc()).limit(limit).all()


def acknowledge_alert(alert_id: int):
    alert = Alert.query.get(alert_id)
    if alert:
        alert.acknowledged = True
        db.session.commit()


# ── Logs ──────────────────────────────────────────────────────────────────────

def add_log(session_id: int, message: str, level: str = "INFO"):
    log = ScanLog(session_id=session_id, message=message, level=level)
    db.session.add(log)
    db.session.commit()


def get_logs(session_id: int):
    return ScanLog.query.filter_by(session_id=session_id).order_by(ScanLog.timestamp).all()


# ── Dashboard Stats ───────────────────────────────────────────────────────────

def get_dashboard_stats() -> dict:
    total_scans      = ScanSession.query.count()
    completed        = ScanSession.query.filter_by(status="COMPLETED").count()
    total_vulns      = VulnFinding.query.count()
    critical_vulns   = VulnFinding.query.filter_by(severity="CRITICAL").count()
    high_vulns       = VulnFinding.query.filter_by(severity="HIGH").count()
    medium_vulns     = VulnFinding.query.filter_by(severity="MEDIUM").count()
    low_vulns        = VulnFinding.query.filter_by(severity="LOW").count()
    unacked_alerts   = Alert.query.filter_by(acknowledged=False).count()
    active_schedules = MonitorSchedule.query.filter_by(active=True).count()
    api_count        = ApiInventory.query.count()

    # Average security and compliance scores from the last 10 completed analyses
    recent_analyses = (
        RiskAnalysis.query
        .join(ScanSession, RiskAnalysis.session_id == ScanSession.id)
        .filter(ScanSession.status == "COMPLETED")
        .order_by(RiskAnalysis.created_at.desc())
        .limit(10)
        .all()
    )
    if recent_analyses:
        avg_security   = round(sum(a.security_score or 0 for a in recent_analyses) / len(recent_analyses), 1)
        avg_compliance = round(sum(a.compliance_score or 0 for a in recent_analyses) / len(recent_analyses), 1)
    else:
        avg_security   = None
        avg_compliance = None

    return {
        "total_scans": total_scans,
        "completed_scans": completed,
        "total_vulns": total_vulns,
        "critical_vulns": critical_vulns,
        "high_vulns": high_vulns,
        "medium_vulns": medium_vulns,
        "low_vulns": low_vulns,
        "unacked_alerts": unacked_alerts,
        "active_schedules": active_schedules,
        "api_count": api_count,
        "avg_security_score": avg_security,
        "avg_compliance_score": avg_compliance,
    }
