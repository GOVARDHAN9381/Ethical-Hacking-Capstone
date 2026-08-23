"""
db/models.py — SQLAlchemy models for the API Security Testing Platform.
"""

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class ScanSession(db.Model):
    __tablename__ = "scan_sessions"
    id           = db.Column(db.Integer, primary_key=True)
    target_url   = db.Column(db.String(512), nullable=False)
    scan_type    = db.Column(db.String(50), default="full")  # full|quick|auth|vuln
    status       = db.Column(db.String(20), default="PENDING")  # PENDING|RUNNING|COMPLETED|FAILED
    error_msg    = db.Column(db.Text, nullable=True)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)

    endpoints    = db.relationship("DiscoveredEndpoint", backref="session", lazy=True, cascade="all, delete-orphan")
    auth_results = db.relationship("AuthTestResult",     backref="session", lazy=True, cascade="all, delete-orphan")
    vuln_findings= db.relationship("VulnFinding",        backref="session", lazy=True, cascade="all, delete-orphan")
    risk_analysis= db.relationship("RiskAnalysis",       backref="session", lazy=True, cascade="all, delete-orphan")
    logs         = db.relationship("ScanLog",            backref="session", lazy=True, cascade="all, delete-orphan")
    alerts       = db.relationship("Alert",              backref="session", lazy=True, cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "target_url": self.target_url,
            "scan_type": self.scan_type,
            "status": self.status,
            "error_msg": self.error_msg,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


class DiscoveredEndpoint(db.Model):
    __tablename__ = "discovered_endpoints"
    id            = db.Column(db.Integer, primary_key=True)
    session_id    = db.Column(db.Integer, db.ForeignKey("scan_sessions.id"), nullable=False)
    path          = db.Column(db.String(512), nullable=False)
    method        = db.Column(db.String(10), default="GET")
    status_code   = db.Column(db.Integer, nullable=True)
    auth_required = db.Column(db.Boolean, default=False)
    auth_type     = db.Column(db.String(50), nullable=True)   # JWT|ApiKey|Basic|OAuth2|None
    response_time = db.Column(db.Float, nullable=True)        # ms
    content_type  = db.Column(db.String(128), nullable=True)
    source        = db.Column(db.String(50), default="probe") # probe|swagger|crawl
    # Module 1 Enhancement: endpoint classification
    category      = db.Column(db.String(50), nullable=True)   # Auth|User|Admin|Payment|Public

    def to_dict(self):
        return {
            "id": self.id,
            "session_id": self.session_id,
            "path": self.path,
            "method": self.method,
            "status_code": self.status_code,
            "auth_required": self.auth_required,
            "auth_type": self.auth_type,
            "response_time": self.response_time,
            "content_type": self.content_type,
            "source": self.source,
            "category": self.category,
        }


class AuthTestResult(db.Model):
    __tablename__ = "auth_test_results"
    id          = db.Column(db.Integer, primary_key=True)
    session_id  = db.Column(db.Integer, db.ForeignKey("scan_sessions.id"), nullable=False)
    endpoint_id = db.Column(db.Integer, db.ForeignKey("discovered_endpoints.id"), nullable=True)
    test_name   = db.Column(db.String(128), nullable=False)
    category    = db.Column(db.String(64), nullable=True)   # JWT|ApiKey|Basic|BOLA|OAuth2
    passed      = db.Column(db.Boolean, default=True)       # True = secure, False = vulnerable
    severity    = db.Column(db.String(20), nullable=True)   # CRITICAL|HIGH|MEDIUM|LOW|INFO
    detail      = db.Column(db.Text, nullable=True)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "session_id": self.session_id,
            "endpoint_id": self.endpoint_id,
            "test_name": self.test_name,
            "category": self.category,
            "passed": self.passed,
            "severity": self.severity,
            "detail": self.detail,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class VulnFinding(db.Model):
    __tablename__ = "vuln_findings"
    id             = db.Column(db.Integer, primary_key=True)
    session_id     = db.Column(db.Integer, db.ForeignKey("scan_sessions.id"), nullable=False)
    endpoint_id    = db.Column(db.Integer, db.ForeignKey("discovered_endpoints.id"), nullable=True)
    vuln_type      = db.Column(db.String(64), nullable=False)   # SQLi|XSS|BOLA|RateLimit...
    owasp_category = db.Column(db.String(10), nullable=True)    # API1..API10
    severity       = db.Column(db.String(20), nullable=False)
    cvss_score     = db.Column(db.Float, nullable=True)
    description    = db.Column(db.Text, nullable=True)
    payload        = db.Column(db.Text, nullable=True)
    evidence       = db.Column(db.Text, nullable=True)
    remediation    = db.Column(db.Text, nullable=True)
    created_at     = db.Column(db.DateTime, default=datetime.utcnow)

    alerts = db.relationship("Alert", backref="finding", lazy=True)

    def to_dict(self):
        return {
            "id": self.id,
            "session_id": self.session_id,
            "endpoint_id": self.endpoint_id,
            "vuln_type": self.vuln_type,
            "owasp_category": self.owasp_category,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "description": self.description,
            "payload": self.payload,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class RiskAnalysis(db.Model):
    __tablename__ = "risk_analyses"
    id                   = db.Column(db.Integer, primary_key=True)
    session_id           = db.Column(db.Integer, db.ForeignKey("scan_sessions.id"), nullable=False)
    overall_score        = db.Column(db.Float, default=0.0)   # 0-10 (risk score)
    security_score       = db.Column(db.Float, default=100.0) # 0-100 (inverted, higher is safer)
    compliance_score     = db.Column(db.Float, default=0.0)   # 0-100 (% OWASP categories clean)
    risk_level           = db.Column(db.String(20), default="INFO")
    total_vulns          = db.Column(db.Integer, default=0)
    critical_count       = db.Column(db.Integer, default=0)
    high_count           = db.Column(db.Integer, default=0)
    medium_count         = db.Column(db.Integer, default=0)
    low_count            = db.Column(db.Integer, default=0)
    summary              = db.Column(db.Text, nullable=True)
    recommendations_json = db.Column(db.Text, nullable=True)   # JSON list
    trend_json           = db.Column(db.Text, nullable=True)   # JSON: {new_issues, resolved, etc.}
    owasp_coverage_json  = db.Column(db.Text, nullable=True)   # JSON: per-category compliance
    created_at           = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        import json
        recs = []
        if self.recommendations_json:
            try:
                recs = json.loads(self.recommendations_json)
            except Exception:
                recs = []
        trend = {}
        if self.trend_json:
            try:
                trend = json.loads(self.trend_json)
            except Exception:
                trend = {}
        owasp_coverage = []
        if self.owasp_coverage_json:
            try:
                owasp_coverage = json.loads(self.owasp_coverage_json)
            except Exception:
                owasp_coverage = []
        return {
            "id": self.id,
            "session_id": self.session_id,
            "overall_score": self.overall_score,
            "security_score": self.security_score,
            "compliance_score": self.compliance_score,
            "risk_level": self.risk_level,
            "total_vulns": self.total_vulns,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "summary": self.summary,
            "recommendations": recs,
            "trend": trend,
            "owasp_coverage": owasp_coverage,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class ApiInventory(db.Model):
    """Stores discovered API asset inventory entries."""
    __tablename__ = "api_inventory"
    id              = db.Column(db.Integer, primary_key=True)
    session_id      = db.Column(db.Integer, db.ForeignKey("scan_sessions.id"), nullable=False)
    api_name        = db.Column(db.String(256), nullable=True)
    base_url        = db.Column(db.String(512), nullable=False)
    version         = db.Column(db.String(64), nullable=True)
    auth_type       = db.Column(db.String(64), nullable=True)
    total_endpoints = db.Column(db.Integer, default=0)
    public_count    = db.Column(db.Integer, default=0)
    auth_count      = db.Column(db.Integer, default=0)
    admin_count     = db.Column(db.Integer, default=0)
    owner           = db.Column(db.String(128), nullable=True)
    swagger_url     = db.Column(db.String(512), nullable=True)
    last_scan       = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "session_id": self.session_id,
            "api_name": self.api_name,
            "base_url": self.base_url,
            "version": self.version,
            "auth_type": self.auth_type,
            "total_endpoints": self.total_endpoints,
            "public_count": self.public_count,
            "auth_count": self.auth_count,
            "admin_count": self.admin_count,
            "owner": self.owner,
            "swagger_url": self.swagger_url,
            "last_scan": self.last_scan.isoformat() if self.last_scan else None,
        }


class ScanComparison(db.Model):
    """Stores change detection results between two consecutive scans."""
    __tablename__ = "scan_comparisons"
    id                 = db.Column(db.Integer, primary_key=True)
    session_id         = db.Column(db.Integer, db.ForeignKey("scan_sessions.id"), nullable=False)
    previous_session_id= db.Column(db.Integer, nullable=True)
    new_endpoints      = db.Column(db.Text, nullable=True)   # JSON list of new paths
    removed_endpoints  = db.Column(db.Text, nullable=True)   # JSON list of removed paths
    auth_changes       = db.Column(db.Text, nullable=True)   # JSON list of auth type changes
    new_vulns          = db.Column(db.Integer, default=0)
    resolved_vulns     = db.Column(db.Integer, default=0)
    risk_delta         = db.Column(db.Float, default=0.0)    # positive = worse, negative = improved
    version_changed    = db.Column(db.Boolean, default=False)
    created_at         = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        import json

        def _safe_load(txt):
            if not txt:
                return []
            try:
                return json.loads(txt)
            except Exception:
                return []

        return {
            "id": self.id,
            "session_id": self.session_id,
            "previous_session_id": self.previous_session_id,
            "new_endpoints": _safe_load(self.new_endpoints),
            "removed_endpoints": _safe_load(self.removed_endpoints),
            "auth_changes": _safe_load(self.auth_changes),
            "new_vulns": self.new_vulns,
            "resolved_vulns": self.resolved_vulns,
            "risk_delta": self.risk_delta,
            "version_changed": self.version_changed,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class MonitorSchedule(db.Model):
    __tablename__ = "monitor_schedules"
    id               = db.Column(db.Integer, primary_key=True)
    target_url       = db.Column(db.String(512), nullable=False)
    scan_type        = db.Column(db.String(50), default="full")
    interval_minutes = db.Column(db.Integer, default=60)
    schedule_preset  = db.Column(db.String(20), nullable=True)  # daily|weekly|monthly|custom
    last_run         = db.Column(db.DateTime, nullable=True)
    next_run         = db.Column(db.DateTime, nullable=True)
    active           = db.Column(db.Boolean, default=True)
    created_at       = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "target_url": self.target_url,
            "scan_type": self.scan_type,
            "interval_minutes": self.interval_minutes,
            "schedule_preset": self.schedule_preset,
            "last_run": self.last_run.isoformat() if self.last_run else None,
            "next_run": self.next_run.isoformat() if self.next_run else None,
            "active": self.active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Alert(db.Model):
    __tablename__ = "alerts"
    id          = db.Column(db.Integer, primary_key=True)
    session_id  = db.Column(db.Integer, db.ForeignKey("scan_sessions.id"), nullable=False)
    finding_id  = db.Column(db.Integer, db.ForeignKey("vuln_findings.id"), nullable=True)
    message     = db.Column(db.Text, nullable=False)
    severity    = db.Column(db.String(20), default="INFO")
    is_new      = db.Column(db.Boolean, default=True)
    acknowledged= db.Column(db.Boolean, default=False)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "session_id": self.session_id,
            "finding_id": self.finding_id,
            "message": self.message,
            "severity": self.severity,
            "is_new": self.is_new,
            "acknowledged": self.acknowledged,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class ScanLog(db.Model):
    __tablename__ = "scan_logs"
    id         = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey("scan_sessions.id"), nullable=False)
    level      = db.Column(db.String(20), default="INFO")
    message    = db.Column(db.Text, nullable=False)
    timestamp  = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "session_id": self.session_id,
            "level": self.level,
            "message": self.message,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }
