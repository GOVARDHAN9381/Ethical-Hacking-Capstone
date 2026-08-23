"""
api/report_routes.py — REST endpoints for generating and downloading audit reports.
"""

import io
import csv
import json
from flask import Blueprint, jsonify, request, Response, make_response
from db.manager import get_scan_full
from db.models import Scan

report_bp = Blueprint("report", __name__)


@report_bp.route("/<int:scan_id>/data", methods=["GET"])
def report_data(scan_id: int):
    """GET /api/report/<id>/data — Structured scan summary for reporting."""
    scan_data = get_scan_full(scan_id)
    if not scan_data:
        return jsonify({"error": "Scan not found"}), 404

    # Calculate aggregate executive metrics
    total_hosts = len(scan_data.get("hosts", []))
    all_ports = []
    all_vulns = []

    for h in scan_data.get("hosts", []):
        all_ports.extend(h.get("ports", []))
        all_vulns.extend(h.get("vulnerabilities", []))

    open_ports = [p for p in all_ports if "open" in p.get("state", "")]

    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for v in all_vulns:
        s = v.get("severity", "INFO")
        sev_counts[s] = sev_counts.get(s, 0) + 1

    max_risk = max([h.get("risk_score", 0) for h in scan_data.get("hosts", [])], default=0)

    summary = {
        "scan": scan_data,
        "metrics": {
            "total_hosts": total_hosts,
            "open_ports_count": len(open_ports),
            "vulnerabilities_count": len(all_vulns),
            "max_risk_score": max_risk,
            "severity_breakdown": sev_counts,
        }
    }
    return jsonify(summary)


@report_bp.route("/<int:scan_id>/export", methods=["GET"])
def export_report(scan_id: int):
    """
    GET /api/report/<id>/export?format=json|csv|html
    Download scan audit report in requested format.
    """
    export_format = request.args.get("format", "json").lower()
    scan_data = get_scan_full(scan_id)
    if not scan_data:
        return jsonify({"error": "Scan not found"}), 404

    filename_base = f"nsaf_audit_report_scan_{scan_id}"

    if export_format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        # Header
        writer.writerow([
            "Host IP", "Hostname", "OS Family", "Risk Level", "Risk Score",
            "Port", "Protocol", "State", "Service", "Software/Version",
            "Vulnerability Type", "CVE", "Severity", "Description", "Remediation"
        ])

        for h in scan_data.get("hosts", []):
            ip = h.get("ip")
            hostname = h.get("hostname")
            os_fam = h.get("os_family") or h.get("os_name")
            risk_lvl = h.get("risk_level")
            risk_score = h.get("risk_score")

            ports = h.get("ports", [])
            vulns = h.get("vulnerabilities", [])

            if not vulns and not ports:
                writer.writerow([ip, hostname, os_fam, risk_lvl, risk_score, "", "", "", "", "", "", "", "", "", ""])
            else:
                for v in vulns:
                    writer.writerow([
                        ip, hostname, os_fam, risk_lvl, risk_score,
                        v.get("port") or "", "tcp", "open", v.get("service") or "", "",
                        v.get("type") or "", v.get("cve") or "", v.get("severity") or "",
                        v.get("description") or "", v.get("remediation") or ""
                    ])

        response = make_response(output.getvalue())
        response.headers["Content-Disposition"] = f"attachment; filename={filename_base}.csv"
        response.headers["Content-Type"] = "text/csv; charset=utf-8"
        return response

    elif export_format == "json":
        response = make_response(json.dumps(scan_data, indent=2))
        response.headers["Content-Disposition"] = f"attachment; filename={filename_base}.json"
        response.headers["Content-Type"] = "application/json"
        return response

    else:  # html download or view
        response = make_response(json.dumps(scan_data, indent=2))
        response.headers["Content-Type"] = "application/json"
        return response
