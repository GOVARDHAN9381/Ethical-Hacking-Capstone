"""
reports/export_generator.py — Module 4: HTML, CSV and JSON Report Generation.
Complements the existing PDF generator with additional export formats.
"""

import os
import csv
import json
from datetime import datetime
from config import REPORTS_DIR


# ── HTML Report ───────────────────────────────────────────────────────────────

_HTML_SEV_COLORS = {
    "CRITICAL": "#ff4757",
    "HIGH":     "#ff6b35",
    "MEDIUM":   "#ffa502",
    "LOW":      "#2ed573",
    "INFO":     "#70a1ff",
}


def _sev_badge_html(severity: str) -> str:
    color = _HTML_SEV_COLORS.get(severity, "#94a3b8")
    return (
        f'<span style="background:{color};color:#fff;padding:2px 8px;'
        f'border-radius:4px;font-size:11px;font-weight:700">{severity}</span>'
    )


def generate_html_report(
    scan: dict,
    endpoints: list[dict],
    findings: list[dict],
    analysis: dict | None,
    auth_results: list[dict] | None = None,
) -> str:
    """Generate a styled HTML security report and return its file path."""
    session_id  = scan.get("id", 0)
    target_url  = scan.get("target_url", "Unknown")
    created_at  = (scan.get("created_at") or datetime.utcnow().isoformat())[:10]

    score       = analysis.get("overall_score", "N/A") if analysis else "N/A"
    sec_score   = analysis.get("security_score", "N/A") if analysis else "N/A"
    comp_score  = analysis.get("compliance_score", "N/A") if analysis else "N/A"
    risk_level  = analysis.get("risk_level", "N/A") if analysis else "N/A"
    risk_color  = _HTML_SEV_COLORS.get(risk_level, "#94a3b8")

    crit  = analysis.get("critical_count", 0) if analysis else 0
    high  = analysis.get("high_count", 0) if analysis else 0
    med   = analysis.get("medium_count", 0) if analysis else 0
    low   = analysis.get("low_count", 0) if analysis else 0

    # Build findings rows
    findings_rows = ""
    for f in findings:
        sev = f.get("severity", "INFO")
        findings_rows += f"""
        <tr>
          <td>{f.get("vuln_type", "Unknown")}</td>
          <td>{_sev_badge_html(sev)}</td>
          <td><code>{f.get("cvss_score", "N/A")}</code></td>
          <td><span style="font-size:11px;background:#1e3a5f;color:#7dd3fc;padding:2px 6px;border-radius:3px">{f.get("owasp_category", "N/A")}</span></td>
          <td><code>{f.get("path", "/") or "/"}</code></td>
          <td style="font-size:12px;color:#94a3b8">{(f.get("description") or "")[:100]}</td>
        </tr>"""

    # Build endpoints rows
    endpoints_rows = ""
    for ep in endpoints[:50]:
        endpoints_rows += f"""
        <tr>
          <td><code style="color:#34d399">{ep.get("method","GET")}</code></td>
          <td><code>{ep.get("path","")}</code></td>
          <td>{ep.get("status_code","—")}</td>
          <td>{"✅ Required" if ep.get("auth_required") else "🔓 None"}</td>
          <td>{ep.get("auth_type") or "—"}</td>
          <td><span style="font-size:11px;background:#1e293b;color:#7dd3fc;padding:2px 6px;border-radius:3px">{ep.get("category") or "Public"}</span></td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>API Security Report — Session #{session_id}</title>
  <style>
    * {{ box-sizing:border-box; margin:0; padding:0 }}
    body {{ font-family:'Segoe UI',Arial,sans-serif; background:#0f172a; color:#e2e8f0; line-height:1.6 }}
    .container {{ max-width:1100px; margin:0 auto; padding:32px 24px }}
    h1 {{ font-size:32px; font-weight:800; background:linear-gradient(135deg,#38bdf8,#818cf8); -webkit-background-clip:text; -webkit-text-fill-color:transparent; margin-bottom:4px }}
    h2 {{ font-size:18px; font-weight:700; color:#7dd3fc; margin:32px 0 12px; border-bottom:1px solid #1e3a5f; padding-bottom:8px }}
    .meta {{ font-size:13px; color:#64748b; margin-bottom:32px }}
    .stat-row {{ display:grid; grid-template-columns:repeat(6,1fr); gap:12px; margin-bottom:32px }}
    .stat {{ background:#1e293b; border:1px solid #1e3a5f; border-radius:10px; padding:16px; text-align:center }}
    .stat .val {{ font-size:26px; font-weight:800 }}
    .stat .lbl {{ font-size:11px; color:#64748b; text-transform:uppercase; margin-top:4px }}
    table {{ width:100%; border-collapse:collapse; background:#1e293b; border-radius:8px; overflow:hidden; font-size:13px }}
    th {{ background:#0f1f3d; color:#7dd3fc; padding:10px 14px; text-align:left; font-weight:600 }}
    td {{ padding:9px 14px; border-bottom:1px solid #0f1f3d; vertical-align:top }}
    tr:hover td {{ background:#162032 }}
    code {{ font-family:'Courier New',monospace; font-size:12px; background:#0f172a; padding:1px 5px; border-radius:3px }}
    .section {{ margin-bottom:40px }}
    footer {{ text-align:center; font-size:11px; color:#334155; margin-top:48px; padding-top:16px; border-top:1px solid #1e293b }}
  </style>
</head>
<body>
<div class="container">
  <h1>🛡️ API Security Report</h1>
  <div class="meta">
    Target: <strong>{target_url}</strong> &nbsp;|&nbsp;
    Session: <strong>#{session_id}</strong> &nbsp;|&nbsp;
    Date: <strong>{created_at}</strong> &nbsp;|&nbsp;
    Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}
  </div>

  <div class="stat-row">
    <div class="stat"><div class="val" style="color:{risk_color}">{sec_score}</div><div class="lbl">Security Score /100</div></div>
    <div class="stat"><div class="val" style="color:{risk_color}">{score}/10</div><div class="lbl">Risk Score</div></div>
    <div class="stat"><div class="val" style="color:#22d3ee">{comp_score}%</div><div class="lbl">Compliance</div></div>
    <div class="stat"><div class="val" style="color:#ff4757">{crit}</div><div class="lbl">Critical</div></div>
    <div class="stat"><div class="val" style="color:#ff6b35">{high}</div><div class="lbl">High</div></div>
    <div class="stat"><div class="val" style="color:#94a3b8">{len(endpoints)}</div><div class="lbl">Endpoints</div></div>
  </div>

  <div class="section">
    <h2>Vulnerability Findings ({len(findings)} total)</h2>
    <table>
      <thead><tr><th>Vulnerability</th><th>Severity</th><th>CVSS</th><th>OWASP</th><th>Path</th><th>Description</th></tr></thead>
      <tbody>{findings_rows if findings_rows else '<tr><td colspan="6" style="text-align:center;color:#64748b;padding:20px">No vulnerabilities found</td></tr>'}</tbody>
    </table>
  </div>

  <div class="section">
    <h2>Discovered Endpoints ({len(endpoints)} total)</h2>
    <table>
      <thead><tr><th>Method</th><th>Path</th><th>Status</th><th>Auth</th><th>Auth Type</th><th>Category</th></tr></thead>
      <tbody>{endpoints_rows if endpoints_rows else '<tr><td colspan="6" style="text-align:center;color:#64748b;padding:20px">No endpoints discovered</td></tr>'}</tbody>
    </table>
  </div>

  {"<div class='section'><h2>AI Risk Summary</h2><p style='color:#94a3b8'>" + (analysis.get("summary") or "") + "</p></div>" if analysis and analysis.get("summary") else ""}

  <footer>
    APIAST — Intelligent API Security Testing &amp; Monitoring Platform &nbsp;|&nbsp;
    Confidential &nbsp;|&nbsp; Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}
  </footer>
</div>
</body>
</html>"""

    filename = f"report_session_{session_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.html"
    out_path = os.path.join(REPORTS_DIR, filename)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    return out_path


# ── CSV Report ────────────────────────────────────────────────────────────────

def generate_csv_report(scan: dict, findings: list[dict]) -> str:
    """Generate a CSV report of all vulnerability findings."""
    session_id = scan.get("id", 0)
    filename   = f"report_session_{session_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    out_path   = os.path.join(REPORTS_DIR, filename)

    fieldnames = [
        "session_id", "vuln_type", "severity", "cvss_score",
        "owasp_category", "path", "description", "payload", "evidence", "remediation",
    ]
    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for f in findings:
            row = {k: f.get(k, "") for k in fieldnames}
            row["session_id"] = session_id
            writer.writerow(row)

    return out_path


# ── JSON Report ───────────────────────────────────────────────────────────────

def generate_json_report(
    scan: dict,
    endpoints: list[dict],
    findings: list[dict],
    analysis: dict | None,
    auth_results: list[dict] | None = None,
) -> str:
    """Generate a structured JSON security report."""
    session_id = scan.get("id", 0)
    filename   = f"report_session_{session_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    out_path   = os.path.join(REPORTS_DIR, filename)

    report = {
        "meta": {
            "generator": "APIAST — Intelligent API Security Testing Platform",
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "session_id": session_id,
            "target_url": scan.get("target_url"),
            "scan_type": scan.get("scan_type"),
            "scan_status": scan.get("status"),
            "created_at": scan.get("created_at"),
            "completed_at": scan.get("completed_at"),
        },
        "risk_summary": {
            "overall_score": analysis.get("overall_score") if analysis else None,
            "security_score": analysis.get("security_score") if analysis else None,
            "compliance_score": analysis.get("compliance_score") if analysis else None,
            "risk_level": analysis.get("risk_level") if analysis else None,
            "critical_count": analysis.get("critical_count", 0) if analysis else 0,
            "high_count": analysis.get("high_count", 0) if analysis else 0,
            "medium_count": analysis.get("medium_count", 0) if analysis else 0,
            "low_count": analysis.get("low_count", 0) if analysis else 0,
            "total_vulns": analysis.get("total_vulns", 0) if analysis else 0,
        },
        "endpoints": endpoints,
        "findings": findings,
        "auth_results": auth_results or [],
        "recommendations": analysis.get("recommendations", []) if analysis else [],
        "ai_summary": analysis.get("summary", "") if analysis else "",
    }

    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)

    return out_path
