"""
reports/pdf_generator.py — Generate PDF security reports using FPDF2.
"""

import os
from datetime import datetime
from fpdf import FPDF, XPos, YPos
from config import REPORTS_DIR, SEVERITY_COLORS


SEVERITY_COLOR_RGB = {
    "CRITICAL": (255, 71, 87),
    "HIGH":     (255, 107, 53),
    "MEDIUM":   (255, 165, 2),
    "LOW":      (46, 213, 115),
    "INFO":     (112, 161, 255),
}

class SecurityReportPDF(FPDF):
    def __init__(self, scan: dict):
        super().__init__()
        self.scan = scan
        self.set_auto_page_break(auto=True, margin=15)
        self.add_font("DejaVu", fname="/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf")
        self.add_font("DejaVu", style="B", fname="/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf")

    def header(self):
        self.set_fill_color(15, 15, 35)
        self.rect(0, 0, 210, 18, "F")
        self.set_font("DejaVu", "B", 11)
        self.set_text_color(100, 200, 255)
        self.set_y(5)
        self.cell(0, 8, "APIAST — Intelligent API Security Testing Platform", align="C")
        self.set_text_color(0, 0, 0)
        self.ln(14)

    def footer(self):
        self.set_y(-12)
        self.set_font("DejaVu", "", 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 8, f"Page {self.page_no()} | Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} | Confidential", align="C")

    def chapter_title(self, title: str):
        self.set_font("DejaVu", "B", 14)
        self.set_fill_color(20, 25, 50)
        self.set_text_color(100, 200, 255)
        self.cell(0, 10, title, new_x=XPos.LMARGIN, new_y=YPos.NEXT, fill=True)
        self.set_text_color(0, 0, 0)
        self.ln(3)

    def severity_badge(self, severity: str, x: float, y: float):
        r, g, b = SEVERITY_COLOR_RGB.get(severity, (128, 128, 128))
        self.set_fill_color(r, g, b)
        self.set_text_color(255, 255, 255)
        self.set_xy(x, y)
        self.set_font("DejaVu", "B", 8)
        self.cell(22, 6, severity, fill=True, align="C")
        self.set_text_color(0, 0, 0)


def generate_pdf_report(scan: dict, endpoints: list, findings: list,
                         auth_results: list, analysis: dict | None) -> str:
    """Generate a PDF security report and return its file path."""
    session_id = scan.get("id", 0)
    target_url = scan.get("target_url", "Unknown")
    created_at = scan.get("created_at", datetime.utcnow().isoformat())

    # Try with custom fonts, fall back to built-in
    try:
        pdf = SecurityReportPDF(scan)
        font_name = "DejaVu"
    except Exception:
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        font_name = "Helvetica"

    # ── Cover Page ────────────────────────────────────────────────────────────
    pdf.add_page()
    pdf.set_fill_color(10, 12, 30)
    pdf.rect(0, 0, 210, 297, "F")

    # Title block
    pdf.set_y(60)
    pdf.set_font(font_name, "B", 28)
    pdf.set_text_color(100, 200, 255)
    pdf.cell(0, 15, "API SECURITY REPORT", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_font(font_name, "", 13)
    pdf.set_text_color(180, 180, 220)
    pdf.cell(0, 10, "Intelligent API Security Testing & Monitoring Platform", align="C",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.ln(15)
    pdf.set_font(font_name, "", 11)
    pdf.set_text_color(200, 200, 200)
    pdf.cell(0, 8, f"Target: {target_url}", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 8, f"Session ID: #{session_id}", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 8, f"Date: {created_at[:10]}", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # Risk Score box
    if analysis:
        score = analysis.get("overall_score", 0)
        risk_level = analysis.get("risk_level", "INFO")
        r, g, b = SEVERITY_COLOR_RGB.get(risk_level, (128, 128, 128))
        pdf.ln(20)
        pdf.set_fill_color(r, g, b)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font(font_name, "B", 36)
        pdf.cell(0, 20, f"{score}/10", align="C", fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font(font_name, "B", 16)
        pdf.cell(0, 10, f"Risk Level: {risk_level}", align="C", fill=True,
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # ── Summary Page ──────────────────────────────────────────────────────────
    pdf.add_page()
    pdf.set_fill_color(255, 255, 255)
    pdf.set_text_color(0, 0, 0)
    pdf.set_font(font_name, "B", 16)
    pdf.set_y(25)
    pdf.cell(0, 10, "Executive Summary", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(3)

    # Stats table
    pdf.set_font(font_name, "", 11)
    stats = [
        ("Target URL", target_url),
        ("Total Endpoints Discovered", str(len(endpoints))),
        ("Total Vulnerabilities", str(len(findings))),
        ("Auth Test Results", str(len(auth_results))),
    ]
    if analysis:
        stats += [
            ("Critical Findings", str(analysis.get("critical_count", 0))),
            ("High Findings", str(analysis.get("high_count", 0))),
            ("Medium Findings", str(analysis.get("medium_count", 0))),
            ("Low Findings", str(analysis.get("low_count", 0))),
            ("Overall Risk Score", f"{analysis.get('overall_score', 0)}/10"),
            ("Risk Level", analysis.get("risk_level", "INFO")),
        ]

    for label, value in stats:
        pdf.set_font(font_name, "B", 10)
        pdf.cell(70, 8, label + ":", border="B")
        pdf.set_font(font_name, "", 10)
        pdf.cell(0, 8, value, border="B", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    if analysis and analysis.get("summary"):
        pdf.ln(5)
        pdf.set_font(font_name, "B", 12)
        pdf.cell(0, 8, "AI Risk Assessment Summary", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font(font_name, "", 10)
        pdf.multi_cell(0, 7, analysis.get("summary", ""))

    # ── Vulnerability Findings ────────────────────────────────────────────────
    if findings:
        pdf.add_page()
        pdf.set_font(font_name, "B", 16)
        pdf.set_y(25)
        pdf.cell(0, 10, "Vulnerability Findings", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        # Table header
        pdf.set_fill_color(20, 25, 60)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font(font_name, "B", 9)
        pdf.cell(60, 8, "Vulnerability Type", fill=True, border=1)
        pdf.cell(25, 8, "Severity", fill=True, border=1, align="C")
        pdf.cell(20, 8, "CVSS", fill=True, border=1, align="C")
        pdf.cell(25, 8, "OWASP", fill=True, border=1, align="C")
        pdf.cell(60, 8, "Path", fill=True, border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        pdf.set_text_color(0, 0, 0)
        pdf.set_font(font_name, "", 8)

        for i, f in enumerate(findings[:50]):  # cap at 50
            bg = (245, 245, 255) if i % 2 == 0 else (255, 255, 255)
            pdf.set_fill_color(*bg)
            sev = f.get("severity", "INFO")
            r, g, b = SEVERITY_COLOR_RGB.get(sev, (128, 128, 128))

            vuln_type = (f.get("vuln_type") or "")[:35]
            cvss = str(f.get("cvss_score", "N/A"))
            owasp = f.get("owasp_category") or "N/A"
            path  = (f.get("path") or "/")[:28]

            pdf.cell(60, 7, vuln_type, fill=True, border=1)
            pdf.set_text_color(r, g, b)
            pdf.set_font(font_name, "B", 8)
            pdf.cell(25, 7, sev, fill=True, border=1, align="C")
            pdf.set_text_color(0, 0, 0)
            pdf.set_font(font_name, "", 8)
            pdf.cell(20, 7, cvss, fill=True, border=1, align="C")
            pdf.cell(25, 7, owasp, fill=True, border=1, align="C")
            pdf.cell(60, 7, path, fill=True, border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # ── Recommendations ───────────────────────────────────────────────────────
    if analysis and analysis.get("recommendations"):
        pdf.add_page()
        pdf.set_font(font_name, "B", 16)
        pdf.set_y(25)
        pdf.cell(0, 10, "Remediation Recommendations", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        recs = analysis.get("recommendations", [])
        for i, rec in enumerate(recs[:10]):
            if isinstance(rec, dict):
                pdf.ln(4)
                pdf.set_font(font_name, "B", 11)
                pdf.set_fill_color(235, 240, 255)
                pdf.cell(0, 8, f"{i+1}. {rec.get('title', 'Recommendation')}", fill=True,
                         new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                steps = rec.get("steps", [])
                if steps:
                    pdf.set_font(font_name, "", 9)
                    for step in steps:
                        pdf.multi_cell(0, 6, f"• {step}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                else:
                    detail = rec.get("detail", "")
                    if detail:
                        pdf.set_font(font_name, "", 9)
                        pdf.multi_cell(0, 6, detail)

    # ── Save ──────────────────────────────────────────────────────────────────
    filename = f"report_session_{session_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
    out_path = os.path.join(REPORTS_DIR, filename)
    pdf.output(out_path)
    return out_path
