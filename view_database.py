"""
view_database.py — Quick Database Viewer for Faculty Presentation.
Run: python view_database.py
"""

import sqlite3
import os

DB_PATH = "apiast.db"

def inspect_db():
    if not os.path.exists(DB_PATH):
        print(f"[!] Database file '{DB_PATH}' not found.")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    print("=" * 70)
    print("           APIAST DATABASE SUMMARY (SQLite: apiast.db)")
    print("=" * 70)

    # 1. List Tables and Row Counts
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
    tables = [t[0] for t in cursor.fetchall()]

    print("\n[+] TABLES AND RECORD COUNTS:")
    for table in tables:
        cursor.execute(f"SELECT COUNT(*) FROM {table}")
        count = cursor.fetchone()[0]
        print(f"  - {table:<25} : {count} records")

    # 2. Show Recent Scan Sessions
    print("\n" + "=" * 70)
    print("[+] RECENT SCAN SESSIONS (table: scan_sessions)")
    print("=" * 70)
    cursor.execute("SELECT id, target_url, scan_type, status, created_at FROM scan_sessions ORDER BY id DESC LIMIT 5;")
    sessions = cursor.fetchall()
    print(f"{'ID':<5} {'Target URL':<30} {'Type':<10} {'Status':<12} {'Created At'}")
    print("-" * 70)
    for s in sessions:
        print(f"{s[0]:<5} {str(s[1])[:28]:<30} {s[2]:<10} {s[3]:<12} {str(s[4])[:19]}")

    # 3. Show Sample Vulnerability Findings
    print("\n" + "=" * 70)
    print("[+] RECENT VULNERABILITY FINDINGS (table: vuln_findings)")
    print("=" * 70)
    cursor.execute("SELECT session_id, vuln_type, severity, cvss_score, owasp_category, payload FROM vuln_findings ORDER BY id DESC LIMIT 5;")
    findings = cursor.fetchall()
    print(f"{'Sess':<6} {'Vulnerability Type':<32} {'Severity':<10} {'CVSS':<6} {'OWASP':<8} {'Payload'}")
    print("-" * 70)
    for f in findings:
        payload_preview = str(f[5] or '').replace('\n', ' ')[:25]
        print(f"#{f[0]:<5} {str(f[1])[:30]:<32} {f[2]:<10} {str(f[3]):<6} {str(f[4]):<8} {payload_preview}")

    # 4. Show Risk Analysis Scores
    print("\n" + "=" * 70)
    print("[+] RECENT RISK ANALYSES (table: risk_analyses)")
    print("=" * 70)
    cursor.execute("SELECT session_id, overall_score, security_score, compliance_score, risk_level, total_vulns, critical_count, high_count FROM risk_analyses ORDER BY id DESC LIMIT 5;")
    analyses = cursor.fetchall()
    print(f"{'Sess':<6} {'Risk(0-10)':<12} {'Security(0-100)':<17} {'Compliance%':<13} {'Level':<10} {'Total':<7} {'Crit':<6} {'High'}")
    print("-" * 70)
    for a in analyses:
        print(f"#{a[0]:<5} {str(a[1]):<12} {str(a[2]):<17} {str(a[3]) + '%':<13} {str(a[4]):<10} {str(a[5]):<7} {str(a[6]):<6} {str(a[7])}")

    print("\n" + "=" * 70)
    conn.close()

if __name__ == "__main__":
    inspect_db()
