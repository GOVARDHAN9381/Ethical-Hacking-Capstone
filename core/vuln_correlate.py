"""
core/vuln_correlate.py — Vulnerability Correlation and Risk Scoring Engine
Correlates discovered services with known risk patterns and assigns severity levels.
"""

import re
import logging
from config import DANGEROUS_PORTS, SERVICE_NAMES

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# CVE Reference Knowledge Base (representative subset; extend as needed)
# Maps regex patterns on (service + version) strings to CVE info
# ─────────────────────────────────────────────────────────────────────────────
CVE_PATTERNS = [
    # OpenSSH
    {"pattern": re.compile(r"OpenSSH[_\s]([0-6]\.|7\.[0-3])", re.I),
     "cve": "CVE-2018-15473", "cvss": 5.3, "severity": "MEDIUM",
     "description": "OpenSSH ≤7.7 username enumeration vulnerability",
     "remediation": "Upgrade OpenSSH to 7.7p1 or later"},

    {"pattern": re.compile(r"OpenSSH[_\s](7\.[0-4])", re.I),
     "cve": "CVE-2016-6210", "cvss": 5.9, "severity": "MEDIUM",
     "description": "OpenSSH timing attack allows username enumeration",
     "remediation": "Upgrade OpenSSH to 7.4+"},

    # Apache
    {"pattern": re.compile(r"Apache[/\s](2\.2\.|2\.4\.[0-3][0-9](?!\d))", re.I),
     "cve": "CVE-2021-41773", "cvss": 9.8, "severity": "CRITICAL",
     "description": "Apache 2.4.49 path traversal and RCE vulnerability",
     "remediation": "Upgrade Apache to 2.4.51 or later immediately"},

    {"pattern": re.compile(r"Apache[/\s]2\.4\.49", re.I),
     "cve": "CVE-2021-41773", "cvss": 9.8, "severity": "CRITICAL",
     "description": "Apache 2.4.49 path traversal / RCE (actively exploited)",
     "remediation": "Upgrade Apache to 2.4.51 or later immediately"},

    {"pattern": re.compile(r"Apache[/\s]2\.4\.50", re.I),
     "cve": "CVE-2021-42013", "cvss": 9.8, "severity": "CRITICAL",
     "description": "Apache 2.4.50 incomplete fix for CVE-2021-41773",
     "remediation": "Upgrade Apache to 2.4.51 or later immediately"},

    # nginx
    {"pattern": re.compile(r"nginx[/\s](1\.[0-9]\.|1\.1[0-4]\.)", re.I),
     "cve": "CVE-2019-9511", "cvss": 7.5, "severity": "HIGH",
     "description": "Nginx HTTP/2 DoS vulnerability (Data Dribble)",
     "remediation": "Upgrade nginx to 1.15.6+ or 1.14.1+"},

    # IIS
    {"pattern": re.compile(r"Microsoft-IIS[/\s][456]\.", re.I),
     "cve": "CVE-2017-7269", "cvss": 10.0, "severity": "CRITICAL",
     "description": "IIS 6.0 WebDAV buffer overflow (EternalBlue variant)",
     "remediation": "Decommission IIS 6.0 immediately — upgrade to IIS 10+"},

    # vsftpd
    {"pattern": re.compile(r"vsftpd\s2\.3\.4", re.I),
     "cve": "CVE-2011-2523", "cvss": 10.0, "severity": "CRITICAL",
     "description": "vsftpd 2.3.4 backdoor — sends shell on ':)' username",
     "remediation": "Remove vsftpd 2.3.4 immediately and replace with secure FTP server"},

    # Samba
    {"pattern": re.compile(r"Samba\s([0-3]\.|4\.[0-6]\.)", re.I),
     "cve": "CVE-2017-7494", "cvss": 9.8, "severity": "CRITICAL",
     "description": "SambaCry — Samba RCE via shared library upload",
     "remediation": "Upgrade Samba to 4.6.4+ or apply patch"},

    # SMB EternalBlue
    {"pattern": re.compile(r"(smb|cifs|windows.*5\.1|windows.*xp)", re.I),
     "cve": "CVE-2017-0144", "cvss": 8.1, "severity": "HIGH",
     "description": "MS17-010 EternalBlue — SMB RCE (WannaCry/NotPetya vector)",
     "remediation": "Apply MS17-010 patch, disable SMBv1, block port 445 at perimeter"},

    # ProFTPD
    {"pattern": re.compile(r"ProFTPD\s1\.[23]\.", re.I),
     "cve": "CVE-2010-4221", "cvss": 10.0, "severity": "CRITICAL",
     "description": "ProFTPD 1.3.2 mod_sql SQL injection / RCE",
     "remediation": "Upgrade ProFTPD to 1.3.6+"},

    # MySQL
    {"pattern": re.compile(r"MySQL\s([0-4]\.|5\.[0-6]\.)", re.I),
     "cve": "CVE-2012-2122", "cvss": 5.1, "severity": "HIGH",
     "description": "MySQL authentication bypass via timing attack",
     "remediation": "Upgrade MySQL to 5.6.6+ and restrict network access"},

    # Redis (unauthenticated)
    {"pattern": re.compile(r"redis_version:([01]\.|2\.|3\.|4\.)", re.I),
     "cve": "CVE-2022-0543", "cvss": 10.0, "severity": "CRITICAL",
     "description": "Redis Lua sandbox escape allowing RCE",
     "remediation": "Upgrade Redis to 6.2.6+ and enable requirepass authentication"},

    # OpenSSL
    {"pattern": re.compile(r"OpenSSL\s1\.[01]\.", re.I),
     "cve": "CVE-2014-0160", "cvss": 7.5, "severity": "HIGH",
     "description": "Heartbleed — OpenSSL memory disclosure",
     "remediation": "Upgrade OpenSSL to 1.0.2 or later, revoke and reissue certificates"},
]

# ─────────────────────────────────────────────────────────────────────────────
# Anonymous FTP Check
# ─────────────────────────────────────────────────────────────────────────────

def check_anonymous_ftp(ip: str, port: int = 21) -> bool:
    """Attempt anonymous FTP login."""
    import socket
    try:
        s = socket.socket()
        s.settimeout(5)
        s.connect((ip, port))
        s.recv(1024)  # welcome banner
        s.send(b"USER anonymous\r\n")
        resp = s.recv(1024).decode("utf-8", errors="replace")
        if "331" in resp or "230" in resp:
            s.send(b"PASS anonymous@test.com\r\n")
            resp2 = s.recv(1024).decode("utf-8", errors="replace")
            s.close()
            return "230" in resp2  # 230 = Login successful
        s.close()
    except Exception:
        pass
    return False


# ─────────────────────────────────────────────────────────────────────────────
# Risk Scoring
# ─────────────────────────────────────────────────────────────────────────────

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
SEVERITY_SCORE = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1, "INFO": 0}


def _compute_host_risk(findings: list[dict]) -> dict:
    """Aggregate findings into an overall host risk score."""
    if not findings:
        return {"score": 0, "level": "INFO", "label": "No Issues Detected"}

    max_severity = max(SEVERITY_ORDER.get(f["severity"], 0) for f in findings)
    total_score = sum(SEVERITY_SCORE.get(f["severity"], 0) for f in findings)
    # Normalize to 0–100
    normalized = min(100, total_score * 5)

    level_map = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "INFO"}
    level = level_map.get(max_severity, "INFO")

    return {"score": normalized, "level": level, "label": f"Risk Score: {normalized}/100"}


def correlate_vulnerabilities(arg1, arg2=None, progress_cb=None) -> dict:
    """
    Wrapper for correlate. Accepts correlate_vulnerabilities(open_ports)
    or correlate_vulnerabilities(ip, open_ports).
    """
    if isinstance(arg1, str) and isinstance(arg2, list):
        return correlate(ip=arg1, open_ports=arg2, progress_cb=progress_cb)
    elif isinstance(arg1, list):
        return correlate(ip="127.0.0.1", open_ports=arg1, progress_cb=progress_cb)
    else:
        return correlate(ip="127.0.0.1", open_ports=[], progress_cb=progress_cb)


def correlate(ip: str, open_ports: list[dict], progress_cb=None) -> dict:
    """
    Main vulnerability correlation function.

    Args:
        ip: Target host IP
        open_ports: Enriched list of port dicts (from service_enum)
        progress_cb: Optional progress callback

    Returns:
        {
            findings: list of vulnerability dicts,
            risk_score: int (0–100),
            risk_level: str,
            attack_surface: dict (summary counts),
            recommendations: list of str
        }
    """
    def emit(msg):
        logger.info(msg)
        if progress_cb:
            progress_cb(msg)


    emit(f"[VULN] Starting vulnerability correlation on {ip} ({len(open_ports)} ports)...")
    findings = []
    seen_cves = set()

    for port_rec in open_ports:
        port = port_rec.get("port")
        state = port_rec.get("state", "")
        if "open" not in state:
            continue

        banner = port_rec.get("banner", "")
        version = port_rec.get("version", "")
        software = port_rec.get("software", "")
        service = port_rec.get("service", "")
        combined_text = f"{software} {version} {banner} {service}"

        # ── Check dangerous ports ─────────────────────────────────────────────
        if port in DANGEROUS_PORTS:
            severity, reason = DANGEROUS_PORTS[port]
            finding = {
                "port": port,
                "service": service,
                "severity": severity,
                "type": "Dangerous Service Exposure",
                "cve": "",
                "cvss": SEVERITY_SCORE.get(severity, 0),
                "description": reason,
                "remediation": _get_port_remediation(port),
                "evidence": f"Port {port} ({service}) is open",
            }
            findings.append(finding)
            emit(f"[VULN]   [{severity}] Port {port} — {reason[:60]}")

        # ── Anonymous FTP check ───────────────────────────────────────────────
        if port == 21:
            emit(f"[VULN]   Checking anonymous FTP on {ip}:21...")
            if check_anonymous_ftp(ip, port):
                findings.append({
                    "port": port,
                    "service": "FTP",
                    "severity": "CRITICAL",
                    "type": "Anonymous FTP Login Allowed",
                    "cve": "CWE-287",
                    "cvss": 9.0,
                    "description": "FTP server allows anonymous login without credentials",
                    "remediation": "Disable anonymous FTP access in vsftpd/ProFTPD configuration",
                    "evidence": "Anonymous login returned 230 response",
                })
                emit(f"[VULN]   [CRITICAL] Anonymous FTP login allowed on {ip}:21!")

        # ── CVE pattern matching ──────────────────────────────────────────────
        for cve_entry in CVE_PATTERNS:
            m = cve_entry["pattern"].search(combined_text)
            if m and cve_entry["cve"] not in seen_cves:
                seen_cves.add(cve_entry["cve"])
                finding = {
                    "port": port,
                    "service": service,
                    "severity": cve_entry["severity"],
                    "type": "Known CVE Match",
                    "cve": cve_entry["cve"],
                    "cvss": cve_entry["cvss"],
                    "description": cve_entry["description"],
                    "remediation": cve_entry["remediation"],
                    "evidence": f"Matched pattern in: {combined_text[:120]}",
                }
                findings.append(finding)
                emit(f"[VULN]   [{cve_entry['severity']}] {cve_entry['cve']} — {cve_entry['description'][:60]}")

        # ── Telnet in-use ─────────────────────────────────────────────────────
        if port == 23 and "open" in state:
            findings.append({
                "port": port,
                "service": "Telnet",
                "severity": "CRITICAL",
                "type": "Insecure Protocol In Use",
                "cve": "CWE-319",
                "cvss": 9.0,
                "description": "Telnet transmits all data (including credentials) in plaintext",
                "remediation": "Disable Telnet immediately. Replace with SSH.",
                "evidence": f"Port 23/tcp is open on {ip}",
            })

    # ── Attack surface summary ────────────────────────────────────────────────
    severity_counts = {s: 0 for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]}
    for f in findings:
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

    open_count = sum(1 for p in open_ports if "open" in p.get("state", ""))
    attack_surface = {
        "open_ports": open_count,
        "total_findings": len(findings),
        **severity_counts,
    }

    risk = _compute_host_risk(findings)

    # ── Recommendations ───────────────────────────────────────────────────────
    recs = _generate_recommendations(findings, open_ports)

    emit(f"[VULN] Correlation complete: {len(findings)} finding(s), risk={risk['level']} ({risk['score']}/100)")

    return {
        "findings": findings,
        "risk_score": risk["score"],
        "risk_level": risk["level"],
        "attack_surface": attack_surface,
        "recommendations": recs,
    }


def _get_port_remediation(port: int) -> str:
    REMEDIATIONS = {
        23:    "Disable Telnet service and deploy SSH with key-based authentication",
        21:    "Disable FTP if possible; use SFTP/SCP. Disable anonymous login.",
        512:   "Disable rexec — use SSH instead",
        513:   "Disable rlogin — use SSH instead",
        514:   "Disable rsh — use SSH instead. If syslog, bind to localhost only.",
        69:    "Disable TFTP or restrict access via firewall rules",
        4444:  "Investigate immediately — this port is commonly used by Metasploit/malware",
        5555:  "Disable Android ADB over network or bind to localhost only",
        2375:  "Bind Docker daemon to Unix socket only; never expose port 2375",
        6379:  "Enable Redis requirepass, bind to 127.0.0.1, disable RESP without auth",
        11211: "Bind Memcached to localhost; enable SASL authentication",
        27017: "Enable MongoDB authentication; bind to 127.0.0.1",
        9200:  "Enable Elasticsearch security; add TLS and authentication",
        5900:  "Use VNC over SSH tunnel; enable strong VNC password",
        3389:  "Enable NLA for RDP; restrict access via firewall; apply all MS patches",
        445:   "Apply MS17-010 patch; disable SMBv1; firewall port 445",
        139:   "Disable NetBIOS over TCP/IP if not needed",
        161:   "Change default SNMP community strings; upgrade to SNMPv3 with auth",
        1433:  "Restrict SQL Server access to application server IPs only",
        3306:  "Bind MySQL to localhost; restrict remote access; use strong passwords",
        5432:  "Restrict PostgreSQL access via pg_hba.conf; use TLS connections",
    }
    return REMEDIATIONS.get(port, "Evaluate whether this service is required; apply least-privilege firewall rules")


def _generate_recommendations(findings: list[dict], open_ports: list[dict]) -> list[str]:
    """Generate prioritized actionable recommendations."""
    recs = []
    severities = {f["severity"] for f in findings}

    if "CRITICAL" in severities:
        recs.append("🔴 IMMEDIATE ACTION REQUIRED: Address all CRITICAL findings before system goes live")
    if any(f.get("cve") for f in findings):
        recs.append("📋 Review all matched CVEs and apply vendor patches or mitigations")
    if any(p["port"] == 23 for p in open_ports if "open" in p.get("state", "")):
        recs.append("🚫 Disable Telnet immediately and replace with SSH")
    if any(p["port"] == 21 for p in open_ports if "open" in p.get("state", "")):
        recs.append("🔐 Audit FTP configuration: disable anonymous access, consider SFTP migration")
    if any(p["port"] in (2375, 2376) for p in open_ports if "open" in p.get("state", "")):
        recs.append("🐳 Docker daemon is network-accessible — restrict to Unix socket immediately")
    if any(p["port"] == 445 for p in open_ports if "open" in p.get("state", "")):
        recs.append("🪟 Ensure MS17-010 is patched, SMBv1 disabled, and SMB access restricted at perimeter")
    if len(open_ports) > 20:
        recs.append(f"📊 Attack surface is large ({len(open_ports)} open ports) — review firewall policy and close unnecessary services")
    if not findings:
        recs.append("✅ No critical issues detected — maintain regular scanning schedule and patch management")
    recs.append("🔄 Schedule follow-up scans monthly and after any infrastructure changes")
    recs.append("📝 Implement a formal vulnerability management program to track and remediate findings")
    return recs
