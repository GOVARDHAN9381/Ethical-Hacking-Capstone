"""
core/service_enum.py — Service Enumeration and Banner Grabbing Module
Identifies running services, protocols, and software versions via banner capture.
"""

import socket
import subprocess
import re
import logging
import requests
import warnings

warnings.filterwarnings("ignore")  # suppress SSL warnings
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Banner Grabbing
# ─────────────────────────────────────────────────────────────────────────────

# Probe payloads for services that don't send banners on connect
PROBE_PAYLOADS = {
    21:   b"",             # FTP sends banner immediately
    22:   b"",             # SSH sends banner immediately
    25:   b"EHLO probe\r\n",
    80:   b"HEAD / HTTP/1.0\r\n\r\n",
    443:  b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n",
    110:  b"",             # POP3 sends banner immediately
    143:  b"",             # IMAP sends banner immediately
    3306: b"\n",
    5432: b"\x00",
    6379: b"*1\r\n$4\r\nPING\r\n",
    9200: b"GET / HTTP/1.0\r\n\r\n",
    27017: b"\x3a\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00",
}

DEFAULT_PAYLOAD = b"\r\n"


def grab_banner(ip: str, port: int, timeout: float = 3.0) -> str:
    """
    Grab a raw service banner via TCP socket.
    Sends a protocol-appropriate probe if needed.
    """
    payload = PROBE_PAYLOADS.get(port, DEFAULT_PAYLOAD)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        if payload:
            s.send(payload)
        banner = b""
        while True:
            chunk = s.recv(1024)
            if not chunk:
                break
            banner += chunk
            if len(banner) > 4096:
                break
        s.close()
        return banner.decode("utf-8", errors="replace").strip()
    except Exception as e:
        logger.debug(f"Banner grab failed {ip}:{port} — {e}")
        return ""


def grab_banner_netcat(ip: str, port: int, timeout: float = 3.0) -> str:
    """Fallback banner grab via netcat subprocess."""
    try:
        result = subprocess.run(
            ["nc", "-w", str(int(timeout)), "-v", ip, str(port)],
            input=PROBE_PAYLOADS.get(port, b"\r\n"),
            capture_output=True,
            timeout=timeout + 2,
        )
        out = (result.stdout + result.stderr).decode("utf-8", errors="replace").strip()
        return out
    except Exception as e:
        logger.debug(f"nc banner failed {ip}:{port} — {e}")
        return ""


# ─────────────────────────────────────────────────────────────────────────────
# HTTP(S) Fingerprinting
# ─────────────────────────────────────────────────────────────────────────────

def http_fingerprint(ip: str, port: int) -> dict:
    """
    Send HTTP HEAD/GET to detect web server, framework, and interesting headers.
    """
    info = {"server": "", "headers": {}, "title": "", "cms": ""}
    schemes = ["https", "http"] if port in (443, 8443, 2083, 2087) else ["http", "https"]

    for scheme in schemes:
        url = f"{scheme}://{ip}:{port}/"
        try:
            resp = requests.get(url, timeout=5, verify=False,
                                headers={"User-Agent": "Mozilla/5.0 (Security Audit)"})
            info["server"] = resp.headers.get("Server", "")
            info["headers"] = dict(resp.headers)
            # Extract title
            title_m = re.search(r"<title[^>]*>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
            if title_m:
                info["title"] = title_m.group(1).strip()[:120]
            # CMS detection
            body = resp.text.lower()
            if "wp-content" in body or "wordpress" in body:
                info["cms"] = "WordPress"
            elif "joomla" in body:
                info["cms"] = "Joomla"
            elif "drupal" in body:
                info["cms"] = "Drupal"
            elif "x-powered-by" in resp.headers:
                info["cms"] = resp.headers["x-powered-by"]
            break
        except Exception:
            continue
    return info


# ─────────────────────────────────────────────────────────────────────────────
# SMB Enumeration via Nmap Scripts
# ─────────────────────────────────────────────────────────────────────────────

def smb_enumerate(ip: str, progress_cb=None) -> dict:
    """
    Run nmap SMB scripts to enumerate OS version, shares, and workgroup.
    """
    def emit(msg):
        logger.debug(msg)
        if progress_cb:
            progress_cb(msg)

    result = {"os": "", "workgroup": "", "shares": [], "raw": ""}
    try:
        emit(f"[SMB] Enumerating SMB on {ip}...")
        cmd = [
            "nmap", "-p", "445,139", "--script",
            "smb-os-discovery,smb-enum-shares,smb-security-mode",
            "-T4", ip
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        raw = proc.stdout
        result["raw"] = raw

        for line in raw.splitlines():
            line = line.strip()
            if "OS:" in line:
                result["os"] = line.split("OS:")[1].strip()
            elif "Workgroup" in line or "Domain" in line:
                result["workgroup"] = line.split(":")[-1].strip()
            elif "Sharename" not in line and "|" in line and "$" not in line:
                share_m = re.search(r"\|\s+(\w[\w\-_ ]+)\s+", line)
                if share_m:
                    result["shares"].append(share_m.group(1).strip())

        emit(f"[SMB] OS={result['os']}  Workgroup={result['workgroup']}  Shares={result['shares']}")
    except Exception as e:
        emit(f"[SMB] Error: {e}")

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Service Version Parsing
# ─────────────────────────────────────────────────────────────────────────────

# Regex patterns to extract version strings from banners
BANNER_VERSION_PATTERNS = [
    (re.compile(r"SSH-(\d[\d.]+\w*)", re.I), "SSH"),
    (re.compile(r"OpenSSH[_\s]([\d.p]+)", re.I), "OpenSSH"),
    (re.compile(r"Apache[/\s]([\d.]+)", re.I), "Apache"),
    (re.compile(r"nginx[/\s]([\d.]+)", re.I), "nginx"),
    (re.compile(r"Microsoft-IIS[/\s]([\d.]+)", re.I), "IIS"),
    (re.compile(r"vsftpd\s([\d.]+)", re.I), "vsftpd"),
    (re.compile(r"ProFTPD\s([\d.]+)", re.I), "ProFTPD"),
    (re.compile(r"Postfix\s+ESMTP", re.I), "Postfix"),
    (re.compile(r"Sendmail\s+([\d.+]+)", re.I), "Sendmail"),
    (re.compile(r"MySQL\s+([\d.]+)", re.I), "MySQL"),
    (re.compile(r"PostgreSQL\s+([\d.]+)", re.I), "PostgreSQL"),
    (re.compile(r"Redis\s+([\d.]+)", re.I), "Redis"),
    (re.compile(r"MongoDB\s+([\d.]+)", re.I), "MongoDB"),
    (re.compile(r"Elasticsearch\s+([\d.]+)", re.I), "Elasticsearch"),
]


def parse_version_from_banner(banner: str) -> tuple[str, str]:
    """
    Extract software name and version from a raw banner string.
    Returns: (software_name, version_string)
    """
    for pattern, name in BANNER_VERSION_PATTERNS:
        m = pattern.search(banner)
        if m:
            version = m.group(1) if m.lastindex else ""
            return name, version
    # Fallback: return first 80 chars of banner as version info
    first_line = banner.splitlines()[0][:80] if banner else ""
    return "", first_line


# ─────────────────────────────────────────────────────────────────────────────
# Main Enumeration Orchestrator
# ─────────────────────────────────────────────────────────────────────────────

def enumerate_services(ip: str, open_ports: list[dict], progress_cb=None) -> list[dict]:
    """
    For each open port, attempt to grab a banner and identify the service.

    Args:
        ip: Target IP address
        open_ports: List of port dicts from port_scanner
        progress_cb: Optional progress callback

    Returns:
        Enriched list of port dicts with banner and version info added.
    """
    def emit(msg):
        logger.info(msg)
        if progress_cb:
            progress_cb(msg)

    emit(f"[ENUM] Starting service enumeration on {ip} ({len(open_ports)} ports)...")
    enriched = []
    has_smb = any(p["port"] in (445, 139) for p in open_ports)

    smb_data = {}
    if has_smb:
        smb_data = smb_enumerate(ip, progress_cb)

    for port_rec in open_ports:
        port = port_rec["port"]
        protocol = port_rec.get("protocol", "tcp")
        rec = dict(port_rec)
        rec["banner"] = ""
        rec["software"] = ""
        rec["http_title"] = ""
        rec["http_server"] = ""
        rec["smb_os"] = ""

        if protocol == "tcp":
            # HTTP fingerprinting for web ports
            if port in (80, 443, 8080, 8443, 8000, 8888, 3000, 9200, 5000):
                emit(f"[ENUM]   HTTP fingerprint {ip}:{port}...")
                http = http_fingerprint(ip, port)
                rec["http_server"] = http.get("server", "")
                rec["http_title"] = http.get("title", "")
                if http.get("server"):
                    rec["banner"] = f"HTTP Server: {http['server']}"
                    if http.get("title"):
                        rec["banner"] += f" | Title: {http['title']}"
                    if http.get("cms"):
                        rec["banner"] += f" | CMS: {http['cms']}"
                soft, ver = parse_version_from_banner(http.get("server", ""))
                rec["software"] = soft or http.get("server", "")
                if ver and not rec.get("version"):
                    rec["version"] = ver

            # SMB
            elif port in (445, 139) and smb_data:
                rec["banner"] = smb_data.get("raw", "")[:300]
                rec["smb_os"] = smb_data.get("os", "")
                rec["software"] = "SMB/CIFS"
                emit(f"[ENUM]   SMB: {ip}:{port} OS={smb_data.get('os', 'N/A')}")

            # Generic banner grab
            else:
                emit(f"[ENUM]   Banner grab {ip}:{port}...")
                banner = grab_banner(ip, port)
                if not banner:
                    banner = grab_banner_netcat(ip, port)
                rec["banner"] = banner[:500] if banner else ""
                soft, ver = parse_version_from_banner(banner)
                rec["software"] = soft
                if ver and not rec.get("version"):
                    rec["version"] = ver
                if banner:
                    emit(f"[ENUM]   Banner({port}): {banner[:80]}")

        enriched.append(rec)

    emit(f"[ENUM] Service enumeration complete on {ip}")
    return enriched
