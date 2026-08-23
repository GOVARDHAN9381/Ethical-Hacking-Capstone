"""
core/os_fingerprint.py — OS and Platform Detection Module
Uses TTL analysis, Nmap OS detection, SMB negotiation, and HTTP headers.
"""

import subprocess
import re
import os
import logging
import socket

logger = logging.getLogger(__name__)

# TTL-based OS heuristics
TTL_FINGERPRINTS = [
    (1,   64,  "Linux / Android / FreeBSD / macOS"),
    (65,  128, "Windows"),
    (129, 255, "Cisco IOS / Network Device / Solaris"),
]

# Device type hints from service combinations
DEVICE_HINTS = {
    frozenset([80, 443]):           "Web Server",
    frozenset([22, 80, 443]):       "Linux Web Server",
    frozenset([3389, 445, 139]):    "Windows Workstation/Server",
    frozenset([22]):                "Linux/Unix Host",
    frozenset([23]):                "Network Device (Telnet enabled)",
    frozenset([161]):               "SNMP Network Device",
    frozenset([5555]):              "Android Device (ADB)",
    frozenset([62078]):             "Apple iOS Device",
    frozenset([9100]):              "Network Printer",
}


def _ttl_os_guess(ttl: int | None) -> str:
    """Map TTL value to OS family."""
    if ttl is None:
        return ""
    for lo, hi, name in TTL_FINGERPRINTS:
        if lo <= ttl <= hi:
            return name
    return "Unknown"


def _nmap_os_detect(ip: str, progress_cb=None) -> dict:
    """
    Run nmap -O for OS detection (requires root).
    Returns dict with os_name, os_family, os_accuracy, cpe.
    """
    def emit(msg):
        logger.debug(msg)
        if progress_cb:
            progress_cb(msg)

    result = {"os_name": "", "os_family": "", "os_accuracy": 0, "cpe": ""}

    if os.geteuid() != 0:
        emit("[OS-FP] Nmap OS detection requires root — skipping")
        return result

    try:
        emit(f"[OS-FP] Running nmap -O on {ip}...")
        cmd = ["nmap", "-O", "--osscan-guess", "-T4", "--max-retries", "2", ip]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        raw = proc.stdout

        for line in raw.splitlines():
            line = line.strip()
            m = re.search(r"OS details?:\s*(.+)", line)
            if m:
                result["os_name"] = m.group(1).strip()

            m2 = re.search(r"Running(?: \(JUST GUESSING\))?:\s*(.+)", line)
            if m2 and not result["os_name"]:
                result["os_name"] = m2.group(1).split(",")[0].strip()

            m3 = re.search(r"accuracy: (\d+)%", line, re.I)
            if m3:
                result["os_accuracy"] = int(m3.group(1))

            m4 = re.search(r"(cpe:/[^\s]+)", line)
            if m4:
                result["cpe"] = m4.group(1)

        # Parse OS family from detected name
        name_lower = result["os_name"].lower()
        if "windows" in name_lower:
            result["os_family"] = "Windows"
        elif any(x in name_lower for x in ("linux", "ubuntu", "debian", "centos", "rhel", "fedora")):
            result["os_family"] = "Linux"
        elif "android" in name_lower:
            result["os_family"] = "Android"
        elif any(x in name_lower for x in ("ios", "macos", "darwin", "osx")):
            result["os_family"] = "macOS/iOS"
        elif any(x in name_lower for x in ("cisco", "juniper", "router", "switch")):
            result["os_family"] = "Network Device"
        elif "freebsd" in name_lower or "openbsd" in name_lower:
            result["os_family"] = "BSD"
        else:
            result["os_family"] = "Unknown"

        emit(f"[OS-FP] Nmap OS: {result['os_name']} ({result['os_accuracy']}%)")
    except Exception as e:
        emit(f"[OS-FP] Nmap OS error: {e}")

    return result


def _http_os_hints(open_ports: list[dict]) -> dict:
    """
    Infer OS from HTTP Server headers.
    """
    hints = {"os_family": "", "detail": ""}
    for p in open_ports:
        server = p.get("http_server", "").lower()
        if "win" in server or "iis" in server:
            hints["os_family"] = "Windows"
            hints["detail"] = f"IIS Server header: {p.get('http_server', '')}"
            break
        elif "ubuntu" in server:
            hints["os_family"] = "Linux (Ubuntu)"
            hints["detail"] = f"Server header: {p.get('http_server', '')}"
            break
        elif "debian" in server:
            hints["os_family"] = "Linux (Debian)"
            hints["detail"] = f"Server header: {p.get('http_server', '')}"
            break
        elif "centos" in server or "rhel" in server or "red hat" in server:
            hints["os_family"] = "Linux (RHEL/CentOS)"
            hints["detail"] = f"Server header: {p.get('http_server', '')}"
            break
    return hints


def _smb_os_detection(open_ports: list[dict]) -> str:
    """Extract OS from SMB enumeration data already embedded in port records."""
    for p in open_ports:
        if p.get("smb_os"):
            return p["smb_os"]
    return ""


def _classify_device_type(open_port_nums: set[int]) -> str:
    """
    Heuristically classify device type from open port combination.
    """
    best_match = ""
    best_overlap = 0
    for hint_ports, device_type in DEVICE_HINTS.items():
        overlap = len(hint_ports & open_port_nums)
        if overlap > best_overlap and overlap == len(hint_ports):
            best_overlap = overlap
            best_match = device_type
    return best_match or "General Host"


def fingerprint_os(ip: str, arg2=None, arg3=None, progress_cb=None) -> dict:
    """
    Main OS fingerprinting function. Combines multiple techniques.
    Supports fingerprint_os(ip, open_ports) or fingerprint_os(ip, host_info, open_ports).
    """
    if isinstance(arg2, list):
        open_ports = arg2
        host_info = arg3 if isinstance(arg3, dict) else {}
    elif isinstance(arg2, dict):
        host_info = arg2
        open_ports = arg3 if isinstance(arg3, list) else []
    else:
        host_info = {}
        open_ports = arg2 or []

    def emit(msg):
        logger.info(msg)
        if progress_cb:
            progress_cb(msg)

    emit(f"[OS-FP] Starting OS fingerprinting on {ip}...")
    result = {
        "os_name": "",
        "os_family": "",
        "os_version": "",
        "device_type": "",
        "confidence": 0,
        "method": "",
        "cpe": "",
        "detail": "",
    }

    open_port_nums = {p["port"] for p in open_ports if isinstance(p, dict) and p.get("state") == "open"}


    # ── Method 1: Nmap OS detection (highest confidence) ─────────────────────
    nmap_os = _nmap_os_detect(ip, progress_cb)
    if nmap_os["os_name"]:
        result.update({
            "os_name": nmap_os["os_name"],
            "os_family": nmap_os["os_family"],
            "confidence": nmap_os["os_accuracy"],
            "method": "Nmap -O",
            "cpe": nmap_os["cpe"],
        })
        emit(f"[OS-FP] Nmap OS: {result['os_name']} ({result['confidence']}%)")

    # ── Method 2: SMB OS discovery ────────────────────────────────────────────
    smb_os = _smb_os_detection(open_ports)
    if smb_os and not result["os_name"]:
        result.update({
            "os_name": smb_os,
            "os_family": "Windows" if "windows" in smb_os.lower() else "Unknown",
            "confidence": 80,
            "method": "SMB OS Discovery",
            "detail": f"SMB negotiation revealed: {smb_os}",
        })
        emit(f"[OS-FP] SMB OS: {smb_os}")
    elif smb_os:
        result["detail"] = f"SMB confirms: {smb_os}"

    # ── Method 3: TTL-based guess ─────────────────────────────────────────────
    ttl = host_info.get("ttl")
    ttl_guess = _ttl_os_guess(ttl)
    if ttl_guess and not result["os_family"]:
        result.update({
            "os_family": ttl_guess,
            "confidence": 50,
            "method": "TTL Analysis",
            "detail": f"TTL={ttl} suggests {ttl_guess}",
        })
        emit(f"[OS-FP] TTL={ttl} → {ttl_guess}")

    # ── Method 4: HTTP header hints ───────────────────────────────────────────
    http_hints = _http_os_hints(open_ports)
    if http_hints["os_family"] and not result["os_family"]:
        result.update({
            "os_family": http_hints["os_family"],
            "confidence": 40,
            "method": "HTTP Header Analysis",
            "detail": http_hints["detail"],
        })
        emit(f"[OS-FP] HTTP header hint: {http_hints['os_family']}")

    # ── Device type classification ────────────────────────────────────────────
    result["device_type"] = _classify_device_type(open_port_nums)

    # ── Android-specific detection ────────────────────────────────────────────
    if 5555 in open_port_nums:
        result.update({
            "os_family": "Android",
            "device_type": "Android Device (ADB Exposed)",
            "confidence": max(result["confidence"], 90),
            "method": "ADB Port Detection",
            "detail": "Port 5555 (ADB) is open — Android device with USB debugging exposed over network",
        })
        emit("[OS-FP] ADB port 5555 detected — Android device!")

    emit(f"[OS-FP] Result: {result['os_family']} | {result['device_type']} | confidence={result['confidence']}%")
    return result
