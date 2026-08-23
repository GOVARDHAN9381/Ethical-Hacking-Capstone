"""
core/port_scanner.py — Multi-Technique Port Scanner
Supports TCP Connect, SYN Stealth (root), UDP scanning, and full Nmap integration.
"""

import socket
import subprocess
import logging
import os
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

from config import COMMON_PORTS, SERVICE_NAMES, DEFAULT_TIMEOUT, SCAN_THREADS

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# TCP Connect Scan (no root required)
# ─────────────────────────────────────────────────────────────────────────────

def _tcp_connect_port(ip: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> dict | None:
    """Try a full TCP 3-way handshake to a port. Returns result dict if open."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        s.close()
        if result == 0:
            return {
                "port": port,
                "protocol": "tcp",
                "state": "open",
                "service": SERVICE_NAMES.get(port, "unknown"),
                "version": "",
                "method": "tcp-connect",
            }
    except Exception:
        pass
    return None


def tcp_connect_scan(ip: str, ports: list[int] = None, progress_cb=None) -> list[dict]:
    """
    Full TCP connect scan using Python sockets.
    Safe to run without root privileges.
    """
    if ports is None:
        ports = COMMON_PORTS

    def emit(msg):
        logger.info(msg)
        if progress_cb:
            progress_cb(msg)

    emit(f"[TCP-SCAN] Starting TCP connect scan on {ip} ({len(ports)} ports, {SCAN_THREADS} threads)...")
    open_ports = []

    with ThreadPoolExecutor(max_workers=SCAN_THREADS) as executor:
        futures = {executor.submit(_tcp_connect_port, ip, port): port for port in ports}
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
                emit(f"[TCP-SCAN]   OPEN  {ip}:{result['port']}/tcp  ({result['service']})")

    open_ports.sort(key=lambda x: x["port"])
    emit(f"[TCP-SCAN] Complete — {len(open_ports)} open TCP port(s) on {ip}")
    return open_ports


# ─────────────────────────────────────────────────────────────────────────────
# SYN Stealth Scan (requires root, uses Scapy)
# ─────────────────────────────────────────────────────────────────────────────

def _syn_probe(ip: str, port: int, timeout: float = 1.5) -> dict | None:
    """Send a SYN packet and check for SYN-ACK (open) or RST (closed)."""
    try:
        from scapy.all import IP, TCP, sr1, conf
        conf.verb = 0
        pkt = IP(dst=ip) / TCP(dport=port, flags="S")
        reply = sr1(pkt, timeout=timeout)
        if reply is None:
            return None
        if reply.haslayer("TCP"):
            flags = reply["TCP"].flags
            if flags == 0x12:  # SYN-ACK
                # Send RST to close the half-open connection
                from scapy.all import send
                rst = IP(dst=ip) / TCP(dport=port, flags="R")
                send(rst, verbose=0)
                return {
                    "port": port,
                    "protocol": "tcp",
                    "state": "open",
                    "service": SERVICE_NAMES.get(port, "unknown"),
                    "version": "",
                    "method": "syn-stealth",
                }
    except Exception as e:
        logger.debug(f"SYN probe failed {ip}:{port} — {e}")
    return None


def syn_stealth_scan(ip: str, ports: list[int] = None, progress_cb=None) -> list[dict]:
    """
    Half-open SYN scan using Scapy. Requires root. Faster and stealthier than connect scan.
    """
    if ports is None:
        ports = COMMON_PORTS

    def emit(msg):
        logger.info(msg)
        if progress_cb:
            progress_cb(msg)

    emit(f"[SYN-SCAN] Starting SYN stealth scan on {ip} ({len(ports)} ports)...")
    open_ports = []

    # Scapy SYN scan is sequential-friendly but we can batch it
    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = {executor.submit(_syn_probe, ip, port): port for port in ports}
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
                emit(f"[SYN-SCAN]   OPEN  {ip}:{result['port']}/tcp  ({result['service']})")

    open_ports.sort(key=lambda x: x["port"])
    emit(f"[SYN-SCAN] Complete — {len(open_ports)} open TCP port(s) on {ip}")
    return open_ports


# ─────────────────────────────────────────────────────────────────────────────
# UDP Scan via Nmap
# ─────────────────────────────────────────────────────────────────────────────

def udp_scan(ip: str, top_n: int = 20, progress_cb=None) -> list[dict]:
    """
    UDP scan using nmap -sU. Requires root.
    Scans the top N UDP ports.
    """
    def emit(msg):
        logger.info(msg)
        if progress_cb:
            progress_cb(msg)

    emit(f"[UDP-SCAN] Starting UDP scan on {ip} (top {top_n} ports)...")
    open_ports = []

    try:
        cmd = ["nmap", "-sU", "--top-ports", str(top_n), "-T4", "--open", "-oG", "-", ip]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        for line in result.stdout.splitlines():
            # Parse greppable nmap output: Ports: 53/open/udp//domain///
            if "Ports:" in line:
                ports_section = line.split("Ports:")[1].strip()
                for entry in ports_section.split(","):
                    entry = entry.strip()
                    parts = entry.split("/")
                    if len(parts) >= 3 and parts[1] in ("open", "open|filtered"):
                        port_num = int(parts[0])
                        svc = parts[4] if len(parts) > 4 and parts[4] else SERVICE_NAMES.get(port_num, "unknown")
                        rec = {
                            "port": port_num,
                            "protocol": "udp",
                            "state": parts[1],
                            "service": svc,
                            "version": "",
                            "method": "udp-nmap",
                        }
                        open_ports.append(rec)
                        emit(f"[UDP-SCAN]   OPEN  {ip}:{port_num}/udp  ({svc})")

    except subprocess.TimeoutExpired:
        emit("[UDP-SCAN] Timeout — partial results returned")
    except Exception as e:
        emit(f"[UDP-SCAN] Error: {e}")

    emit(f"[UDP-SCAN] Complete — {len(open_ports)} open/filtered UDP port(s) on {ip}")
    return open_ports


# ─────────────────────────────────────────────────────────────────────────────
# Full Nmap Scan (service version + scripts)
# ─────────────────────────────────────────────────────────────────────────────

def nmap_full_scan(ip: str, ports: list[int] = None, progress_cb=None) -> dict:
    """
    Run nmap -sV -sC with version detection and default scripts.
    Parses output for service/version info.

    Returns:
        {
            "ports": [...],
            "os_guess": str,
            "raw_output": str
        }
    """
    def emit(msg):
        logger.info(msg)
        if progress_cb:
            progress_cb(msg)

    port_arg = ",".join(str(p) for p in (ports or COMMON_PORTS))
    emit(f"[NMAP-FULL] Running nmap -sV -sC on {ip}...")

    is_root = (os.geteuid() == 0)
    scan_type = "-sS" if is_root else "-sT"

    cmd = [
        "nmap", scan_type, "-sV", "--version-intensity", "5",
        "-sC", "-T4", "--open",
        "-p", port_arg,
        ip
    ]
    if is_root:
        cmd.insert(1, "-O")  # OS detection requires root

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        raw = result.stdout
        emit("[NMAP-FULL] Scan complete — parsing output...")
        parsed = _parse_nmap_output(raw, ip)
        parsed["raw_output"] = raw
        for p in parsed.get("ports", []):
            emit(f"[NMAP-FULL]   {p['port']}/{p['protocol']}  {p['state']}  {p['service']}  {p['version']}")
        return parsed
    except subprocess.TimeoutExpired:
        emit("[NMAP-FULL] Timeout during full scan")
        return {"ports": [], "os_guess": "", "raw_output": "TIMEOUT"}
    except Exception as e:
        emit(f"[NMAP-FULL] Error: {e}")
        return {"ports": [], "os_guess": "", "raw_output": str(e)}


def _parse_nmap_output(raw: str, ip: str) -> dict:
    """Parse nmap text output into structured port records."""
    ports = []
    os_guess = ""

    port_re = re.compile(
        r"^(\d+)/(tcp|udp)\s+(open\S*)\s+(\S+)(?:\s+(.*))?$"
    )
    os_re = re.compile(r"OS details?:\s*(.+)")
    os_cpe_re = re.compile(r"Running(?: \(JUST GUESSING\))?:\s*(.+)")

    for line in raw.splitlines():
        line = line.strip()
        m = port_re.match(line)
        if m:
            version_str = (m.group(5) or "").strip()
            ports.append({
                "port": int(m.group(1)),
                "protocol": m.group(2),
                "state": m.group(3),
                "service": m.group(4),
                "version": version_str,
                "method": "nmap-full",
            })
        om = os_re.search(line)
        if om:
            os_guess = om.group(1).strip()
        om2 = os_cpe_re.search(line)
        if om2 and not os_guess:
            os_guess = om2.group(1).strip()

    return {"ports": ports, "os_guess": os_guess}


# ─────────────────────────────────────────────────────────────────────────────
# Orchestrator
# ─────────────────────────────────────────────────────────────────────────────

def scan_host(ip: str, scan_type: str = "full", custom_ports: list[int] = None,
              progress_cb=None) -> dict:
    """
    Orchestrate scanning for a single host.

    scan_type options:
        'quick'   — TCP connect on common ports
        'syn'     — SYN stealth + UDP (root required)
        'full'    — Nmap -sV -sC (recommended)
        'custom'  — TCP connect on custom_ports list
    """
    is_root = (os.geteuid() == 0)
    ports = custom_ports or COMMON_PORTS

    def emit(msg):
        logger.info(msg)
        if progress_cb:
            progress_cb(msg)

    emit(f"[SCAN] Host {ip} — scan_type={scan_type}, root={is_root}")

    if scan_type == "full":
        result = nmap_full_scan(ip, ports, progress_cb)
        return result

    elif scan_type == "syn" and is_root:
        tcp_ports = syn_stealth_scan(ip, ports, progress_cb)
        udp_ports = udp_scan(ip, 20, progress_cb)
        return {"ports": tcp_ports + udp_ports, "os_guess": "", "raw_output": ""}

    elif scan_type == "syn" and not is_root:
        emit("[SCAN] SYN scan requires root — falling back to TCP connect scan")
        tcp_ports = tcp_connect_scan(ip, ports, progress_cb)
        return {"ports": tcp_ports, "os_guess": "", "raw_output": ""}

    else:  # quick / custom
        tcp_ports = tcp_connect_scan(ip, ports, progress_cb)
        return {"ports": tcp_ports, "os_guess": "", "raw_output": ""}


def scan_ports(ip: str, scan_type: str = "full", custom_ports: list[int] = None,
               progress_cb=None) -> list[dict]:
    """
    Wrapper around scan_host to return a list of port dicts.
    """
    res = scan_host(ip=ip, scan_type=scan_type, custom_ports=custom_ports, progress_cb=progress_cb)
    return res.get("ports", [])

