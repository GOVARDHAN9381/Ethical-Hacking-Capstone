"""
core/discovery.py — Host Discovery Module
Performs ICMP ping sweep and ARP sweep to identify live hosts on a network.
"""

import subprocess
import socket
import ipaddress
import time
import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)


def _icmp_ping_scapy(ip: str, timeout: float = 1.5) -> dict | None:
    """Send an ICMP echo request using Scapy. Requires root."""
    try:
        from scapy.all import IP, ICMP, sr1, conf
        conf.verb = 0
        pkt = IP(dst=ip) / ICMP()
        reply = sr1(pkt, timeout=timeout)
        if reply is not None:
            ttl = reply.ttl if hasattr(reply, 'ttl') else None
            rtt = round((reply.time - pkt.sent_time) * 1000, 2) if hasattr(reply, 'time') else None
            return {"ip": ip, "ttl": ttl, "rtt_ms": rtt, "method": "ICMP-Scapy"}
    except Exception as e:
        logger.debug(f"Scapy ICMP failed for {ip}: {e}")
    return None


def _icmp_ping_nmap(ip: str) -> dict | None:
    """Fallback: use nmap -sn for ICMP ping."""
    try:
        result = subprocess.run(
            ["nmap", "-sn", "--send-ip", "-T4", ip],
            capture_output=True, text=True, timeout=10
        )
        if "Host is up" in result.stdout:
            # Extract latency if present
            rtt = None
            for line in result.stdout.splitlines():
                if "latency" in line.lower():
                    parts = line.split()
                    for i, p in enumerate(parts):
                        if "s" in p and i > 0:
                            try:
                                rtt = round(float(p.replace("s", "")) * 1000, 2)
                            except ValueError:
                                pass
            return {"ip": ip, "ttl": None, "rtt_ms": rtt, "method": "ICMP-Nmap"}
    except Exception as e:
        logger.debug(f"Nmap ICMP failed for {ip}: {e}")
    return None


def _arp_sweep_scapy(network: str, timeout: float = 2.0) -> list[dict]:
    """
    ARP sweep using Scapy. Works only on the local subnet. Requires root.
    Returns a list of discovered hosts with MAC addresses.
    """
    hosts = []
    try:
        from scapy.all import ARP, Ether, srp, conf
        conf.verb = 0
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
        answered, _ = srp(pkt, timeout=timeout, retry=1)
        for _, rcv in answered:
            hosts.append({
                "ip": rcv.psrc,
                "mac": rcv.hwsrc,
                "ttl": None,
                "rtt_ms": None,
                "method": "ARP",
            })
    except Exception as e:
        logger.debug(f"ARP sweep failed for {network}: {e}")
    return hosts


def _resolve_hostname(ip: str) -> str:
    """Attempt reverse DNS lookup."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def discover_hosts(target: str, progress_cb=None) -> list[dict]:
    """
    Main entry point for host discovery.

    Args:
        target: Single IP (e.g. '192.168.1.1'), CIDR (e.g. '192.168.1.0/24'),
                or range (e.g. '192.168.1.1-254').
        progress_cb: Optional callable(message: str) for live progress updates.

    Returns:
        List of dicts: {ip, mac, hostname, ttl, rtt_ms, method}
    """
    is_root = (os.geteuid() == 0)
    hosts_found: dict[str, dict] = {}

    def emit(msg):
        logger.info(msg)
        if progress_cb:
            progress_cb(msg)

    emit(f"[DISCOVERY] Starting host discovery on target: {target}")
    emit(f"[DISCOVERY] Running as {'root' if is_root else 'non-root'}")

    # ── Expand target into list of IPs ───────────────────────────────────────
    ips_to_probe = _expand_target(target)
    emit(f"[DISCOVERY] Expanded to {len(ips_to_probe)} host address(es)")

    # ── ARP sweep (local subnet, root only) ──────────────────────────────────
    if is_root and "/" in target:
        emit(f"[DISCOVERY] Performing ARP sweep on {target}...")
        arp_results = _arp_sweep_scapy(target)
        for h in arp_results:
            h["hostname"] = _resolve_hostname(h["ip"])
            hosts_found[h["ip"]] = h
            emit(f"[DISCOVERY]   ✓ ARP: {h['ip']}  MAC={h['mac']}  hostname={h['hostname'] or 'N/A'}")

    # ── ICMP ping sweep ───────────────────────────────────────────────────────
    emit(f"[DISCOVERY] Performing ICMP ping sweep ({len(ips_to_probe)} hosts, 50 threads)...")

    def probe(ip):
        # Skip if already found via ARP
        if ip in hosts_found:
            return None
        if is_root:
            result = _icmp_ping_scapy(ip)
        else:
            result = _icmp_ping_nmap(ip)
        return result

    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(probe, ip): ip for ip in ips_to_probe}
        for future in as_completed(futures):
            result = future.result()
            if result:
                ip = result["ip"]
                if ip not in hosts_found:
                    result["mac"] = ""
                    result["hostname"] = _resolve_hostname(ip)
                    hosts_found[ip] = result
                    emit(f"[DISCOVERY]   ✓ ICMP: {ip}  TTL={result.get('ttl')}  RTT={result.get('rtt_ms')}ms  hostname={result.get('hostname') or 'N/A'}")

    # ── If no results (firewall blocking ICMP), try TCP connect to port 80/443 ─
    if not hosts_found and len(ips_to_probe) <= 256:
        emit("[DISCOVERY] ICMP returned no results — attempting TCP connect fallback (port 80/443)...")
        def tcp_probe(ip):
            for port in (80, 443, 22, 445):
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(1.0)
                    if s.connect_ex((ip, port)) == 0:
                        s.close()
                        return {"ip": ip, "mac": "", "ttl": None, "rtt_ms": None, "method": f"TCP-{port}"}
                    s.close()
                except Exception:
                    pass
            return None
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(tcp_probe, ip): ip for ip in ips_to_probe}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    ip = result["ip"]
                    result["hostname"] = _resolve_hostname(ip)
                    hosts_found[ip] = result
                    emit(f"[DISCOVERY]   ✓ TCP: {ip}  port={result['method']}  hostname={result.get('hostname') or 'N/A'}")

    live_hosts = list(hosts_found.values())
    emit(f"[DISCOVERY] Complete — {len(live_hosts)} live host(s) found.")
    return live_hosts


def _expand_target(target: str) -> list[str]:
    """
    Expand a target string into a list of individual IP addresses.
    Supports: single IP, CIDR notation, IP range (x.x.x.start-end).
    """
    target = target.strip()
    ips = []

    try:
        # CIDR
        if "/" in target:
            net = ipaddress.ip_network(target, strict=False)
            ips = [str(ip) for ip in net.hosts()]
        # Range: 192.168.1.1-50
        elif "-" in target.split(".")[-1]:
            prefix = ".".join(target.split(".")[:-1])
            last_octet = target.split(".")[-1]
            start, end = last_octet.split("-")
            ips = [f"{prefix}.{i}" for i in range(int(start), int(end) + 1)]
        # Single IP
        else:
            socket.inet_aton(target)  # validate
            ips = [target]
    except Exception as e:
        logger.error(f"Failed to parse target '{target}': {e}")

    return ips
