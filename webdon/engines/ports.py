#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ports engine — TCP connect scan of common ports (authorized only).

v5.1 TWO-TIER classification — every port result is exactly one of:

- tcp_open: SYN/connect answered, NO banner or protocol response
  identified. INFORMATIONAL ONLY — never a vulnerability, never
  counted in the score. Often a firewall answering SYNs, not a
  service at all. Never again reported as "61 open ports" meaning
  61 services.
- service_confirmed: a banner or protocol response was matched to
  a service/version (SSH banner, HTTP response, TLS handshake,
  MySQL/Redis/PostgreSQL greeting...). Only a service_confirmed
  port on a risky service is a real finding.

No authentication is ever attempted — no logins, no commands.
Authorized targets only: without a signed scope the engine
returns "not_tested".
"""
import concurrent.futures
import socket
import ssl

NAME = "ports"
TITLE = "Port Scan (TCP connect)"

PHASES = ["common ports connect scan", "service identification"]

COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 465: "smtps",
    587: "smtp", 993: "imaps", 995: "pop3s", 3306: "mysql",
    5432: "postgres", 6379: "redis", 8080: "http-alt", 8443: "https-alt",
    27017: "mongodb",
}

TLS_PORTS = (443, 8443, 465, 993, 995)
RISKY_PORTS = {21, 23, 3306, 5432, 6379, 27017}

BANNER_SIGNS = [
    ("SSH-", "ssh"), ("HTTP/", "http"),
    ("mysql_native_password", "mysql"), ("mysql", "mysql"),
    ("Redis", "redis"), ("RFB ", "vnc"), ("PostgreSQL", "postgres"),
    ("MongoDB", "mongodb"), ("220", "smtp/ftp"),
]


def _identify(banner):
    if not banner:
        return None, False
    if banner.startswith("SSH-"):
        return "ssh", True
    if banner.startswith("HTTP/"):
        return "http", True
    low = banner.lower()
    for sign, service in BANNER_SIGNS:
        if sign.lower() in low or sign in banner:
            return service, False
    return None, False


def _grab(sock, timeout=0.6):
    try:
        sock.settimeout(timeout)
        return sock.recv(256).decode(errors="ignore").strip()[:120]
    except Exception:
        return ""


def _http_probe(sock):
    try:
        sock.settimeout(1.0)
        sock.sendall(b"HEAD / HTTP/1.0\r\nHost: x\r\n\r\n")
        data = sock.recv(256).decode(errors="ignore")
        return data.startswith("HTTP/")
    except Exception:
        return False


def check_port(ip, port, timeout=0.5):
    """Connect to one port. Returns a result dict or None (closed)."""
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except Exception:
        return None
    try:
        banner = _grab(sock)
        service, confirmed = _identify(banner)
        # v5.1: only two tiers. A matched banner IS a confirmation.
        state = "service_confirmed" if (confirmed or service) \
            else "tcp_open"
        tls_info = None
        if port in TLS_PORTS:
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                wrapped = ctx.wrap_socket(sock, server_hostname=ip)
                cert = wrapped.getpeercert(binary_form=False) or {}
                tls_info = {"version": wrapped.version(),
                            "cipher": (wrapped.cipher() or [None])[0],
                            "issuer": str(cert.get("issuer", ""))[:120]}
                wrapped.close()
                state = "service_confirmed"
                service = service or "tls"
            except Exception:
                pass
        elif not confirmed and _http_probe(sock):
            state = "service_confirmed"
            service = service or "http"
        return {"port": port,
                "service": service or COMMON_PORTS.get(port, "?"),
                "state": state, "banner": banner, "tls": tls_info}
    finally:
        try:
            sock.close()
        except Exception:
            pass


def scan_ports(ip, ports=None, timeout=0.5, workers=10):
    """Scan a list of ports on one IP. Returns sorted open results."""
    ports = sorted(ports if ports is not None else COMMON_PORTS)
    found = []
    with concurrent.futures.ThreadPoolExecutor(
            max_workers=workers) as pool:
        futs = {pool.submit(check_port, ip, p, timeout): p for p in ports}
        for fut in futs:
            try:
                res = fut.result()
            except Exception:
                res = None
            if res:
                found.append(res)
    return sorted(found, key=lambda r: r["port"])


def run(ctx):
    if not ctx.get("authorized"):
        return {"engine": NAME, "status": "not_tested",
                "findings": [], "data": {"note": "needs authorization"}}
    ips = ctx.get("ips") or []
    if not ips:
        return {"engine": NAME, "status": "error",
                "findings": [], "data": {"error": "no IP resolved"}}
    ip = ips[0]
    timeout = 0.5
    open_ports = scan_ports(ip, timeout=timeout)
    by_state = {}
    for item in open_ports:
        by_state[item["state"]] = by_state.get(item["state"], 0) + 1
    findings = []
    for item in open_ports:
        if item["port"] not in RISKY_PORTS:
            continue
        if item["state"] == "service_confirmed":
            findings.append({
                "severity": "high", "confirmation": "confirmed",
                "name": "Sensitive service confirmed: %s on port %d"
                        % (item["service"], item["port"]),
                "evidence": "port %d service_confirmed, banner: %s"
                            % (item["port"], item.get("banner") or "—"),
                "fix": "Close port %d to the internet or restrict it "
                       "to trusted networks only." % item["port"],
                "port_state": "service_confirmed",
                "port_class": "service_confirmed",
                "banner": item.get("banner") or ""})
        else:
            # tcp_open: informational ONLY — never a vulnerability,
            # never scored. The service (if any) is unidentified.
            findings.append({
                "severity": "info", "confirmation": "info",
                "name": "Port %d open but service unidentified "
                        "(tcp_open)" % item["port"],
                "evidence": "port %d answered TCP but sent no banner "
                            "— often a firewall answering SYNs, not a "
                            "service. tcp_open is informational only."
                            % item["port"],
                "fix": "Confirm from inside the network whether a "
                       "service really listens on port %d."
                       % item["port"],
                "port_state": "tcp_open",
                "port_class": "tcp_open"})
    tcp_open_ports = [i for i in open_ports
                      if i["state"] == "tcp_open"]
    confirmed_ports = [i for i in open_ports
                       if i["state"] == "service_confirmed"]
    return {"engine": NAME, "status": "completed", "findings": findings,
            "data": {"ip": ip, "open_ports": open_ports,
                     "open_count": len(open_ports),
                     "by_state": by_state,
                     "tcp_open_count": len(tcp_open_ports),
                     "service_confirmed_count": len(confirmed_ports),
                     "tcp_open_ports": tcp_open_ports,
                     "service_confirmed_ports": confirmed_ports,
                     "confirmed_count": len(confirmed_ports),
                     "probed": len(COMMON_PORTS),
                     "total": len(COMMON_PORTS)}}
