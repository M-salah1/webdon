#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Nmap adapter — service & port discovery (v3.00 NET).

Runs the real Nmap binary when it is installed:
  nmap -sV -Pn -T4 --top-ports 100 -oX - <ip>
No OS detection (-O) — that needs root; the adapter says so.
Results are parsed from Nmap's XML output (-oX -).

A service is "identified" only when a banner or version string
was actually read — never guessed from the port number alone.
An open port with no service info stays "tcp_open".

When Nmap is not installed the adapter falls back to the
built-in TCP connect scan (same as the ports engine) and says
so honestly: status "not_installed (fallback)".
"""
import xml.etree.ElementTree as ET

from . import NOT_INSTALLED, adapter_result, finding, is_installed, require_scope, run_cmd

NAME = "nmap"
TITLE = "Nmap — service & port discovery"
BINARY = "nmap"


def build_args(ip):
    """Nmap argv: version detection, top 100 ports, XML to stdout.

    Deliberately no -O (OS detection needs root) and no -A.
    """
    return [BINARY, "-sV", "-Pn", "-T4", "--top-ports", "100",
            "-oX", "-", ip]


def parse_xml(text):
    """Parse Nmap -oX XML. Returns a list of open-port dicts.

    A port is "service_identified" only when <service> carries a
    name/product/version; otherwise it is "tcp_open".
    """
    out = []
    if not (text or "").strip().startswith("<"):
        return out
    try:
        root = ET.fromstring(text)
    except Exception:
        return out
    for host in root.iter("host"):
        for port in host.iter("port"):
            try:
                portid = int(port.get("portid"))
            except (TypeError, ValueError):
                continue
            state_el = port.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            service_el = port.find("service")
            name = ""
            product = ""
            version = ""
            if service_el is not None:
                name = (service_el.get("name") or "").strip()
                product = (service_el.get("product") or "").strip()
                version = (service_el.get("version") or "").strip()
            service = " ".join(p for p in (product, version) if p) or name
            identified = bool(service)
            out.append({
                "port": portid,
                "service": service or _guess(portid),
                "state": "service_identified" if identified else "tcp_open",
                "identified": identified,
                "banner": service if identified else "",
            })
    return sorted(out, key=lambda r: r["port"])


def _guess(port):
    """Port-number label only — used for display, never as proof."""
    from ..engines import ports as ports_mod
    return ports_mod.COMMON_PORTS.get(port, "?")


def connect_fallback(ctx):
    """Built-in TCP connect scan of the 19 common ports."""
    from ..engines import ports as ports_mod
    ips = ctx.get("ips") or []
    if not ips:
        return [], "no IP resolved"
    found = ports_mod.scan_ports(ips[0], timeout=0.5)
    return found, None


def _findings_for(open_ports):
    from ..engines import ports as ports_mod
    findings = []
    for item in open_ports:
        if item["port"] in ports_mod.RISKY_PORTS and item.get("state") in (
                "service_confirmed", "service_identified"):
            findings.append(finding(
                "high", "Sensitive service on port %d" % item["port"],
                "port %d %s" % (item["port"], item.get("service") or ""),
                "Close port %d or restrict it to trusted networks."
                % item["port"], confirmation="confirmed"))
    return findings


def run(ctx, timeout=180, runner=run_cmd):
    require_scope(ctx)
    ips = ctx.get("ips") or []
    ip = ips[0] if ips else ""
    if not ip:
        return adapter_result(NAME, "error", [],
                              {"error": "no IP resolved"})
    if is_installed(BINARY):
        rc, out, err = runner(build_args(ip), timeout=timeout)
        if rc == -1:
            return adapter_result(NAME, "error", [],
                                  {"error": err or "nmap timed out"})
        open_ports = parse_xml(out)
        return adapter_result(
            NAME, "completed", _findings_for(open_ports),
            {"ip": ip, "open_ports": open_ports,
             "open_count": len(open_ports),
             "identified_count": sum(
                 1 for p in open_ports if p.get("identified")),
             "mode": "nmap -sV --top-ports 100 (no -O: needs root)",
             "stderr": (err or "")[:200]})
    found, err = connect_fallback(ctx)
    if err:
        return adapter_result(NAME, "error", [], {"error": err})
    return adapter_result(
        NAME, NOT_INSTALLED, _findings_for(found),
        {"ip": ip, "open_ports": found, "open_count": len(found),
         "mode": "not_installed (fallback) — built-in connect scan",
         "note": "nmap is not installed; used the built-in TCP "
                 "connect scan instead. Install: tools install nmap",
         "install": "tools install nmap"})
