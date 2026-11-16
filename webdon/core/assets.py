#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Asset Intelligence — one linked inventory: domain, IPs, ports,
certificates, technologies, cookies, pages — and the links between
them.
"""


def build_assets(scan_like, ctx):
    """Build the asset inventory from scan results + context."""
    results = scan_like.get("results") or {}
    whois = (results.get("whois") or {}).get("data") or {}
    tls = (results.get("tls") or {}).get("data") or {}
    tech = (results.get("tech") or {}).get("data") or {}
    ports = (results.get("ports") or {}).get("data") or {}
    cookies = (results.get("cookies") or {}).get("data") or {}
    crawl = (results.get("crawl") or {}).get("data") or {}
    ipintel = (results.get("ipintel") or {}).get("data") or {}
    fields = whois.get("fields") or {}
    return {
        "domain": ctx.get("domain"),
        "ips": ctx.get("ips") or [],
        "ip_country": ipintel.get("country") or "UNKNOWN",
        "ip_hosting": ipintel.get("hosting") or "UNKNOWN",
        "registrar": fields.get("registrar") or "UNKNOWN",
        "registrant": fields.get("org") or fields.get("registrant")
                      or "UNKNOWN",
        "domain_expires": fields.get("expires") or "UNKNOWN",
        "domain_days_left": whois.get("days_left"),
        "cert_days_left": tls.get("days_left"),
        "server": tech.get("server") or "UNKNOWN",
        "technologies": tech.get("technologies") or [],
        "open_ports": [p.get("port") for p in ports.get("open_ports") or []],
        "cookie_names": [c.get("name") for c in cookies.get("cookies") or []],
        "page_count": crawl.get("page_count", 0),
        "cms": tech.get("cms") or "UNKNOWN",
    }
