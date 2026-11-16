#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IP Follow-up engine — the second phase: investigate the IP alone.

After the site scan, WEBDON continues the investigation on the
resolved IP itself: reverse DNS (PTR), ASN, geolocation (country),
hosting provider / ISP, the open ports found by the ports engine,
and any other public IP intelligence. This is the "search the IP
alone, continue the search" step — automatic in every profile.
"""
from ..core.http import reverse_dns
from .dns import ip_intel

NAME = "ipintel"
TITLE = "IP Follow-up — investigate the IP alone"

PHASES = ["reverse DNS", "ASN & geolocation", "hosting provider",
          "IP + ports correlation"]


def run(ctx):
    ips = ctx.get("ips") or []
    findings = []
    data = {"ips": ips, "ip": ips[0] if ips else None,
            "reverse_dns": {}, "intel": {}, "country": None,
            "asn": None, "hosting": None, "open_ports": []}
    if not ips:
        return {"engine": NAME, "status": "error",
                "findings": [],
                "data": {"error": "no IP resolved for the site"}}
    ip = ips[0]
    ptr = reverse_dns(ip)
    if ptr:
        data["reverse_dns"][ip] = ptr
    intel = ip_intel(ip, timeout=ctx.get("timeout", 8))
    data["intel"] = intel
    data["country"] = intel.get("country")
    data["asn"] = intel.get("asn")
    data["hosting"] = intel.get("hosting")
    ports_data = ctx.get("ports_data") or {}
    data["open_ports"] = [p.get("port")
                          for p in ports_data.get("open_ports") or []]
    data["open_count"] = len(data["open_ports"])
    if not intel:
        findings.append({
            "severity": "info",
            "name": "No public IP intelligence available for %s" % ip,
            "evidence": "ip-api.com returned no data for this IP",
            "fix": "No action — the IP simply has no public intel "
                   "record; check it manually in your own network."})
    else:
        findings.append({
            "severity": "info",
            "name": "IP %s located in %s (%s), hosted by %s"
                    % (ip, intel.get("country") or "UNKNOWN",
                       intel.get("asn") or "ASN UNKNOWN",
                       intel.get("hosting") or "UNKNOWN"),
            "evidence": "reverse DNS: %s" % (ptr or "none"),
            "fix": "Confirm the hosting provider matches the site "
                   "owner's known provider."})
    if data["open_ports"]:
        findings.append({
            "severity": "info",
            "name": "IP %s has %d open port(s): %s"
                    % (ip, len(data["open_ports"]),
                       ", ".join(str(p) for p in data["open_ports"])),
            "evidence": "ports engine result for the same IP",
            "fix": "Review every open port in the ports engine section "
                   "of this report."})
    return {"engine": NAME, "status": "completed",
            "findings": findings, "data": data}
