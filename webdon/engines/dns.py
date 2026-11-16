#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DNS/IP engine — records, reverse DNS, ASN, geolocation, hosting.

A/AAAA/MX/NS/TXT/CNAME/SOA/CAA/DS via DNS-over-HTTPS, SPF/DMARC/
DNSSEC from TXT records, reverse DNS (PTR) for each resolved IP,
and public IP intelligence (country, ASN, hosting provider/ISP)
from the public ip-api.com service. Everything is public data;
missing records are findings with fixes, never guesses.
"""
from ..core.http import doh, fetch_json, resolve_ips, reverse_dns

NAME = "dns"
TITLE = "DNS / IP Intelligence"

PHASES = ["DNS records", "mail authentication", "reverse DNS",
          "ASN & geolocation"]

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA", "DS"]
IP_API_URL = "http://ip-api.com/json/%s?fields=status,country,countryCode,org,isp,as,query"


def ip_intel(ip, timeout=8):
    """Public IP intelligence for one IP. Returns a dict or {}."""
    if not ip:
        return {}
    data, _err = fetch_json(IP_API_URL % ip, timeout=timeout,
                            max_bytes=50000)
    if not data or data.get("status") != "success":
        return {}
    return {"ip": ip, "country": data.get("country"),
            "country_code": data.get("countryCode"),
            "asn": data.get("as"), "org": data.get("org"),
            "isp": data.get("isp"),
            "hosting": data.get("org") or data.get("isp")}


def run(ctx):
    domain = ctx.get("domain") or ""
    findings = []
    data = {"domain": domain, "records": {}, "spf": False,
            "dmarc": False, "dnssec": False, "dmarc_record": None,
            "ips": ctx.get("ips") or [], "reverse_dns": {},
            "ip_intel": []}
    if not domain or "." not in domain or domain.startswith("127.") \
            or domain == "localhost":
        data["note"] = "Local test target — no public DNS exists."
        return {"engine": NAME, "status": "completed",
                "findings": [], "data": data}
    timeout = ctx.get("timeout", 8)
    for rtype in RECORD_TYPES:
        try:
            data["records"][rtype] = doh(domain, rtype, timeout=timeout)
        except Exception:
            data["records"][rtype] = []
    txt = data["records"].get("TXT") or []
    data["spf"] = any("v=spf1" in r for r in txt)
    dmarc_txt = doh("_dmarc." + domain, "TXT", timeout=timeout)
    data["dmarc_record"] = next(
        (r for r in dmarc_txt if "v=DMARC1" in r), None)
    data["dmarc"] = data["dmarc_record"] is not None
    data["dnssec"] = bool(data["records"].get("DS"))
    if not data["ips"]:
        data["ips"] = resolve_ips(domain, timeout=timeout)
    for ip in data["ips"][:4]:
        ptr = reverse_dns(ip)
        if ptr:
            data["reverse_dns"][ip] = ptr
        intel = ip_intel(ip, timeout=timeout)
        if intel:
            data["ip_intel"].append(intel)
    if data["ip_intel"]:
        first = data["ip_intel"][0]
        data["country"] = first.get("country")
        data["asn"] = first.get("asn")
        data["hosting"] = first.get("hosting")
    if not data["spf"]:
        findings.append({
            "severity": "low", "name": "No SPF record",
            "evidence": "no v=spf1 TXT record for %s" % domain,
            "fix": "Publish an SPF TXT record listing the servers "
                   "allowed to send mail for the domain."})
    if not data["dmarc"]:
        findings.append({
            "severity": "medium", "name": "No DMARC record",
            "evidence": "no v=DMARC1 TXT record at _dmarc.%s" % domain,
            "fix": "Publish a DMARC record (start with p=none, then "
                   "quarantine/reject)."})
    if not data["dnssec"]:
        findings.append({
            "severity": "low", "name": "DNSSEC not enabled",
            "evidence": "no DS record for %s" % domain,
            "fix": "Enable DNSSEC at the registrar and publish DS "
                   "records."})
    if not data["records"].get("MX"):
        findings.append({
            "severity": "info", "name": "No MX records",
            "evidence": "no MX record for %s" % domain,
            "fix": "Add MX records if the domain should receive mail."})
    return {"engine": NAME, "status": "completed",
            "findings": findings, "data": data}
