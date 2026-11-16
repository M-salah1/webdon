#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WHOIS engine — owner identity from public registration records.

RFC 3912 port-43 WHOIS with referral following (IANA -> registry
-> registrar). Public fields only: registrar, creation/expiry
dates, organization, country, nameservers.

Redacted / privacy-protected data is reported UNKNOWN, never
probed or guessed. Admin identity comes ONLY from the public
WHOIS organization or a public security.txt contact — if neither
is published, the admin is UNKNOWN.
"""
import datetime

from ..core import whois as whois_mod
from ..core.http import get

NAME = "whois"
TITLE = "WHOIS — Owner Intelligence"

PHASES = ["IANA referral", "registry query", "admin & dates"]


def _days_left(datestr):
    """Days from now until a date string. None if unparsable."""
    if not datestr:
        return None
    text = datestr.strip()
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d", "%d-%b-%Y", "%Y-%m-%d %H:%M:%S"):
        try:
            d = datetime.datetime.strptime(text[:19], fmt)
            return (d - datetime.datetime.utcnow()).days
        except Exception:
            continue
    # ISO with timezone offset, e.g. 2030-01-01T00:00:00+00:00
    try:
        d = datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))
        now = datetime.datetime.now(datetime.timezone.utc)
        return (d - now).days
    except Exception:
        return None


def run(ctx):
    domain = ctx.get("domain") or ""
    findings = []
    data = {"domain": domain, "fields": {}, "nameservers": [],
            "servers_queried": [], "days_left": None,
            "admin": "UNKNOWN", "admin_source": None,
            "error": None}
    if not domain or "." not in domain or domain.startswith("127.") \
            or domain == "localhost":
        data["note"] = "Local test target — no public registration exists."
        return {"engine": NAME, "status": "completed",
                "findings": [], "data": data}
    result = whois_mod.whois_lookup(domain)
    data["fields"] = result.get("fields") or {}
    data["nameservers"] = result.get("nameservers") or []
    data["servers_queried"] = result.get("servers_queried") or []
    data["error"] = result.get("error")
    fields = data["fields"]
    if fields.get("expires"):
        data["days_left"] = _days_left(fields["expires"])
        if data["days_left"] is not None:
            if data["days_left"] < 0:
                findings.append({
                    "severity": "critical",
                    "name": "Domain registration EXPIRED",
                    "evidence": "expired %s" % str(fields["expires"])[:10],
                    "fix": "Renew the domain registration immediately."})
            elif data["days_left"] < 30:
                findings.append({
                    "severity": "medium",
                    "name": "Domain registration expires soon",
                    "evidence": "%d days left (expires %s)"
                                % (data["days_left"],
                                   str(fields["expires"])[:10]),
                    "fix": "Renew the domain registration before it "
                           "expires."})
    # Admin identity: public WHOIS organization only.
    org = fields.get("org") or fields.get("registrant")
    if org:
        data["admin"] = org
        data["admin_source"] = "public WHOIS organization"
    else:
        # Fallback: public security.txt contact (published by the
        # site itself). Content summary only — never a private contact.
        base = (ctx.get("url") or "").rstrip("/")
        r = get(base + "/.well-known/security.txt", timeout=8,
                max_bytes=20000)
        if r.get("status") == 200 and r.get("body"):
            for line in r["body"].splitlines():
                if line.lower().startswith("contact:"):
                    data["admin"] = line.split(":", 1)[1].strip()[:120]
                    data["admin_source"] = "public security.txt contact"
                    break
    if data["admin"] == "UNKNOWN":
        findings.append({
            "severity": "info",
            "name": "Admin identity UNKNOWN (not published)",
            "evidence": "WHOIS organization redacted/absent and no "
                        "public security.txt contact found",
            "fix": "No action — private admin identity is not public "
                   "information and must not be probed."})
    if data["error"] and not fields:
        return {"engine": NAME, "status": "error",
                "findings": findings, "data": data}
    return {"engine": NAME, "status": "completed",
            "findings": findings, "data": data}
