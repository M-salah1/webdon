#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Timeline engine — dated history from public facts only.

Events: domain creation/expiry (WHOIS), TLS certificate
notBefore/notAfter, earliest known facts. Each event carries its
source. Failed sources are reported as unknown, not absent.
"""
import datetime

NAME = "timeline"
TITLE = "Forensics Timeline"

PHASES = ["domain events", "certificate events"]


def _parse_date(text):
    if not text:
        return None
    text = str(text).strip()
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d", "%b %d %H:%M:%S %Y %Z"):
        try:
            return datetime.datetime.strptime(text[:19], fmt)
        except Exception:
            continue
    try:
        return datetime.datetime.fromisoformat(
            text.replace("Z", "+00:00")).replace(tzinfo=None)
    except Exception:
        return None


def build_timeline(whois_data, tls_data):
    """Build dated events from WHOIS + TLS data. Returns a list."""
    events = []
    fields = (whois_data or {}).get("fields") or {}
    for key, label in (("created", "Domain registered"),
                       ("updated", "Domain last updated"),
                       ("expires", "Domain expires")):
        d = _parse_date(fields.get(key))
        if d:
            events.append({"date": d.strftime("%Y-%m-%d"),
                           "event": label,
                           "source": "WHOIS",
                           "value": str(fields.get(key))[:30]})
    cert = (tls_data or {}).get("cert") or {}
    for key, label in (("not_before", "TLS certificate issued"),
                       ("not_after", "TLS certificate expires")):
        d = _parse_date(cert.get(key))
        if d:
            events.append({"date": d.strftime("%Y-%m-%d"),
                           "event": label,
                           "source": "TLS certificate",
                           "value": str(cert.get(key))[:30]})
    events.sort(key=lambda e: e["date"])
    return events


def run(ctx):
    whois_data = ctx.get("whois") or {}
    tls_data = ctx.get("tls") or {}
    events = build_timeline(whois_data, tls_data)
    data = {"events": events, "event_count": len(events)}
    findings = []
    if not events:
        findings.append({"severity": "info",
                         "name": "No dated public events found",
                         "evidence": "WHOIS and TLS gave no usable dates",
                         "fix": "No action — the timeline is empty because "
                                "the sources gave no dates, not because "
                                "nothing happened."})
    return {"engine": NAME, "status": "completed",
            "findings": findings, "data": data}
