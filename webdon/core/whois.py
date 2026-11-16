#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WHOIS client — RFC 3912, plain TCP port 43, with referral following.

Public registration data only. The parser returns public fields
(registrar, creation/expiry dates, organization, country). Fields
that are redacted, privacy-protected or absent are returned as
None — the caller reports them as UNKNOWN, never guessed.

No secrets are ever requested or stored here.
"""
import re
import socket

IANA_SERVER = "whois.iana.org"
DEFAULT_TIMEOUT = 10

# Field labels we recognise, in priority order per logical field.
FIELD_PATTERNS = {
    "registrar": [r"Registrar:\s*(.+)", r"registrar:\s*(.+)",
                  r"Sponsoring Registrar:\s*(.+)"],
    "created": [r"Creation Date:\s*(.+)", r"Created On:\s*(.+)",
                r"Registered on:\s*(.+)", r"created:\s*(.+)"],
    "expires": [r"Registry Expiry Date:\s*(.+)",
                r"Registrar Registration Expiration Date:\s*(.+)",
                r"Expiry Date:\s*(.+)", r"Expiration Time:\s*(.+)",
                r"paid-till:\s*(.+)"],
    "updated": [r"Updated Date:\s*(.+)", r"Last Updated:\s*(.+)",
                r"changed:\s*(.+)"],
    "org": [r"Registrant Organization:\s*(.+)",
            r"Registrant Organisation:\s*(.+)",
            r"org:\s*(.+)", r"OrgName:\s*(.+)"],
    "registrant": [r"Registrant Name:\s*(.+)",
                   r"Registrant:\s*(.+)",
                   r"person:\s*(.+)"],
    "country": [r"Registrant Country:\s*(.+)",
                r"Registrant State/Province:.*\n.*Country:\s*(.+)",
                r"Country:\s*(.+)", r"country:\s*(.+)"],
    "status": [r"Domain Status:\s*(.+)", r"status:\s*(.+)"],
}

REDACTED_MARKERS = (
    "redacted for privacy", "privacy protected", "not disclosed",
    "redacted", "privacy service", "whois privacy", "data protected",
    "please query the rdds", "gdpr masked",
)


def _is_redacted(value):
    if not value:
        return True
    low = value.strip().lower()
    if not low or low in ("-", "--", "n/a", "none", "unknown"):
        return True
    return any(m in low for m in REDACTED_MARKERS)


def query_whois(server, query, timeout=DEFAULT_TIMEOUT):
    """One raw WHOIS query over TCP port 43. Returns text or ''."""
    try:
        sock = socket.create_connection((server, 43), timeout=timeout)
    except Exception:
        return ""
    try:
        sock.settimeout(timeout)
        sock.sendall((query + "\r\n").encode())
        chunks = []
        while True:
            try:
                data = sock.recv(4096)
            except Exception:
                break
            if not data:
                break
            chunks.append(data)
            if sum(len(c) for c in chunks) > 200000:
                break
        return b"".join(chunks).decode(errors="ignore")
    finally:
        try:
            sock.close()
        except Exception:
            pass


def parse_whois(text):
    """Parse public fields from raw WHOIS text.

    Returns {"fields": {...}, "nameservers": [...],
             "referral_server": str|None, "raw_lines": int}.
    Redacted values are returned as None (caller shows UNKNOWN).
    The raw text itself is NOT kept — only parsed public fields.
    """
    fields = {}
    for key, patterns in FIELD_PATTERNS.items():
        value = None
        for pat in patterns:
            m = re.search(pat, text or "", re.I | re.M)
            if m:
                value = m.group(1).strip()
                break
        if key == "status":
            values = re.findall(r"Domain Status:\s*(.+)", text or "", re.I)
            fields["status"] = [v.strip() for v in values][:6] or None
            continue
        if value is not None and _is_redacted(value):
            value = None
        fields[key] = value
    nameservers = []
    for m in re.finditer(r"Name Server:\s*(\S+)", text or "", re.I):
        ns = m.group(1).strip().lower()
        if ns not in nameservers:
            nameservers.append(ns)
    referral = None
    # Registrar replies use "Whois Server:"; IANA replies use
    # "whois:" (e.g. "whois: whois.verisign-grs.com" for .com).
    m = re.search(r"Whois Server:\s*(\S+)", text or "", re.I)
    if not m:
        m = re.search(r"^whois:\s*(\S+)", text or "", re.I | re.M)
    if m:
        referral = m.group(1).strip()
    return {"fields": fields, "nameservers": nameservers[:10],
            "referral_server": referral,
            "raw_lines": len((text or "").splitlines())}


def whois_lookup(domain, timeout=DEFAULT_TIMEOUT):
    """Full WHOIS lookup with referral following (max 2 hops).

    Returns {"domain", "fields", "nameservers", "servers_queried",
             "error"}. Never raises.
    """
    result = {"domain": domain, "fields": {}, "nameservers": [],
              "servers_queried": [], "error": None}
    if not domain or "." not in domain:
        result["error"] = "invalid domain"
        return result
    tld = domain.rsplit(".", 1)[-1].lower()
    text = query_whois(IANA_SERVER, tld, timeout=timeout)
    if not text:
        result["error"] = "whois.iana.org unreachable"
        return result
    result["servers_queried"].append(IANA_SERVER)
    parsed = parse_whois(text)
    server = parsed.get("referral_server")
    if not server:
        result["error"] = "no WHOIS server for .%s in IANA reply" % tld
        result["fields"] = parsed["fields"]
        result["nameservers"] = parsed["nameservers"]
        return result
    text2 = query_whois(server, domain, timeout=timeout)
    if not text2:
        result["error"] = "WHOIS server %s unreachable" % server
        return result
    result["servers_queried"].append(server)
    parsed2 = parse_whois(text2)
    # Follow one more referral (thick vs thin registry).
    referral2 = parsed2.get("referral_server")
    if referral2 and referral2 != server:
        text3 = query_whois(referral2, domain, timeout=timeout)
        if text3:
            result["servers_queried"].append(referral2)
            parsed3 = parse_whois(text3)
            for key, val in parsed3["fields"].items():
                if val and not parsed2["fields"].get(key):
                    parsed2["fields"][key] = val
            for ns in parsed3["nameservers"]:
                if ns not in parsed2["nameservers"]:
                    parsed2["nameservers"].append(ns)
    result["fields"] = parsed2["fields"]
    result["nameservers"] = parsed2["nameservers"]
    return result
