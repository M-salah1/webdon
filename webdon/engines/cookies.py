#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cookies engine — full cookie inventory, names and flags only.

Every Set-Cookie header from the homepage and every crawled page
is parsed into: name, Secure / HttpOnly / SameSite flags, domain,
path, expiry, session vs persistent, first-party vs third-party.

Cookie VALUES are NEVER collected, shown or stored. The parser
splits off the value and discards it immediately; only the name
survives. Any test value (e.g. "abc123") must never appear in any
output of this engine.
"""


def parse_cookie_header(raw, site_host=""):
    """Parse ONE Set-Cookie header line into a value-free record.

    Returns {"name", "secure", "httponly", "samesite", "domain",
             "path", "expires", "max_age", "session",
             "third_party"}. The value is discarded, never returned.
    """
    parts = [p.strip() for p in (raw or "").split(";")]
    if not parts or "=" not in parts[0]:
        return None
    name = parts[0].split("=", 1)[0].strip()
    if not name:
        return None
    flags = [p.lower() for p in parts[1:]]

    def _attr(attr):
        for p in flags:
            if p.startswith(attr + "="):
                return p.split("=", 1)[1].strip()
        return None

    domain = _attr("domain")
    third = False
    if domain and site_host:
        host = site_host.lower().lstrip(".")
        dom = domain.lower().lstrip(".")
        third = not (host == dom or host.endswith("." + dom)
                     or dom.endswith("." + host))
    return {"name": name,
            "secure": any(p == "secure" for p in flags),
            "httponly": any(p == "httponly" for p in flags),
            "samesite": _attr("samesite"),
            "domain": domain, "path": _attr("path"),
            "expires": _attr("expires"), "max_age": _attr("max-age"),
            "session": _attr("expires") is None
                       and _attr("max-age") is None,
            "third_party": third}


def analyze_cookies(raw_headers, site_host="", https=True):
    """Parse many Set-Cookie lines. Returns (cookies, findings).

    Guaranteed value-free: no value from any header appears in the
    returned data or findings.
    """
    cookies = []
    seen = set()
    findings = []
    for raw in raw_headers or []:
        cookie = parse_cookie_header(raw, site_host)
        if not cookie:
            continue
        key = (cookie["name"], cookie.get("domain") or "",
               cookie.get("path") or "")
        if key in seen:
            continue
        seen.add(key)
        cookies.append(cookie)
        name = cookie["name"]
        if not cookie["secure"] and https:
            findings.append({"severity": "medium",
                             "name": "Cookie without Secure flag",
                             "evidence": "cookie %s" % name,
                             "fix": "Set the Secure flag on every cookie."})
        if not cookie["httponly"]:
            findings.append({"severity": "medium",
                             "name": "Cookie without HttpOnly flag",
                             "evidence": "cookie %s" % name,
                             "fix": "Set the HttpOnly flag so JavaScript "
                                    "cannot read the cookie."})
        if not cookie["samesite"]:
            findings.append({"severity": "low",
                             "name": "Cookie without SameSite attribute",
                             "evidence": "cookie %s" % name,
                             "fix": "Set SameSite=Lax (or Strict) on "
                                    "cookies."})
        if cookie["third_party"]:
            findings.append({"severity": "info",
                             "name": "Third-party cookie: %s" % name,
                             "evidence": "cookie %s domain %s"
                                         % (name, cookie.get("domain")),
                             "fix": "Review third-party cookies; remove "
                                    "any that are not needed."})
    return cookies, findings


NAME = "cookies"
TITLE = "Cookie Analysis"

PHASES = ["homepage cookies", "crawled-page cookies"]


def run(ctx):
    https = (ctx.get("url") or "").startswith("https://")
    host = ctx.get("host") or ""
    raw = list(ctx.get("cookie_headers") or [])
    cookies, findings = analyze_cookies(raw, host, https)
    data = {"cookies": cookies, "count": len(cookies),
            "session_count": sum(1 for c in cookies if c["session"]),
            "third_party_count": sum(1 for c in cookies
                                     if c["third_party"]),
            "names": [c["name"] for c in cookies]}
    return {"engine": NAME, "status": "completed",
            "findings": findings, "data": data}
