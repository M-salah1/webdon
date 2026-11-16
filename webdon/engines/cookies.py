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

v5.1 COOKIE CONTEXT ANALYSIS — a cookie is classified by context
BEFORE it is judged, because the same missing flag means different
things for different cookies:

- session: name patterns sessionid / PHPSESSID / JSESSIONID /
  connect.sid (+ path /). Missing Secure = HIGH, missing
  HttpOnly = MEDIUM — a stolen session cookie is a stolen account.
- csrf: csrf / xsrf / _csrf_token. A CSRF cookie is MEANT to be
  read by JavaScript, so missing HttpOnly on it is EXPECTED and is
  NOT a finding — it is recorded informational with the
  explanation. (Missing Secure on HTTPS is still flagged, LOW.)
- tracking/analytics: _ga / _gid / _fbp / _gcl_au / _hj*. Missing
  Secure is flagged LOW only when set over plain HTTP (the real
  risk there is cleartext transport); over HTTPS it is not
  flagged. Missing HttpOnly is never flagged — analytics JS needs
  to read them.
- functional/preference: theme / lang / cart / prefs / settings.
  Low priority: missing Secure over HTTPS = LOW, HttpOnly never
  flagged (JS may need them).
- unknown: the old rules (Secure/Httponly medium, SameSite low).

NOTE on value shape: the task's "long random value shape" check
for session cookies is deliberately NOT done — cookie values are
never collected, so a value's shape can never be inspected. Name
+ path is what classifies a session cookie here.

Each cookie finding states its context and WHY the flag matters
(or doesn't) for that context, and remediation is per context.
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


SESSION_PATTERNS = ("sessionid", "phpsessid", "jsessionid",
                    "connect.sid", "sessid", "session_id", "sid")
CSRF_PATTERNS = ("csrf", "xsrf", "_csrf_token", "csrf_token",
                 "xsrf-token")
TRACKING_PATTERNS = ("_ga", "_gid", "_fbp", "_gcl_au", "_hj",
                     "_gat", "_ga_", "amp_", "__utm")
FUNCTIONAL_PATTERNS = ("theme", "lang", "locale", "cart",
                       "prefs", "preferences", "settings",
                       "timezone", "currency", "consent")


def classify_cookie(name, path=""):
    """Classify a cookie by context from its name (+ path).

    Returns one of: session / csrf / tracking / functional /
    unknown. Name patterns only — the value is never available
    (never collected), so value shape is not used.
    """
    low = (name or "").lower()
    for pat in CSRF_PATTERNS:
        if pat in low:
            return "csrf"
    for pat in SESSION_PATTERNS:
        if pat in low:
            return "session"
    for pat in TRACKING_PATTERNS:
        if pat in low:
            return "tracking"
    for pat in FUNCTIONAL_PATTERNS:
        if pat in low:
            return "functional"
    if (path or "") == "/" and low in ("sess", "auth", "token",
                                       "login"):
        return "session"
    return "unknown"


# Severity per (context, missing flag). None = do not flag.
CONTEXT_SEVERITY = {
    # session: Secure HIGH (hijack over HTTP), HttpOnly MEDIUM.
    ("session", "secure"): "high",
    ("session", "httponly"): "medium",
    ("session", "samesite"): "low",
    # csrf: HttpOnly is EXPECTED to be missing (JS must read it).
    ("csrf", "secure"): "low",
    ("csrf", "httponly"): None,
    ("csrf", "samesite"): "low",
    # tracking: Secure LOW only over plain HTTP; HttpOnly never.
    ("tracking", "secure_http"): "low",
    ("tracking", "httponly"): None,
    ("tracking", "samesite"): None,
    # functional: Secure LOW over HTTPS; HttpOnly never.
    ("functional", "secure"): "low",
    ("functional", "httponly"): None,
    ("functional", "samesite"): None,
    # unknown: the old rules.
    ("unknown", "secure"): "medium",
    ("unknown", "httponly"): "medium",
    ("unknown", "samesite"): "low",
}

WHY = {
    ("session", "secure"): "a session cookie without Secure can be "
        "stolen on any plain-HTTP request — a stolen session is a "
        "stolen account.",
    ("session", "httponly"): "a session cookie without HttpOnly can "
        "be read by injected JavaScript (XSS) — a stolen session is "
        "a stolen account.",
    ("session", "samesite"): "without SameSite a session cookie is "
        "sent on cross-site requests, enabling CSRF.",
    ("csrf", "secure"): "a CSRF token sent over plain HTTP can be "
        "intercepted, weakening the CSRF defence.",
    ("csrf", "httponly"): "a CSRF cookie is MEANT to be read by "
        "JavaScript (the page must send the token back) — missing "
        "HttpOnly is expected, not a vulnerability.",
    ("csrf", "samesite"): "without SameSite the CSRF token cookie is "
        "sent on cross-site requests.",
    ("tracking", "secure_http"): "set over plain HTTP, this tracking "
        "cookie travels in cleartext and can be read/modified on the "
        "network.",
    ("functional", "secure"): "a preference cookie without Secure "
        "can be sent over plain HTTP and tampered with.",
    ("unknown", "secure"): "without Secure this cookie can be sent "
        "over plain HTTP and stolen on the network.",
    ("unknown", "httponly"): "without HttpOnly this cookie can be "
        "read by injected JavaScript (XSS).",
    ("unknown", "samesite"): "without SameSite this cookie is sent "
        "on cross-site requests.",
}



def analyze_cookies(raw_headers, site_host="", https=True):
    """Parse many Set-Cookie lines. Returns (cookies, findings).

    Guaranteed value-free: no value from any header appears in the
    returned data or findings. Every cookie carries its `context`
    (session / csrf / tracking / functional / unknown) and every
    finding states that context and WHY the flag matters for it.
    CSRF cookies missing HttpOnly are NOT vulnerability findings —
    they are recorded as info findings (and in `context_notes` in
    run()) with the explanation.
    """
    cookies = []
    seen = set()
    findings = []
    context_notes = []
    for raw in raw_headers or []:
        cookie = parse_cookie_header(raw, site_host)
        if not cookie:
            continue
        key = (cookie["name"], cookie.get("domain") or "",
               cookie.get("path") or "")
        if key in seen:
            continue
        seen.add(key)
        cookie["context"] = classify_cookie(cookie["name"],
                                            cookie.get("path"))
        cookies.append(cookie)
        name = cookie["name"]
        ctx = cookie["context"]

        def _flag(flag, title, fix):
            sev = CONTEXT_SEVERITY.get((ctx, flag))
            if sev is None:
                return
            why = WHY.get((ctx, flag), "")
            findings.append({
                "severity": sev,
                "name": title,
                "evidence": "cookie %s (%s context) — %s"
                            % (name, ctx, why),
                "fix": fix,
                "cookie_context": ctx,
                "cookie_name": name})

        if not cookie["secure"] and https:
            _flag("secure", "Cookie without Secure flag",
                  "Set the Secure flag on %s (%s cookie) so it is "
                  "never sent over plain HTTP." % (name, ctx))
        elif not cookie["secure"] and not https                 and ctx == "tracking":
            # Tracking cookie set over plain HTTP: the cleartext
            # transport itself is the risk — flag it LOW.
            sev = CONTEXT_SEVERITY.get(("tracking", "secure_http"))
            if sev:
                findings.append({
                    "severity": sev,
                    "name": "Cookie without Secure flag",
                    "evidence": "cookie %s (tracking context) — %s"
                                % (name, WHY[("tracking",
                                              "secure_http")]),
                    "fix": "Serve the site over HTTPS and set the "
                           "Secure flag on %s." % name,
                    "cookie_context": ctx, "cookie_name": name})
        if not cookie["httponly"]:
            if ctx == "csrf":
                # EXPECTED: a CSRF cookie must be readable by JS.
                context_notes.append(
                    "CSRF cookie %s has no HttpOnly flag — expected: "
                    "the page's JavaScript must read the token to "
                    "send it back. Not a vulnerability." % name)
                findings.append({
                    "severity": "info",
                    "name": "CSRF cookie without HttpOnly "
                            "(expected — informational)",
                    "evidence": "cookie %s (csrf context) — %s"
                                % (name, WHY[("csrf", "httponly")]),
                    "fix": "No action — do NOT add HttpOnly to a "
                           "CSRF cookie; the page needs to read it.",
                    "cookie_context": ctx, "cookie_name": name})
            else:
                _flag("httponly", "Cookie without HttpOnly flag",
                      "Set the HttpOnly flag on %s (%s cookie) so "
                      "JavaScript cannot read it." % (name, ctx))
        if not cookie["samesite"]:
            _flag("samesite", "Cookie without SameSite attribute",
                  "Set SameSite=Lax (or Strict) on %s (%s cookie)."
                  % (name, ctx))
        if cookie["third_party"]:
            findings.append({"severity": "info",
                             "name": "Third-party cookie: %s" % name,
                             "evidence": "cookie %s domain %s"
                                         % (name, cookie.get("domain")),
                             "fix": "Review third-party cookies; remove "
                                    "any that are not needed.",
                             "cookie_context": ctx,
                             "cookie_name": name})
    return cookies, findings




NAME = "cookies"
TITLE = "Cookie Analysis"

PHASES = ["homepage cookies", "crawled-page cookies"]


def run(ctx):
    https = (ctx.get("url") or "").startswith("https://")
    host = ctx.get("host") or ""
    raw = list(ctx.get("cookie_headers") or [])
    cookies, findings = analyze_cookies(raw, host, https)
    context_notes = [
        f["evidence"] for f in findings
        if f.get("cookie_context") == "csrf"
        and f.get("severity") == "info"]
    by_context = {}
    for c in cookies:
        by_context[c["context"]] = by_context.get(c["context"], 0) + 1
    data = {"cookies": cookies, "count": len(cookies),
            "session_count": sum(1 for c in cookies if c["session"]),
            "third_party_count": sum(1 for c in cookies
                                     if c["third_party"]),
            "names": [c["name"] for c in cookies],
            "by_context": by_context,
            "context_notes": context_notes}
    return {"engine": NAME, "status": "completed",
            "findings": findings, "data": data}
