#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Correlation Engine — merges duplicate findings across engines
(one finding per problem) and detects attack chains no single
engine can see. Also records contradictions between engines.
"""
from ..core import scoring as scoring_mod


def correlate(evidence, results):
    """Deduplicate by finding name; detect chains and contradictions.
    Returns (findings, chains, contradictions)."""
    seen = {}
    findings = []
    for ev in evidence:
        key = ev.get("name")
        if key in seen:
            continue
        seen[key] = ev
        findings.append(ev)
    chains = []
    names = {f.get("name", "") for f in findings}
    has_cookie_no_secure = any("Cookie without Secure" in n for n in names)
    has_no_hsts = any("Strict-Transport-Security" in n for n in names)
    has_http = any("plain HTTP" in n for n in names)
    if has_cookie_no_secure and (has_no_hsts or has_http):
        chains.append({
            "severity": "high",
            "name": "Session hijack chain: cookie without Secure + "
                    "no HSTS / plain HTTP",
            "evidence": "A session cookie without the Secure flag on a "
                        "site without HSTS can be stolen on an insecure "
                        "network.",
            "fix": "Set Secure + HttpOnly + SameSite on all cookies, "
                   "serve HTTPS only and enable HSTS."})
    has_xss_csp = any("Content-Security-Policy" in n for n in names)
    has_cookie_no_httponly = any("Cookie without HttpOnly" in n
                                 for n in names)
    if has_xss_csp and has_cookie_no_httponly:
        chains.append({
            "severity": "high",
            "name": "XSS session-theft chain: no CSP + cookie without "
                    "HttpOnly",
            "evidence": "Without CSP, injected scripts run; without "
                        "HttpOnly they can read session cookies.",
            "fix": "Add a strict Content-Security-Policy and set "
                   "HttpOnly on every cookie."})
    has_config = any("exposed" in n.lower() and "config" in n.lower()
                     for n in names)
    has_git = any(".git" in n for n in names)
    if has_config and has_git:
        chains.append({
            "severity": "high",
            "name": "Source + secrets exposure chain: .git and config "
                    "files both public",
            "evidence": "Public .git plus public config files can expose "
                        "source code and credentials together.",
            "fix": "Block /.git/ and all config/dotfiles on the web "
                   "server and rotate any exposed credentials."})
    contradictions = []
    tls = (results.get("tls") or {}).get("data") or {}
    headers = (results.get("headers") or {}).get("data") or {}
    if tls.get("days_left") is not None and tls["days_left"] < 0:
        if "strict-transport-security" in (headers.get("headers_present")
                                           or []):
            contradictions.append(
                "HSTS is present but the TLS certificate is expired — "
                "browsers will still refuse the site.")
    return findings, chains, contradictions
