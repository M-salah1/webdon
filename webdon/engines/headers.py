#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Security Headers engine — full inventory of response headers.

Checks the presence and the strength of every common security
header (CSP, HSTS, X-Frame-Options, X-Content-Type-Options,
Referrer-Policy, Permissions-Policy, Cross-Origin-*, Expect-CT)
and reports missing/weak ones with fixes. Presence-only analysis
of the live response — no payloads, no bypass attempts.
"""
import re

NAME = "headers"
TITLE = "Security Headers"

PHASES = ["header inventory", "weak-value analysis"]

HEADER_CHECKS = [
    ("content-security-policy", "high",
     "Missing Content-Security-Policy",
     "Add a Content-Security-Policy header that only allows trusted sources."),
    ("strict-transport-security", "medium",
     "Missing Strict-Transport-Security (HSTS)",
     "Add Strict-Transport-Security: max-age=31536000; includeSubDomains."),
    ("x-frame-options", "medium",
     "Missing X-Frame-Options (clickjacking protection)",
     "Add X-Frame-Options: SAMEORIGIN (or frame-ancestors in CSP)."),
    ("x-content-type-options", "low",
     "Missing X-Content-Type-Options",
     "Add X-Content-Type-Options: nosniff."),
    ("referrer-policy", "low",
     "Missing Referrer-Policy",
     "Add Referrer-Policy: strict-origin-when-cross-origin."),
    ("permissions-policy", "low",
     "Missing Permissions-Policy",
     "Add a Permissions-Policy header disabling unused features."),
    ("cross-origin-opener-policy", "low",
     "Missing Cross-Origin-Opener-Policy",
     "Add Cross-Origin-Opener-Policy: same-origin."),
    ("cross-origin-resource-policy", "low",
     "Missing Cross-Origin-Resource-Policy",
     "Add Cross-Origin-Resource-Policy: same-origin."),
]


def _finding(sev, name, evidence, fix):
    return {"severity": sev, "name": name, "evidence": evidence, "fix": fix}


def analyze_headers(headers, url=""):
    """Pure analysis of a lower-cased header dict.

    Returns (findings, data). Used by the engine and the tests.
    """
    findings = []
    data = {"headers_present": [], "headers_missing": [],
            "headers_seen": sorted(headers.keys()),
            "https": (url or "").startswith("https://")}
    for name, sev, title, fix in HEADER_CHECKS:
        if name in headers:
            data["headers_present"].append(name)
        else:
            data["headers_missing"].append(name)
            findings.append(_finding(sev, title, "header %s absent" % name,
                                     fix))
    csp = headers.get("content-security-policy", "")
    if csp and ("unsafe-inline" in csp or "unsafe-eval" in csp
                or "*" in csp):
        findings.append(_finding(
            "medium", "Weak Content-Security-Policy",
            "CSP allows unsafe-inline / unsafe-eval / wildcard sources",
            "Remove unsafe-inline, unsafe-eval and * from the CSP; "
            "use nonces or hashes for inline scripts."))
        data["csp_weak"] = True
    hsts = headers.get("strict-transport-security", "")
    if hsts:
        m = re.search(r"max-age=(\d+)", hsts)
        if m and int(m.group(1)) < 31536000:
            findings.append(_finding(
                "low", "Short HSTS max-age",
                "max-age=%s (under one year)" % m.group(1),
                "Raise max-age to 31536000 and add includeSubDomains."))
        data["hsts"] = hsts
    xfo = headers.get("x-frame-options", "")
    if xfo and xfo.strip().upper() not in ("DENY", "SAMEORIGIN"):
        findings.append(_finding(
            "low", "Weak X-Frame-Options value",
            "X-Frame-Options: %s" % xfo[:60],
            "Use X-Frame-Options: DENY or SAMEORIGIN."))
    server = headers.get("server", "")
    if server and re.search(r"/\d", server):
        findings.append(_finding(
            "low", "Server version disclosed",
            "Server: %s" % server[:80],
            "Hide the version: ServerTokens Prod (Apache) or "
            "server_tokens off (Nginx)."))
        data["server_header"] = server
    powered = headers.get("x-powered-by", "")
    if powered:
        findings.append(_finding(
            "low", "Technology disclosed via X-Powered-By",
            "X-Powered-By: %s" % powered[:80],
            "Remove the X-Powered-By header."))
        data["x_powered_by"] = powered
    if not data["https"]:
        findings.append(_finding(
            "high", "Site served over plain HTTP",
            url, "Redirect all traffic to HTTPS and enable HSTS."))
    return findings, data


def run(ctx):
    if ctx.get("status") is None:
        return {"engine": NAME, "status": "error",
                "findings": [],
                "data": {"error": "homepage unreachable"}}
    headers = ctx.get("headers") or {}
    findings, data = analyze_headers(headers, ctx.get("url") or "")
    return {"engine": NAME, "status": "completed",
            "findings": findings, "data": data}
