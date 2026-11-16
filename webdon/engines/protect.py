#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Protections engine — detect WAF / CDN / rate-limit presence.

Presence-only detection from response headers and server banners:
Cloudflare, Akamai, Sucuri, Imperva/Incapsula, AWS CloudFront,
Fastly, ModSecurity, rate-limit headers (X-RateLimit-*, Retry-After),
CSP and HSTS.

NO bypass testing, NO payloads, NO exploitation — the tool reports
that a protection exists; it never tries to get around it.
"""

NAME = "protect"
TITLE = "Protection Detection (WAF/CDN)"

PHASES = ["WAF/CDN fingerprint", "rate-limit & policy headers"]

WAF_SIGNS = [
    ("cf-ray", "Cloudflare (CDN/WAF)"),
    ("cf-cache-status", "Cloudflare (CDN/WAF)"),
    ("x-sucuri-id", "Sucuri WAF"),
    ("x-sucuri-cache", "Sucuri WAF"),
    ("x-iinfo", "Incapsula / Imperva WAF"),
    ("x-cdn", "CDN (generic)"),
    ("x-akamai-transformed", "Akamai CDN/WAF"),
    ("x-amz-cf-id", "AWS CloudFront CDN"),
    ("x-amz-cf-pop", "AWS CloudFront CDN"),
    ("x-fastly-request-id", "Fastly CDN"),
    ("x-mod-security", "ModSecurity WAF"),
    ("x-protected-by", "WAF (generic)"),
    ("server", None),  # handled separately (cloudflare server value)
]

RATE_LIMIT_HEADERS = ["x-ratelimit-limit", "x-ratelimit-remaining",
                      "x-ratelimit-reset", "retry-after",
                      "ratelimit-limit", "ratelimit-remaining"]


def detect_protections(headers):
    """Pure detection from a lower-cased header dict.

    Returns (protections, findings, data).
    """
    protections = []
    findings = []
    for header, label in WAF_SIGNS:
        if header in headers:
            if label is None:
                continue
            if label not in protections:
                protections.append(label)
    server = headers.get("server", "")
    if "cloudflare" in server.lower() and \
            "Cloudflare (CDN/WAF)" not in protections:
        protections.append("Cloudflare (CDN/WAF)")
    if "sucuri" in server.lower() and "Sucuri WAF" not in protections:
        protections.append("Sucuri WAF")
    if "akamai" in server.lower() and "Akamai CDN/WAF" not in protections:
        protections.append("Akamai CDN/WAF")
    rate = [h for h in RATE_LIMIT_HEADERS if h in headers]
    has_csp = "content-security-policy" in headers
    has_hsts = "strict-transport-security" in headers
    data = {"protections": protections,
            "rate_limit_headers": rate,
            "has_csp": has_csp, "has_hsts": has_hsts}
    if protections:
        findings.append({"severity": "info",
                         "name": "Protection detected: %s"
                                 % ", ".join(protections),
                         "evidence": "headers: %s" % ", ".join(
                             h for h, _ in WAF_SIGNS if h in headers),
                         "fix": "Protections are present — no bypass is "
                                "tested by this tool."})
    else:
        findings.append({"severity": "low",
                         "name": "No WAF/CDN detected in headers",
                         "evidence": "no known WAF/CDN header present",
                         "fix": "Consider a WAF/CDN in front of the site "
                                "if it faces the public internet."})
    if rate:
        findings.append({"severity": "info",
                         "name": "Rate-limit headers present",
                         "evidence": "headers: %s" % ", ".join(rate),
                         "fix": "Keep rate limiting enabled on login and "
                                "API endpoints."})
    else:
        findings.append({"severity": "low",
                         "name": "No rate-limit headers seen",
                         "evidence": "no X-RateLimit-* or Retry-After "
                                     "header on the homepage",
                         "fix": "Add rate limiting (and its headers) on "
                                "sensitive endpoints."})
    return protections, findings, data


def run(ctx):
    if ctx.get("status") is None:
        return {"engine": NAME, "status": "error",
                "findings": [],
                "data": {"error": "homepage unreachable"}}
    headers = ctx.get("headers") or {}
    _protections, findings, data = detect_protections(headers)
    return {"engine": NAME, "status": "completed",
            "findings": findings, "data": data}
