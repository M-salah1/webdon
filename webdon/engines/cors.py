#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CORS engine — analyse CORS headers only.

Reads Access-Control-Allow-Origin / Allow-Credentials /
Allow-Methods / Allow-Headers from the live response and reports
risky combinations (wildcard origin + credentials is the classic
one). Header analysis only — no exploit attempts, no cross-origin
requests are ever sent.
"""

NAME = "cors"
TITLE = "CORS Analysis"

PHASES = ["CORS header analysis"]


def analyze_cors(headers):
    """Pure analysis of a lower-cased header dict.

    Returns (findings, data).
    """
    findings = []
    origin = headers.get("access-control-allow-origin")
    creds = headers.get("access-control-allow-credentials")
    methods = headers.get("access-control-allow-methods")
    hdrs = headers.get("access-control-allow-headers")
    data = {"allow_origin": origin,
            "allow_credentials": creds,
            "allow_methods": methods,
            "allow_headers": hdrs,
            "cors_enabled": origin is not None}
    if origin == "*" and creds and creds.strip().lower() == "true":
        findings.append({"severity": "high",
                         "name": "CORS: wildcard origin with credentials",
                         "evidence": "Access-Control-Allow-Origin: * + "
                                     "Allow-Credentials: true",
                         "fix": "Never combine Access-Control-Allow-Origin: "
                                "* with Allow-Credentials: true. Echo back "
                                "only trusted origins."})
    elif origin == "*":
        findings.append({"severity": "medium",
                         "name": "CORS: wildcard origin allows any site",
                         "evidence": "Access-Control-Allow-Origin: *",
                         "fix": "Restrict Access-Control-Allow-Origin to "
                                "the trusted origins that need it."})
    elif origin:
        findings.append({"severity": "info",
                         "name": "CORS restricted to one origin",
                         "evidence": "Access-Control-Allow-Origin: %s"
                                     % origin[:80],
                         "fix": "Keep the origin list minimal and review "
                                "it regularly."})
    if creds and creds.strip().lower() == "true" and origin \
            and origin != "*":
        findings.append({"severity": "info",
                         "name": "CORS allows credentials for one origin",
                         "evidence": "Allow-Credentials: true for %s"
                                     % origin[:80],
                         "fix": "Make sure that origin is fully trusted; "
                                "credentials are shared with it."})
    return findings, data


def run(ctx):
    if ctx.get("status") is None:
        return {"engine": NAME, "status": "error",
                "findings": [],
                "data": {"error": "homepage unreachable"}}
    headers = ctx.get("headers") or {}
    findings, data = analyze_cors(headers)
    return {"engine": NAME, "status": "completed",
            "findings": findings, "data": data}
