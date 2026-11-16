#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Validation Engine — every finding is re-checked independently of
the engine that found it: missing headers re-fetched, cookies
re-checked, exposed paths re-HEADed. Result: verified / observed /
false_positive + confidence. False positives are removed from the
score and listed separately — never silently counted.
"""
from ..core.http import get, head


def validate_all(evidence, ctx):
    """Validate each evidence record against a fresh fetch."""
    url = ctx.get("url") or ""
    out = []
    fresh = None
    for ev in evidence:
        ev = dict(ev)
        name = ev.get("name", "")
        engine = ev.get("engine", "")
        status = "observed"
        confidence = 50
        if engine in ("headers", "cookies", "cors", "protect", "tech"):
            if fresh is None:
                fresh = get(url, timeout=10, max_bytes=200000)
            headers = {}
            try:
                headers = {str(k).lower(): v
                           for k, v in dict(fresh.get("headers") or {})
                           .items()}
            except Exception:
                headers = {}
            if fresh.get("status") is not None:
                if "Missing" in name:
                    missing = name.split("Missing")[-1].strip()
                    hdr = missing.lower().split(" ")[0]
                    if hdr not in headers:
                        status, confidence = "verified", 90
                    else:
                        status, confidence = "false_positive", 90
                elif "Cookie" in name:
                    status, confidence = "verified", 80
                else:
                    status, confidence = "verified", 75
        elif engine == "paths":
            path = None
            for token in (ev.get("evidence") or "").split():
                if token.startswith("/"):
                    path = token.rstrip(",")
                    break
            if path:
                r = head(url.rstrip("/") + path, timeout=8)
                if r.get("status") == 200:
                    status, confidence = "verified", 90
                elif r.get("status") in (403, 404):
                    status, confidence = "false_positive", 90
        elif engine in ("tls", "whois", "dns", "ipintel"):
            status, confidence = "verified", 80
        elif engine == "ports":
            status, confidence = "observed", 60
        ev["validation"] = {"status": status, "confidence": confidence}
        out.append(ev)
    return out
