#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""wireshark — traffic analysis engine wrapper (v3.00 NET).

Thin wrapper around webdon.adapters.wireshark: a bounded tshark
capture of the user's own traffic to the target when capture is
permitted, otherwise an honest fallback to WEBDON's own request
log. Scope-gated like every WEBDON engine.
"""
from ..adapters import wireshark as adapter_mod

NAME = "wireshark"
TITLE = "wireshark (tshark) — traffic analysis"

PHASES = ['traffic capture', 'DNS/TLS/HTTP analysis']


def run(ctx):
    if not ctx.get("authorized"):
        return {"engine": NAME, "status": "not_tested",
                "findings": [], "data": {"note": "needs authorization"}}
    try:
        res = adapter_mod.run(ctx)
    except PermissionError:
        return {"engine": NAME, "status": "not_tested",
                "findings": [], "data": {"note": "needs authorization"}}
    except Exception as exc:
        return {"engine": NAME, "status": "error",
                "findings": [], "data": {"error": str(exc)[:200]}}
    return {"engine": NAME, "status": res.get("status", "completed"),
            "findings": res.get("findings") or [],
            "data": res.get("data") or {}}
