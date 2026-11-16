#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""subfinder — subdomains engine wrapper (v2.00 HIVE).

Thin wrapper around webdon.adapters.subfinder: when the external
binary is installed it runs it; otherwise the adapter falls back
to the built-in stdlib equivalent and says so honestly.
Scope-gated like every WEBDON engine.
"""
from ..adapters import subfinder as adapter_mod

NAME = "subfinder"
TITLE = "subfinder — subdomains"

PHASES = ['subdomain enumeration', 'wildcard check']


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
