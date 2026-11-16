#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""openvas — system vulnerability assessment engine wrapper (v3.00 NET).

Thin wrapper around webdon.adapters.openvas: the built-in
outdated-service banner heuristic always runs; the real
OpenVAS/GVM server is a bridge (export a task for a PC/server).
Scope-gated like every WEBDON engine.
"""
from ..adapters import openvas as adapter_mod

NAME = "openvas"
TITLE = "openvas — system vulnerability assessment"

PHASES = ['outdated-service heuristic', 'GVM bridge status']


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
