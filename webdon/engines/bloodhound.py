#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""bloodhound — AD relationship/permission engine wrapper (v3.00 NET).

Thin wrapper around webdon.adapters.bloodhound. In a hive the
adapter reports bridge / not_applicable — BloodHound CE needs a
Neo4j server plus a SharpHound collection from a domain host.
Scope-gated like every WEBDON engine.
"""
from ..adapters import bloodhound as adapter_mod

NAME = "bloodhound"
TITLE = "bloodhound — AD relationships & permissions"

PHASES = ['AD indicator check', 'collection/bridge status']


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
