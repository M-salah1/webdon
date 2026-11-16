#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""netexec — Windows / AD assessment engine wrapper (v3.00 NET).

Thin wrapper around webdon.adapters.netexec. In a hive the
adapter only checks applicability (AD indicators present or
not) — it never runs NetExec automatically and never uses
credentials. The explicit opt-in run lives in the console
(`netexec run <ip>`) and is anonymous/guest only.
Scope-gated like every WEBDON engine.
"""
from ..adapters import netexec as adapter_mod

NAME = "netexec"
TITLE = "netexec — Windows / AD assessment"

PHASES = ['AD indicator check', 'opt-in status']


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
