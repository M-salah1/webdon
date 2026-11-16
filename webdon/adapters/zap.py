#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ZAP bridge — export a ZAP context + scan plan for a PC (v3.00).

Full OWASP ZAP is a Java application: it is best on a computer,
not practical on ARM64 Termux. WEBDON never pretends ZAP ran:
  * `zap export <url>` always works — writes a context file +
    a step-by-step plan to run on a PC.
  * `zap run <url>` only runs when zap.sh / zap is actually
    installed; otherwise it reports honestly and gives the PC steps.
"""
import json
import os

from . import adapter_result, is_installed, require_scope, run_cmd

NAME = "zap"
TITLE = "ZAP bridge — PC scan plan"
BINARY = "zap.sh"

PC_STEPS = [
    "On a PC: install OWASP ZAP (Java 11+) from the official "
    "ZAP download page.",
    "Import webdon-zap-context.json (File > Import Context) or open "
    "the target URL in ZAP.",
    "Run the Automated Scan (Attack > Automated Scan) or the "
    "baseline: zap.sh -cmd -quickurl <url> -quickout zap-report.html",
    "Review ZAP alerts and fix them; re-run WEBDON hive to confirm.",
]


def detect():
    """Return the ZAP binary path if installed, else None."""
    for cand in ("zap.sh", "zap", "zaproxy"):
        path = is_installed(cand)
        if path:
            return cand
    return None


def export_plan(url, out_dir=".", scope_host=""):
    """Write context + plan files. Returns (context_path, plan_path)."""
    ctx = {"tool": "WEBDON v3.00 HIVE - ZAP bridge",
           "target": url, "scope_host": scope_host,
           "include": [url + "/*"],
           "exclude": [],
           "plan": ["spider", "active-scan-baseline"],
           "note": "Run this plan in OWASP ZAP on a PC; ZAP is not "
                   "practical on ARM64 Termux."}
    ctx_path = os.path.join(out_dir, "webdon-zap-context.json")
    with open(ctx_path, "w", encoding="utf-8") as f:
        json.dump(ctx, f, ensure_ascii=False, indent=2)
    plan_path = os.path.join(out_dir, "webdon-zap-plan.md")
    with open(plan_path, "w", encoding="utf-8") as f:
        f.write("# WEBDON - ZAP scan plan for %s\n\n" % url)
        for i, step in enumerate(PC_STEPS, 1):
            f.write("%d. %s\n" % (i, step))
    return ctx_path, plan_path


def run(ctx, timeout=600, runner=run_cmd):
    """Run ZAP only if it is really installed; else honest report."""
    require_scope(ctx)
    binary = detect()
    if not binary:
        return adapter_result(
            NAME, "not_installed", [],
            {"note": "OWASP ZAP is not installed here; full ZAP is "
                     "best on a PC (Java) and not practical on ARM64 "
                     "Termux - use: zap export <url>, then follow "
                     "webdon-zap-plan.md on a PC",
             "pc_steps": PC_STEPS})
    url = ctx.get("url", "")
    rc, out, err = runner(
        [binary, "-cmd", "-quickurl", url, "-quickout",
         "webdon-zap-report.html"], timeout=timeout)
    if rc == -1:
        return adapter_result(NAME, "error", [],
                              {"error": err or "zap timed out"})
    return adapter_result(NAME, "completed", [],
                          {"report": "webdon-zap-report.html", "rc": rc,
                           "note": "ZAP baseline report written; "
                                   "review its alerts in the HTML file"})
