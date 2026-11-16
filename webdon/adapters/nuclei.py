#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Nuclei adapter — template-based vulnerability detection (v2.00).

Runs the real Nuclei binary when installed, in detection-only
mode: `-severity low,medium,high,critical -exclude-tags dos
-rate-limit 50`. DoS / destructive tags are always excluded and
the argument builder is tested for that. JSONL output is parsed
into unified findings; raw request/response bodies are never kept.

Fallback when Nuclei is not installed: status
"not_installed (fallback)" — the built-in WEBDON engines (headers,
paths, cookies, TLS, CORS) already cover misconfiguration
detection, and the adapter says so instead of inventing results.
"""
from . import (NOT_INSTALLED, adapter_result, finding, is_installed,
               require_scope, run_cmd)

NAME = "nuclei"
TITLE = "Nuclei — template detection"
BINARY = "nuclei"

SEVERITY_MAP = {"critical": "critical", "high": "high",
                "medium": "medium", "low": "low", "info": "info"}


def build_args(url):
    """Exact argv for a detection-only Nuclei run. DoS tags excluded."""
    return [BINARY, "-u", url,
            "-severity", "low,medium,high,critical",
            "-exclude-tags", "dos",
            "-rate-limit", "50",
            "-jsonl", "-silent"]


def parse_jsonl(text):
    """Parse Nuclei JSONL output into unified findings.

    Only template-id, severity, name and matched host are kept.
    `request` / `response` / `curl-command` fields are dropped by
    the sanitizer — a matched template never leaks a body here.
    """
    findings = []
    templates = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            import json
            item = json.loads(line)
        except Exception:
            continue
        info = item.get("info") or {}
        tid = str(item.get("template-id") or info.get("name") or "unknown")
        sev = SEVERITY_MAP.get(
            str(info.get("severity", "info")).lower(), "info")
        templates.append(tid)
        findings.append(finding(
            sev, "Nuclei: %s" % tid,
            "template %s matched on %s"
            % (tid, str(item.get("host") or item.get("matched-at")
                       or "")[:120]),
            "Review template %s and fix the reported issue on the "
            "target; re-run to confirm." % tid,
            confirmation="confirmed" if sev in ("critical", "high")
            else "indicator"))
    return findings, templates


def run(ctx, timeout=180, runner=run_cmd):
    """Run Nuclei for ctx['url'] (scope-gated). Returns adapter result."""
    require_scope(ctx)
    url = ctx.get("url", "")
    if not is_installed(BINARY):
        return adapter_result(
            NAME, NOT_INSTALLED, [],
            {"note": "nuclei is not installed; fallback: built-in "
                     "WEBDON engines (headers, paths, cookies, TLS, "
                     "CORS) already ran misconfiguration detection",
             "install": "tools install nuclei"})
    rc, out, err = runner(build_args(url), timeout=timeout)
    if rc == -1:
        return adapter_result(NAME, "error", [],
                              {"error": err or "nuclei timed out"})
    findings, templates = parse_jsonl(out)
    return adapter_result(
        NAME, "completed", findings,
        {"templates_matched": len(templates),
         "templates": sorted(set(templates))[:50],
         "stderr": (err or "")[:200]})
