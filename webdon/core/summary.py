#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Executive Summary — one short, honest summary per scan.

Built from the finished scan dict only (never re-fetches anything):
score + grade, the four separate metrics, the owner (public records
only — UNKNOWN when redacted or unavailable), the top 5 verified
findings with their fix, and the top 3 priority actions. Stored on
the scan as scan["summary"] and re-printable from SQLite history
with the console command `summary <id>`.
"""
import time

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _owner_block(scan):
    results = scan.get("results") or {}
    whois = (results.get("whois") or {}).get("data") or {}
    tls = (results.get("tls") or {}).get("data") or {}
    assets = scan.get("assets") or {}
    fields = whois.get("fields") or {}
    return {
        "registrar": fields.get("registrar") or assets.get("registrar")
                     or "UNKNOWN",
        "registrant": fields.get("org") or fields.get("registrant")
                      or assets.get("registrant") or "UNKNOWN",
        "country": fields.get("country") or "UNKNOWN",
        "domain": scan.get("domain") or "UNKNOWN",
        "domain_expires": fields.get("expires")
                          or assets.get("domain_expires") or "UNKNOWN",
        "domain_days_left": whois.get("days_left")
                            if whois.get("days_left") is not None
                            else assets.get("domain_days_left"),
        "cert_days_left": tls.get("days_left")
                          if tls.get("days_left") is not None
                          else assets.get("cert_days_left"),
        "ip_country": assets.get("ip_country") or "UNKNOWN",
        "ip_hosting": assets.get("ip_hosting") or "UNKNOWN",
    }


def build_summary(scan):
    """Build the executive summary dict for a finished scan."""
    findings = list(scan.get("findings") or [])
    actionable = [f for f in findings if f.get("severity") != "info"]
    actionable.sort(key=lambda f: (
        SEV_ORDER.get(f.get("severity"), 5),
        0 if f.get("confirmation") == "confirmed" else 1))
    top = actionable[:5]
    actions = []
    for f in top:
        fix = (f.get("fix") or "").strip()
        if fix and fix not in actions:
            actions.append(fix)
    for fix in (scan.get("recommendations") or []):
        if len(actions) >= 3:
            break
        if fix and fix not in actions:
            actions.append(fix)
    actions = actions[:3]
    metrics = scan.get("metrics") or {}
    coverage = scan.get("coverage") or {}
    summary = {
        "tool": scan.get("tool", "WEBDON v1.00"),
        "target": scan.get("target"),
        "profile": scan.get("profile"),
        "score": scan.get("score"),
        "grade": scan.get("grade"),
        "metrics": {
            "security_score": metrics.get("security_score",
                                          scan.get("score")),
            "confidence": metrics.get("confidence",
                                      scan.get("confidence")),
            "coverage_percent": metrics.get(
                "coverage_percent", coverage.get("percent")),
            "verification_rate": metrics.get("verification_rate"),
        },
        "owner": _owner_block(scan),
        "counts": scan.get("severity_distribution") or {},
        "top_findings": [
            {"severity": f.get("severity"),
             "confirmation": f.get("confirmation"),
             "name": f.get("name"),
             "evidence": (f.get("evidence") or "")[:160],
             "fix": f.get("fix") or ""} for f in top],
        "priority_actions": actions,
        "limits": scan.get("limits") or {},
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                      time.gmtime()),
    }
    return summary


def format_summary(summary, lang="en"):
    """Plain-text rendering of a summary dict."""
    lines = ["=" * 60,
             "WEBDON v1.00 — Executive Summary",
             "Target: %s   Profile: %s" % (
                 summary.get("target"), summary.get("profile"))]
    score = summary.get("score")
    lines.append("Score: %s   Grade: %s" % (
        "INCOMPLETE" if score is None else "%s%%" % score,
        summary.get("grade")))
    m = summary.get("metrics") or {}
    lines.append("Security Score: %s | Confidence: %s%% | Coverage: %s%% "
                 "| Verification Rate: %s%%" % (
                     m.get("security_score"), m.get("confidence"),
                     m.get("coverage_percent"),
                     m.get("verification_rate")))
    o = summary.get("owner") or {}
    lines.append("Owner: registrar=%s | registrant=%s | country=%s | "
                 "domain expires=%s (%s days left) | cert days left=%s" % (
                     o.get("registrar"), o.get("registrant"),
                     o.get("country"), o.get("domain_expires"),
                     o.get("domain_days_left"), o.get("cert_days_left")))
    lines.append("IP: country=%s | hosting=%s" % (
        o.get("ip_country"), o.get("ip_hosting")))
    lines.append("Findings: %s" % (
        ", ".join("%s=%d" % (k, v)
                  for k, v in (summary.get("counts") or {}).items() if v)
        or "0"))
    lines.append("-" * 60)
    lines.append("Top findings:")
    if summary.get("top_findings"):
        for f in summary["top_findings"]:
            lines.append("  [%s|%s] %s" % (
                (f.get("severity") or "").upper(),
                f.get("confirmation") or "indicator", f.get("name")))
            lines.append("      Fix: %s" % f.get("fix"))
    else:
        lines.append("  (no actionable findings)")
    lines.append("Priority actions:")
    if summary.get("priority_actions"):
        for a in summary["priority_actions"]:
            lines.append("  • %s" % a)
    else:
        lines.append("  (none)")
    lines.append("=" * 60)
    return "\n".join(lines)
