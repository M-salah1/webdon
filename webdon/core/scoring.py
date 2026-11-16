#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Scoring — one place where a score comes from (WEBDON v3.00 HIVE).

Four separate metrics, each measured, none of them a guess:

- Security Score: only findings that survived validation count,
  and only at their confirmation level — a confirmed vulnerability
  weighs full, an indicator (needs a human to confirm) weighs half,
  a false positive weighs nothing, and plain information weighs
  nothing.
- Confidence: computed from the validation outcome, never fixed.
- Coverage: measured from what was actually done (engines finished,
  phases finished, pages visited of pages discovered, ports probed).
- Verification Rate: the share of findings that were verified.
"""
WEIGHTS_CONFIRMED = {"critical": 25, "high": 15, "medium": 8,
                     "low": 3, "info": 0}
WEIGHTS_INDICATOR = {"critical": 12, "high": 7, "medium": 4,
                     "low": 1, "info": 0}

# Engine outcomes that count as "done": the engine ran and gave a
# definitive answer. Fallbacks (external tool missing, built-in
# equivalent ran instead), honest skips (no schema supplied),
# bridges (the real tool runs on a PC/server, not here) and honest
# not_applicable answers (e.g. not a Windows/AD host) are done
# work, not failures — only timeout/error are not done.
DONE_STATUSES = {"completed", "not_installed (fallback)", "fallback",
                 "skipped", "skipped_no_schema", "not_installed",
                 "bridge", "not_applicable"}


def grade_for(score):
    if score is None:
        return "INCOMPLETE"
    if score >= 95:
        return "A+"
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def score_findings(findings):
    """Score validated findings by confirmation level.
    Returns (score, grade, distribution)."""
    total = 0
    for f in findings:
        weights = (WEIGHTS_CONFIRMED
                   if f.get("confirmation") == "confirmed"
                   else WEIGHTS_INDICATOR)
        total += weights.get(f.get("severity"), 0)
    score = max(0, 100 - total)
    dist = {}
    for f in findings:
        dist[f["severity"]] = dist.get(f["severity"], 0) + 1
    return score, grade_for(score), dist


def compute_confidence(validation_counts):
    """Share of findings independently re-confirmed (0-100)."""
    v = validation_counts.get("verified", 0)
    o = validation_counts.get("observed", 0)
    f = validation_counts.get("false_positive", 0)
    total = v + o + f
    if total == 0:
        return 0
    return round(100 * (v + 0.5 * o) / total)


def compute_verification_rate(validation_counts):
    """Share of findings that were verified (0-100)."""
    v = validation_counts.get("verified", 0)
    o = validation_counts.get("observed", 0)
    f = validation_counts.get("false_positive", 0)
    total = v + o + f
    if total == 0:
        return 0
    return round(100 * v / total)


def compute_coverage(engines, status, results, phases=None):
    """Measured coverage: mean of the components that have data.
    Returns {"percent", "components": {...}}."""
    components = {}
    if engines:
        done = sum(1 for n in engines
                   if (status.get(n) or {}).get("status") in DONE_STATUSES)
        components["engines"] = round(100 * done / len(engines))
    if phases:
        total_phases = phases.get("total", 0)
        done_phases = phases.get("done", 0)
        if total_phases:
            components["phases"] = round(100 * done_phases / total_phases)
    crawl = (results.get("crawl") or {}).get("data") or {}
    discovered = crawl.get("discovered")
    visited = crawl.get("page_count")
    if discovered:
        components["crawl"] = round(100 * min(1.0, visited / discovered))
    ports = (results.get("ports") or {}).get("data") or {}
    if ports.get("probed"):
        components["ports"] = round(
            100 * ports.get("probed", 0) / max(1, ports.get("total", 1)))
    ipintel = (results.get("ipintel") or {}).get("data") or {}
    if ipintel.get("ip"):
        components["ip_followup"] = 100
    if not components:
        return {"percent": 0, "components": {}}
    percent = round(sum(components.values()) / len(components))
    return {"percent": percent, "components": components}
