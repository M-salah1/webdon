#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Validation stage (v4.00 EVIDENCE) — runs after every wave.

Three steps, in order, for every finding:

1. RE-PROBE — the existing validator re-fetches the exact
   URL/header/banner that produced the finding (missing headers
   re-fetched, cookies re-checked, exposed paths re-HEADed).
   A finding that does not reproduce is demoted to
   false_positive with a reason; one that reproduces is verified.
2. KNOWN FALSE-POSITIVE RULES — artefacts the tool itself can
   recognise: the sandbox egress proxy intercepting TLS (the
   homepage fetches fine while every TLS handshake fails), HTTP
   403 presented as a vulnerability (403 alone proves nothing),
   a bare "HTTP 200" with no path (200 alone proves nothing),
   a "Server version disclosed" flag on a bare "cloudflare"
   header (no version in it), and wildcard-DNS inflation.
3. CROSS-ENGINE CORROBORATION — a finding backed by 2+ independent
   engines (distinct signals) is promoted to confirmed; a
   single-signal finding stays suspected (indicator). Corroboration
   never overrides a false_positive verdict.

Every finding must carry a structured evidence object
(`evidence_obj`); one without it is rejected (never scored).
"""
import os

from ..core import evidence as evidence_mod
from ..core import validator as validator_mod

# Finding groups whose members corroborate each other. Two
# findings in the same group, from DIFFERENT engines, count as
# two independent signals for the same underlying problem.
CORROBORATION_GROUPS = {
    "plain-http": ("plain http", "no tls"),
    "tls-weak": ("weak tls", "no modern tls", "tls 1.0", "tls 1.1"),
    "config-exposed": ("config", ".env", ".git", "backup", "dump",
                       "phpinfo"),
    "cookie-secure": ("cookie without secure",),
    "server-version": ("server version disclosed",
                       "technology disclosed"),
}


def _group_of(name):
    text = (name or "").lower()
    for key, patterns in CORROBORATION_GROUPS.items():
        if any(p in text for p in patterns):
            return key
    return None


def _is_sandbox_tls_artefact(ev, ctx):
    """TLS handshakes all failed while the homepage fetched fine.

    In the sandbox the egress proxy intercepts TLS; on a real
    Termux connection this does not happen. The homepage fetch
    succeeding (status not None) while every TLS handshake fails
    is the artefact signature.
    """
    if "TLS handshake failed for all versions" not in (
            ev.get("name") or ""):
        return False
    if ctx.get("status") is None:
        return False
    return bool(os.environ.get("http_proxy")
                or os.environ.get("https_proxy")
                or os.environ.get("HTTP_PROXY")
                or os.environ.get("HTTPS_PROXY")
                or ctx.get("status") is not None)


def apply_fp_rules(ev, ctx):
    """Apply the known-FP ruleset to one validated finding.

    Returns a reason string when the finding is a false positive,
    else None. Never raises.
    """
    name = ev.get("name") or ""
    low = name.lower()
    if "403" in name and "vulnerab" in low:
        return ("HTTP 403 is not a vulnerability by itself — the "
                "server refused, nothing was exposed.")
    if _is_sandbox_tls_artefact(ev, ctx):
        return ("Sandbox egress proxy intercepts TLS: the homepage "
                "fetched fine while every TLS handshake failed. "
                "Re-run on Termux for a true TLS result.")
    observed = ((ev.get("evidence_obj") or {}).get("observed") or "")
    if observed.strip() == "HTTP 200":
        return ("A bare HTTP 200 proves nothing — no path, header "
                "or content was observed.")
    if "server version disclosed" in low and \
            "cloudflare" in observed.lower() and \
            "/" not in observed.split("cloudflare", 1)[-1][:12]:
        return ("The Server header is just 'cloudflare' — it "
                "discloses no version.")
    return None


def corroborate(evidence):
    """Promote single-engine 'observed' findings backed by 2+
    independent engines in the same corroboration group."""
    groups = {}
    for ev in evidence:
        key = _group_of(ev.get("name", ""))
        if not key:
            continue
        groups.setdefault(key, []).append(ev)
    for key, members in groups.items():
        engines = {m.get("engine") for m in members}
        if len(engines) < 2:
            continue
        for ev in members:
            ev["corroborated_by"] = sorted(engines)
            val = ev.get("validation") or {}
            if val.get("status") == "observed":
                val["status"] = "verified"
                val["confidence"] = max(val.get("confidence", 50), 85)
                val["corroborated"] = True
                ev["validation"] = val


def run(evidence, ctx):
    """Run the full validation stage on the evidence list.

    Returns the (mutated) evidence list. Each record keeps its
    validation status: verified / observed / false_positive, plus
    `fp_reason` when a known-FP rule fired and `corroborated_by`
    when another engine backs it. Findings without a valid
    evidence object are marked false_positive with a reason.
    """
    evidence = validator_mod.validate_all(evidence, ctx)
    for ev in evidence:
        if not ev.get("evidence_obj"):
            ev["evidence_obj"] = evidence_mod.build_evidence_obj(ev, ctx)
        try:
            evidence_mod.require_evidence(ev)
        except ValueError as exc:
            ev["validation"] = {"status": "false_positive",
                                "confidence": 90,
                                "reason": str(exc)}
            ev["fp_reason"] = str(exc)
            continue
        reason = apply_fp_rules(ev, ctx)
        if reason:
            ev["validation"] = {"status": "false_positive",
                                "confidence": 90, "reason": reason}
            ev["fp_reason"] = reason
    corroborate(evidence)
    return evidence
