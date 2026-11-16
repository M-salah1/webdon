#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Finding enrichment (v4.00 EVIDENCE) — one place that turns a raw
engine finding into a complete, reportable finding:

    finding_id   — stable per-scan id (F-001, ...)
    finding_key  — stable across scans (history + FP marks)
    evidence_obj — structured evidence (see core.evidence)
    cwe / cvss   — CWE + computed CVSS, or None when no defensible
                   mapping exists (never invented)
    remediation  — precise fix (header value, nginx + Apache
                   snippets, file, verify step) or None for info
    fix          — one-line summary (the remediation summary when
                   one exists, else the engine's own fix)

Everything is sanitized: no credential, cookie or session value
can reach a report through here.
"""
from ..adapters import sanitize as _sanitize
from . import cwe_map as cwe_map_mod
from . import evidence as evidence_mod
from . import remediation as remediation_mod


def enrich_finding(finding, ctx=None, finding_id=None):
    """Enrich one finding dict in place; returns it."""
    ctx = ctx or {}
    if finding_id:
        finding["finding_id"] = finding_id
    finding["finding_key"] = evidence_mod.finding_key(
        finding.get("name", ""))
    if not finding.get("evidence_obj"):
        finding["evidence_obj"] = evidence_mod.build_evidence_obj(
            finding, ctx)
    # Nuclei classification (cve_id / cwe_id / cvss_vector) wins
    # over the mapping table; NVD enriches a CVE id when reachable.
    cwe_map_mod.enrich(finding)
    rem = remediation_mod.build(finding, ctx)
    finding["remediation"] = rem
    if rem:
        finding["fix"] = rem["summary"]
    return _sanitize(finding)


def enrich_all(findings, ctx=None, start=1):
    """Enrich a list of findings; assigns F-001... ids in order.

    `start` continues the numbering of a previous list — ids must
    be unique across findings + false positives + chains of one
    scan, or `findings mark-fp/unmark <F-xxx>` is ambiguous.
    """
    out = []
    for i, f in enumerate(findings or []):
        out.append(enrich_finding(f, ctx, "F-%03d" % (start + i)))
    return out
