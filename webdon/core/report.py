#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WEBDON reports: terminal, JSON, interactive HTML and PDF (v5.00).

Every report shows the same honest picture: score (or INCOMPLETE),
coverage, per-engine status, unified findings with EVIDENCE
(observed value, location, timestamp, engine, probe method),
CVSS v3.1 + CWE where a defensible mapping exists (null otherwise
— never invented), precise remediation, the limits block (what
cannot be known), and recommendations.

v5.00 DEEP-DIVE adds the investigation chains: every finding
carries depth / parent / chain, the deep-dive block (deepest
chain, follow-up probes, new findings per depth level, which
budget stopped the dive) is printed and exported, and the HTML
report shows the chains as collapsible trees.

Secret values never appear — engines only record names, flags and
redacted evidence, and the sanitizer strips any credential,
cookie or session value from evidence objects.
"""
import html as html_mod
import json
import time

from .. import __version__
from . import pdf as pdf_mod
from .i18n import t

TOOL_LABEL = "WEBDON v%s HIVE" % __version__

SEV_ORDER = ["critical", "high", "medium", "low", "info"]

# v3.00 NET — the network & systems tools of Wave 6.
NET_ENGINES = ("nmap", "wireshark", "openvas", "netexec", "bloodhound")


def net_section(scan):
    """Per-tool status of the Network & Systems wave.

    Returns a list of (name, status, mode) — every status honest:
    ran / fallback / bridge / not_applicable / skipped, never
    invented. Empty when the scan has no NET engines (old scans).
    """
    rows = []
    results = scan.get("results") or {}
    status = scan.get("engine_status") or {}
    for name in NET_ENGINES:
        if name not in (scan.get("engines") or []):
            continue
        res = results.get(name) or {}
        data = res.get("data") or {}
        mode = (data.get("mode") or data.get("note") or "")
        rows.append((name,
                     (status.get(name) or {}).get("status")
                     or res.get("status", "not_run"),
                     mode[:120]))
    return rows


def deepdive_summary(scan):
    """The v5.00 deep-dive block of a scan (defaults for old scans)."""
    dd = scan.get("deepdive") or {}
    return {
        "status": dd.get("status", "not_run"),
        "max_depth": dd.get("max_depth", 0),
        "deepest": dd.get("deepest", 0),
        "probes_run": dd.get("probes_run", 0),
        "probes_planned": dd.get("probes_planned", 0),
        "probes_deduped": dd.get("probes_deduped", 0),
        "probe_budget": dd.get("probe_budget"),
        "time_budget_s": dd.get("time_budget_s"),
        "new_findings": dd.get("new_findings", 0),
        "new_findings_by_depth": dd.get("new_findings_by_depth") or {},
        "stop_reason": dd.get("stop_reason"),
        "depth_clamped": dd.get("depth_clamped", False),
    }


def finding_trees(scan):
    """Nested investigation trees (v5.00) from parent_id links."""
    from . import deepdive as deepdive_mod
    return deepdive_mod.build_trees(scan.get("findings") or [])


def _tree_to_dict(node):
    f = node["finding"]
    return {"finding_id": f.get("finding_id"), "name": f.get("name"),
            "severity": f.get("severity"), "depth": f.get("depth", 0),
            "parent_id": f.get("parent_id"),
            "chain": f.get("chain"),
            "children": [_tree_to_dict(c)
                         for c in node.get("children") or []]}


def print_deepdive(scan):
    """Terminal deep-dive summary (v5.00): deepest chain, probes,
    new findings per depth level, and which budget stopped it."""
    dd = deepdive_summary(scan)
    if dd["status"] == "not_run":
        return
    print("Deep-dive: status=%s max_depth=%d deepest=%d "
          "follow-up probes=%d (planned %d, deduped %d)" % (
              dd["status"], dd["max_depth"], dd["deepest"],
              dd["probes_run"], dd["probes_planned"],
              dd["probes_deduped"]))
    by_depth = dd["new_findings_by_depth"]
    if by_depth:
        print("  New findings per depth: %s" % ", ".join(
            "L%s=%s" % (k, v) for k, v in sorted(by_depth.items())))
    else:
        print("  New findings per depth: none")
    if dd["stop_reason"]:
        print("  Stopped by budget: %s" % dd["stop_reason"])
    elif dd["status"] == "completed":
        print("  Dive finished: no further follow-ups found")
    if dd["depth_clamped"]:
        print("  Note: requested depth was outside 1-5 and clamped")


def _print_tree(node, indent=2):
    f = node["finding"]
    print("%s%s [%s|depth %s] %s (%s)" % (
        " " * indent, f.get("finding_id", "?"),
        (f.get("severity") or "").upper(), f.get("depth", 0),
        f.get("name"), f.get("chain") or f.get("finding_id", "?")))
    if f.get("follow_ups"):
        print("%s  via probes: %s" % (
            " " * indent, ", ".join(f["follow_ups"])))
    for child in node.get("children") or []:
        _print_tree(child, indent + 2)


def print_chains(scan):
    """Print every investigation tree with depth, parent and the
    probe that produced each child (v5.00 `report chains`)."""
    trees = finding_trees(scan)
    print("=" * 60)
    print("Investigation chains — %s" % scan.get("target"))
    print_deepdive(scan)
    shown = 0
    for node in trees:
        if not node.get("children"):
            continue
        shown += 1
        _print_tree(node)
    if not shown:
        print("  (no chains — no finding produced a follow-up)")
    print("=" * 60)


def print_finding_chain(scan, finding_id):
    """Print one investigation tree, rooted at one finding."""
    trees = finding_trees(scan)
    wanted = (finding_id or "").strip().upper()

    def _find(node):
        if (node["finding"].get("finding_id") or "").upper() == wanted:
            return node
        for child in node.get("children") or []:
            hit = _find(child)
            if hit:
                return hit
        return None

    for root in trees:
        hit = _find(root)
        if hit:
            print("=" * 60)
            print("Chain — %s" % hit["finding"].get("chain"))
            _print_tree(hit)
            print("=" * 60)
            return True
    print("finding not found: %s" % finding_id)
    return False


def evidence_text(finding):
    """One-line evidence string for a finding (old or new scan)."""
    obj = finding.get("evidence_obj") or {}
    if obj.get("observed"):
        return obj["observed"]
    return finding.get("evidence", "") or ""


def score_line(scan, lang):
    if scan.get("score") is None:
        return "%s: %s   %s: %s   %s: %s%%   %s: %s s" % (
            t(lang, "score"), t(lang, "incomplete"),
            t(lang, "grade"), t(lang, "incomplete"),
            t(lang, "coverage"),
            (scan.get("coverage") or {}).get("percent", 0),
            t(lang, "duration"), scan.get("duration_s"))
    return "%s: %s%%   %s: %s   %s: %s%%   %s: %s%%   %s: %s%%   %s: %s s" % (
        t(lang, "score"), scan.get("score"),
        t(lang, "grade"), scan.get("grade"),
        t(lang, "confidence"), scan.get("confidence"),
        t(lang, "coverage"), (scan.get("coverage") or {}).get("percent", 0),
        t(lang, "verification_rate"),
        (scan.get("metrics") or {}).get("verification_rate", 0),
        t(lang, "duration"), scan.get("duration_s"))


def _print_finding(f, lang):
    cvss = f.get("cvss") or {}
    cwe = f.get("cwe") or {}
    conf = f.get("confirmation") or (
        (f.get("validation") or {}).get("status") == "verified"
        and "confirmed" or "indicator")
    print("  [%s|%s] %s" % (f["severity"].upper(), conf, f["name"]))
    if cvss.get("score") is not None:
        print("      CVSS %.1f (%s) %s  CWE-%s: %s" % (
            cvss["score"], cvss.get("severity", ""),
            cvss.get("vector", ""), cwe.get("id", "?") or "?",
            cwe.get("name", "")))
    elif cwe.get("id"):
        print("      CWE-%s: %s (no defensible CVSS)" % (
            cwe.get("id"), cwe.get("name", "")))
    ev = f.get("evidence_obj") or {}
    print("      Evidence: %s" % evidence_text(f)[:160])
    if ev.get("location"):
        print("      Location: %s | %s | %s" % (
            ev.get("location"), ev.get("method", ""),
            ev.get("timestamp", "")))
    v = f.get("validation") or {}
    print("      %s: %s (%s%%)%s" % (t(lang, "validation"),
                                     v.get("status"),
                                     v.get("confidence"),
                                     (" — corroborated by %s" % ", ".join(
                                         f.get("corroborated_by") or []))
                                     if f.get("corroborated_by") else ""))
    rem = f.get("remediation") or {}
    if rem.get("summary"):
        print("      Fix: %s" % rem["summary"][:200])
    if rem.get("verify"):
        print("      Verify: %s" % rem["verify"][:200])


def print_report(scan, lang="ar"):
    print("=" * 60)
    print("%s — %s" % (TOOL_LABEL, t(lang, "report")))
    print("%s: %s" % (t(lang, "target"), scan.get("target")))
    print("%s: %s" % (t(lang, "profile"), scan.get("profile")))
    print(score_line(scan, lang))
    val = scan.get("validation") or {}
    if val:
        print("%s: %s %s, %s %s, %s %s" % (
            t(lang, "validation"), val.get("verified", 0),
            t(lang, "verified"), val.get("observed", 0),
            t(lang, "observed"), val.get("false_positive", 0),
            t(lang, "false_positives")))
    dist = scan.get("severity_distribution") or {}
    print("%s: %s" % (t(lang, "findings"),
                      ", ".join("%s=%d" % (k, v) for k, v in dist.items()
                                if v) or "0"))
    comps = ((scan.get("coverage") or {}).get("components") or {})
    if comps:
        print("%s: %s" % (t(lang, "coverage"),
                          ", ".join("%s %s%%" % (k, v)
                                    for k, v in comps.items())))
    print("Phases: %d/%d" % (
        (scan.get("coverage") or {}).get("phases_done", 0),
        (scan.get("coverage") or {}).get("phases_total", 0)))
    print_deepdive(scan)
    if scan.get("chains"):
        print("%s:" % t(lang, "chains"))
        for c in scan["chains"]:
            print("  [%s] %s" % (c["severity"].upper(), c["name"]))
            print("      %s" % c.get("evidence", "")[:200])
    if scan.get("contradictions"):
        print("%s:" % t(lang, "contradictions"))
        for c in scan["contradictions"]:
            print("  • %s" % c[:200])
    print("=" * 60)
    print("%s:" % t(lang, "engine_status"))
    for name in scan.get("engines") or []:
        run = (scan.get("engine_status") or {}).get(name) or {}
        line = "  • %s: %s (%ss" % (name, run.get("status"),
                                   run.get("duration_s"))
        if run.get("retries"):
            line += ", %d retries" % run["retries"]
        if run.get("error"):
            line += " — %s" % str(run["error"])[:70]
        print(line + ")")
    net_rows = net_section(scan)
    if net_rows:
        print("-" * 60)
        print("Network & Systems (Wave 6):")
        for name, st, mode in net_rows:
            print("  • %s: %s — %s" % (name, st, mode))
    print("-" * 60)
    print("%s:" % t(lang, "findings"))
    for f in scan.get("findings") or []:
        _print_finding(f, lang)
    if scan.get("false_positives"):
        print("-" * 60)
        print("%s (suppressed, not deleted):" % t(lang, "false_positives"))
        for fp in scan["false_positives"]:
            print("  ✗ %s (%s) — %s" % (
                fp["name"], fp.get("engine"),
                (fp.get("validation") or {}).get("reason")
                or fp.get("fp_reason") or ""))
    assets = scan.get("assets") or {}
    if assets:
        print("-" * 60)
        print("%s: %s" % (t(lang, "assets"), assets.get("domain")))
        print("  IPs: %s  |  country: %s  |  hosting: %s" % (
            ", ".join(assets.get("ips") or []) or "—",
            assets.get("ip_country") or "—",
            assets.get("ip_hosting") or "—"))
        print("  CMS: %s  |  registrar: %s  |  domain days left: %s" % (
            assets.get("cms") or "—", assets.get("registrar") or "—",
            assets.get("domain_days_left")))
        print("  ports: %s" % (
            ", ".join(str(p) for p in assets.get("open_ports") or [])
            or "—"))
    limits = scan.get("limits") or {}
    if limits:
        print("-" * 60)
        print("%s:" % t(lang, "limits_title"))
        for key, val in limits.items():
            print("  • %s: %s" % (key, val))
    summary = scan.get("summary")
    if summary:
        print("=" * 60)
        print("%s — Executive Summary" % TOOL_LABEL)
        print("Score: %s  Grade: %s  |  Owner: %s / %s" % (
            "INCOMPLETE" if summary.get("score") is None
            else "%s%%" % summary.get("score"), summary.get("grade"),
            (summary.get("owner") or {}).get("registrar"),
            (summary.get("owner") or {}).get("registrant")))
        for f in summary.get("top_findings") or []:
            print("  [%s] %s" % ((f.get("severity") or "").upper(),
                                 f.get("name")))
            print("      Fix: %s" % f.get("fix"))
        for a in summary.get("priority_actions") or []:
            print("  • Priority: %s" % a)
    print("=" * 60)
    print("%s:" % t(lang, "recommendations"))
    for fix in (scan.get("recommendations") or [])[:8]:
        print("  • %s" % fix)
    print("=" * 60)


def to_json(scan, path):
    """Raw scan dump (kept for --json / dashboard compatibility)."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(scan, f, ensure_ascii=False, indent=2)
    return path


def to_json_report(scan, path):
    """Full machine-readable report (v4.00): findings with
    evidence/CVSS/CWE/remediation, scores, coverage, timeline
    references and suppressed false positives."""
    report = {
        "report_version": "5.00",
        "tool": scan.get("tool", TOOL_LABEL),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                      time.gmtime()),
        "target": scan.get("target"),
        "profile": scan.get("profile"),
        "scan_id": scan.get("scan_id"),
        "scores": {
            "security_score": scan.get("score"),
            "grade": scan.get("grade"),
            "confidence": scan.get("confidence"),
            "coverage_percent": (scan.get("coverage") or {})
                                .get("percent"),
            "verification_rate": (scan.get("metrics") or {})
                                 .get("verification_rate"),
        },
        "coverage": scan.get("coverage"),
        "validation": scan.get("validation"),
        "severity_distribution": scan.get("severity_distribution"),
        "findings": scan.get("findings") or [],
        "false_positives_suppressed": scan.get("false_positives") or [],
        "chains": scan.get("chains") or [],
        "deepdive": deepdive_summary(scan),
        "finding_chains": [_tree_to_dict(n) for n in finding_trees(scan)
                           if n.get("children")],
        "contradictions": scan.get("contradictions") or [],
        "assets": scan.get("assets") or {},
        "limits": scan.get("limits") or {},
        "recommendations": scan.get("recommendations") or [],
        "summary": scan.get("summary") or {},
        "timeline_refs": {
            "target": scan.get("target"),
            "finished_at": scan.get("finished_at"),
            "note": "Use: report timeline <target> for the full "
                    "history of this target.",
        },
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    return path


def to_pdf(scan, path):
    """Professional PDF report (stdlib-only writer)."""
    return pdf_mod.report_pdf(scan, path)


def _sev_chart(dist):
    """Inline SVG bar chart of the severity distribution."""
    colors = {"critical": "#dc2626", "high": "#ea580c",
              "medium": "#ca8a04", "low": "#2563eb", "info": "#64748b"}
    total = max(1, sum(dist.values()))
    bars = []
    y = 8
    for sev in SEV_ORDER:
        count = dist.get(sev, 0)
        width = int(320 * count / total) if count else 0
        bars.append(
            '<text x="0" y="%d" fill="#e5e7eb" font-size="12">%s</text>'
            '<rect x="90" y="%d" width="%d" height="14" fill="%s"/>'
            '<text x="%d" y="%d" fill="#e5e7eb" font-size="12">%d</text>'
            % (y + 11, sev, y, width, colors[sev],
               95 + width, y + 11, count))
        y += 22
    return ('<svg width="460" height="%d" role="img" '
            'aria-label="Severity distribution">%s</svg>'
            % (y, "".join(bars)))


def to_html(scan, path):
    """Interactive self-contained HTML report (v4.00).

    No external JS/CSS: inline SVG severity chart, sortable /
    filterable findings table (vanilla JS), expandable evidence
    and remediation per finding, executive summary, scope +
    methodology + limitations, CVSS/CWE columns.
    """
    def esc(v):
        return html_mod.escape(str(v))

    dist = scan.get("severity_distribution") or {}
    rows = ""
    for f in scan.get("findings") or []:
        cvss = f.get("cvss") or {}
        cwe = f.get("cwe") or {}
        cvss_txt = ("%.1f (%s)<br><small>%s</small>" % (
            cvss["score"], cvss.get("severity", ""),
            esc(cvss.get("vector", "")))) \
            if cvss.get("score") is not None else "—"
        cwe_txt = ('<a href="%s">%s</a><br><small>%s</small>' % (
            esc(cwe.get("url", "")), esc(cwe.get("id", "") or "—"),
            esc(cwe.get("name", "")))) if cwe.get("id") else "—"
        ev = f.get("evidence_obj") or {}
        rem = f.get("remediation") or {}
        rem_html = ""
        if rem.get("summary"):
            parts = ["<b>Fix:</b> " + esc(rem["summary"])]
            if rem.get("header"):
                parts.append("<b>Header:</b> <code>%s</code>"
                             % esc(rem["header"]))
            if rem.get("nginx"):
                parts.append("<b>nginx:</b> <code>%s</code>"
                             % esc(rem["nginx"]))
            if rem.get("apache"):
                parts.append("<b>Apache:</b> <code>%s</code>"
                             % esc(rem["apache"]))
            if rem.get("file"):
                parts.append("<b>Where:</b> " + esc(rem["file"]))
            if rem.get("verify"):
                parts.append("<b>Verify:</b> <code>%s</code>"
                             % esc(rem["verify"]))
            rem_html = "<br>".join(parts)
        rows += (
            "<tr data-sev=\"%s\"><td>%s</td><td>%s</td><td>%s</td>"
            "<td>%s</td><td>%s</td>"
            "<td><details><summary>evidence</summary>"
            "Observed: %s<br>Location: %s<br>Method: %s<br>"
            "Engine: %s<br>Time: %s<br>Validation: %s (%s%%)%s"
            "</details></td>"
            "<td><details><summary>remediation</summary>%s</details>"
            "</td></tr>"
            % (esc(f.get("severity", "")),
               esc(f.get("severity", "")),
               esc(f.get("name", "")),
               cvss_txt, cwe_txt,
               esc(f.get("confirmation", "")),
               esc(evidence_text(f)[:300]),
               esc(ev.get("location", "")),
               esc(ev.get("method", "")),
               esc(ev.get("engine", f.get("engine", ""))),
               esc(ev.get("timestamp", "")),
               esc((f.get("validation") or {}).get("status", "")),
               esc((f.get("validation") or {}).get("confidence", "")),
               ("<br>Corroborated by: " + esc(", ".join(
                   f.get("corroborated_by") or "")))
               if f.get("corroborated_by") else "",
               rem_html or "—"))
    engines = ""
    for name in scan.get("engines") or []:
        run = (scan.get("engine_status") or {}).get(name) or {}
        engines += "<li>%s: %s (%ss)</li>" % (esc(name),
                                              esc(run.get("status", "")),
                                              esc(run.get("duration_s", "")))
    limits = "".join("<li><b>%s:</b> %s</li>" % (esc(k), esc(v))
                     for k, v in (scan.get("limits") or {}).items())
    net_rows = "".join(
        "<li>%s: %s — %s</li>" % (esc(n), esc(s), esc(m))
        for n, s, m in net_section(scan))
    net_html = ("<h2>Network &amp; Systems</h2><ul>%s</ul>" % net_rows
                if net_rows else "")
    fps = "".join(
        "<li>%s (%s) — %s</li>" % (
            esc(fp.get("name", "")), esc(fp.get("engine", "")),
            esc((fp.get("validation") or {}).get("reason")
                or fp.get("fp_reason") or ""))
        for fp in scan.get("false_positives") or [])
    fps_html = ("<h2>Suppressed false positives</h2><ul>%s</ul>" % fps
                if fps else "")
    def _node_html(node):
        f = node["finding"]
        label = "%s [%s|depth %s] %s (%s)" % (
            esc(f.get("finding_id", "?")),
            esc((f.get("severity") or "").upper()),
            esc(f.get("depth", 0)), esc(f.get("name", "")),
            esc(f.get("chain") or f.get("finding_id", "?")))
        kids = "".join(_node_html(c)
                       for c in node.get("children") or [])
        return "<li>%s%s</li>" % (
            label, ("<ul>%s</ul>" % kids) if kids else "")

    chains_html = ""
    chain_trees = [n for n in finding_trees(scan)
                   if n.get("children")]
    if chain_trees:
        parts = []
        for node in chain_trees:
            parts.append(
                "<details><summary>Chain %s</summary><ul>%s</ul>"
                "</details>" % (
                    esc(node["finding"].get("chain") or ""),
                    _node_html(node)))
        dd = deepdive_summary(scan)
        chains_html = (
            "<h2>Investigation chains (deep-dive)</h2>"
            "<p>Deepest chain: %s &nbsp; Follow-up probes: %s &nbsp; "
            "New findings: %s &nbsp; Stopped by: %s</p>%s" % (
                esc(dd["deepest"]), esc(dd["probes_run"]),
                esc(dd["new_findings"]),
                esc(dd["stop_reason"] or "—"), "".join(parts)))
    score = scan.get("score")
    score_txt = "INCOMPLETE" if score is None else "%s%% (%s)" % (
        score, scan.get("grade"))
    summary = scan.get("summary") or {}
    top = "".join(
        "<li>[%s] %s — Fix: %s</li>" % (
            esc((f.get("severity") or "").upper()), esc(f.get("name")),
            esc(f.get("fix") or ""))
        for f in (summary.get("top_findings") or []))
    doc = """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>WEBDON Report — %s</title>
<style>body{font-family:sans-serif;margin:2em;background:#0b1220;color:#e5e7eb}
h1,h2{color:#7dd3fc}table{border-collapse:collapse;width:100%%}
td,th{border:1px solid #334155;padding:6px;text-align:left;vertical-align:top}
th{cursor:pointer}code{background:#1e293b;padding:1px 4px}
input,button{margin:4px;padding:6px}details summary{cursor:pointer}
.sev-critical{color:#f87171}.sev-high{color:#fb923c}</style></head>
<body><h1>WEBDON v%s — Security Audit Report</h1>
<p><b>Target:</b> %s &nbsp; <b>Profile:</b> %s &nbsp; <b>Score:</b> %s
&nbsp; <b>Confidence:</b> %s%% &nbsp; <b>Coverage:</b> %s%%
&nbsp; <b>Verification rate:</b> %s%% &nbsp; <b>Duration:</b> %s s</p>
<h2>Executive summary</h2><ul>%s</ul>
<h2>Severity distribution</h2>%s
<h2>Scope and methodology</h2>
<p>Authorized target only (signed scope). Passive and presence-only
checks: DNS/WHOIS (public records), TLS, security headers, cookies
(names/flags only), CORS, crawl, ports, IP follow-up, and
professional tool adapters in detection-only mode. No exploitation,
no payloads, no bypass testing, no brute force, no login bypass.
Every finding carries evidence (observed value, location, timestamp,
engine, probe method) and, where a defensible mapping exists, a CWE
and a CVSS v3.1 score computed from the vector — never invented.
Findings marked as false positives by the operator are suppressed
from the score and listed below, never silently deleted.</p>
<h2>Engines</h2><ul>%s</ul>
%s
<h2>Findings</h2>
<input id="q" type="text" placeholder="Filter findings..."
 oninput="filterRows()">
<button onclick="filterSev('')">All</button>
<button onclick="filterSev('critical')">Critical</button>
<button onclick="filterSev('high')">High</button>
<button onclick="filterSev('medium')">Medium</button>
<button onclick="filterSev('low')">Low</button>
<button onclick="filterSev('info')">Info</button>
<table id="ft"><thead><tr>
<th onclick="sortTable(0)">Severity</th>
<th onclick="sortTable(1)">Finding</th>
<th onclick="sortTable(2)">CVSS</th>
<th>CWE</th><th>Confirmation</th><th>Evidence</th>
<th>Remediation</th></tr></thead><tbody>%s</tbody></table>
%s
%s
<h2>What cannot be known</h2><ul>%s</ul>
<h2>Recommendations</h2><ul>%s</ul>
<p>WEBDON v%s HIVE — FOX COMPANY — Developer: Hafed Mehdi Salah Eddine</p>
<script>
var sevFilter='';
function filterRows(){var q=document.getElementById('q').value.toLowerCase();
var rows=document.querySelectorAll('#ft tbody tr');
rows.forEach(function(r){var ok=r.textContent.toLowerCase().includes(q);
if(sevFilter && r.dataset.sev!==sevFilter) ok=false;
r.style.display=ok?'':'none';});}
function filterSev(s){sevFilter=s;filterRows();}
function sortTable(col){var t=document.getElementById('ft');
var tb=t.tBodies[0];var rows=Array.from(tb.rows);
var asc=t.dataset.asc!=='1';t.dataset.asc=asc?'1':'0';
rows.sort(function(a,b){var x=a.cells[col].textContent;
var y=b.cells[col].textContent;return asc?x.localeCompare(y):y.localeCompare(x);});
rows.forEach(function(r){tb.appendChild(r);});}
</script>
</body></html>""" % (
        esc(scan.get("target")), __version__,
        esc(scan.get("target")), esc(scan.get("profile")), esc(score_txt),
        esc(scan.get("confidence", 0)),
        esc((scan.get("coverage") or {}).get("percent", 0)),
        esc((scan.get("metrics") or {}).get("verification_rate", 0)),
        esc(scan.get("duration_s")), top, _sev_chart(dist), engines,
        net_html, rows, fps_html, chains_html, limits,
        "".join("<li>%s</li>" % esc(x)
                for x in scan.get("recommendations") or []),
        __version__)
    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)
    return path


def print_compare(diff, id_a, id_b):
    """Terminal rendering of a scan comparison (v4.00)."""
    print("=" * 60)
    print("Compare #%s -> #%s" % (id_a, id_b))
    print("Score: %s -> %s   (delta: %s)" % (
        diff["score"][0], diff["score"][1],
        ("+%s" % diff["score_delta"])
        if diff.get("score_delta") is not None and diff["score_delta"] > 0
        else diff.get("score_delta")))
    print("Coverage: %s%% -> %s%%" % (
        diff["coverage"][0], diff["coverage"][1]))
    print("New (%d):" % len(diff.get("new") or []))
    for f in diff.get("new") or []:
        print("  + [%s] %s" % (f["severity"].upper(), f["name"]))
    print("Fixed (%d):" % len(diff.get("fixed") or []))
    for f in diff.get("fixed") or []:
        print("  - [%s] %s" % (f["severity"].upper(), f["name"]))
    print("Persisting (%d):" % len(diff.get("persisting") or []))
    for f in diff.get("persisting") or []:
        print("  = [%s] %s" % (f["severity"].upper(), f["name"]))
    print("Changed (%d):" % len(diff.get("changed") or []))
    for c in diff.get("changed") or []:
        print("  ~ %s: %s -> %s" % (c["name"], c["from"], c["to"]))
    print("FP-suppressed (%d):" % len(diff.get("fp_suppressed") or []))
    for f in diff.get("fp_suppressed") or []:
        print("  x [%s] %s" % (f["severity"].upper(), f["name"]))
    print("=" * 60)


def print_timeline(tl):
    """Terminal rendering of a target timeline (v4.00)."""
    print("=" * 60)
    print("Timeline — %s" % tl.get("target"))
    print("Score over time:")
    for s in tl.get("scans") or []:
        score = s["score"] if s["score"] is not None else "INCOMPLETE"
        print("  #%s  %s  score=%s grade=%s findings=%d "
              "opened=%d closed=%d" % (
                  s["id"], s.get("finished_at") or "", score,
                  s.get("grade"), s.get("findings", 0),
                  len(s.get("opened") or []),
                  len(s.get("closed") or [])))
    print("Findings (first seen / last seen):")
    for f in tl.get("findings") or []:
        print("  • %s — first: %s  last: %s  status: %s" % (
            f.get("finding_name"), f.get("first_seen"),
            f.get("last_seen"), f.get("status")))
    print("Change events:")
    if not tl.get("events"):
        print("  (no changes)")
    for e in tl.get("events") or []:
        print("  %s  %s  %s (#%s)" % (
            e.get("date"), e.get("type"), e.get("finding_name"),
            e.get("scan_id")))
    print("=" * 60)
