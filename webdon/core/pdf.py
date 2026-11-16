#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Professional PDF reports (v4.00 EVIDENCE) — pure-Python minimal
PDF writer, standard library only.

No new dependency: reportlab is used only if it is already
installed (it is not required and never installed by WEBDON).
The writer below produces a valid multi-page PDF: cover page,
executive summary, severity distribution, findings with
CVSS/CWE + evidence + remediation, remediation appendix, and
scope / limitations / disclaimer. Non-Latin-1 characters are
replaced (PDF literal strings here are WinAnsi) — the HTML
report is the full-fidelity version for Arabic text.
"""
import textwrap

from .. import __version__

PAGE_W, PAGE_H = 595, 842
MARGIN = 50
LINE_H = 14


def _clean(text):
    """Latin-1 safe text for PDF literal strings."""
    out = []
    for ch in str(text or ""):
        if ord(ch) < 32 and ch not in ("\n", "\t"):
            continue
        out.append(ch if ord(ch) < 256 else "?")
    return "".join(out)


def _esc(text):
    return _clean(text).replace("\\", "\\\\").replace("(", "\\(") \
        .replace(")", "\\)")


class _Page:
    def __init__(self):
        self.lines = []  # (text, size, bold)

    def add(self, text, size=10, bold=False):
        self.lines.append((text, size, bold))


class PDFReport:
    """Collects pages, then renders one PDF byte string."""

    def __init__(self, title):
        self.title = title
        self.pages = [_Page()]

    def _cur(self):
        return self.pages[-1]

    def _fit(self, text, size, width_chars):
        return textwrap.wrap(text, width=width_chars) or [""]

    def text(self, text, size=10, bold=False):
        width_chars = max(20, int((PAGE_W - 2 * MARGIN) / (size * 0.55)))
        for line in _clean(text).split("\n"):
            for piece in self._fit(line, size, width_chars):
                self._cur().add(piece, size, bold)

    def heading(self, text, size=14):
        self._cur().add("", 10)
        self.text(text, size=size, bold=True)

    def blank(self):
        self._cur().add("", 10)

    def new_page(self):
        self.pages.append(_Page())

    def _render_page(self, page, number, total):
        ops = ["BT"]
        y = PAGE_H - MARGIN
        for text, size, bold in page.lines:
            if y < MARGIN + 20:
                break
            font = "/F2" if bold else "/F1"
            ops.append("%s %d Tf %d %d Td (%s) Tj" % (
                font, size, MARGIN, y, _esc(text)))
            y -= LINE_H if size <= 10 else int(size * 1.25)
        ops.append("ET")
        ops.append("BT /F1 8 Tf %d 30 Td (Page %d of %d) Tj ET" % (
            MARGIN, number, total))
        return "\n".join(ops)

    def render(self):
        """Return the full PDF as bytes."""
        # Paginate: split overflowing pages by line count.
        pages = []
        for page in self.pages:
            cur, count = _Page(), 0
            max_lines = 44  # conservative: headings take more height
            for text, size, bold in page.lines:
                if count >= max_lines:
                    pages.append(cur)
                    cur, count = _Page(), 0
                cur.add(text, size, bold)
                count += 1
            pages.append(cur)
        total = len(pages)
        objects = []
        # 1: Catalog, 2: Pages, 3: Font F1, 4: Font F2.
        content_ids = []
        page_ids = []
        next_id = 5
        for _ in pages:
            content_ids.append(next_id)
            page_ids.append(next_id + 1)
            next_id += 2
        kids = " ".join("%d 0 R" % pid for pid in page_ids)
        objects.append((1, "<< /Type /Catalog /Pages 2 0 R >>"))
        objects.append((2, "<< /Type /Pages /Kids [%s] /Count %d >>"
                        % (kids, total)))
        objects.append((3, "<< /Type /Font /Subtype /Type1 "
                        "/BaseFont /Helvetica >>"))
        objects.append((4, "<< /Type /Font /Subtype /Type1 "
                        "/BaseFont /Helvetica-Bold >>"))
        for i, page in enumerate(pages):
            stream = self._render_page(page, i + 1, total)
            raw = stream.encode("latin-1", "replace")
            objects.append((content_ids[i],
                            "<< /Length %d >>\nstream\n%s\nendstream"
                            % (len(raw), stream)))
            objects.append((page_ids[i],
                            "<< /Type /Page /Parent 2 0 R "
                            "/MediaBox [0 0 %d %d] "
                            "/Resources << /Font << /F1 3 0 R "
                            "/F2 4 0 R >> >> "
                            "/Contents %d 0 R >>"
                            % (PAGE_W, PAGE_H, content_ids[i])))
        out = [b"%PDF-1.4"]
        offsets = {}
        for obj_id, body in sorted(objects):
            offsets[obj_id] = sum(len(b) + 1 for b in out)
            out.append(("%d 0 obj" % obj_id).encode("latin-1"))
            out.append(body.encode("latin-1", "replace"))
            out.append(b"endobj")
        xref_pos = sum(len(b) + 1 for b in out)
        max_id = max(offsets)
        xref = ["xref", "0 %d" % (max_id + 1),
                "0000000000 65535 f "]
        for obj_id in range(1, max_id + 1):
            xref.append("%010d 00000 n " % offsets.get(obj_id, 0))
        xref.append("trailer << /Size %d /Root 1 0 R >>" % (max_id + 1))
        xref.append("startxref")
        xref.append(str(xref_pos))
        xref.append("%%EOF")
        out.append("\n".join(xref).encode("latin-1"))
        return b"\n".join(out)


def report_pdf(scan, path):
    """Write a professional PDF report for a scan dict."""
    title = "WEBDON v%s — Security Audit Report" % __version__
    doc = PDFReport(title)
    score = scan.get("score")
    score_txt = "INCOMPLETE" if score is None else "%s%% (%s)" % (
        score, scan.get("grade"))
    # ---- cover page ----
    doc.text("WEBDON v%s" % __version__, size=22, bold=True)
    doc.text("Security Audit Report", size=16, bold=True)
    doc.blank()
    doc.text("Target: %s" % (scan.get("target") or "—"), size=12)
    doc.text("Profile: %s" % (scan.get("profile") or "—"), size=12)
    doc.text("Score: %s" % score_txt, size=12, bold=True)
    doc.text("Confidence: %s%%   Coverage: %s%%   Verification rate: "
             "%s%%" % (scan.get("confidence", 0),
                       (scan.get("coverage") or {}).get("percent", 0),
                       (scan.get("metrics") or {})
                       .get("verification_rate", 0)), size=12)
    doc.text("Duration: %s s   Finished: %s" % (
        scan.get("duration_s"), scan.get("finished_at") or "—"),
        size=12)
    doc.text("Developer: Hafed Mehdi Salah Eddine — Algeria",
             size=11)
    doc.text("FOX COMPANY — defensive audit only, authorized "
             "targets", size=11)
    # ---- executive summary ----
    doc.new_page()
    doc.heading("Executive Summary", size=16)
    summary = scan.get("summary") or {}
    doc.text("Score %s. %d findings (%s)." % (
        score_txt, len(scan.get("findings") or []),
        ", ".join("%s=%d" % (k, v)
                  for k, v in (scan.get("severity_distribution")
                               or {}).items() if v) or "none"))
    for f in (summary.get("top_findings") or [])[:5]:
        doc.text("[%s] %s" % ((f.get("severity") or "").upper(),
                              f.get("name")), size=11, bold=True)
        doc.text("Fix: %s" % (f.get("fix") or ""), size=10)
    doc.heading("Severity distribution", size=14)
    dist = scan.get("severity_distribution") or {}
    total = max(1, sum(dist.values()))
    for sev in ("critical", "high", "medium", "low", "info"):
        count = dist.get(sev, 0)
        bar = "#" * int(40 * count / total) if count else ""
        doc.text("%-9s %3d  %s" % (sev, count, bar), size=11)
    doc.heading("Scope and methodology", size=14)
    doc.text("Authorized target only (signed scope). Passive and "
             "presence-only checks: DNS/WHOIS (public records), "
             "TLS, security headers, cookies (names/flags only), "
             "CORS, crawl, ports, IP follow-up, and professional "
             "tool adapters in detection-only mode. No exploitation, "
             "no payloads, no bypass testing, no brute force, no "
             "login bypass.")
    doc.text("Every finding carries evidence (observed value, "
             "location, timestamp, engine, probe method) and, where "
             "a defensible mapping exists, a CWE and a CVSS v3.1 "
             "score computed from the vector — never invented.")
    # ---- findings ----
    doc.new_page()
    doc.heading("Findings", size=16)
    findings = scan.get("findings") or []
    if not findings:
        doc.text("No findings.")
    for f in findings:
        cvss = f.get("cvss") or {}
        cwe = f.get("cwe") or {}
        doc.text("[%s|%s] %s" % (
            (f.get("severity") or "").upper(),
            f.get("confirmation") or "indicator", f.get("name")),
            size=11, bold=True)
        if cvss.get("score") is not None:
            doc.text("CVSS %.1f (%s)  %s  CWE-%s: %s" % (
                cvss["score"], cvss.get("severity", ""),
                cvss.get("vector", ""), cwe.get("id", "?") or "?",
                cwe.get("name", "")), size=10)
        elif cwe.get("id"):
            doc.text("CWE-%s: %s (no defensible CVSS)" % (
                cwe.get("id"), cwe.get("name", "")), size=10)
        ev = f.get("evidence_obj") or {}
        doc.text("Evidence: %s | %s | %s | %s" % (
            ev.get("observed", f.get("evidence", ""))[:120],
            ev.get("location", ""), ev.get("engine", ""),
            ev.get("timestamp", "")), size=10)
        rem = f.get("remediation") or {}
        if rem.get("summary"):
            doc.text("Fix: %s" % rem["summary"], size=10)
        if rem.get("verify"):
            doc.text("Verify: %s" % rem["verify"], size=10)
        doc.blank()
    suppressed = scan.get("false_positives") or []
    if suppressed:
        doc.heading("Suppressed false positives", size=14)
        for fp in suppressed:
            doc.text("- %s (%s): %s" % (
                fp.get("name"), fp.get("engine"),
                (fp.get("validation") or {}).get("reason")
                or fp.get("fp_reason") or ""), size=10)
    # ---- remediation appendix ----
    doc.new_page()
    doc.heading("Remediation appendix", size=16)
    for f in findings:
        rem = f.get("remediation") or {}
        if not rem:
            continue
        doc.text("%s" % f.get("name"), size=11, bold=True)
        if rem.get("header"):
            doc.text("Header: %s" % rem["header"], size=10)
        if rem.get("nginx"):
            doc.text("nginx: %s" % rem["nginx"], size=10)
        if rem.get("apache"):
            doc.text("Apache: %s" % rem["apache"], size=10)
        if rem.get("file"):
            doc.text("Where: %s" % rem["file"], size=10)
        if rem.get("verify"):
            doc.text("Verify: %s" % rem["verify"], size=10)
        doc.blank()
    doc.heading("Limits and disclaimer", size=14)
    for key, val in (scan.get("limits") or {}).items():
        doc.text("- %s: %s" % (key, val), size=10)
    doc.text("This report reflects only what was observed at scan "
             "time on the authorized target. Scores are evidence-"
             "based; suspected findings weigh half. Re-run after "
             "fixing to confirm remediation.", size=10)
    with open(path, "wb") as fh:
        fh.write(doc.render())
    return path
