#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Burp-like module — built-in, no Burp Suite binary (v2.00).

Burp Suite Professional is commercial and cannot be bundled.
WEBDON ships a built-in equivalent for the authorized target only:
  * proxy   — a local request log: every request WEBDON itself
              makes is recorded (method, URL, status, header NAMES
              only — header values are never stored, so no cookie
              or auth value can leak into the log).
  * repeater — resend one recorded request with edited headers,
              same authorized host only, GET/HEAD only.
  * sitemap — the crawled URL tree from the crawl engine.
  * scanner — the built-in misconfiguration scan summary
              (headers / cookies / paths / CORS findings).

NO intruder / brute force, NO auth bypass, ever.
"""
from ..core.http import request as http_request

NAME = "burp"
TITLE = "Burp-like — proxy / repeater / sitemap / scanner"


class ProxyLog:
    """In-memory log of WEBDON's own requests (names only)."""

    def __init__(self):
        self.entries = []
        self._next_id = 1

    def record(self, method, url, status=None, header_names=None):
        entry = {"id": self._next_id, "method": method.upper(),
                 "url": str(url)[:300], "status": status,
                 "headers": sorted(header_names or [])}
        self._next_id += 1
        self.entries.append(entry)
        return entry

    def get(self, entry_id):
        for e in self.entries:
            if e["id"] == entry_id:
                return e
        return None

    def list(self):
        return list(self.entries)


def repeater(log, entry_id, scope, extra_headers=None):
    """Resend one recorded request with edited headers.

    Scope-gated and same-host only; GET/HEAD only. Returns the
    raw HTTP result dict (status/headers/body-truncated) or an
    error dict. Header VALUES supplied by the operator are sent
    on the wire but never stored.
    """
    entry = log.get(entry_id)
    if not entry:
        return {"error": "no recorded request #%s" % entry_id}
    url = entry["url"]
    if not scope.is_authorized(url):
        return {"error": "no signed scope for %s" % url}
    if entry["method"] not in ("GET", "HEAD"):
        return {"error": "repeater supports GET/HEAD only"}
    headers = dict(extra_headers or {})
    res = http_request(url, method=entry["method"], headers=headers,
                       timeout=15, max_bytes=50000)
    return {"status": res.get("status"),
            "final_url": res.get("final_url"),
            "elapsed_ms": res.get("elapsed_ms"),
            "body_preview": (res.get("body") or "")[:500],
            "error": res.get("error")}


def sitemap(pages):
    """URL tree from crawled pages: {path: [children]} (paths only)."""
    tree = {}
    for p in pages or []:
        url = p.get("url") if isinstance(p, dict) else str(p)
        if not url:
            continue
        try:
            path = url.split("/", 3)[3] if url.count("/") >= 3 else "/"
        except Exception:
            path = "/"
        path = "/" + path
        parent = path.rsplit("/", 1)[0] or "/"
        tree.setdefault(parent, [])
        if path not in tree[parent] and path != parent:
            tree[parent].append(path)
    return {k: sorted(v) for k, v in sorted(tree.items())}


def scanner_summary(scan):
    """Misconfiguration summary of a stored scan (counts by area)."""
    areas = {"headers": 0, "cookies": 0, "paths": 0, "cors": 0,
             "tls": 0, "ports": 0, "nuclei": 0, "other": 0}
    for f in scan.get("findings") or []:
        eng = (f.get("engine") or "").lower()
        if eng in areas:
            areas[eng] += 1
        else:
            areas["other"] += 1
    return {"score": scan.get("score"), "grade": scan.get("grade"),
            "findings_by_area": areas,
            "total_findings": len(scan.get("findings") or [])}
