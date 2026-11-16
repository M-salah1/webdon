#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Crawler engine — same-host crawl (bounded pages/depth).

Breadth-first crawl collecting internal links, pages with status
and title, scripts, stylesheets, forms and Set-Cookie headers
(names are parsed later by the cookies engine — values are never
stored here either, only the raw header lines the cookies engine
needs to parse names/flags from; the header lines are dropped
from the final report data after parsing).
"""
import re
import urllib.parse

from ..core.http import get

NAME = "crawl"
TITLE = "Crawler — paths & pages"

PHASES = ["homepage", "same-origin links", "assets & forms"]


def _links(base, html):
    out = set()
    for href in re.findall(r'href\s*=\s*["\']([^"\']+)', html, re.I):
        full = urllib.parse.urljoin(base, href.split("#")[0])
        if full.startswith(("http://", "https://")):
            out.add(full)
    return out


def run(ctx):
    base = ctx.get("url") or ""
    host = ctx.get("host") or ""
    timeout = ctx.get("timeout", 8)
    max_pages = int(ctx.get("max_pages", 15))
    if ctx.get("profile") == "forensic":
        max_pages = 30
    elif ctx.get("profile") == "deep":
        max_pages = 20
    queue = [base]
    seen = set()
    pages = []
    scripts = set()
    styles = set()
    forms = 0
    cookie_headers = []
    while queue and len(pages) < max_pages:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        r = get(url, timeout=timeout, max_bytes=200000)
        try:
            for c in (r.get("headers") or {}).get_all("Set-Cookie") or []:
                cookie_headers.append(c)
        except Exception:
            pass
        if r.get("status") != 200 or not r.get("body"):
            pages.append({"url": url, "status": r.get("status"),
                          "title": ""})
            continue
        body = r["body"]
        m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        pages.append({"url": url, "status": r["status"],
                      "title": (m.group(1).strip()[:80] if m else "")})
        forms += len(re.findall(r"<form\b", body, re.I))
        for src in re.findall(r'<script[^>]+src\s*=\s*["\']([^"\']+)',
                              body, re.I):
            scripts.add(urllib.parse.urljoin(url, src))
        for href in re.findall(
                r'<link[^>]+rel\s*=\s*["\']stylesheet["\'][^>]+href\s*=\s*["\']([^"\']+)',
                body, re.I):
            styles.add(urllib.parse.urljoin(url, href))
        for link in _links(url, body):
            if link not in seen and len(queue) < max_pages * 2:
                try:
                    if urllib.parse.urlparse(link).netloc == host:
                        queue.append(link)
                except Exception:
                    pass
    return {"engine": NAME, "status": "completed", "findings": [],
            "data": {"pages": pages, "page_count": len(pages),
                     "discovered": len(seen),
                     "paths": sorted({urllib.parse.urlparse(p["url"]).path
                                      or "/" for p in pages}),
                     "scripts": sorted(scripts)[:20],
                     "stylesheets": sorted(styles)[:20],
                     "forms": forms,
                     "cookie_headers": cookie_headers}}
