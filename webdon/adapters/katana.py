#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Katana adapter — crawl with JS discovery (v2.00).

Runs the real Katana binary when installed
(`katana -u <url> -depth 3 -js-crawl`). Fallback: the built-in
WEBDON crawler's pages + scripts (already collected in ctx).
Only same-origin URLs are ever kept.
"""
from urllib.parse import urlparse

from . import NOT_INSTALLED, adapter_result, is_installed, require_scope, run_cmd

NAME = "katana"
TITLE = "Katana — crawl + JS"
BINARY = "katana"


def build_args(url):
    return [BINARY, "-u", url, "-depth", "3", "-js-crawl", "-silent"]


def parse_list(text, base_host):
    """Parse one-URL-per-line output, same-origin only."""
    out = []
    for line in (text or "").splitlines():
        u = line.strip()
        if not u.startswith("http"):
            continue
        try:
            host = urlparse(u).netloc.lower()
        except Exception:
            continue
        if host == base_host or host.endswith("." + base_host):
            if u not in out:
                out.append(u)
    return sorted(out)


def fallback_urls(ctx):
    """Built-in crawler results already in ctx (pages + scripts)."""
    urls = []
    for p in ctx.get("pages") or []:
        u = p.get("url") if isinstance(p, dict) else str(p)
        if u and u not in urls:
            urls.append(u)
    for s in ctx.get("scripts") or []:
        if s and s not in urls:
            urls.append(s)
    return sorted(urls)


def run(ctx, timeout=120, runner=run_cmd):
    require_scope(ctx)
    url = ctx.get("url", "")
    host = ctx.get("host", "").split(":")[0].lower()
    if not is_installed(BINARY):
        urls = fallback_urls(ctx)
        return adapter_result(
            NAME, NOT_INSTALLED, [],
            {"urls": urls, "count": len(urls),
             "source": "built-in crawler (fallback)",
             "note": "katana is not installed; fallback: built-in crawl",
             "install": "tools install katana"})
    rc, out, err = runner(build_args(url), timeout=timeout)
    if rc == -1:
        return adapter_result(NAME, "error", [],
                              {"error": err or "katana timed out"})
    urls = parse_list(out, host)
    if not urls:
        urls = fallback_urls(ctx)
    return adapter_result(NAME, "completed", [],
                          {"urls": urls, "count": len(urls),
                           "source": "katana",
                           "stderr": (err or "")[:200]})
