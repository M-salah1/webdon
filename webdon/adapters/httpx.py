#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""httpx adapter — live probe: status, title, tech, TLS (v2.00).

Runs the real httpx binary when installed
(`httpx -u <url> -status-code -title -tech-detect -tls-probe`).
Fallback: the built-in stdlib HTTP layer fetches the same facts
(status, title, server/tech from headers) — never invented.
"""
import json
import re

from ..core.http import get as http_get
from . import NOT_INSTALLED, adapter_result, is_installed, require_scope, run_cmd

NAME = "httpx"
TITLE = "httpx — live probe"
BINARY = "httpx"

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def build_args(url):
    return [BINARY, "-u", url, "-status-code", "-title",
            "-tech-detect", "-tls-probe", "-json", "-silent"]


def parse_json(text):
    """Parse httpx -json lines. Keeps status/title/tech/TLS only."""
    data = {"probed": 0}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except Exception:
            continue
        data["probed"] += 1
        data["url"] = str(item.get("url") or "")[:200]
        data["status_code"] = item.get("status_code")
        data["title"] = str(item.get("title") or "")[:200]
        data["webserver"] = str(item.get("webserver") or "")[:120]
        tech = item.get("tech") or []
        data["tech"] = [str(t)[:80] for t in tech][:20]
        tls = item.get("tls") or {}
        if tls:
            data["tls"] = {"version": tls.get("version"),
                           "cipher": tls.get("cipher")}
    return data


def fallback_probe(ctx):
    """Built-in stdlib live probe (status, title, server, tech)."""
    r = http_get(ctx.get("url", ""), timeout=10, max_bytes=200000)
    title = ""
    m = TITLE_RE.search(r.get("body") or "")
    if m:
        title = re.sub(r"\s+", " ", m.group(1)).strip()[:200]
    headers = r.get("headers") or {}
    try:
        headers = {str(k).lower(): v for k, v in dict(headers).items()}
    except Exception:
        headers = {}
    tech = []
    if headers.get("server"):
        tech.append("server:%s" % str(headers["server"])[:80])
    if headers.get("x-powered-by"):
        tech.append("powered-by:%s" % str(headers["x-powered-by"])[:80])
    return {"probed": 1 if r.get("status") is not None else 0,
            "url": ctx.get("url", ""),
            "status_code": r.get("status"),
            "title": title, "tech": tech,
            "fallback": "stdlib http probe"}


def run(ctx, timeout=60, runner=run_cmd):
    require_scope(ctx)
    url = ctx.get("url", "")
    if not is_installed(BINARY):
        return adapter_result(NAME, NOT_INSTALLED, [],
                              {**fallback_probe(ctx),
                               "note": "httpx is not installed; fallback: "
                                       "built-in stdlib live probe",
                               "install": "tools install httpx"})
    rc, out, err = runner(build_args(url), timeout=timeout)
    if rc == -1:
        return adapter_result(NAME, "error", [],
                              {"error": err or "httpx timed out"})
    data = parse_json(out)
    if not data.get("probed"):
        data = {**fallback_probe(ctx), "note": "httpx returned no "
                                               "result; stdlib probe used"}
    return adapter_result(NAME, "completed", [], data)
