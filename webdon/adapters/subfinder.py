#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Subfinder adapter — subdomain enumeration (v3.00).

Runs the real Subfinder binary when installed
(`subfinder -d <domain> -silent`). Fallback: crt.sh Certificate
Transparency logs (public data, stdlib HTTP) plus a wildcard
check (does a random label resolve?). IP targets are skipped —
there are no subdomains of an IP.
"""
import json
import re

from ..core.http import fetch_json, resolve_ips
from . import NOT_INSTALLED, adapter_result, is_installed, require_scope, run_cmd

NAME = "subfinder"
TITLE = "Subfinder — subdomains"
BINARY = "subfinder"

_LABEL = re.compile(r"^[A-Za-z0-9_-]{1,63}$")


def build_args(domain):
    return [BINARY, "-d", domain, "-silent"]


def parse_list(text):
    """Parse one-subdomain-per-line output into a sorted unique list."""
    out = []
    for line in (text or "").splitlines():
        name = line.strip().lower().rstrip(".")
        if name and "." in name and name not in out:
            out.append(name)
    return sorted(out)


def crtsh_fallback(domain):
    """Public CT logs via crt.sh. Returns a sorted unique list."""
    url = ("https://crt.sh/?q=%%25.%s&output=json"
           % domain)
    data, _err = fetch_json(url, timeout=15, max_bytes=1000000)
    if not data:
        return []
    out = []
    for row in data:
        raw = str(row.get("name_value") or "")
        for name in raw.splitlines():
            name = name.strip().lower().rstrip(".")
            if name.startswith("*."):
                name = name[2:]
            if name.endswith("." + domain) or name == domain:
                if name not in out:
                    out.append(name)
    return sorted(out)


def wildcard_check(domain):
    """True if a random non-existent label resolves (wildcard DNS)."""
    import secrets
    label = "webdon-wildcard-%s" % secrets.token_hex(4)
    return bool(resolve_ips("%s.%s" % (label, domain), timeout=5))


def run(ctx, timeout=120, runner=run_cmd):
    require_scope(ctx)
    domain = ctx.get("domain", "")
    if not domain or "." not in domain or domain[0].isdigit():
        return adapter_result(NAME, "skipped", [],
                              {"note": "no domain to enumerate "
                                      "(IP target or no host)"})
    if not is_installed(BINARY):
        subs = crtsh_fallback(domain)
        return adapter_result(
            NAME, NOT_INSTALLED, [],
            {"subdomains": subs, "count": len(subs),
             "wildcard": wildcard_check(domain),
             "source": "crt.sh CT logs (fallback)",
             "note": "subfinder is not installed; fallback: crt.sh",
             "install": "tools install subfinder"})
    rc, out, err = runner(build_args(domain), timeout=timeout)
    if rc == -1:
        return adapter_result(NAME, "error", [],
                              {"error": err or "subfinder timed out"})
    subs = parse_list(out)
    if not subs:
        subs = crtsh_fallback(domain)
    return adapter_result(
        NAME, "completed", [],
        {"subdomains": subs, "count": len(subs),
         "wildcard": wildcard_check(domain), "source": "subfinder",
         "stderr": (err or "")[:200]})
