#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Leaked-credentials Verify mode — HIBP Pwned Passwords, k-anonymity.

The owner types a candidate password hidden (getpass). WEBDON
hashes it with SHA-1, sends ONLY the first 5 hash characters to
the Have I Been Pwned Pwned Passwords range API, and answers
YES/NO + breach count only.

The password itself is NEVER shown, stored or logged — it never
leaves the process except as 5 hash characters, and the full hash
is never transmitted. No harvesting or displaying of any real
leaked password, ever. If the API is unreachable, the answer is
UNKNOWN, not a guess.
"""
import hashlib

from ..core.http import get

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/%s"


def check_pwned(password, fetcher=None):
    """Check one owner-provided password against HIBP (k-anonymity).

    Returns {"status": "pwned"|"not_pwned"|"unknown",
             "count": int|None, "error": str|None}.
    The password and its full hash never appear in the result.
    """
    if not password:
        return {"status": "unknown", "count": None,
                "error": "empty password"}
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    fetch = fetcher or get
    try:
        r = fetch(HIBP_RANGE_URL % prefix, timeout=12, max_bytes=1000000)
    except Exception as exc:
        return {"status": "unknown", "count": None, "error": str(exc)}
    if r.get("status") != 200 or not r.get("body"):
        return {"status": "unknown", "count": None,
                "error": r.get("error") or "HIBP unreachable"}
    for line in r["body"].splitlines():
        parts = line.strip().split(":")
        if len(parts) == 2 and parts[0].strip().upper() == suffix:
            try:
                return {"status": "pwned",
                        "count": int(parts[1].strip()), "error": None}
            except ValueError:
                return {"status": "pwned", "count": 1, "error": None}
    return {"status": "not_pwned", "count": 0, "error": None}


def verify_secret(scan, secret, timeout=10):
    """Legacy in-scan check: does an owner-provided value appear in
    any public place the scan found? Answers YES/NO + location only.
    The value never appears in any result or report."""
    from ..core.http import get as _get
    urls = []
    def add(u):
        if u and u not in urls and len(urls) < 25:
            urls.append(u)
    add(scan.get("target"))
    res = scan.get("results") or {}
    crawl = (res.get("crawl") or {}).get("data") or {}
    for p in crawl.get("pages") or []:
        add(p.get("url"))
    found = []
    checked = 0
    for url in urls:
        r = _get(url, timeout=timeout, max_bytes=200000)
        checked += 1
        if r.get("body") and secret in r["body"]:
            found.append({"where": url, "kind": "public content"})
    return {"found": found, "checked": checked}
