#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Content-aware response analysis — the honesty layer.

A bare HTTP 200 proves nothing. A server can answer 200 with an
error page. This module answers the real question: is this response
a REAL file?

- fingerprint_error_page: fetch two random non-existent paths and
  learn what this server's error page looks like.
- classify: one status code, one verdict — ok / error_page_200 /
  redirect / auth_required / forbidden / absent / rate_limited /
  server_error / unreachable.
"""
import hashlib
import random
import re
import string

from ..core.http import get

_ERROR_MARKERS = ("404", "not found", "page introuvable", "not exist")


def _normalize(body):
    """Strip digits and collapse whitespace so dynamic bits
    (request ids, timestamps) do not change the fingerprint."""
    body = re.sub(r"\d+", "#", body or "")
    return re.sub(r"\s+", " ", body).strip()


def _fingerprint_of(body):
    norm = _normalize(body)
    return {"length": len(norm),
            "sha256": hashlib.sha256(norm.encode(errors="ignore"))
                      .hexdigest()[:16],
            "sample": norm[:120]}


def fingerprint_error_page(base, timeout=6):
    """Learn the server's error page by requesting two random paths."""
    fps = []
    for _ in range(2):
        probe = "".join(random.choice(string.ascii_lowercase)
                        for _ in range(16))
        r = get("%s/webdon-no-such-page-%s.html" % (base, probe),
                timeout=timeout, max_bytes=50000)
        if r.get("status") is not None:
            fps.append({"status": r.get("status"),
                        **_fingerprint_of(r.get("body") or "")})
    if not fps:
        return None
    return fps[0]


def classify(status, content_type, size, body, error_fp):
    """One verdict for one response. Returns {"kind", "detail"}."""
    if status is None:
        return {"kind": "unreachable", "detail": "no response"}
    if status in (301, 302, 303, 307, 308):
        return {"kind": "redirect", "detail": "HTTP %s" % status}
    if status == 401:
        return {"kind": "auth_required",
                "detail": "authentication required (HTTP 401)"}
    if status == 403:
        return {"kind": "forbidden",
                "detail": "access forbidden (HTTP 403) — not a finding"}
    if status == 404:
        return {"kind": "absent", "detail": "HTTP 404"}
    if status == 429:
        return {"kind": "rate_limited",
                "detail": "rate limited (HTTP 429)"}
    if status >= 500:
        return {"kind": "server_error", "detail": "HTTP %s" % status}
    if status != 200:
        return {"kind": "other", "detail": "HTTP %s" % status}
    if error_fp:
        fp = _fingerprint_of(body or "")
        if fp["sha256"] == error_fp["sha256"]:
            return {"kind": "error_page_200",
                    "detail": "body matches the server error page"}
        if (abs(fp["length"] - error_fp["length"])
                <= max(5, error_fp["length"] // 10)
                and any(m in fp["sample"].lower()
                        for m in _ERROR_MARKERS)):
            return {"kind": "error_page_200",
                    "detail": "body looks like the server error page"}
    if (content_type or "").startswith("text/html") and size < 2000 \
            and any(m in (body or "").lower()[:500]
                    for m in _ERROR_MARKERS):
        return {"kind": "error_page_200",
                "detail": "small HTML body mentioning a missing page"}
    return {"kind": "ok", "detail": "HTTP 200, real content"}
