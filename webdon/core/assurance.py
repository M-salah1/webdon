#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Professional Assurance (v5.1) — evidence-sufficiency gate +
standalone evidence bundles.

Two things live here:

1. SUFFICIENCY GATE. A finding may reach `confirmed` ONLY when its
   evidence meets a defined minimum for its type (SUFFICIENCY table
   below). Otherwise it stays `suspected` and the finding names the
   missing evidence (`evidence_gap`). The gate runs AFTER validation
   and AFTER the deep-dive, in the scoring pipeline (engine
   _finalize and deepdive apply_to_scan), and it can only demote a
   `confirmed` claim — never promote a finding whose evidence is
   thin. `evidence_score` is 0-100 per finding; `sufficiency` is
   pass/fail + gap. No finding may be `confirmed` with sufficiency
   fail (regression-tested in tests/test_assurance.py).

   Per-type minimum evidence (the table):
   - header:  header absent on >=2 distinct URLs, OR on 1 URL plus
              a re-probe (validation verified / deep-dive re-probe).
   - cookie:  cookie name + flag state observed, plus a re-probe
              (validation verified) confirming the flags.
   - tls:     a completed handshake AND a parsed certificate
              (or, for "No TLS", the plain-HTTP response itself).
   - port:    a banner or protocol response matched to a service
              (service_confirmed) — never a bare TCP answer.
   - config:  HEAD 200 on the exact path, plus a re-probe.
   - dns/whois: the record observed, plus a re-probe/verification.
   - cors/tech/protect/generic: the observation plus a re-probe
              (validation verified) or a second independent signal.

2. EVIDENCE BUNDLES. One standalone bundle per finding, stored in
   the `evidence_bundles` SQLite table (see core/storage): the full
   HTTP request (method, URL, headers, body excerpt if any) AND
   the full HTTP response (status, headers, body excerpt, truncated
   at a safe size), both REDACTED by the sanitizer, plus
   `verified_at` and the engine/method that produced it. Findings
   with no HTTP request/response (DNS-only, TLS handshake, TCP
   probe, HEAD-only config check) say so explicitly
   (`request_response: null`, reason recorded) instead of
   pretending. Old scans get bundles built from their stored
   evidence where possible, else marked `legacy_evidence`.

Secret/cookie/session values are never stored: request/response
headers are name-only for sensitive names, Set-Cookie values and
Authorization tokens are redacted, and body excerpts are truncated
and passed through the same value redaction as evidence objects.
"""
import re

from ..adapters import _redact_values as _redact_text

MAX_BODY_EXCERPT = 4000
MAX_HEADER_VALUE = 200

# Finding types whose evidence is an HTTP request/response. Any
# other engine's findings get request_response: null + a reason.
HTTP_ENGINES = {"headers", "cookies", "cors", "protect", "tech",
                "crawl"}
# HEAD-only: the request exists (HEAD) but no response body is
# ever downloaded, so there is no response excerpt to store.
HEAD_ONLY_ENGINES = {"paths"}

SENSITIVE_HEADER_NAMES = {
    "cookie", "set-cookie", "authorization", "proxy-authorization",
    "x-api-key", "api-key",
}

# ---------------------------------------------------------------- types

# (type, how it is recognised) — engine first, name keywords second.
_HEADER_NAMES = ("content-security-policy", "strict-transport-security",
                 "x-frame-options", "x-content-type-options",
                 "referrer-policy", "permissions-policy",
                 "cross-origin-opener-policy",
                 "cross-origin-resource-policy", "expect-ct")


def classify_finding(finding):
    """Return the sufficiency type of one finding."""
    engine = (finding.get("engine") or "").lower()
    name = (finding.get("name") or "").lower()
    if engine == "ports" or name.startswith("port ") \
            or "neighbour port" in name or "sensitive service" in name:
        return "port"
    if engine == "tls" or "tls" in name or "certificate" in name \
            or "plain http" in name:
        return "tls"
    if engine == "cookies" or "cookie" in name:
        return "cookie"
    if engine == "headers" or name.startswith("missing ") \
            or name.startswith("weak ") and any(
                h in name for h in _HEADER_NAMES) \
            or any(h in name for h in _HEADER_NAMES):
        return "header"
    if engine == "paths" or "config" in name or ".env" in name \
            or ".git" in name:
        return "config"
    if engine == "dns" or "dns" in name or "spf" in name \
            or "dmarc" in name:
        return "dns"
    if engine == "whois" or "whois" in name or "registrar" in name:
        return "whois"
    if engine == "cors" or "cors" in name:
        return "cors"
    if engine == "tech" or "server version" in name \
            or "technology disclosed" in name or "x-powered-by" in name:
        return "tech"
    if engine == "protect" or "waf" in name or "protection" in name:
        return "protect"
    return "generic"


def _verified(finding):
    """True when an independent re-probe confirmed the finding."""
    if finding.get("reprobe_verified"):
        return True
    val = finding.get("validation") or {}
    return val.get("status") == "verified"


def _observed_urls(finding, ctx=None):
    """Distinct URLs the evidence was observed on."""
    urls = set()
    for u in (finding.get("observed_urls") or []):
        if u:
            urls.add(u)
    ev = finding.get("evidence_obj") or {}
    loc = ev.get("location") or ""
    if loc.startswith("http"):
        urls.add(loc.split()[0])
    ev_text = finding.get("evidence") or ""
    m = re.findall(r"https?://\S+", ev_text)
    for u in m:
        urls.add(u.rstrip(","))
    # Header-audit evidence names its page count explicitly:
    # "header X absent on 3 of 5 crawled pages: <urls...>".
    m = re.search(r"absent on (\d+) of (\d+)", ev_text)
    if m and int(m.group(1)) >= 2:
        urls.add("__multi__")
        urls.add("__multi2__")
    if ctx:
        pages = ctx.get("pages") or []
        if isinstance(pages, list) and len(pages) >= 2 \
                and "header" in (finding.get("name") or "").lower():
            pass  # pages alone do not prove the header is missing there
    return urls


def _tls_detail(finding, ctx=None):
    """TLS evidence detail: handshake done? cert parsed?"""
    detail = finding.get("tls_detail") or finding.get("evidence_detail") \
        or {}
    if isinstance(detail, dict) and detail:
        return detail
    tls_data = {}
    if ctx:
        tls_data = (ctx.get("tls") or {})
        if not tls_data and (ctx.get("results") or {}).get("tls"):
            tls_data = ((ctx.get("results") or {}).get("tls") or {}) \
                .get("data") or {}
    cert = tls_data.get("cert") or {}
    return {"handshake": bool(tls_data.get("versions"))
            or bool(tls_data.get("cipher")),
            "cert_parsed": bool(cert.get("not_after")
                                or cert.get("subject")),
            "chain_valid": tls_data.get("chain_valid"),
            "proxy_artefact": bool(tls_data.get("proxy_artefact"))}


def assess(finding, ctx=None):
    """Assess one finding against its type's sufficiency minimum.

    Returns {"type", "evidence_score" (0-100), "sufficiency" bool,
    "evidence_gap" (str or None), "reasons" [...]}. Never raises.
    """
    ftype = classify_finding(finding)
    verified = _verified(finding)
    corroborated = bool(finding.get("corroborated_by"))
    reasons = []
    gap = None
    score = 0
    passed = False
    name = (finding.get("name") or "").lower()
    ev = finding.get("evidence_obj") or {}
    observed = (ev.get("observed") or finding.get("evidence") or "")

    if ftype == "header":
        urls = _observed_urls(finding, ctx)
        n = len(urls)
        if n >= 2:
            score = 100 if verified else 85
            passed = True
            reasons.append("header observed absent on %d distinct URLs"
                           % n)
        elif n == 1 and verified:
            score = 75
            passed = True
            reasons.append("header observed absent on 1 URL + re-probe")
        else:
            score = 40 if n == 1 else 20
            gap = ("needs header observed on a second distinct URL "
                   "or a re-probe confirming its absence")
            reasons.append("only %d URL observed, no re-probe" % n)
    elif ftype == "cookie":
        has_name = bool(observed.strip())
        if has_name and verified:
            score = 90 if corroborated else 80
            passed = True
            reasons.append("cookie name + flags observed and re-probed")
        elif has_name:
            score = 50
            gap = "needs re-probe confirming the cookie flags"
            reasons.append("cookie observed once, no re-probe")
        else:
            score = 20
            gap = "needs cookie name + flag state observed"
            reasons.append("no cookie observation recorded")
    elif ftype == "tls":
        if "no tls" in name or "plain http" in name:
            # The plain-HTTP response itself is the evidence.
            if observed:
                score = 85
                passed = True
                reasons.append("plain-HTTP response observed")
            else:
                score = 20
                gap = "needs the plain-HTTP response observed"
        else:
            detail = _tls_detail(finding, ctx)
            if detail.get("proxy_artefact"):
                score = 30
                gap = ("TLS evidence inconclusive — intercepting proxy "
                       "suspected; re-run on Termux without a proxy")
                reasons.append("proxy artefact: handshake intercepted")
            elif detail.get("handshake") and detail.get("cert_parsed"):
                score = 100 if detail.get("chain_valid") else 90
                passed = True
                reasons.append("handshake completed + certificate parsed")
            elif detail.get("handshake"):
                score = 55
                gap = "needs certificate parsed (subject/SAN/expiry)"
                reasons.append("handshake done, no certificate parsed")
            else:
                score = 20
                gap = "needs completed TLS handshake + certificate parsed"
                reasons.append("no completed handshake recorded")
    elif ftype == "port":
        state = finding.get("port_state") or finding.get("port_class") \
            or ""
        text = (observed + " " + str(finding.get("evidence") or "")) \
            .lower()
        banner = bool(finding.get("banner")) or "banner:" in text \
            and "no banner" not in text
        if state == "service_confirmed" or "service_confirmed" in text:
            score = 95 if banner else 90
            passed = True
            reasons.append("banner/protocol response matched a service")
        elif state == "service_identified":
            # Legacy state: a banner was matched, same as confirmed.
            score = 85
            passed = True
            reasons.append("banner matched a service (legacy state)")
        else:
            score = 25
            gap = "needs banner"
            reasons.append("bare TCP answer only — no banner/protocol")
    elif ftype == "config":
        if verified:
            score = 90
            passed = True
            reasons.append("HEAD 200 on exact path + re-probe")
        elif observed:
            score = 60
            gap = "needs re-probe (HEAD) confirming the path is live"
            reasons.append("HEAD 200 observed once, no re-probe")
        else:
            score = 20
            gap = "needs HEAD 200 on the exact config path"
    elif ftype in ("dns", "whois"):
        if observed and verified:
            score = 85
            passed = True
            reasons.append("public record observed + verified")
        elif observed:
            score = 60
            gap = "needs re-probe verifying the public record"
            reasons.append("record observed once, no re-probe")
        else:
            score = 20
            gap = "needs the public record observed"
    elif ftype in ("cors", "tech", "protect"):
        if verified:
            score = 80
            passed = True
            reasons.append("observation + re-probe")
        elif observed:
            score = 45
            gap = "needs re-probe confirming the observation"
            reasons.append("observed once, no re-probe")
        else:
            score = 20
            gap = "needs the observation recorded"
    else:  # generic
        if observed and verified:
            score = 80
            passed = True
            reasons.append("observation + independent re-probe")
        elif observed and corroborated:
            score = 70
            passed = True
            reasons.append("observation + second independent engine")
        elif observed:
            score = 45
            gap = "needs independent re-probe"
            reasons.append("observed once, no re-probe")
        else:
            score = 20
            gap = "needs the observation recorded with location"

    if corroborated and score < 100:
        score = min(100, score + 5)
    return {"type": ftype, "evidence_score": int(score),
            "sufficiency": bool(passed), "evidence_gap": gap,
            "reasons": reasons}


def apply_assurance(findings, ctx=None):
    """Apply the sufficiency gate to a list of findings, in place.

    Every finding gains `evidence_score` (0-100), `sufficiency`
    {"pass": bool, "gap": str|None} and `evidence_gap`. A finding
    reaches `confirmed` ONLY when sufficiency passes; otherwise its
    confirmation becomes `suspected` (never `confirmed`). Info
    findings keep confirmation "info". Returns the findings.
    """
    for f in findings or []:
        if (f.get("severity") or "") == "info":
            result = assess(f, ctx)
            f["evidence_score"] = result["evidence_score"]
            f["sufficiency"] = {"pass": result["sufficiency"],
                                "gap": result["evidence_gap"]}
            f["evidence_gap"] = result["evidence_gap"]
            f["confirmation"] = "info"
            continue
        result = assess(f, ctx)
        f["evidence_score"] = result["evidence_score"]
        f["sufficiency"] = {"pass": result["sufficiency"],
                            "gap": result["evidence_gap"]}
        f["evidence_gap"] = result["evidence_gap"]
        if result["sufficiency"]:
            f["confirmation"] = "confirmed"
        else:
            f["confirmation"] = "suspected"
    return findings


# ---------------------------------------------------------------- bundles

def _redact_headers(headers):
    """Header dict -> redacted copy (names kept, sensitive values
    replaced, values truncated)."""
    out = {}
    for key, val in (headers or {}).items():
        kl = str(key).lower()
        if kl in SENSITIVE_HEADER_NAMES:
            out[str(key)] = "[REDACTED]"
        else:
            out[str(key)] = _redact_text(str(val))[:MAX_HEADER_VALUE]
    return out


def _redact_body(body):
    """Body excerpt: truncated to a safe size, secrets redacted."""
    if not body:
        return ""
    return _redact_text(str(body))[:MAX_BODY_EXCERPT]


def _http_reason(finding):
    """Why this finding has no HTTP request/response."""
    engine = (finding.get("engine") or "").lower()
    if engine in HEAD_ONLY_ENGINES:
        return ("HEAD-only existence check — the response body of a "
                "config path is never downloaded, so no response "
                "excerpt exists; status is recorded in evidence")
    if engine == "tls":
        return ("TLS handshake finding — no HTTP request/response; "
                "the handshake and certificate are the evidence")
    if engine in ("dns", "whois"):
        return ("DNS/WHOIS finding — no HTTP request/response "
                "exists; the public record is the evidence")
    if engine == "ports":
        return ("TCP probe finding — no HTTP request/response; the "
                "banner/protocol response is the evidence")
    if engine == "deepdive":
        return ("deep-dive probe finding — no single HTTP "
                "request/response; the probe method is recorded in "
                "evidence_obj")
    return ("no HTTP request/response for this finding type — "
            "evidence is recorded in evidence_obj")


def build_bundle(finding, ctx=None, request=None, response=None,
                 verified_at=None):
    """Build one standalone evidence bundle for a finding.

    `request`/`response` are explicit dicts when the caller has
    them; otherwise the homepage request/response from ctx is used
    for HTTP-engine findings. Returns a dict with
    request_response True/False (+ reason when False), always
    redacted. Never raises.
    """
    from . import evidence as evidence_mod

    ctx = ctx or {}
    engine = (finding.get("engine") or "").lower()
    fid = finding.get("finding_id") or "?"
    verified = verified_at or evidence_mod.utcnow()
    bundle = {
        "bundle_id": "EB-%s" % fid,
        "finding_id": fid,
        "finding_name": finding.get("name"),
        "engine": engine,
        "method": (finding.get("evidence_obj") or {}).get("method")
                  or finding.get("engine") or "",
        "verified_at": verified,
        "request_response": None,
        "request": None,
        "response": None,
        "reason": None,
        "legacy": False,
    }
    req = request
    resp = response
    if req is None and resp is None:
        if engine in HTTP_ENGINES:
            req = ctx.get("request") or {
                "method": "GET", "url": ctx.get("url") or "",
                "headers": {"User-Agent": "WEBDON"},
                "body_excerpt": ""}
            resp = ctx.get("response") or {
                "status": ctx.get("status"),
                "headers": ctx.get("headers") or {},
                "body_excerpt": (ctx.get("html") or "")[:MAX_BODY_EXCERPT]}
        elif engine in HEAD_ONLY_ENGINES:
            # HEAD request exists; there is deliberately no body.
            loc = (finding.get("evidence_obj") or {}).get("location") \
                or ctx.get("url") or ""
            req = {"method": "HEAD", "url": loc, "headers": {},
                   "body_excerpt": ""}
            bundle["request"] = req
            bundle["request_response"] = None
            bundle["reason"] = _http_reason(finding)
            return bundle
    if req is None and resp is None:
        bundle["reason"] = _http_reason(finding)
        return bundle
    bundle["request_response"] = True
    bundle["request"] = {
        "method": (req or {}).get("method") or "GET",
        "url": (req or {}).get("url") or ctx.get("url") or "",
        "headers": _redact_headers((req or {}).get("headers") or {}),
        "body_excerpt": _redact_body((req or {}).get("body_excerpt")
                                     or (req or {}).get("body") or ""),
    }
    bundle["response"] = {
        "status": (resp or {}).get("status"),
        "headers": _redact_headers((resp or {}).get("headers") or {}),
        "body_excerpt": _redact_body(
            (resp or {}).get("body_excerpt")
            or (resp or {}).get("body") or ""),
    }
    return bundle


def build_bundles(findings, ctx=None):
    """Build bundles for a list of findings. Returns a list."""
    return [build_bundle(f, ctx) for f in (findings or [])]


def migrate_bundle(finding, target=""):
    """Build a bundle for an OLD scan's finding from its stored
    evidence where possible, else mark it `legacy_evidence`.

    A legacy bundle has request_response null, reason
    "legacy_evidence — ...", and legacy True. It never invents a
    request/response that was not stored.
    """
    from . import evidence as evidence_mod

    ev = finding.get("evidence_obj") or {}
    bundle = {
        "bundle_id": "EB-%s" % (finding.get("finding_id") or "?"),
        "finding_id": finding.get("finding_id") or "?",
        "finding_name": finding.get("name"),
        "engine": finding.get("engine") or "",
        "method": ev.get("method") or "",
        "verified_at": ev.get("timestamp") or evidence_mod.utcnow(),
        "request_response": None,
        "request": None,
        "response": None,
        "reason": None,
        "legacy": True,
    }
    if ev.get("location") and ev.get("observed"):
        bundle["reason"] = (
            "legacy_evidence — scan predates standalone bundles; "
            "bundle rebuilt from stored evidence (location + "
            "observed value only, no request/response was stored)")
    else:
        bundle["reason"] = (
            "legacy_evidence — scan predates standalone bundles and "
            "stored no evidence object to rebuild from")
    return bundle
