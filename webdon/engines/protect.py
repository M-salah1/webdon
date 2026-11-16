#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Protections engine — detect WAF / CDN / rate-limit presence.

v5.1 WAF CONFIDENCE: the old binary verdict (WAF detected / not
detected) is replaced by a probability — `waf_likelihood` 0-100%
with the contributing signals listed (known WAF headers, a
WAF-identifying Server header, a block response to a benign
probe, status-code pattern, WAF cookie names). Never report "no
WAF" as a certainty: when no signal is observed the verdict is
`waf_likelihood: low (e.g. 8%) — no WAF signals observed`, with
the checks performed named. Detection-only: benign GET/OPTIONS
probes only, no bypass attempts, no payloads.

Presence-only detection from response headers and server banners:
Cloudflare, Akamai, Sucuri, Imperva/Incapsula, AWS CloudFront,
Fastly, ModSecurity, rate-limit headers (X-RateLimit-*, Retry-After),
CSP and HSTS.
"""

NAME = "protect"
TITLE = "Protection Detection (WAF/CDN)"

PHASES = ["WAF/CDN fingerprint", "rate-limit & policy headers"]

WAF_SIGNS = [
    ("cf-ray", "Cloudflare (CDN/WAF)"),
    ("cf-cache-status", "Cloudflare (CDN/WAF)"),
    ("x-sucuri-id", "Sucuri WAF"),
    ("x-sucuri-cache", "Sucuri WAF"),
    ("x-iinfo", "Incapsula / Imperva WAF"),
    ("x-cdn", "CDN (generic)"),
    ("x-akamai-transformed", "Akamai CDN/WAF"),
    ("x-amz-cf-id", "AWS CloudFront CDN"),
    ("x-amz-cf-pop", "AWS CloudFront CDN"),
    ("x-fastly-request-id", "Fastly CDN"),
    ("x-mod-security", "ModSecurity WAF"),
    ("x-protected-by", "WAF (generic)"),
    ("server", None),  # handled separately (cloudflare server value)
]

RATE_LIMIT_HEADERS = ["x-ratelimit-limit", "x-ratelimit-remaining",
                      "x-ratelimit-reset", "retry-after",
                      "ratelimit-limit", "ratelimit-remaining"]

# (header, weight, vendor) — a known WAF header is a strong signal.
WAF_HEADER_WEIGHTS = {
    "cf-ray": (40, "Cloudflare"),
    "cf-cache-status": (25, "Cloudflare"),
    "x-sucuri-id": (40, "Sucuri"),
    "x-sucuri-cache": (25, "Sucuri"),
    "x-iinfo": (40, "Incapsula / Imperva"),
    "x-akamai-transformed": (30, "Akamai"),
    "x-amz-cf-id": (25, "AWS CloudFront"),
    "x-amz-cf-pop": (15, "AWS CloudFront"),
    "x-fastly-request-id": (25, "Fastly"),
    "x-mod-security": (40, "ModSecurity"),
    "x-protected-by": (30, "WAF (generic)"),
    "x-cdn": (10, "CDN (generic)"),
}

WAF_SERVER_SIGNS = [
    ("cloudflare", 25, "Cloudflare"),
    ("sucuri", 25, "Sucuri"),
    ("akamai", 25, "Akamai"),
    ("imperva", 25, "Imperva"),
    ("incapsula", 25, "Incapsula"),
    ("mod_security", 25, "ModSecurity"),
    ("f5", 15, "F5 BIG-IP"),
    ("awselb", 15, "AWS ELB"),
]

# WAF-identifying cookie names (names only — values never read).
WAF_COOKIE_NAMES = ("__cfduid", "cf_clearance", "awsalb", "awsalbapp",
                    "awselb", "ak_bmsc", "bm_sz", "sucuri",
                    "incap_ses_", "visid_incap_")

# Baseline when nothing is observed: low, but never 0 — absence of
# signals is not proof of absence.
NO_SIGNAL_LIKELIHOOD = 8


def analyze_waf(headers, cookie_names=None, status=None,
                probe_blocked=False):
    """Pure WAF-likelihood analysis from headers (+ cookie names).

    Returns {"waf_likelihood", "signals", "checks_performed",
    "verdict", "protections"}. `signals` is a list of
    {"signal", "weight", "observed", "detail"}. Never raises.
    """
    headers = headers or {}
    signals = []
    protections = []
    score = 0

    def _add(signal, weight, observed, detail=""):
        nonlocal score
        signals.append({"signal": signal, "weight": weight,
                        "observed": bool(observed), "detail": detail})
        if observed:
            score += weight

    checks = ["known WAF headers (cf-ray, x-sucuri-id, x-iinfo, "
              "x-akamai-transformed, x-amz-cf-id, x-fastly-request-id, "
              "x-mod-security, x-protected-by)",
              "WAF-identifying Server header",
              "WAF cookie names (__cfduid, cf_clearance, AWSALB, "
              "Akamai BM cookies)",
              "block response to a benign probe (GET/OPTIONS)",
              "status-code pattern"]
    for header, label in WAF_SIGNS:
        if header in headers:
            if label is None:
                continue
            if label not in protections:
                protections.append(label)
            weight, vendor = WAF_HEADER_WEIGHTS.get(header, (15, label))
            _add("known WAF header: %s (%s)" % (header, vendor),
                 weight, True, "header %s present" % header)
    server = headers.get("server", "")
    for needle, weight, vendor in WAF_SERVER_SIGNS:
        if needle in server.lower():
            if vendor == "Cloudflare" and \
                    "Cloudflare (CDN/WAF)" not in protections:
                protections.append("Cloudflare (CDN/WAF)")
            _add("WAF-identifying Server header (%s)" % vendor,
                 weight, True, "Server: %s" % server[:60])
            break
    for name in (cookie_names or []):
        low = (name or "").lower()
        if any(low.startswith(p) or p in low
               for p in WAF_COOKIE_NAMES):
            _add("WAF cookie name observed: %s" % name, 20, True,
                 "cookie %s is a known WAF/session cookie" % name)
            break
    _add("block response to a benign probe", 25, probe_blocked,
         "benign GET/OPTIONS returned a WAF-style block"
         if probe_blocked else "benign GET/OPTIONS not blocked")
    if status in (403, 406, 419, 501) and protections:
        _add("status-code pattern (%s with WAF headers)" % status,
             10, True, "HTTP %s alongside WAF headers" % status)
    else:
        _add("status-code pattern", 10, False,
             "no WAF-style block status observed")
    if not any(s["observed"] for s in signals):
        likelihood = NO_SIGNAL_LIKELIHOOD
        verdict = ("low — no WAF signals observed (absence of "
                   "signals is not proof of absence)")
    else:
        likelihood = min(100, score)
        if likelihood >= 60:
            verdict = "likely — WAF probably present"
        elif likelihood >= 30:
            verdict = "possible — some WAF signals observed"
        else:
            verdict = "low — weak WAF signals only"
    return {"waf_likelihood": likelihood, "signals": signals,
            "checks_performed": checks, "verdict": verdict,
            "protections": protections}


def detect_protections(headers):
    """Pure detection from a lower-cased header dict.

    Returns (protections, findings, data). v5.1: the WAF verdict
    is a likelihood with signals, never a binary "no WAF".
    """
    protections = []
    findings = []
    for header, label in WAF_SIGNS:
        if header in headers:
            if label is None:
                continue
            if label not in protections:
                protections.append(label)
    server = headers.get("server", "")
    if "cloudflare" in server.lower() and \
            "Cloudflare (CDN/WAF)" not in protections:
        protections.append("Cloudflare (CDN/WAF)")
    if "sucuri" in server.lower() and "Sucuri WAF" not in protections:
        protections.append("Sucuri WAF")
    if "akamai" in server.lower() and "Akamai CDN/WAF" not in protections:
        protections.append("Akamai CDN/WAF")
    rate = [h for h in RATE_LIMIT_HEADERS if h in headers]
    has_csp = "content-security-policy" in headers
    has_hsts = "strict-transport-security" in headers
    waf = analyze_waf(headers)
    protections = waf["protections"] or protections
    data = {"protections": protections,
            "rate_limit_headers": rate,
            "has_csp": has_csp, "has_hsts": has_hsts,
            "waf_likelihood": waf["waf_likelihood"],
            "waf_signals": waf["signals"],
            "waf_verdict": waf["verdict"],
            "waf_checks": waf["checks_performed"]}
    if protections:
        findings.append({"severity": "info",
                         "name": "Protection detected: %s"
                                 % ", ".join(protections),
                         "evidence": "headers: %s" % ", ".join(
                             h for h, _ in WAF_SIGNS if h in headers),
                         "fix": "Protections are present — no bypass is "
                                "tested by this tool."})
    # v5.1: never "No WAF" as a certainty — a likelihood instead.
    findings.append({"severity": "info",
                     "name": "WAF likelihood %d%% — %s"
                             % (waf["waf_likelihood"], waf["verdict"]),
                     "evidence": "signals observed: %s; checks: %s"
                                 % (", ".join(
                                     s["signal"] for s in waf["signals"]
                                     if s["observed"])
                                    or "none",
                                    "; ".join(waf["checks_performed"])),
                     "fix": "A low likelihood does not prove no WAF "
                            "exists — it only means no WAF signal was "
                            "observed on the homepage."})
    if rate:
        findings.append({"severity": "info",
                         "name": "Rate-limit headers present",
                         "evidence": "headers: %s" % ", ".join(rate),
                         "fix": "Keep rate limiting enabled on login and "
                                "API endpoints."})
    else:
        findings.append({"severity": "low",
                         "name": "No rate-limit headers seen",
                         "evidence": "no X-RateLimit-* or Retry-After "
                                     "header on the homepage",
                         "fix": "Add rate limiting (and its headers) on "
                                "sensitive endpoints."})
    return protections, findings, data


def benign_probe(url, timeout=8):
    """Benign WAF probe: one plain GET + one OPTIONS, no payloads.

    Returns True when the response looks like a WAF block
    (403/406/419 with WAF-ish headers or a block page marker).
    Never raises; no bypass attempt of any kind.
    """
    from ..core.http import get, request

    try:
        r = get(url, timeout=timeout, max_bytes=20000)
        status = r.get("status")
        hdrs = {str(k).lower(): v
                for k, v in dict(r.get("headers") or {}).items()}
        wafish = any(h in hdrs for h in WAF_HEADER_WEIGHTS)
        body = (r.get("body") or "").lower()
        if status in (403, 406, 419) and (wafish or "blocked" in body
                                          or "waf" in body
                                          or "cloudflare" in body):
            return True
        r2 = request(url, method="OPTIONS", timeout=timeout,
                     max_bytes=5000)
        if r2.get("status") in (403, 406, 419):
            hdrs2 = {str(k).lower(): v for k, v in
                     dict(r2.get("headers") or {}).items()}
            if any(h in hdrs2 for h in WAF_HEADER_WEIGHTS):
                return True
    except Exception:
        pass
    return False


def run(ctx):
    if ctx.get("status") is None:
        return {"engine": NAME, "status": "error",
                "findings": [],
                "data": {"error": "homepage unreachable"}}
    headers = ctx.get("headers") or {}
    cookie_names = []
    for raw in (ctx.get("cookie_headers") or []):
        try:
            cookie_names.append(raw.split(";", 1)[0].split("=", 1)[0])
        except Exception:
            pass
    probe_blocked = False
    if ctx.get("authorized") and ctx.get("url"):
        try:
            probe_blocked = benign_probe(ctx["url"])
        except Exception:
            probe_blocked = False
    waf = analyze_waf(headers, cookie_names,
                      status=ctx.get("status"),
                      probe_blocked=probe_blocked)
    _protections, findings, data = detect_protections(headers)
    # The probe result refines the likelihood (same signals, one
    # extra observation) — recompute with the probe outcome.
    data["waf_likelihood"] = waf["waf_likelihood"]
    data["waf_signals"] = waf["signals"]
    data["waf_verdict"] = waf["verdict"]
    data["waf_checks"] = waf["checks_performed"]
    data["waf_probe_blocked"] = probe_blocked
    data["protections"] = waf["protections"] or data["protections"]
    for f in findings:
        if f["name"].startswith("WAF likelihood"):
            f["name"] = "WAF likelihood %d%% — %s" % (
                waf["waf_likelihood"], waf["verdict"])
            observed = [s["signal"] for s in waf["signals"]
                        if s["observed"]]
            f["evidence"] = "signals observed: %s; checks: %s" % (
                ", ".join(observed) or "none",
                "; ".join(waf["checks_performed"]))
    return {"engine": NAME, "status": "completed",
            "findings": findings, "data": data}
