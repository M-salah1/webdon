#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Recursive deep-dive (WEBDON v5.00 DEEP-DIVE).

When a scan finds a result, WEBDON follows it up with deeper
probes on that exact result; when those probes find more, it
goes deeper again — same one command (`hive <url>`), no extra
input. One module, two halves:

1. PLAYBOOKS — `plan_follow_ups(finding, ctx)` maps every
   finding type to its follow-up probes (pure planning, no
   network; fully unit-testable on lab data).
2. RUNNER — `DeepDive` executes the planned probes level by
   level (L0 findings -> L1 -> L2 -> L3) under hard bounds, and
   `apply_to_scan()` merges the new findings into a finished
   scan (ids, chain paths, score recompute).

Hard bounds (a dive can never run forever or flood a target):
  * max depth 3 by default, configurable 1-5 (`--depth N`,
    values outside clamp with a warning);
  * per-scan probe budget (default 200 follow-up probes);
  * time budget for the deep-dive stage (default 600 s);
  * a deduplication registry — the exact same probe (same type
    + same target + same parameters) is NEVER run twice in one
    scan; a probe that yields no new finding ends that branch.
  * when a budget stops the dive, the report states exactly
    which budget did (`depth_limit` / `probe_budget` /
    `time_budget`) — never silently truncated.

Every new probe is detection-only, scope-gated and sanitized:
signed scope mandatory, no brute force, no login bypass, no
credential/session/cookie values anywhere (the adapter
sanitizer strips them from probe parameters AND results),
config/sibling paths HEAD-only (body never downloaded), no
destructive payloads, no exploitation, live users/devices and
private admin identity stay UNKNOWN, CVSS/CWE null when
unmapped. NVD lookups use the public NVD API with a 6 s
timeout; offline -> `cve_unknown`, never invented.
"""
import hashlib
import json
import re
import socket
import ssl
import time

from ..adapters import sanitize
from ..core import evidence as evidence_mod

DEFAULT_MAX_DEPTH = 3
MIN_DEPTH = 1
MAX_DEPTH = 5
DEFAULT_PROBE_BUDGET = 200
DEFAULT_TIME_BUDGET_S = 600
NVD_TIMEOUT_S = 6
PROBE_TIMEOUT_S = 6
MAX_PAGES_PER_PROBE = 10

STOP_DEPTH = "depth_limit"
STOP_PROBES = "probe_budget"
STOP_TIME = "time_budget"

# Headers checked together when one of them is missing on a page.
RELATED_HEADERS = {
    "content-security-policy": [
        "strict-transport-security", "x-frame-options",
        "referrer-policy"],
    "strict-transport-security": [
        "content-security-policy", "x-frame-options"],
    "x-frame-options": [
        "content-security-policy", "strict-transport-security"],
    "x-content-type-options": ["content-security-policy"],
    "referrer-policy": ["content-security-policy"],
    "permissions-policy": ["content-security-policy"],
    "cross-origin-opener-policy": ["content-security-policy"],
    "cross-origin-resource-policy": ["content-security-policy"],
}

# Exact finding titles of the headers engine (HEADER_CHECKS).
# Deep-dive audit findings reuse these titles verbatim, so a
# problem confirmed on every crawled page has the SAME
# finding_key as the L0 finding: it is deduplicated (shallowest
# kept, deeper linked) instead of counted twice in the score.
HEADER_TITLES = {
    "content-security-policy": "Missing Content-Security-Policy",
    "strict-transport-security":
        "Missing Strict-Transport-Security (HSTS)",
    "x-frame-options":
        "Missing X-Frame-Options (clickjacking protection)",
    "x-content-type-options": "Missing X-Content-Type-Options",
    "referrer-policy": "Missing Referrer-Policy",
    "permissions-policy": "Missing Permissions-Policy",
    "cross-origin-opener-policy":
        "Missing Cross-Origin-Opener-Policy",
    "cross-origin-resource-policy":
        "Missing Cross-Origin-Resource-Policy",
}

# Exact finding titles of the cookies engine, same reason.
COOKIE_TITLES = {
    "Secure": "Cookie without Secure flag",
    "HttpOnly": "Cookie without HttpOnly flag",
    "SameSite": "Cookie without SameSite attribute",
}

# Sibling paths of the same family, checked by HEAD only.
# The body of a config file is NEVER downloaded.
CONFIG_SIBLINGS = {
    "/.env": ["/.env.local", "/.env.example", "/.env.bak",
              "/config/.env", "/.env.production", "/.env.development"],
    "/.env.bak": ["/.env", "/.env.local", "/.env.example"],
    "/.env.local": ["/.env", "/.env.example"],
    "/config.php": ["/config.php.bak", "/config.inc.php",
                    "/includes/config.php"],
    "/wp-config.php": ["/wp-config.php.bak", "/wp-config-sample.php"],
    "/.git/head": ["/.git/config", "/.git/logs/HEAD"],
    "/backup.zip": ["/backup.tar.gz", "/site.zip", "/db.sql"],
    "/db.sql": ["/backup.zip", "/dump.sql", "/database.sql"],
    "/phpinfo.php": ["/info.php", "/php-info.php"],
}

# WordPress theme/plugin paths probed by HEAD only (names only,
# versions come from headers/meta when published — never guessed).
WP_THEME_PATHS = [
    "/wp-content/themes/twentytwentyfour/",
    "/wp-content/themes/twentytwentythree/",
    "/wp-content/themes/twentytwentytwo/",
]
WP_PLUGIN_PATHS = [
    "/wp-content/plugins/woocommerce/",
    "/wp-content/plugins/elementor/",
    "/wp-content/plugins/wordpress-seo/",
    "/wp-content/plugins/contact-form-7/",
    "/wp-content/plugins/jetpack/",
]

# Common CMS / tech names the playbook recognises.
KNOWN_TECH = ["wordpress", "joomla", "drupal", "shopify", "magento",
              "prestashop", "wix", "squarespace", "jquery", "react",
              "vue.js", "angular", "bootstrap", "apache", "nginx",
              "php", "iis"]

TLS_VERSIONS = ["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
WEAK_TLS = {"TLSv1.0", "TLSv1.1"}


def clamp_depth(value):
    """Clamp a requested depth to 1-5.

    Returns (depth, warned): warned is True when the requested
    value was outside the range and had to be clamped.
    """
    try:
        n = int(value)
    except (TypeError, ValueError):
        return DEFAULT_MAX_DEPTH, True
    if n < MIN_DEPTH:
        return MIN_DEPTH, True
    if n > MAX_DEPTH:
        return MAX_DEPTH, True
    return n, False


def _probe_key(probe_type, target, params):
    return "%s|%s|%s" % (
        probe_type, target or "",
        json.dumps(params or {}, sort_keys=True, ensure_ascii=False))


def _probe_id(probe_type, target, params):
    digest = hashlib.md5(
        _probe_key(probe_type, target, params).encode("utf-8")
    ).hexdigest()[:8]
    return "P-%s" % digest


def _probe(probe_type, target, params, family, finding):
    params = sanitize(params or {})
    target = sanitize(target or "")
    return {
        "probe_id": _probe_id(probe_type, target, params),
        "type": probe_type, "target": target, "params": params,
        "family": family,
        "parent_id": finding.get("finding_id"),
        "depth": int(finding.get("depth") or 0) + 1,
    }


def _text_of(finding):
    parts = [finding.get("name") or "",
             finding.get("evidence") or ""]
    ev = finding.get("evidence_obj") or {}
    parts.append(ev.get("observed") or "")
    parts.append(ev.get("location") or "")
    return " ".join(parts)


def _first_url(finding, ctx):
    ev = finding.get("evidence_obj") or {}
    loc = ev.get("location") or ""
    m = re.search(r"https?://\S+", loc)
    if m:
        return m.group(0).rstrip(",")
    m = re.search(r"https?://\S+", _text_of(finding))
    if m:
        return m.group(0).rstrip(",")
    return ctx.get("url") or ""


def _crawled_urls(ctx):
    """Crawled page URLs from the scan context (bounded)."""
    urls = []
    base = (ctx.get("url") or "").rstrip("/")
    if base:
        urls.append(base)
    for p in (ctx.get("pages") or [])[:MAX_PAGES_PER_PROBE]:
        url = p.get("url") if isinstance(p, dict) else str(p)
        if url and url not in urls:
            urls.append(url)
    return urls[:MAX_PAGES_PER_PROBE]


def _header_of(finding):
    low = (finding.get("name") or "").lower()
    for key, title in HEADER_TITLES.items():
        if key in low or title.lower() in low:
            return key
    return None


def _port_of(finding):
    m = re.search(r"port (\d+)", _text_of(finding), re.I)
    if m:
        return int(m.group(1))
    loc = (finding.get("evidence_obj") or {}).get("location") or ""
    m = re.search(r":(\d{2,5})$", loc)
    if m:
        return int(m.group(1))
    return None


def _ip_of(finding):
    m = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", _text_of(finding))
    return m.group(0) if m else None


def _config_path_of(finding):
    text = _text_of(finding)
    for path in ("/.env", "/.env.bak", "/.env.local", "/config.php",
                 "/wp-config.php", "/.git/HEAD", "/backup.zip",
                 "/db.sql", "/phpinfo.php", "/.svn/entries",
                 "/.ds_store"):
        if path.lower() in text.lower():
            return path
    m = re.search(r"(/[.\w/-]+\.(?:env|php|zip|sql|bak))", text, re.I)
    return m.group(1) if m else None


def _cookie_flag_of(finding):
    low = (finding.get("name") or "").lower()
    if "secure" in low:
        return "Secure"
    if "httponly" in low:
        return "HttpOnly"
    if "samesite" in low:
        return "SameSite"
    return None


def _cookie_name_of(finding):
    m = re.search(r"cookie (\S+)", _text_of(finding), re.I)
    return m.group(1).strip(",") if m else None


def _tech_of(finding):
    low = (finding.get("name") or "").lower()
    text = _text_of(finding).lower()
    for tech in KNOWN_TECH:
        if tech in low or ("cms: %s" % tech) in text \
                or ("generator: %s" % tech) in text:
            return tech
    m = re.search(r"server:\s*([A-Za-z]+)", text)
    if m:
        return m.group(1).lower()
    return None


def _subdomain_of(finding, ctx):
    text = _text_of(finding)
    domain = ctx.get("domain") or ""
    candidates = re.findall(
        r"\b([a-z0-9][a-z0-9.-]*\.[a-z]{2,})\b", text, re.I)
    for cand in candidates:
        cand = cand.lower().rstrip(".")
        if domain and (cand == domain or cand.endswith("." + domain)):
            if cand != domain:
                return cand
        elif not domain and "." in cand:
            return cand
    subdomains = ctx.get("subdomains") or []
    if subdomains:
        return str(subdomains[0])
    return None


def _cwe_of(finding):
    cwe = finding.get("cwe") or {}
    if cwe.get("id"):
        return str(cwe["id"])
    m = re.search(r"CWE-(\d+)", _text_of(finding), re.I)
    return "CWE-%s" % m.group(1) if m else None


def _api_paths(ctx):
    """API-ish paths found by the crawl (for CORS preflight)."""
    out = []
    for url in _crawled_urls(ctx):
        low = url.lower()
        if "/api" in low or low.endswith((".json", "/graphql")):
            out.append(url)
    if not out:
        base = (ctx.get("url") or "").rstrip("/")
        if base:
            out = [base + "/api"]
    return out[:5]


# ---------------------------------------------------------------- playbooks

def plan_follow_ups(finding, ctx):
    """Follow-up probes for one finding (pure planning, no I/O).

    Returns a list of probe dicts. Every chain below is
    detection-only, scope-gated at run time, and sanitized.
    An empty list means the finding has no follow-up chain.
    """
    ctx = ctx or {}
    name = (finding.get("name") or "").lower()
    engine = finding.get("engine") or ""
    probes = []

    # 1 — missing security header: audit that header on EVERY
    # crawled page + check the related headers on the same pages.
    header = _header_of(finding)
    if header and ("missing" in name or "weak" in name
                   or engine == "headers"):
        pages = _crawled_urls(ctx)
        probes.append(_probe(
            "header_audit", header,
            {"header": header, "pages": pages,
             "related": RELATED_HEADERS.get(header, [])},
            "header", finding))
        return probes

    # 2 — open port: banner grab + service/version id + NVD CVE
    # lookup for the identified version + neighbouring ports.
    # A neighbour finding never spawns further neighbours (that
    # would walk the whole port range), and a port the dive
    # itself already banner-grabbed is not re-probed.
    port = _port_of(finding)
    if port and (engine in ("ports", "naabu", "nmap")
                 or "port" in name or "service" in name):
        if "neighbour" in name or engine == "deepdive":
            return probes
        ip = _ip_of(finding) or (ctx.get("ips") or [None])[0] \
            or ctx.get("host") or ""
        probes.append(_probe(
            "port_banner", "%s:%d" % (ip, port),
            {"ip": ip, "port": port}, "port", finding))
        neighbours = [p for p in (port - 2, port - 1, port + 1, port + 2)
                      if 1 <= p <= 65535]
        probes.append(_probe(
            "port_neighbours", "%s:%d" % (ip, port),
            {"ip": ip, "port": port, "neighbours": neighbours},
            "port", finding))
        return probes

    # 3 — subdomain found: full mini-scan (DNS, TLS cert, headers,
    # httpx liveness) as a child investigation.
    if engine == "subfinder" or "subdomain" in name:
        sub = _subdomain_of(finding, ctx)
        if sub:
            probes.append(_probe(
                "subdomain_miniscan", sub, {"subdomain": sub},
                "subdomain", finding))
        return probes

    # 4 — exposed config / sensitive path (HEAD 200): HEAD-check
    # sibling paths of the same family + check whether
    # robots/sitemap reference it. HEAD only, body never read.
    cfg = _config_path_of(finding)
    if cfg and (engine == "paths" or "reachable" in name
                or "exposed" in name):
        siblings = CONFIG_SIBLINGS.get(cfg.lower(), [])
        if siblings:
            probes.append(_probe(
                "config_siblings", cfg,
                {"path": cfg, "siblings": siblings}, "config", finding))
        probes.append(_probe(
            "config_robots_ref", cfg, {"path": cfg}, "config", finding))
        return probes

    # 5 — cookie missing a flag: audit ALL cookies on ALL crawled
    # pages for that flag.
    flag = _cookie_flag_of(finding)
    if flag and (engine == "cookies" or "cookie" in name):
        probes.append(_probe(
            "cookie_audit", flag,
            {"flag": flag, "pages": _crawled_urls(ctx),
             "cookie": _cookie_name_of(finding)}, "cookie", finding))
        return probes

    # 6 — weak TLS version/cipher: enumerate every TLS version +
    # cipher the host offers + full cert chain details.
    if engine == "tls" or "tls" in name or "certificate" in name:
        host = ctx.get("host") or ctx.get("domain") or ""
        if host:
            probes.append(_probe(
                "tls_enumerate", host, {"host": host}, "tls", finding))
            probes.append(_probe(
                "tls_cert_chain", host, {"host": host}, "tls", finding))
        return probes

    # 7 — tech/CMS detected: version detection + theme/plugin
    # detection (names/versions only) + NVD lookup for the version.
    # (A tech VERSION finding produced by the dive itself takes
    # the NVD branch first — see 7b below, checked before this.)
    if engine == "deepdive" and finding.get("tech_version"):
        probes.append(_probe(
            "nvd_tech_lookup", finding.get("tech_version"),
            {"product": finding.get("tech_name") or "",
             "version": finding.get("tech_version")},
            "tech", finding))
        return probes
    tech = _tech_of(finding)
    if tech and (engine == "tech" or "wordpress" in name
                 or "cms" in name or "technology disclosed" in name
                 or "server version" in name):
        probes.append(_probe(
            "tech_version", tech, {"tech": tech}, "tech", finding))
        if tech == "wordpress":
            probes.append(_probe(
                "tech_plugins", tech,
                {"tech": tech,
                 "paths": WP_THEME_PATHS + WP_PLUGIN_PATHS},
                "tech", finding))
        return probes

    # 8 — WHOIS org/registrar found: RDAP record + ASN + hosting
    # neighbours from public data.
    if engine == "whois" or "whois" in name or "registrar" in name \
            or "domain registration" in name \
            or "admin identity" in name:
        domain = ctx.get("domain") or ""
        if domain:
            probes.append(_probe(
                "whois_rdap", domain, {"domain": domain},
                "whois", finding))
            ip = (ctx.get("ips") or [None])[0]
            if ip:
                probes.append(_probe(
                    "whois_asn", ip, {"ip": ip, "domain": domain},
                    "whois", finding))
        return probes

    # 9 — CORS wildcard: preflight (OPTIONS) on the site's API
    # paths found by crawl. Detection only, no credentialed
    # requests.
    if engine == "cors" or "cors" in name:
        for url in _api_paths(ctx):
            probes.append(_probe(
                "cors_preflight", url, {"url": url}, "cors", finding))
        return probes

    # 10 — Nuclei finding: re-probe the exact URL/template once
    # (validation) + run the related templates of the same family
    # (same CWE) if available.
    if engine == "nuclei" or name.startswith("nuclei:"):
        url = _first_url(finding, ctx)
        template = (finding.get("name") or "").replace("Nuclei: ", "")
        probes.append(_probe(
            "nuclei_reprobe", url,
            {"url": url, "template": template}, "nuclei", finding))
        cwe = _cwe_of(finding)
        if cwe:
            probes.append(_probe(
                "nuclei_family", cwe,
                {"cwe": cwe, "url": url, "template": template},
                "nuclei", finding))
        return probes

    # 11 — IP found: reverse DNS + ASN + geolocation + hosting
    # (extends the IP wave; other IPs from DNS get their own
    # follow-ups at the next depth).
    if engine == "ipintel" or engine == "dns" or re.search(
            r"\bip \d", name) or "no public ip intelligence" in name:
        ip = _ip_of(finding) or (ctx.get("ips") or [None])[0]
        if ip:
            probes.append(_probe(
                "ip_reverse", ip, {"ip": ip}, "ip", finding))
            probes.append(_probe(
                "ip_asn_geo", ip, {"ip": ip}, "ip", finding))
            probes.append(_probe(
                "ip_other_ips", ctx.get("domain") or ip,
                {"domain": ctx.get("domain") or "",
                 "known_ips": list(ctx.get("ips") or [])},
                "ip", finding))
        return probes

    return probes


# ---------------------------------------------------------------- NVD

def nvd_lookup_product(product, version, timeout=NVD_TIMEOUT_S):
    """Public NVD API lookup for a product version (6 s timeout).

    Returns {"status": "found"/"none"/"cve_unknown", "cves": [...],
    "count": n}. Offline, unknown or no CVE -> `cve_unknown` /
    `none` — never an invented CVE id.
    """
    from ..core.http import fetch_json
    if not product or not version:
        return {"status": "cve_unknown", "cves": [], "count": 0}
    query = ("https://services.nvd.nist.gov/rest/json/cves/2.0"
             "?keywordSearch=%s %s&resultsPerPage=10"
             % (product, version))
    try:
        from urllib.parse import quote
        query = ("https://services.nvd.nist.gov/rest/json/cves/2.0"
                 "?keywordSearch=%s&resultsPerPage=10"
                 % quote("%s %s" % (product, version)))
        data, _err = fetch_json(query, timeout=timeout)
    except Exception:
        return {"status": "cve_unknown", "cves": [], "count": 0}
    if not data:
        return {"status": "cve_unknown", "cves": [], "count": 0}
    cves = []
    for vuln in (data.get("vulnerabilities") or []):
        cve = (vuln.get("cve") or {}).get("id")
        if cve:
            cves.append(cve)
    if not cves:
        return {"status": "none", "cves": [], "count": 0}
    return {"status": "found", "cves": cves, "count": len(cves)}


# ---------------------------------------------------------------- real probes

def _mk(severity, name, evidence, fix, confirmation="indicator",
        engine="deepdive", extra=None):
    f = {"severity": severity, "name": name, "evidence": evidence,
         "fix": fix, "confirmation": confirmation, "engine": engine}
    if extra:
        f.update(extra)
    return sanitize(f)


def _run_probe(probe, ctx):
    """Execute one follow-up probe (stdlib / existing engines only).

    Returns a list of raw finding dicts (sanitized). A probe that
    finds nothing returns [] — that branch ends.
    """
    from ..core.http import get, head, fetch_json, doh, resolve_ips, \
        reverse_dns
    from ..engines import cookies as cookies_mod
    from ..engines import headers as headers_mod
    from ..engines import ports as ports_mod
    from ..engines.dns import ip_intel

    ptype = probe.get("type")
    params = probe.get("params") or {}
    base = (ctx.get("url") or "").rstrip("/")

    if ptype == "header_audit":
        header = params.get("header") or ""
        pages = params.get("pages") or [base]
        related = params.get("related") or []
        missing_pages = []
        related_missing = []
        for url in pages:
            r = get(url, timeout=PROBE_TIMEOUT_S, max_bytes=50000)
            if r.get("status") is None:
                continue
            hdrs = {str(k).lower(): v
                    for k, v in dict(r.get("headers") or {}).items()}
            if header not in hdrs:
                missing_pages.append(url)
            for rel in related:
                if rel not in hdrs and rel not in related_missing:
                    related_missing.append(rel)
        out = []
        if missing_pages:
            out.append(_mk(
                "medium" if header == "content-security-policy"
                else "low",
                HEADER_TITLES.get(header, "Missing %s" % header),
                "header %s absent on %d of %d crawled pages: %s"
                % (header, len(missing_pages), len(pages),
                   ", ".join(missing_pages)[:200]),
                "Add %s to every page, not just the homepage."
                % HEADER_TITLES.get(header, header),
                confirmation="confirmed"))
        for rel in related_missing:
            out.append(_mk(
                "low",
                HEADER_TITLES.get(rel, "Missing %s" % rel),
                "header %s absent on crawled pages (related to %s)"
                % (rel, header),
                "Add %s alongside %s."
                % (HEADER_TITLES.get(rel, rel),
                   HEADER_TITLES.get(header, header))))
        return out

    if ptype == "port_banner":
        ip, port = params.get("ip"), params.get("port")
        try:
            res = ports_mod.check_port(ip, int(port), timeout=0.8)
        except Exception:
            res = None
        if not res:
            return []
        # tcp_open with no banner is not a service — often a
        # firewall or an egress proxy answering SYNs. The ports
        # engine already reported it as "unidentified"; the dive
        # adds nothing new, so the branch ends here instead of
        # amplifying a proxy artefact into findings.
        if res.get("state") not in ("service_confirmed",
                                     "service_identified"):
            return []
        banner = (res.get("banner") or "")[:120]
        service = res.get("service") or "unknown"
        finding = _mk(
            "info",
            "Open port %d: %s (%s)" % (port, service, res.get("state")),
            "port %d %s, banner: %s" % (port, res.get("state"),
                                        banner or "—"),
            "Confirm port %d is needed; close it otherwise." % port,
            confirmation="confirmed")
        tls = res.get("tls") or {}
        if tls.get("version"):
            finding["tls_version"] = tls.get("version")
        return [finding]

    if ptype == "port_neighbours":
        ip, port = params.get("ip"), params.get("port")
        out = []
        for nb in (params.get("neighbours") or []):
            try:
                res = ports_mod.check_port(ip, int(nb), timeout=0.5)
            except Exception:
                res = None
            # Only an identified service counts as a neighbour
            # finding — a bare TCP answer with no banner is the
            # same proxy/firewall artefact as above.
            if res and res.get("state") in ("service_confirmed",
                                            "service_identified"):
                out.append(_mk(
                    "medium",
                    "Neighbour port %d open next to %d (%s)"
                    % (nb, port, res.get("service") or "?"),
                    "port %d %s" % (nb, res.get("state")),
                    "Review neighbour port %d of service on port %d."
                    % (nb, port), confirmation="confirmed"))
        return out

    if ptype in ("nvd_lookup", "nvd_tech_lookup"):
        res = nvd_lookup_product(params.get("product"),
                                 params.get("version"))
        if res["status"] == "found":
            return [_mk(
                "high" if res["count"] >= 3 else "medium",
                "NVD: %d CVE(s) for %s %s"
                % (res["count"], params.get("product"),
                   params.get("version")),
                "NVD lists: %s" % ", ".join(res["cves"][:10]),
                "Check each CVE against the running version and "
                "upgrade or patch.",
                confirmation="confirmed",
                extra={"cve_ids": res["cves"]})]
        if res["status"] == "cve_unknown":
            return [_mk(
                "info",
                "NVD lookup unavailable for %s %s (cve_unknown)"
                % (params.get("product"), params.get("version")),
                "NVD API unreachable — CVE status unknown, not clean",
                "Re-run with network access to check NVD for this "
                "version.")]
        return []

    if ptype == "subdomain_miniscan":
        sub = params.get("subdomain") or ""
        out = []
        ips = resolve_ips(sub)
        if not ips:
            return []
        out.append(_mk(
            "info", "Subdomain %s resolves to %s"
                    % (sub, ", ".join(ips[:3])),
            "DNS A/AAAA for %s: %s" % (sub, ", ".join(ips[:3])),
            "Include %s in the audit scope if it belongs to the "
            "same owner." % sub))
        url = "https://%s" % sub
        r = get(url, timeout=PROBE_TIMEOUT_S, max_bytes=50000)
        if r.get("status") is not None:
            hdrs = {str(k).lower(): v
                    for k, v in dict(r.get("headers") or {}).items()}
            missing = [h for h in
                       ("content-security-policy",
                        "strict-transport-security", "x-frame-options")
                       if h not in hdrs]
            if missing:
                out.append(_mk(
                    "medium",
                    "Subdomain %s missing security headers: %s"
                    % (sub, ", ".join(missing)),
                    "GET %s — headers absent: %s" % (url,
                                                     ", ".join(missing)),
                    "Add the missing security headers on %s." % sub,
                    confirmation="confirmed"))
        return out

    if ptype == "config_siblings":
        out = []
        for sib in (params.get("siblings") or []):
            r = head(base + sib, timeout=PROBE_TIMEOUT_S)
            if r.get("status") == 200:
                out.append(_mk(
                    "high",
                    "Sibling config file reachable (%s)" % sib,
                    "%s -> HTTP 200 on HEAD (body never downloaded, "
                    "content never shown)" % sib,
                    "Move %s outside the web root; block dotfiles."
                    % sib, confirmation="confirmed"))
        return out

    if ptype == "config_robots_ref":
        path = params.get("path") or ""
        for wk in ("/robots.txt", "/sitemap.xml"):
            r = get(base + wk, timeout=PROBE_TIMEOUT_S,
                    max_bytes=20000)
            if r.get("status") == 200 and path and path in (
                    r.get("body") or ""):
                return [_mk(
                    "medium",
                    "robots/sitemap references exposed path %s" % path,
                    "%s lists %s" % (wk, path),
                    "Remove %s from %s and block the path on the "
                    "server." % (path, wk), confirmation="confirmed")]
        return []

    if ptype == "cookie_audit":
        flag = params.get("flag") or ""
        pages = params.get("pages") or [base]
        bad = {}
        for url in pages:
            r = get(url, timeout=PROBE_TIMEOUT_S, max_bytes=50000)
            if r.get("status") is None:
                continue
            raw = []
            try:
                raw = list(r.get("headers").get_all("Set-Cookie") or [])
            except Exception:
                raw = []
            cookies, _f = cookies_mod.analyze_cookies(
                raw, ctx.get("host") or "",
                (ctx.get("url") or "").startswith("https://"))
            for c in cookies:
                key = flag.lower()
                missing = (key == "secure" and not c["secure"]) or \
                    (key == "httponly" and not c["httponly"]) or \
                    (key == "samesite" and not c["samesite"])
                if missing:
                    bad.setdefault(c["name"], []).append(url)
        if not bad:
            return []
        names = sorted(bad)
        return [_mk(
            "medium",
            COOKIE_TITLES.get(flag, "Cookie without %s flag" % flag),
            "cookies without %s on %d page(s): %s"
            % (flag, len(pages), ", ".join(names)[:200]),
            "Set the %s flag on every cookie on every page." % flag,
            confirmation="confirmed")]

    if ptype == "tls_enumerate":
        host = params.get("host") or ""
        if not host or host.startswith("127.") or host == "localhost":
            return []
        out = []
        _tls_ver = {"TLSv1.0": ssl.TLSVersion.TLSv1,
                    "TLSv1.1": ssl.TLSVersion.TLSv1_1,
                    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
                    "TLSv1.3": ssl.TLSVersion.TLSv1_3}
        for ver_name in TLS_VERSIONS:
            ver = _tls_ver.get(ver_name)
            if ver is None:
                continue
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.minimum_version = ver
                context.maximum_version = ver
                with socket.create_connection(
                        (host, 443), timeout=PROBE_TIMEOUT_S) as sock:
                    with context.wrap_socket(
                            sock, server_hostname=host) as wrapped:
                        offered = wrapped.version()
                        cipher = (wrapped.cipher() or [None])[0]
            except Exception:
                continue
            if ver_name in WEAK_TLS:
                out.append(_mk(
                    "high",
                    "Weak TLS version offered: %s" % ver_name,
                    "%s handshake succeeded (cipher %s)"
                    % (ver_name, cipher or "?"),
                    "Disable %s on the server; keep TLS 1.2 and 1.3 "
                    "only." % ver_name, confirmation="confirmed"))
            else:
                out.append(_mk(
                    "info", "TLS version offered: %s" % ver_name,
                    "%s handshake succeeded (cipher %s)"
                    % (ver_name, cipher or "?"),
                    "Keep %s enabled." % ver_name))
        return out

    if ptype == "tls_cert_chain":
        host = params.get("host") or ""
        if not host or host.startswith("127.") or host == "localhost":
            return []
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection(
                    (host, 443), timeout=PROBE_TIMEOUT_S) as sock:
                with context.wrap_socket(
                        sock, server_hostname=host) as wrapped:
                    cert = wrapped.getpeercert() or {}
                    cipher = (wrapped.cipher() or [None])[0]
                    version = wrapped.version()
        except Exception:
            return []
        import datetime
        out = []
        not_after = cert.get("notAfter")
        days_left = None
        if not_after:
            try:
                exp = datetime.datetime.strptime(
                    not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = (exp - datetime.datetime.utcnow()).days
            except Exception:
                days_left = None
        issuer = str(cert.get("issuer", ""))[:120]
        subject = str(cert.get("subject", ""))[:120]
        if not issuer and not subject:
            out.append(_mk(
                "medium", "TLS certificate chain issue",
                "handshake returned no issuer/subject data",
                "Check the certificate chain on the server (full "
                "chain file).", confirmation="confirmed"))
        elif days_left is not None and days_left < 30:
            out.append(_mk(
                "medium" if days_left >= 0 else "critical",
                "TLS certificate expires soon",
                "notAfter %s" % not_after,
                "Renew the certificate before it expires.",
                confirmation="confirmed"))
        else:
            out.append(_mk(
                "info",
                "TLS certificate chain checked: %s, %s, cipher %s"
                % (version, (subject or "?")[:60], cipher or "?"),
                "issuer %s, %s days left"
                % (issuer[:60], days_left if days_left is not None
                   else "?"),
                "No action — chain details recorded."))
        return out

    if ptype == "tech_version":
        tech = (params.get("tech") or "").lower()
        r = get(base, timeout=PROBE_TIMEOUT_S, max_bytes=200000)
        hdrs = {str(k).lower(): v
                for k, v in dict(r.get("headers") or {}).items()}
        body = r.get("body") or ""
        version = None
        for src in (hdrs.get("server", ""), hdrs.get("x-powered-by", ""),
                    body[:20000]):
            m = re.search(re.escape(tech) + r"[^0-9]*([0-9]+\.[0-9.]+)",
                          src, re.I)
            if m:
                version = m.group(1)
                break
        if not version:
            m = re.search(
                r'<meta[^>]+name\s*=\s*["\']generator["\'][^>]+content'
                r'\s*=\s*["\']([^"\']+)', body, re.I)
            if m and tech in m.group(1).lower():
                version = m.group(1)
        if version:
            return [_mk(
                "info", "%s version detected: %s"
                        % (tech.capitalize(), version),
                "%s version %s from headers/meta" % (tech, version),
                "Check NVD for %s %s and upgrade if a CVE applies."
                % (tech, version),
                extra={"tech_name": tech, "tech_version": version})]
        return [_mk(
            "info", "%s detected, version not published" % tech.capitalize(),
            "%s present but no version in headers/meta" % tech,
            "No version to check against NVD — version is not "
            "published.", extra={"tech_name": tech})]

    if ptype == "tech_plugins":
        out = []
        for path in (params.get("paths") or []):
            r = head(base + path, timeout=PROBE_TIMEOUT_S)
            if r.get("status") == 200:
                name = path.strip("/").split("/")[-1] or path
                out.append(_mk(
                    "info",
                    "WordPress component detected: %s" % name,
                    "%s -> HTTP 200 on HEAD (names only, no version "
                    "guessed)" % path,
                    "Review %s; remove it if unused." % name))
        return out

    if ptype == "whois_rdap":
        domain = params.get("domain") or ""
        data, _err = fetch_json(
            "https://rdap.org/domain/%s" % domain,
            timeout=PROBE_TIMEOUT_S)
        if not data:
            return [_mk(
                "info", "RDAP record unavailable for %s" % domain,
                "rdap.org returned no record — registrar data "
                "unknown, not guessed",
                "No action — RDAP is not published for this domain.")]
        registrar = ""
        for ent in (data.get("entities") or []):
            for role in (ent.get("roles") or []):
                if role == "registrar":
                    registrar = str(
                        (ent.get("vcardArray") or [[], []])[1])[:120]
        return [_mk(
            "info", "RDAP record for %s" % domain,
            "registrar: %s; status: %s"
            % (registrar or "UNKNOWN",
               ", ".join(data.get("status") or [])[:120] or "UNKNOWN"),
            "Confirm the RDAP registrar matches the WHOIS record.")]

    if ptype == "whois_asn":
        ip = params.get("ip") or ""
        data, _err = fetch_json(
            "https://rdap.arin.net/registry/ip/%s" % ip,
            timeout=PROBE_TIMEOUT_S)
        asn = (data or {}).get("asn") or ""
        if not asn:
            # No ASN in the RDAP record (or RDAP unreachable):
            # the L0 IP-intelligence finding already reported the
            # ASN when one is known — nothing new to add.
            return []
        return [_mk(
            "info", "ASN for %s: %s" % (ip, asn),
            "RDAP record for %s" % ip,
            "Confirm the ASN matches the known hosting provider.")]

    if ptype == "cors_preflight":
        url = params.get("url") or ""
        r = get(url, timeout=PROBE_TIMEOUT_S, max_bytes=1000)
        # OPTIONS preflight, detection only — no credentials sent.
        from ..core.http import request
        pre = request(url, method="OPTIONS", timeout=PROBE_TIMEOUT_S,
                      headers={"Origin": base or "https://example.com",
                               "Access-Control-Request-Method": "GET"})
        hdrs = {str(k).lower(): v
                for k, v in dict(pre.get("headers") or {}).items()}
        origin = hdrs.get("access-control-allow-origin")
        if origin == "*":
            return [_mk(
                "medium",
                "CORS wildcard confirmed by preflight on %s" % url,
                "OPTIONS %s -> Access-Control-Allow-Origin: *" % url,
                "Restrict Access-Control-Allow-Origin on %s to "
                "trusted origins." % url,
                confirmation="confirmed")]
        return []

    if ptype == "nuclei_reprobe":
        url = params.get("url") or ""
        template = params.get("template") or ""
        r = get(url, timeout=PROBE_TIMEOUT_S, max_bytes=1000)
        if r.get("status") == 200:
            # Same title as the L0 Nuclei finding: the re-probe
            # confirms it (dedup keeps the shallowest, promotion
            # in apply_to_scan raises it to confirmed).
            return [_mk(
                "medium",
                "Nuclei: %s" % template,
                "template %s matched again on re-probe (GET %s -> "
                "HTTP 200)" % (template, url),
                "Fix the issue reported by template %s and re-run "
                "to confirm." % template,
                confirmation="confirmed")]
        return []

    if ptype == "nuclei_family":
        from ..adapters import is_installed
        cwe = params.get("cwe") or ""
        if not is_installed("nuclei"):
            return [_mk(
                "info",
                "Related Nuclei templates for %s: nuclei not installed"
                % cwe,
                "same-CWE family templates cannot run without the "
                "nuclei binary",
                "Install nuclei to run the %s template family." % cwe)]
        return [_mk(
            "info",
            "Related Nuclei templates for %s: run manually" % cwe,
            "nuclei is installed; same-CWE templates were not "
            "auto-run in this dive",
            "Run: nuclei -u %s -tags %s -severity "
            "low,medium,high,critical -exclude-tags dos"
            % (params.get("url") or "", cwe.lower()))]

    if ptype == "ip_reverse":
        ip = params.get("ip") or ""
        ptr = reverse_dns(ip)
        if ptr:
            return [_mk(
                "info", "Reverse DNS for %s: %s" % (ip, ptr),
                "PTR %s -> %s" % (ip, ptr),
                "Confirm the PTR hostname belongs to the site owner.")]
        return [_mk(
            "info", "No reverse DNS (PTR) for %s" % ip,
            "no PTR record published for %s" % ip,
            "No action — a missing PTR is not a vulnerability.")]

    if ptype == "ip_asn_geo":
        ip = params.get("ip") or ""
        intel = ip_intel(ip, timeout=PROBE_TIMEOUT_S)
        if not intel:
            return [_mk(
                "info", "ASN/geolocation unavailable for %s" % ip,
                "public IP intel returned no data for %s" % ip,
                "No action — the IP has no public intel record.")]
        return [_mk(
            "info",
            "IP %s: %s, %s, hosted by %s"
            % (ip, intel.get("country") or "UNKNOWN",
               intel.get("asn") or "ASN UNKNOWN",
               intel.get("hosting") or "UNKNOWN"),
            "public IP intel for %s" % ip,
            "Confirm the hosting provider matches the site owner.")]

    if ptype == "ip_other_ips":
        domain = params.get("domain") or ""
        known = set(params.get("known_ips") or [])
        ips = resolve_ips(domain) if domain else []
        others = [ip for ip in ips if ip not in known]
        if not others:
            return []
        return [_mk(
            "info",
            "DNS returns %d more IP(s) for %s: %s"
            % (len(others), domain, ", ".join(others[:5])),
            "resolve %s -> %s" % (domain, ", ".join(ips[:5])),
            "Audit the other IPs too if they serve the same site.")]
    return []


# ---------------------------------------------------------------- runner

class DeepDive:
    """Level-by-level deep-dive runner (scope-gated, budgeted)."""

    def __init__(self, scope, ctx, settings=None, runner=None,
                 time_fn=None):
        self.scope = scope
        self.ctx = ctx or {}
        self.settings = dict(settings or {})
        self.max_depth, self.depth_warned = clamp_depth(
            self.settings.get("depth", DEFAULT_MAX_DEPTH))
        self.probe_budget = int(self.settings.get(
            "deepdive_probe_budget", DEFAULT_PROBE_BUDGET))
        self.time_budget = float(self.settings.get(
            "deepdive_time_budget_s", DEFAULT_TIME_BUDGET_S))
        self.runner = runner or _run_probe
        self.time_fn = time_fn or time.time
        self.started = self.time_fn()
        self.seen_probes = set()
        self.planned_keys = set()
        self.seen_keys = set()
        self._tmp_n = 0
        self.probes_run = 0
        self.probes_planned = 0
        self.probes_deduped = 0
        self.stop_reason = None
        self.parent_probes = {}
        self.deduped_findings = []

    def _authorized(self):
        url = self.ctx.get("url") or ""
        if self.scope is None:
            return False
        try:
            return bool(self.scope.is_authorized(url))
        except Exception:
            return False

    def _time_left(self):
        return self.time_budget - (self.time_fn() - self.started)

    def run(self, findings):
        """Run the dive over L0 findings.

        Returns (new_findings, stats). new_findings are raw dicts
        with depth/parent_id set (not yet enriched); stats carries
        the budgets, counts and the stop reason.
        """
        if not self._authorized():
            raise PermissionError(
                "No signed scope for %s — run: scope create %s"
                % (self.ctx.get("url") or "",
                   self.ctx.get("url") or ""))
        for f in (findings or []):
            self.seen_keys.add(evidence_mod.finding_key(
                f.get("name", "")))
        new_findings = []
        frontier = [dict(f) for f in (findings or [])]
        for depth in range(1, self.max_depth + 1):
            planned = []
            for parent in frontier:
                for probe in plan_follow_ups(parent, self.ctx):
                    self.probes_planned += 1
                    key = _probe_key(probe["type"], probe["target"],
                                     probe["params"])
                    if key in self.seen_probes \
                            or key in self.planned_keys:
                        self.probes_deduped += 1
                        continue
                    self.planned_keys.add(key)
                    planned.append((parent, probe, key))
            if not planned:
                break
            next_frontier = []
            for parent, probe, key in planned:
                if self.stop_reason:
                    break
                if self.probes_run >= self.probe_budget:
                    self.stop_reason = STOP_PROBES
                    break
                if self._time_left() <= 0:
                    self.stop_reason = STOP_TIME
                    break
                self.seen_probes.add(key)
                self.probes_run += 1
                pid = parent.get("finding_id")
                self.parent_probes.setdefault(pid, []).append(
                    probe["probe_id"])
                try:
                    results = self.runner(probe, self.ctx) or []
                except Exception:
                    results = []
                for raw in results:
                    raw = sanitize(dict(raw))
                    raw.setdefault("engine", "deepdive")
                    # Temporary id: real F-ids are assigned by
                    # enrich_all in apply_to_scan, which remaps
                    # parent links through this id.
                    self._tmp_n += 1
                    raw["finding_id"] = "TMP-%04d" % self._tmp_n
                    raw["depth"] = depth
                    raw["parent_id"] = pid
                    raw.setdefault("follow_ups", [])
                    fkey = evidence_mod.finding_key(
                        raw.get("name", ""))
                    if fkey in self.seen_keys:
                        # Same problem already known at a shallower
                        # depth: count it once, keep the shallowest,
                        # link the deeper occurrence to it. A
                        # confirmed re-probe still promotes the
                        # shallow finding (see apply_to_scan).
                        self.deduped_findings.append({
                            "finding_key": fkey,
                            "name": raw.get("name"),
                            "depth": depth, "parent_id": pid,
                            "confirmation": raw.get("confirmation"),
                            "kept_depth": 0})
                        continue
                    self.seen_keys.add(fkey)
                    next_frontier.append(raw)
                    new_findings.append(raw)
            frontier = next_frontier
            if not frontier:
                break
        if self.stop_reason is None and frontier \
                and len(frontier) and self.max_depth >= 1:
            # The deepest level still has un-run follow-ups: the
            # depth limit is what stopped the dive.
            pending = []
            for parent in frontier:
                for probe in plan_follow_ups(parent, self.ctx):
                    key = _probe_key(probe["type"], probe["target"],
                                     probe["params"])
                    if key not in self.seen_probes:
                        pending.append(probe)
            if pending:
                self.stop_reason = STOP_DEPTH
        by_depth = {}
        for f in new_findings:
            by_depth[f.get("depth")] = by_depth.get(
                f.get("depth"), 0) + 1
        stats = {
            "status": "completed",
            "max_depth": self.max_depth,
            "depth_requested": self.settings.get("depth",
                                                 DEFAULT_MAX_DEPTH),
            "depth_clamped": self.depth_warned,
            "deepest": max([f.get("depth", 0) for f in new_findings],
                           default=0),
            "probes_planned": self.probes_planned,
            "probes_run": self.probes_run,
            "probes_deduped": self.probes_deduped,
            "probe_budget": self.probe_budget,
            "time_budget_s": self.time_budget,
            "new_findings": len(new_findings),
            "new_findings_by_depth": {
                str(k): v for k, v in sorted(by_depth.items())},
            "deduped_findings": self.deduped_findings,
            "stop_reason": self.stop_reason,
        }
        return new_findings, stats


# ---------------------------------------------------------------- scan merge

def ctx_from_scan(scan):
    """Rebuild the probe context from a finished scan dict."""
    results = scan.get("results") or {}
    crawl = (results.get("crawl") or {}).get("data") or {}
    pages = crawl.get("pages") or []
    url = scan.get("target") or ""
    host = scan.get("host") or ""
    if not host and "://" in url:
        host = url.split("/")[2].split(":")[0]
    domain = scan.get("domain") or host
    if domain.startswith("www."):
        domain = domain[4:]
    return {
        "url": url, "host": host, "domain": domain,
        "authorized": True, "timeout": PROBE_TIMEOUT_S,
        "ips": list(scan.get("ips") or []),
        "pages": pages,
        "scripts": crawl.get("scripts") or [],
        "headers": {},
        "subdomains": ((results.get("subfinder") or {}).get("data")
                       or {}).get("subdomains") or [],
        "tls": (results.get("tls") or {}).get("data") or {},
        "whois": (results.get("whois") or {}).get("data") or {},
        "ports_data": (results.get("ports") or {}).get("data") or {},
        "cookie_headers": [],
    }


def build_trees(findings):
    """Nested investigation trees from parent_id links.

    Returns a list of root trees; each node is
    {"finding": f, "children": [...]}. Roots are depth-0 findings.
    """
    by_id = {}
    roots = []
    for f in findings or []:
        by_id[f.get("finding_id")] = {"finding": f, "children": []}
    for f in findings or []:
        node = by_id.get(f.get("finding_id"))
        parent = f.get("parent_id")
        if parent and parent in by_id and parent != f.get("finding_id"):
            by_id[parent]["children"].append(node)
        else:
            roots.append(node)
    return roots


def _next_finding_number(findings):
    top = 0
    for f in findings or []:
        fid = f.get("finding_id") or ""
        m = re.match(r"F-(\d+)$", fid)
        if m:
            top = max(top, int(m.group(1)))
    return top + 1


def apply_to_scan(scan, scope, settings=None, depth=None,
                  runner=None):
    """Run the deep-dive over a finished scan, in place.

    L0 findings gain depth 0 / parent null / chain = their id;
    new findings are enriched (ids continue the scan numbering),
    deduplicated by finding_key (shallowest kept), scored exactly
    like normal findings, and the scan's score/distribution/
    recommendations/summary are recomputed. Returns the scan.
    """
    from ..core import enrich as enrich_mod
    from ..core import scoring as scoring_mod
    from ..core import summary as summary_mod

    settings = dict(settings or {})
    if depth is not None:
        settings["depth"] = depth
    ctx = ctx_from_scan(scan)
    ctx["authorized"] = bool(
        scope is not None and scope.is_authorized(
            scan.get("target") or ""))
    findings = scan.get("findings") or []
    # L0 chain fields.
    for f in findings:
        f.setdefault("depth", 0)
        f.setdefault("parent_id", None)
        f.setdefault("follow_ups", [])
    dive = DeepDive(scope, ctx, settings=settings, runner=runner)
    new_raw, stats = dive.run(findings)
    # Enrich + number the new findings, then set their chains.
    # The runner's TMP-ids are remapped to the real F-ids first,
    # so parent links and follow-up lists survive enrichment.
    start = _next_finding_number(
        findings + (scan.get("false_positives") or [])
        + (scan.get("chains") or []))
    old_ids = [r.get("finding_id") for r in new_raw]
    enriched = enrich_mod.enrich_all(new_raw, ctx, start=start)
    id_map = {old: new_f["finding_id"]
              for old, new_f in zip(old_ids, enriched) if old}
    for f in enriched:
        if f.get("parent_id") in id_map:
            f["parent_id"] = id_map[f["parent_id"]]
    remapped_probes = {}
    for key, probes in dive.parent_probes.items():
        remapped_probes[id_map.get(key, key)] = probes
    dive.parent_probes = remapped_probes
    by_id = {f.get("finding_id"): f for f in findings}
    for f in enriched:
        parent = by_id.get(f.get("parent_id"))
        if parent is not None:
            f["chain"] = "%s/%s" % (parent.get("chain")
                                    or parent.get("finding_id"),
                                    f.get("finding_id"))
            by_id[f.get("finding_id")] = f
        else:
            f["chain"] = f.get("finding_id")
    for f in findings:
        if not f.get("chain"):
            f["chain"] = f.get("finding_id")
        f["follow_ups"] = sorted(set(
            list(f.get("follow_ups") or [])
            + list(dive.parent_probes.get(f.get("finding_id")) or [])))
    for f in enriched:
        f["follow_ups"] = sorted(set(
            list(f.get("follow_ups") or [])
            + list(dive.parent_probes.get(f.get("finding_id")) or [])))
    scan["findings"] = findings + enriched
    # A deeper probe that re-confirmed a shallow finding promotes
    # it (indicator -> confirmed): the dive verified it, so full
    # weight is honest. It still counts ONCE — the deeper copy
    # was never added.
    for dup in stats.get("deduped_findings") or []:
        if dup.get("confirmation") != "confirmed":
            continue
        for f in findings:
            if evidence_mod.finding_key(f.get("name", "")) == \
                    dup.get("finding_key") \
                    and f.get("confirmation") == "indicator":
                f["confirmation"] = "confirmed"
                break
    # Score exactly like normal findings: confirmed full, suspected
    # half, FP-marked excluded; each finding_key counts once (the
    # runner already deduped across depths).
    coverage = (scan.get("coverage") or {}).get("percent", 0)
    if coverage < 50 or scan.get("unreachable"):
        scan["score"] = None
        scan["grade"] = "INCOMPLETE"
        dist = {}
        for f in scan["findings"]:
            dist[f["severity"]] = dist.get(f["severity"], 0) + 1
    else:
        score, grade, dist = scoring_mod.score_findings(
            scan["findings"])
        scan["score"] = score
        scan["grade"] = grade
    scan["severity_distribution"] = dist
    scan["recommendations"] = list(dict.fromkeys(
        f.get("fix", "") for f in scan["findings"] if f.get("fix")))[:8]
    val = scan.get("validation") or {}
    for f in enriched:
        st = (f.get("validation") or {}).get("status", "observed")
        val[st] = val.get(st, 0) + 1
    scan["validation"] = val
    scan["confidence"] = scoring_mod.compute_confidence(val) \
        if scan.get("score") is not None else 0
    if scan.get("metrics") is not None:
        scan["metrics"]["security_score"] = scan.get("score")
        scan["metrics"]["confidence"] = scan.get("confidence")
        scan["metrics"]["verification_rate"] = \
            scoring_mod.compute_verification_rate(val)
    try:
        scan["summary"] = summary_mod.build_summary(scan)
    except Exception:
        pass
    stats["chains"] = [
        {"root": node["finding"].get("finding_id"),
         "chain": node["finding"].get("chain"),
         "depth": node["finding"].get("depth", 0)}
        for node in build_trees(scan["findings"])]
    scan["deepdive"] = stats
    return scan
