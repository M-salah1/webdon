#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Evidence Collector — every finding becomes one evidence record:
engine, time, what was seen. One ID per record.

v4.00 EVIDENCE: every finding now also carries a structured
`evidence_obj` — the machine-checkable evidence object:

    {"observed":   redacted observed value (never a secret/cookie/
                   session value — engines only record names, flags
                   and statuses),
     "location":   exact URL / path / host:port where it was seen,
     "timestamp":  UTC ISO time of the observation,
     "engine":     producing engine name,
     "method":     how it was probed (GET headers, HEAD path, TLS
                   handshake, ...),
     "observation": one-line raw observation summary}

The human-readable `evidence` STRING is kept unchanged for
backward compatibility (reports, summary, old tests and old
scans all use it). `evidence_obj` is the object the validator
requires: a finding without it is rejected. Old scans (string
evidence only) are migrated on load by `migrate_finding()`.
"""
import re
import time

from ..adapters import sanitize as _sanitize

# How each engine probed — recorded on every evidence object.
PROBE_METHODS = {
    "headers": "GET {url} — response headers",
    "cookies": "GET {url} — Set-Cookie headers (names/flags only)",
    "cors": "GET {url} — CORS response headers",
    "protect": "GET {url} — response headers (WAF/CDN/rate-limit)",
    "tech": "GET {url} — headers + HTML meta",
    "crawl": "GET {url} — same-origin crawl",
    "paths": "HEAD {location} — existence check, body never read",
    "tls": "TLS handshake probe to {host}:443",
    "dns": "DNS-over-HTTPS records for {host}",
    "whois": "WHOIS query (port 43) for {host}",
    "ports": "TCP connect probe to {host}:{port}",
    "ipintel": "Public IP intelligence for {host}",
    "timeline": "Public records timeline for {host}",
    "httpx": "httpx live probe of {url}",
    "subfinder": "Subdomain enumeration for {host} (CT log)",
    "katana": "Katana crawl of {url}",
    "nuclei": "Nuclei template match on {url}",
    "naabu": "Naabu port probe of {host}",
    "schemathesis": "Schemathesis API check on {url}",
    "nmap": "Nmap service probe of {host}",
    "wireshark": "Traffic analysis for {host}",
    "openvas": "OpenVAS banner heuristic for {host}",
    "netexec": "NetExec AD probe of {host}",
    "bloodhound": "BloodHound AD analysis for {host}",
}


def utcnow():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def finding_key(name):
    """Stable key for one finding type, across scans.

    Used for the finding history (first/last seen) and for
    false-positive marks: the same problem on the same target
    always has the same key.
    """
    text = (name or "").lower()
    text = re.sub(r"[^a-z0-9]+", " ", text)
    return " ".join(text.split())


def _location_from(finding, ctx):
    """Exact location of the observation."""
    ev_text = finding.get("evidence") or ""
    url = ctx.get("url") or ""
    if ev_text.startswith("/"):
        return url.rstrip("/") + ev_text.split()[0]
    m = re.search(r"https?://\S+", ev_text)
    if m:
        return m.group(0).rstrip(",")
    engine = finding.get("engine", "")
    if engine == "tls":
        return "%s:443" % (ctx.get("host") or "")
    if engine == "ports":
        m = re.search(r"port (\d+)", ev_text)
        if m:
            return "%s:%s" % (ctx.get("ips", [""])[0]
                              or ctx.get("host") or "", m.group(1))
    return url


def build_evidence_obj(finding, ctx=None):
    """Build the structured evidence object for one finding.

    The observed value is the engine's (already redacted) evidence
    string, passed through the adapter sanitizer so no credential,
    cookie or session value can ever land in a report.
    """
    ctx = ctx or {}
    ev_text = finding.get("evidence") or ""
    engine = finding.get("engine", "")
    location = _location_from(finding, ctx)
    method = (PROBE_METHODS.get(engine, "probe of {url}")
              .replace("{url}", ctx.get("url") or "")
              .replace("{host}", ctx.get("host") or "")
              .replace("{location}", location)
              .replace("{port}", ""))
    obj = {
        "observed": (ev_text or "")[:300],
        "location": location,
        "timestamp": utcnow(),
        "engine": engine,
        "method": method,
        "observation": (ev_text or "")[:300],
    }
    return _sanitize(obj)


def migrate_finding(finding, target=""):
    """Backward-compatible load: give an old (string-evidence-only)
    finding a structured evidence object, in place."""
    if finding.get("evidence_obj"):
        return finding
    ctx = {"url": target or finding.get("evidence") or ""}
    if target:
        try:
            ctx["host"] = target.split("/")[2].split(":")[0]
        except Exception:
            ctx["host"] = ""
    finding["evidence_obj"] = build_evidence_obj(finding, ctx)
    return finding


def require_evidence(finding):
    """Return the finding's evidence object, or raise ValueError.

    A finding with no evidence object — or one missing a required
    field — is rejected by the validator, never scored silently.
    """
    obj = finding.get("evidence_obj")
    if not isinstance(obj, dict):
        raise ValueError("finding %r has no evidence object"
                         % (finding.get("name") or "?",))
    for field in ("observed", "location", "timestamp", "engine",
                  "method"):
        if not obj.get(field):
            raise ValueError("evidence object of %r is missing %s"
                             % (finding.get("name") or "?", field))
    return obj


def collect(findings):
    """Turn raw findings into evidence records."""
    out = []
    for i, f in enumerate(findings or []):
        item = dict(f)
        item["evidence_id"] = "EV-%04d" % (i + 1)
        item["collected_at"] = utcnow()
        item.setdefault("validation", {"status": "observed",
                                       "confidence": 50})
        out.append(item)
    return out
