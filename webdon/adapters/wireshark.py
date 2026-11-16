#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Wireshark (tshark) adapter — traffic analysis of the user's
OWN traffic to the target only (v3.00 NET).

When tshark is installed AND capture is permitted (root on
Termux — packet capture needs privileges), a short bounded
capture is run with a capture filter limited to the target IP:
  tshark -i any -c 200 -f "host <target-ip>" -T fields \
      -e frame.number -e ip.proto -e dns.qry.name \
      -e tls.handshake.version -e http.request.method -e http.host
Only field values are kept: DNS names queried, TLS handshake
versions, HTTP methods/hosts. No packet payloads are ever kept,
and no credential/cookie/session value is stored — the shared
sanitizer drops them before anything is returned.

When tshark is missing, or capture is denied / the process is
not root, the adapter falls back to WEBDON's own request log:
the homepage request plus the crawled pages (method/URL/status
+ TLS data already measured) — labelled honestly as
"fallback: own-request-log". It NEVER captures traffic to other
hosts and NEVER claims to sniff anyone else's traffic.
"""
import os

from . import NOT_INSTALLED, adapter_result, finding, is_installed, require_scope, run_cmd

NAME = "wireshark"
TITLE = "Wireshark (tshark) — traffic analysis"
BINARY = "tshark"

FALLBACK_MODE = "fallback: own-request-log — tshark needs root; " \
                "capture not available here"


def is_root():
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def build_args(ip, iface="any", count=200):
    """Bounded capture, filter limited to the target IP only."""
    return [BINARY, "-i", iface, "-c", str(count),
            "-f", "host %s" % ip,
            "-T", "fields",
            "-e", "frame.number", "-e", "ip.proto",
            "-e", "dns.qry.name", "-e", "tls.handshake.version",
            "-e", "http.request.method", "-e", "http.host"]


def parse_fields(text):
    """Parse tshark -T fields output (tab-separated).

    Columns: frame, ip.proto, dns.qry.name, tls version,
    http method, http host. Returns a summary dict with counts
    and distinct values only — no payloads.
    """
    packets = 0
    dns_names = set()
    tls_versions = set()
    http_methods = set()
    http_hosts = set()
    for line in (text or "").splitlines():
        if not line.strip():
            continue
        packets += 1
        cols = line.split("\t")
        # dns.qry.name is column 2, tls version column 3,
        # http method column 4, http host column 5.
        if len(cols) > 2 and cols[2].strip():
            dns_names.add(cols[2].strip()[:120])
        if len(cols) > 3 and cols[3].strip():
            tls_versions.add(cols[3].strip()[:40])
        if len(cols) > 4 and cols[4].strip():
            http_methods.add(cols[4].strip()[:16])
        if len(cols) > 5 and cols[5].strip():
            http_hosts.add(cols[5].strip()[:120])
    return {"packets": packets,
            "dns_queries": sorted(dns_names),
            "tls_versions": sorted(tls_versions),
            "http_methods": sorted(http_methods),
            "http_hosts": sorted(http_hosts)}


def own_traffic_fallback(ctx):
    """Analysis of WEBDON's own requests (no capture needed).

    Uses the homepage request, the crawled pages and the TLS
    data already measured — method/URL/status and header names
    only, never values.
    """
    pages = ctx.get("pages") or []
    tls = ctx.get("tls") or {}
    hosts = set()
    methods = set()
    for p in pages:
        url = p.get("url") if isinstance(p, dict) else str(p)
        if url:
            methods.add("GET")
            try:
                hosts.add(url.split("/")[2])
            except IndexError:
                pass
    if ctx.get("url"):
        methods.add("GET")
        try:
            hosts.add(ctx["url"].split("/")[2])
        except IndexError:
            pass
    tls_versions = []
    versions = tls.get("versions")
    if isinstance(versions, dict):
        # The TLS engine records {label: bool} — True only when
        # that handshake SUCCEEDED. A False entry means the
        # version was attempted and failed: it was NOT observed
        # in traffic and must not be reported as supported.
        tls_versions.extend(str(v)[:40] for v, ok in versions.items()
                            if ok)
    elif isinstance(versions, list):
        tls_versions.extend(str(v)[:40] for v in versions)
    if tls.get("version"):
        tls_versions.append(str(tls["version"])[:40])
    return {"packets": len(pages) + (1 if ctx.get("url") else 0),
            "dns_queries": sorted(hosts),
            "tls_versions": sorted(set(tls_versions)),
            "http_methods": sorted(methods),
            "http_hosts": sorted(hosts),
            "source": "own-request-log"}


def _findings_for(summary):
    findings = []
    for ver in summary.get("tls_versions") or []:
        if ver in ("0x0301", "0x0302", "TLSv1.0", "TLSv1.1",
                   "TLS 1.0", "TLS 1.1"):
            findings.append(finding(
                "medium", "Outdated TLS version seen in traffic",
                "TLS handshake version %s observed in the target's "
                "traffic" % ver,
                "Disable TLS 1.0/1.1 on the server; require TLS 1.2+.",
                confirmation="indicator"))
    if "GET" in (summary.get("http_methods") or []) and not (
            summary.get("tls_versions")):
        findings.append(finding(
            "medium", "Plaintext HTTP traffic to the target",
            "HTTP requests observed with no TLS handshake in the "
            "captured traffic",
            "Serve the site over HTTPS only and redirect HTTP to "
            "HTTPS.", confirmation="indicator"))
    return findings


def run(ctx, timeout=90, runner=run_cmd):
    require_scope(ctx)
    ips = ctx.get("ips") or []
    ip = ips[0] if ips else ""
    if not ip:
        return adapter_result(NAME, "error", [],
                              {"error": "no IP resolved"})
    if is_installed(BINARY) and is_root():
        rc, out, err = runner(build_args(ip), timeout=timeout)
        if rc == 0:
            summary = parse_fields(out)
            summary["source"] = "tshark capture (host %s only)" % ip
            return adapter_result(
                NAME, "completed", _findings_for(summary),
                {"ip": ip, "mode": "tshark -c 200, filter host %s" % ip,
                 "capture": summary})
        # Capture failed (permission denied etc.) — fall through to
        # the honest own-request-log fallback.
        err_note = (err or "")[:200]
    elif is_installed(BINARY):
        err_note = "tshark installed but no root — capture denied"
    else:
        err_note = "tshark is not installed"
    summary = own_traffic_fallback(ctx)
    return adapter_result(
        NAME, NOT_INSTALLED if not is_installed(BINARY) else "fallback",
        _findings_for(summary),
        {"ip": ip, "mode": FALLBACK_MODE,
         "note": FALLBACK_MODE + " (%s)" % err_note,
         "capture": summary,
         "install": "tools install tshark"})
