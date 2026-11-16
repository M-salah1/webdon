#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Naabu adapter — port scan (v3.00).

SYN scanning needs privileges. On Termux (no root) Naabu cannot
do a SYN scan, so the adapter ALWAYS falls back to the built-in
TCP connect scan and says so honestly:
"connect-scan fallback, SYN unavailable without root".
When running as root and Naabu is installed, the real Naabu
binary is used (`naabu -host <ip> -top-ports 100 -silent -json`).
"""
import os

from . import NOT_INSTALLED, adapter_result, finding, is_installed, require_scope, run_cmd

NAME = "naabu"
TITLE = "Naabu — port scan"
BINARY = "naabu"

FALLBACK_NOTE = "connect-scan fallback, SYN unavailable without root"


def is_root():
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def build_args(ip):
    return [BINARY, "-host", ip, "-top-ports", "100", "-silent", "-json"]


def parse_json(text):
    """Parse Naabu -json lines: {"host":..,"port":..} per open port."""
    import json
    out = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except Exception:
            continue
        if item.get("port"):
            out.append({"port": int(item["port"]),
                        "service": str(item.get("service") or "")[:40],
                        "state": "tcp_open"})
    return sorted(out, key=lambda r: r["port"])


def connect_fallback(ctx):
    """Built-in TCP connect scan of the 19 common ports."""
    from ..engines import ports as ports_mod
    ips = ctx.get("ips") or []
    if not ips:
        return [], "no IP resolved"
    found = ports_mod.scan_ports(ips[0], timeout=0.5)
    return found, None


def _findings_for(open_ports):
    from ..engines import ports as ports_mod
    findings = []
    for item in open_ports:
        if item["port"] in ports_mod.RISKY_PORTS and item.get("state") in (
                "service_confirmed", "service_identified"):
            findings.append(finding(
                "high", "Sensitive service on port %d" % item["port"],
                "port %d %s" % (item["port"], item.get("service") or ""),
                "Close port %d or restrict it to trusted networks."
                % item["port"], confirmation="confirmed"))
    return findings


def run(ctx, timeout=120, runner=run_cmd):
    require_scope(ctx)
    ips = ctx.get("ips") or []
    ip = ips[0] if ips else ""
    if not ip:
        return adapter_result(NAME, "error", [],
                              {"error": "no IP resolved"})
    if is_root() and is_installed(BINARY):
        rc, out, err = runner(build_args(ip), timeout=timeout)
        if rc == -1:
            return adapter_result(NAME, "error", [],
                                  {"error": err or "naabu timed out"})
        open_ports = parse_json(out)
        return adapter_result(
            NAME, "completed", _findings_for(open_ports),
            {"ip": ip, "open_ports": open_ports,
             "open_count": len(open_ports), "mode": "syn",
             "stderr": (err or "")[:200]})
    # Not root, or Naabu missing: honest connect-scan fallback.
    found, err = connect_fallback(ctx)
    if err:
        return adapter_result(NAME, "error", [], {"error": err})
    return adapter_result(
        NAME, NOT_INSTALLED if not is_installed(BINARY) else "fallback",
        _findings_for(found),
        {"ip": ip, "open_ports": found, "open_count": len(found),
         "mode": FALLBACK_NOTE,
         "note": FALLBACK_NOTE + ("; naabu is not installed"
                                  if not is_installed(BINARY)
                                  else "; naabu installed but no root"),
         "install": "tools install naabu"})
