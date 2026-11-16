#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NetExec adapter — Windows / Active Directory assessment (v3.00 NET).

NetExec (nxc) assesses Windows/AD hosts — it does NOT apply to
websites. This adapter therefore runs only when earlier waves
found Windows/AD indicators (AD ports open on the target), and
even then only with the operator's explicit opt-in
(`netexec run <ip>` after the hive). It NEVER runs automatically
with credentials.

Hard rules, enforced in code and tested:
  * anonymous/guest enumeration ONLY by default (-u '' -p '').
  * NO password spraying, NO brute force, NO pass-the-hash,
    NO wordlist of any kind — the forbidden flags are rejected
    by build_args() and asserted in the tests.
  * Credentials, if the owner ever supplies them for their OWN
    host, come via getpass/env only and are never stored or shown.
  * Without AD indicators the adapter reports "not_applicable"
    with the evidence — it never invents a Windows host.
"""
from . import NOT_INSTALLED, adapter_result, finding, is_installed, require_scope, run_cmd

NAME = "netexec"
TITLE = "NetExec — Windows / Active Directory assessment"
BINARY = "nxc"

# Windows / AD service ports (from the Nmap/ports results).
AD_PORTS = {88: "kerberos", 135: "rpc", 139: "netbios-ssn",
            389: "ldap", 445: "smb", 636: "ldaps",
            3268: "global-catalog", 3269: "global-catalog-ssl"}

# Flags that must never appear in any NetExec invocation.
FORBIDDEN_FLAGS = {"--spray", "--brute", "--bruteforce", "--hash",
                   "--pass", "--password", "--passwords", "--pth",
                   "--pass-the-hash", "--wordlist", "-w", "--users-file",
                   "--no-bruteforce"}


def detect_ad_indicators(ctx):
    """Look for Windows/AD indicators in the merged open ports.

    Reads ctx["open_ports_all"] (set by the engine), plus the
    ports/nmap results. Returns a dict with the evidence.
    """
    open_ports = set()
    for p in ctx.get("open_ports_all") or []:
        try:
            open_ports.add(int(p))
        except (TypeError, ValueError):
            pass
    for src_key in ("ports_data", "nmap_data"):
        for item in ((ctx.get(src_key) or {}).get("open_ports") or []):
            try:
                open_ports.add(int(item.get("port")))
            except (TypeError, ValueError):
                pass
    found = sorted(p for p in open_ports if p in AD_PORTS)
    return {"ad_ports_open": found,
            "ad_services": [AD_PORTS[p] for p in found],
            "is_windows_ad": bool(found),
            "evidence": ("AD ports open: %s" % ", ".join(
                "%d/%s" % (p, AD_PORTS[p]) for p in found))
            if found else "no AD ports (88/135/139/389/445/636/3268/"
                          "3269) open on the target",
            "open_ports_seen": sorted(open_ports)}


def build_args(ip, action="shares"):
    """NetExec argv — anonymous enumeration ONLY.

    -u '' -p '' is the documented anonymous/guest check. Any
    forbidden flag raises ValueError before anything runs.
    """
    if action not in ("shares", "users"):
        raise ValueError("unknown netexec action: %s" % action)
    args = [BINARY, "smb", ip, "-u", "", "-p", "",
            "--%s" % action]
    for flag in args:
        if flag in FORBIDDEN_FLAGS:
            raise ValueError("forbidden NetExec flag: %s" % flag)
    return args


def parse_output(text):
    """Parse nxc output lines into share/user names (names only)."""
    shares = []
    users = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        low = line.lower()
        if "share" in low and ("read" in low or "write" in low):
            parts = line.split()
            if parts:
                shares.append(parts[-1][:80])
        elif "user" in low:
            parts = line.split()
            if parts:
                users.append(parts[-1][:80])
    return {"shares": sorted(set(shares)), "users": sorted(set(users))}


def run(ctx, timeout=120, runner=run_cmd):
    """Hive behaviour: applicability check only, never automatic
    credential use. Returns not_applicable / skipped / fallback.
    """
    require_scope(ctx)
    ips = ctx.get("ips") or []
    ip = ips[0] if ips else ""
    if not ip:
        return adapter_result(NAME, "error", [],
                              {"error": "no IP resolved"})
    indicators = detect_ad_indicators(ctx)
    base = {"ip": ip, "indicators": indicators,
            "mode": "Windows/AD assessment — anonymous only, "
                    "explicit opt-in required"}
    if not indicators["is_windows_ad"]:
        return adapter_result(
            NAME, "not_applicable", [],
            {**base,
             "note": "not_applicable: target is not a Windows/AD "
                     "host — " + indicators["evidence"]})
    if not is_installed(BINARY):
        return adapter_result(
            NAME, NOT_INSTALLED, [],
            {**base,
             "note": "AD indicators found (%s) but nxc is not "
                     "installed. Install: tools install netexec, "
                     "then run: netexec run %s"
                     % (indicators["evidence"], ip),
             "install": "tools install netexec"})
    return adapter_result(
        NAME, "skipped", [],
        {**base,
         "note": "AD indicators found (%s). NetExec is NOT run "
                 "automatically — opt in with: netexec run %s "
                 "(anonymous/guest enumeration only, no passwords)"
                 % (indicators["evidence"], ip)})


def run_explicit(ctx, timeout=120, runner=run_cmd):
    """Explicit opt-in run (console `netexec run <ip>`).

    Anonymous/guest enumeration of shares and users only.
    Still refuses without AD indicators or without the binary.
    """
    require_scope(ctx)
    ips = ctx.get("ips") or []
    ip = ips[0] if ips else ""
    if not ip:
        return adapter_result(NAME, "error", [],
                              {"error": "no IP resolved"})
    indicators = detect_ad_indicators(ctx)
    if not indicators["is_windows_ad"]:
        return adapter_result(
            NAME, "not_applicable", [],
            {"ip": ip, "indicators": indicators,
             "note": "not_applicable: target is not a Windows/AD "
                     "host — " + indicators["evidence"]})
    if not is_installed(BINARY):
        return adapter_result(NAME, NOT_INSTALLED, [],
                              {"ip": ip, "indicators": indicators,
                               "note": "nxc is not installed — "
                                       "tools install netexec"})
    findings = []
    data = {"ip": ip, "indicators": indicators, "mode": "anonymous",
            "shares": [], "users": []}
    for action in ("shares", "users"):
        rc, out, err = runner(build_args(ip, action), timeout=timeout)
        if rc == -1:
            return adapter_result(NAME, "error", [],
                                  {"error": err or "nxc timed out",
                                   "ip": ip, "indicators": indicators})
        parsed = parse_output(out)
        data["shares"].extend(parsed["shares"])
        data["users"].extend(parsed["users"])
    data["shares"] = sorted(set(data["shares"]))
    data["users"] = sorted(set(data["users"]))
    if data["shares"]:
        findings.append(finding(
            "medium", "SMB shares visible to anonymous/guest",
            "shares: %s" % ", ".join(data["shares"][:5]),
            "Restrict anonymous/guest access to SMB shares on "
            "the Windows host.", confirmation="indicator"))
    return adapter_result(NAME, "completed", findings, data)
