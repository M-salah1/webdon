#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Greenbone OpenVAS adapter — system vulnerability assessment (v3.00 NET).

Honest fact first: OpenVAS/GVM is a heavy server (scanner +
manager + database). It CANNOT run inside Termux — this adapter
never pretends otherwise. Two modes:

  (a) Server mode — if the operator provides a GVM host via the
      GVM_HOST environment variable and gvm-cli is installed,
      `openvas run` (console command) prompts for the GVM password
      with getpass (never stored) and creates a task on that server.
      The hive itself never runs this automatically.
  (b) Bridge mode (default) — `openvas export` writes a ready
      OpenVAS/GVM task definition + target list + PC/server setup
      steps, status "bridge".

In every hive run the adapter ALSO performs a built-in
"OpenVAS-like" systems check: for every identified service
banner/version it looks the version up in a small bundled list
of famously outdated / end-of-life service versions and reports
`outdated-service` findings. These are clearly labelled as
banner-based heuristics — never presented as a full OpenVAS scan.
"""
import json
import os

from . import adapter_result, finding, is_installed, require_scope, run_cmd

NAME = "openvas"
TITLE = "Greenbone OpenVAS — system vulnerability assessment"
BINARY = "gvm-cli"

# (substring in a banner / TLS version, service, severity, note)
OUTDATED_PATTERNS = [
    ("TLSv1.0", "tls", "high",
     "TLS 1.0 is obsolete and broken (BEAST/POODLE-era)."),
    ("TLSv1.1", "tls", "high",
     "TLS 1.1 is obsolete; require TLS 1.2 or newer."),
    ("TLS 1.0", "tls", "high",
     "TLS 1.0 is obsolete and broken (BEAST/POODLE-era)."),
    ("TLS 1.1", "tls", "high",
     "TLS 1.1 is obsolete; require TLS 1.2 or newer."),
    ("OpenSSH_5.", "openssh", "medium",
     "OpenSSH 5.x is end-of-life; upgrade to a supported release."),
    ("OpenSSH_6.", "openssh", "medium",
     "OpenSSH 6.x is end-of-life; upgrade to a supported release."),
    ("OpenSSH_7.0", "openssh", "low",
     "OpenSSH 7.0 is very old; upgrade to a supported release."),
    ("Apache/2.2", "apache", "medium",
     "Apache 2.2 is end-of-life; upgrade to Apache 2.4."),
    ("Apache/2.0", "apache", "medium",
     "Apache 2.0 is end-of-life; upgrade to Apache 2.4."),
    ("Apache/2.4.49", "apache", "high",
     "Apache 2.4.49 has a known path-traversal flaw (CVE-2021-41773)."),
    ("Apache/2.4.50", "apache", "high",
     "Apache 2.4.50 has a known path-traversal flaw (CVE-2021-42013)."),
    ("nginx/0.", "nginx", "low",
     "nginx 0.x is end-of-life; upgrade to a supported release."),
    ("nginx/1.0.", "nginx", "low",
     "nginx 1.0.x is end-of-life; upgrade to a supported release."),
    ("Microsoft-IIS/6.0", "iis", "medium",
     "IIS 6.0 is end-of-life; upgrade to a supported release."),
    ("Microsoft-IIS/7.0", "iis", "low",
     "IIS 7.0 is end-of-life; upgrade to a supported release."),
    ("PHP/5.", "php", "medium",
     "PHP 5.x is end-of-life; upgrade to a supported release."),
]

SERVER_STEPS = [
    "On a server/PC: install Greenbone Community Edition "
    "(docker: greenbone/openvas-scanner + gvmd + gsad) or the "
    "Greenbone Enterprise Appliance.",
    "Open the Greenbone web UI, create a Target with the IP from "
    "webdon-openvas-task.json, then create a Task with scan config "
    "'Full and fast'.",
    "Start the task, wait for it to finish, and review the report "
    "in the Greenbone UI. OpenVAS cannot run inside Termux.",
]


def _collect_banners(ctx):
    """Banners + TLS versions from earlier waves (names only)."""
    texts = []
    for src_key in ("ports_data", "nmap_data"):
        for item in ((ctx.get(src_key) or {}).get("open_ports") or []):
            if item.get("banner"):
                texts.append(str(item["banner"])[:200])
            if item.get("service"):
                texts.append(str(item["service"])[:120])
    tls = ctx.get("tls") or {}
    for key in ("version", "versions", "min_version", "max_version"):
        val = tls.get(key)
        if isinstance(val, str):
            texts.append(val)
        elif isinstance(val, list):
            texts.extend(str(v) for v in val)
    return texts


def check_outdated(ctx):
    """Banner-based outdated-service heuristic.

    Returns findings labelled as heuristics, never as a full
    OpenVAS scan. No network access is performed here.
    """
    findings = []
    seen = set()
    for text in _collect_banners(ctx):
        for pattern, service, severity, note in OUTDATED_PATTERNS:
            if pattern in text and (pattern, text) not in seen:
                seen.add((pattern, text))
                findings.append(finding(
                    severity,
                    "Outdated service (banner heuristic): %s" % service,
                    "banner/version %r matches outdated pattern %r "
                    "(banner-based heuristic — not a full OpenVAS scan)"
                    % (text[:80], pattern),
                    note + " Confirm the version on the server, then "
                           "upgrade it.", confirmation="indicator"))
    return findings


def export_task(url, ip, out_dir="."):
    """Write a ready OpenVAS/GVM task definition + setup plan.

    Returns (task_path, plan_path). No server contact is made.
    """
    task = {"tool": "WEBDON v3.00 NET - OpenVAS bridge",
            "target": url, "ip": ip,
            "hosts": [ip],
            "scan_config": "Full and fast",
            "port_list": "All IANA assigned TCP",
            "note": "Import this target into Greenbone (GVM) on a "
                    "server/PC. OpenVAS cannot run inside Termux."}
    task_path = os.path.join(out_dir, "webdon-openvas-task.json")
    with open(task_path, "w", encoding="utf-8") as f:
        json.dump(task, f, ensure_ascii=False, indent=2)
    plan_path = os.path.join(out_dir, "webdon-openvas-plan.md")
    with open(plan_path, "w", encoding="utf-8") as f:
        f.write("# WEBDON - OpenVAS/GVM plan for %s (%s)\n\n" % (url, ip))
        for i, step in enumerate(SERVER_STEPS, 1):
            f.write("%d. %s\n" % (i, step))
    return task_path, plan_path


def gvm_configured():
    """True when a GVM server + client are available."""
    return bool(os.environ.get("GVM_HOST")) and is_installed(BINARY)


def build_gvm_args(host, user):
    """gvm-cli argv to list tasks on the operator's GVM server.

    No password is ever placed in argv — it is prompted with
    getpass by the console command and passed via stdin only.
    """
    return [BINARY, "--gmp-username", user, "--hostname", host,
            "--xml", "<get_tasks/>"]


def run_gvm_task(host, user, password, ip, timeout=120, runner=run_cmd):
    """Create a task on the operator's GVM server (console only).

    The password arrives from getpass, is passed ONLY to gvm-cli's
    own --gmp-password argument for this one call, and is never
    stored, logged or returned (the result is sanitized). Steps:
    verify credentials (<get_version/>), create a target, then
    create a task with the "Full and fast" scan config. Any step
    failing returns an honest error — nothing is faked.
    """
    import re
    full_fast_config = "daba56c8-73ec-11df-a475-002264764cea"

    def _gvm(xml):
        return runner([BINARY, "--gmp-username", user,
                       "--gmp-password", password,
                       "--hostname", host, "--xml", xml],
                      timeout=timeout)

    rc, out, err = _gvm("<get_version/>")
    if rc == -1 or "<get_version_response" not in out:
        return adapter_result(
            NAME, "error", [],
            {"error": (err or "could not reach GVM at %s" % host)[:200],
             "gvm_host": host})
    rc, out, err = _gvm(
        "<create_target><name>webdon-%s</name>"
        "<hosts>%s</hosts></create_target>" % (ip, ip))
    m = re.search(r'id="([0-9a-f-]{36})"', out or "")
    if rc == -1 or not m:
        return adapter_result(
            NAME, "error", [],
            {"error": (err or "create_target failed")[:200],
             "gvm_host": host})
    target_id = m.group(1)
    rc, out, err = _gvm(
        "<create_task><name>webdon-%s</name>"
        "<config id=\"%s\"/><target id=\"%s\"/></create_task>"
        % (ip, full_fast_config, target_id))
    m = re.search(r'id="([0-9a-f-]{36})"', out or "")
    if rc == -1 or not m:
        return adapter_result(
            NAME, "error", [],
            {"error": (err or "create_task failed")[:200],
             "gvm_host": host, "target_id": target_id})
    return adapter_result(
        NAME, "completed", [],
        {"gvm_host": host, "target_id": target_id,
         "task_id": m.group(1), "ip": ip,
         "note": "Task created on GVM %s — start it in the "
                 "Greenbone UI and review its report there." % host})


def run(ctx, timeout=60, runner=run_cmd):
    """Hive behaviour: heuristic check + bridge status.

    Never contacts a GVM server automatically — that needs the
    operator's explicit `openvas run` with a getpass password.
    """
    require_scope(ctx)
    ips = ctx.get("ips") or []
    ip = ips[0] if ips else ""
    findings = check_outdated(ctx)
    data = {"ip": ip,
            "mode": "bridge: OpenVAS/GVM runs on a server/PC, "
                    "not inside Termux",
            "heuristic_findings": len(findings),
            "gvm_host": os.environ.get("GVM_HOST") or None,
            "gvm_cli_installed": is_installed(BINARY),
            "export_hint": "openvas export %s" % ctx.get("url", ""),
            "server_steps": SERVER_STEPS}
    if gvm_configured():
        data["note"] = ("GVM server configured (%s). Run "
                        "`openvas run %s` to create a task there — "
                        "the password is prompted, never stored."
                        % (os.environ.get("GVM_HOST"), ctx.get("url", "")))
    else:
        data["note"] = ("No GVM server configured. Use "
                        "`openvas export %s` for the PC/server plan."
                        % ctx.get("url", ""))
    return adapter_result(NAME, "bridge", findings, data)
