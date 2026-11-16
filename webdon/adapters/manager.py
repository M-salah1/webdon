#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tool manager — detect / install the professional tools (v2.00).

`tools list`  — status table for all 9 tools (installed version,
not_installed, fallback, bridge).
`tools check <name>` — run the version check now.
`tools install <name>` — Termux ARM64 first: detect `uname -m`
(aarch64) and install ProjectDiscovery tools via Go, or pip for
schemathesis. Every install is verified with a version check
afterwards and reported honestly (success / failed + the exact
manual command). A tool is never claimed installed without
running its version check.
"""
import os
import platform
import subprocess

from . import is_installed, run_cmd, version_of

GO_BASE = "github.com/projectdiscovery"

# name -> {kind, binary, version_args, install}
TOOLS = {
    "nuclei": {
        "kind": "binary (go)", "binary": "nuclei",
        "version_args": ("-version",),
        "install_go": GO_BASE + "/nuclei/v3/cmd/nuclei@latest",
        "install_pkg": None,
        "note": "Template-based vulnerability detection",
    },
    "httpx": {
        "kind": "binary (go)", "binary": "httpx",
        "version_args": ("-version",),
        "install_go": GO_BASE + "/httpx/cmd/httpx@latest",
        "install_pkg": None,
        "note": "Live probe: status / title / tech / TLS",
    },
    "subfinder": {
        "kind": "binary (go)", "binary": "subfinder",
        "version_args": ("-version",),
        "install_go": GO_BASE + "/subfinder/v2/cmd/subfinder@latest",
        "install_pkg": None,
        "note": "Subdomain enumeration",
    },
    "katana": {
        "kind": "binary (go)", "binary": "katana",
        "version_args": ("-version",),
        "install_go": GO_BASE + "/katana/cmd/katana@latest",
        "install_pkg": None,
        "note": "Crawl with JS discovery",
    },
    "naabu": {
        "kind": "binary (go)", "binary": "naabu",
        "version_args": ("-version",),
        "install_go": GO_BASE + "/naabu/v2/cmd/naabu@latest",
        "install_pkg": None,
        "note": "Port scan (SYN needs root; Termux uses connect fallback)",
    },
    "schemathesis": {
        "kind": "python (pip)", "binary": "schemathesis",
        "version_args": ("--version",),
        "install_go": None,
        "install_pkg": "pip install schemathesis",
        "note": "API schema checks (needs an OpenAPI schema file)",
    },
    "zap": {
        "kind": "bridge (PC)", "binary": "zap.sh",
        "version_args": ("-version",),
        "install_go": None,
        "install_pkg": None,
        "note": "OWASP ZAP: bridge only — best on a PC, not on Termux",
    },
    "neo": {
        "kind": "cloud hook", "binary": None,
        "version_args": (),
        "install_go": None,
        "install_pkg": None,
        "note": "Neo cloud: export always; push needs NEO_API_KEY",
    },
    "burp": {
        "kind": "built-in", "binary": None,
        "version_args": (),
        "install_go": None,
        "install_pkg": None,
        "note": "Built-in Burp-like: proxy / repeater / sitemap / scanner",
    },
}


def arch():
    """CPU architecture, e.g. aarch64 on Termux ARM64."""
    try:
        return platform.machine() or "unknown"
    except Exception:
        return "unknown"


def check(name):
    """Version check for one tool. Returns a status dict."""
    info = TOOLS.get(name)
    if not info:
        return {"name": name, "status": "unknown_tool"}
    if info["kind"] in ("built-in", "cloud hook"):
        return {"name": name, "status": info["kind"],
                "version": None, "note": info["note"]}
    binary = info["binary"]
    ver = version_of(binary, info["version_args"], timeout=20)
    if ver:
        return {"name": name, "status": "installed", "version": ver,
                "note": info["note"]}
    return {"name": name, "status": "not_installed", "version": None,
            "note": info["note"]}


def list_all():
    """Status table for every tool."""
    return [check(name) for name in TOOLS]


def install_cmd(name):
    """The exact manual install command for a tool (or None)."""
    info = TOOLS.get(name)
    if not info:
        return None
    if info.get("install_go"):
        return "go install %s" % info["install_go"]
    return info.get("install_pkg")


def install(name, timeout=600, runner=run_cmd):
    """Install one tool, then verify with a version check.

    Returns a dict with installed=True only when the version
    check succeeds afterwards. On failure the exact manual
    command is included so the operator can run it by hand.
    """
    info = TOOLS.get(name)
    if not info:
        return {"name": name, "installed": False,
                "error": "unknown tool: %s" % name}
    if info["kind"] in ("built-in", "cloud hook", "bridge (PC)"):
        return {"name": name, "installed": False,
                "error": "%s is %s — nothing to install here"
                         % (name, info["kind"]),
                "note": info["note"]}
    if check(name)["status"] == "installed":
        return {"name": name, "installed": True,
                "version": check(name)["version"],
                "note": "already installed"}
    cmd = install_cmd(name)
    if not cmd:
        return {"name": name, "installed": False,
                "error": "no install method for %s" % name}
    if info.get("install_go") and not is_installed("go"):
        return {"name": name, "installed": False,
                "error": "go is not installed — run: pkg install golang",
                "manual_command": cmd}
    argv = cmd.split()
    rc, _out, err = runner(argv, timeout=timeout)
    ver = check(name)
    if ver["status"] == "installed":
        return {"name": name, "installed": True,
                "version": ver["version"], "arch": arch(),
                "method": cmd}
    return {"name": name, "installed": False,
            "error": (err or "install command exited %s" % rc)[:300],
            "manual_command": cmd, "arch": arch()}
