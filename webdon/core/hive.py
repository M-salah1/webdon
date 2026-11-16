#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HIVE — one command runs everything, like a beehive (v5.00).

`hive <url>` / `auto <url>` / `python3 webdon.py --hive <url>`:
the operator gives only the URL; WEBDON runs six waves in
parallel inside the normal engine machinery:

  Wave 1 — recon:     crawl, headers, tls, tech, httpx, subfinder
  Wave 2 — web:       dns, whois, cookies, cors, protect, paths,
                      katana, nuclei
  Wave 3 — vuln/scan: ports, naabu, schemathesis (schema only)
  Wave 4 — IP alone:  ipintel, timeline
  Wave 5 — NET:       nmap, wireshark, openvas, netexec +
                      bloodhound (AD applicability from merged ports)
  Wave 6 — report:    unified score + JSON/HTML.

v5.00 DEEP-DIVE — after the six waves, every finding is
followed up recursively (max depth 3 by default, `--depth N`
1-5): missing header -> audit it on every crawled page, open
port -> banner + neighbours + NVD, subdomain -> mini-scan,
exposed config -> sibling HEAD checks, and so on. Same one
command, no extra input. `deep <url>` is hive with depth 3.

Every wave runs under the same budgets, timeouts and scope gate
as a normal scan; partial results are saved and resumable.
No artificial delays — thoroughness comes from engine breadth.
"""
from . import deepdive as deepdive_mod
from . import engine as engine_mod
from ..adapters import manager as manager_mod
from ..engines import PHASES

HIVE_WAVES = [
    ("wave1-recon", ["crawl", "headers", "tls", "tech",
                     "httpx", "subfinder"]),
    ("wave2-web", ["dns", "whois", "cookies", "cors", "protect",
                   "paths", "katana", "nuclei"]),
    ("wave3-vuln", ["ports", "naabu", "schemathesis"]),
    ("wave4-ip", ["ipintel", "timeline"]),
    ("wave5-net", ["nmap", "wireshark", "openvas", "netexec",
                   "bloodhound"]),
    ("wave6-report", []),
]

HIVE_PROFILE = "hive"


def wave_names():
    return [name for name, _ in HIVE_WAVES]


def total_phases():
    return engine_mod.total_phases(HIVE_PROFILE)


def adapter_status(scan):
    """Per-adapter status table from a hive scan's results."""
    out = {}
    for name in ("nuclei", "httpx", "subfinder", "katana", "naabu",
                 "schemathesis", "nmap", "wireshark", "openvas",
                 "netexec", "bloodhound"):
        res = (scan.get("results") or {}).get(name) or {}
        data = res.get("data") or {}
        out[name] = {
            "status": res.get("status", "not_run"),
            "mode": data.get("mode") or data.get("source")
                    or data.get("note") or "",
            "installed": res.get("status") not in (
                "not_installed (fallback)", "not_installed"),
        }
    out["zap"] = {"status": "bridge",
                  "mode": "export only on Termux; full ZAP on a PC",
                  "installed": False}
    out["neo"] = {"status": "cloud hook",
                  "mode": "export always; push needs NEO_API_KEY",
                  "installed": False}
    out["burp"] = {"status": "built-in",
                   "mode": "proxy / repeater / sitemap / scanner",
                   "installed": True}
    return out


def run_hive(url, scope=None, settings=None, progress=None,
             schema_path=None, depth=None):
    """Run a full HIVE investigation + recursive deep-dive.

    Refuses without a signed scope. Raises PermissionError when
    the target has no signed scope. Returns the scan dict with
    an extra "hive" block and a "deepdive" block.

    `depth` (1-5, default 3) caps how deep the dive follows a
    finding; values outside clamp with a warning in the
    deep-dive block (`depth_clamped: true`).
    """
    from ..core.scope import normalize_url
    url = normalize_url(url)
    if scope is None or not scope.is_authorized(url):
        raise PermissionError(
            "No signed scope for %s — run: scope create %s" % (url, url))
    settings = dict(settings or {})
    if schema_path:
        settings["schema_path"] = schema_path
    settings.setdefault("scan_budget_s", 900)
    if depth is not None:
        settings["depth"] = depth
    scan = engine_mod.run_scan(url, profile=HIVE_PROFILE, scope=scope,
                               settings=settings, progress=progress)
    scan["kind"] = "webdon-hive"
    scan["hive"] = {
        "waves": wave_names(),
        "phases": total_phases(),
        "adapters": adapter_status(scan),
        "tools": {t["name"]: t["status"]
                  for t in manager_mod.list_all()},
    }
    # Deep-dive stage (v5.00) — recursive follow-ups on every
    # finding, same scope, same budgets. Never raises out of
    # run_hive: a failed dive is recorded, the hive scan stands.
    try:
        deepdive_mod.apply_to_scan(scan, scope, settings=settings)
    except PermissionError:
        raise
    except Exception as exc:
        scan["deepdive"] = {
            "status": "error", "max_depth": 0, "deepest": 0,
            "probes_run": 0, "new_findings": 0,
            "new_findings_by_depth": {}, "stop_reason": None,
            "error": str(exc)[:200]}
    return scan
