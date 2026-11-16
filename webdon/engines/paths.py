#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Paths engine — discover site paths and check exposed config files.

Part 1 — paths: same-origin paths found by the crawl, plus the
well-known files robots.txt / sitemap.xml / security.txt (presence
+ content summary only, no secrets).

Part 2 — exposed config files: existence is checked by HTTP HEAD
ONLY. The body of a config file is NEVER downloaded, NEVER read,
NEVER stored and NEVER displayed. A HEAD 200 on a config path is
reported as a HIGH exposure risk with remediation only — zero
content shown. A HEAD 403/404 means not exposed. This engine
never issues a GET for a config path.
"""
from ..core import content as content_mod
from ..core.http import get, head

NAME = "paths"
TITLE = "Paths & Exposed Config Check"

PHASES = ["crawled paths inventory", "well-known files",
          "config exposure check (HEAD only)"]

# (path, severity, name, fix) — checked by HEAD only.
CONFIG_PATHS = [
    ("/.env", "high", "Environment file reachable (.env)",
     "Move .env outside the web root; block dotfiles on the server."),
    ("/.env.bak", "high", "Backup environment file reachable",
     "Delete backup files from the web root."),
    ("/config.php", "medium", "Config file reachable (config.php)",
     "Block direct access to config files."),
    ("/wp-config.php", "high", "WordPress config reachable",
     "Block access to wp-config.php."),
    ("/.git/HEAD", "high", "Git repository reachable (.git/HEAD)",
     "Block access to /.git/ on the web server."),
    ("/.svn/entries", "medium", "Subversion metadata reachable",
     "Block access to /.svn/ on the web server."),
    ("/.DS_Store", "low", "macOS metadata file reachable",
     "Delete .DS_Store files from the web root."),
    ("/backup.zip", "high", "Backup archive reachable",
     "Move backups outside the web root."),
    ("/db.sql", "high", "Database dump reachable",
     "Move database dumps outside the web root."),
    ("/phpinfo.php", "medium", "phpinfo() page reachable",
     "Remove phpinfo pages from production."),
]

WELL_KNOWN = ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt"]


def check_config_paths(base, timeout=8, head_fn=None):
    """Check config paths by HEAD only. Returns (findings, checked).

    `head_fn` is injected by tests to prove no GET is ever issued.
    No response body is ever read here.
    """
    do_head = head_fn or head
    findings = []
    checked = []
    for path, sev, name, fix in CONFIG_PATHS:
        r = do_head(base + path, timeout=timeout)
        status = r.get("status")
        checked.append({"path": path, "status": status,
                        "method": "HEAD"})
        if status == 200:
            findings.append({
                "severity": sev, "name": name, "confirmation": "confirmed",
                "evidence": "%s -> HTTP 200 on HEAD (body never "
                            "downloaded, content never shown)" % path,
                "fix": fix})
        elif status in (301, 302, 303, 307, 308):
            findings.append({
                "severity": "info",
                "name": "%s redirects (HTTP %s)" % (path, status),
                "evidence": "%s -> HTTP %s on HEAD" % (path, status),
                "fix": "Confirm the redirect target does not expose the "
                       "file."})
    return findings, checked


def run(ctx):
    base = (ctx.get("url") or "").rstrip("/")
    timeout = ctx.get("timeout", 8)
    findings = []
    crawl_data = {}
    pages = ctx.get("pages") or []
    paths = sorted({p.get("url", "").replace(base, "") or "/"
                    for p in pages})
    data = {"paths": paths, "path_count": len(paths),
            "well_known": {}, "config_checked": [], "config_hits": 0}
    # Well-known files: GET is fine here — these are public files
    # meant to be read; only a short summary is stored, never secrets.
    for wk in WELL_KNOWN:
        r = get(base + wk, timeout=timeout, max_bytes=20000)
        body = r.get("body") or ""
        entry = {"status": r.get("status"),
                 "bytes": len(body),
                 "summary": ""}
        if r.get("status") == 200 and body:
            if wk.endswith("robots.txt"):
                disallow = [l.strip() for l in body.splitlines()
                            if l.strip().lower().startswith("disallow:")]
                entry["summary"] = "%d Disallow rules" % len(disallow)
            elif wk.endswith("sitemap.xml"):
                entry["summary"] = "%d <loc> entries" % body.count("<loc>")
            elif wk.endswith("security.txt"):
                contacts = [l.strip() for l in body.splitlines()
                            if l.strip().lower().startswith("contact:")]
                entry["summary"] = "%d Contact lines (values not stored)" \
                    % len(contacts)
        data["well_known"][wk] = entry
        if r.get("status") == 200:
            findings.append({"severity": "info",
                             "name": "%s present" % wk,
                             "evidence": "%s -> HTTP 200 (%s)"
                                         % (wk, entry["summary"]),
                             "fix": "Keep %s up to date; do not list "
                                    "sensitive paths in it." % wk})
    cfg_findings, checked = check_config_paths(base, timeout=timeout)
    findings.extend(cfg_findings)
    data["config_checked"] = checked
    data["config_hits"] = len(cfg_findings)
    return {"engine": NAME, "status": "completed",
            "findings": findings, "data": data}
