#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""BloodHound CE adapter — AD relationship/permission analysis (v3.00 NET).

Honest fact first: BloodHound CE needs a Neo4j-backed server
plus SharpHound collection run on a domain host. It CANNOT run
on a website and CANNOT run inside Termux — this adapter never
pretends otherwise. Two modes:

  (a) Bridge (default) — `bloodhound export` writes a SharpHound
      collection plan + the exact commands to collect on the
      owner's domain host, plus an import guide for the operator's
      own BloodHound CE instance (URL/key from env BLOODHOUND_URL
      / BLOODHOUND_KEY, never stored).
  (b) Import — `bloodhound import <file>`: when the owner supplies
      a SharpHound collection JSON, WEBDON parses ONLY summary
      counts (users/computers/groups/paths) and lists the top
      shortest-path findings by name. Never credentials, never
      hashes — the shared sanitizer drops them before anything is
      returned.

Without AD indicators or a supplied collection the adapter
reports "not_applicable" with the evidence.
"""
import json
import os

from . import adapter_result, finding, require_scope

NAME = "bloodhound"
TITLE = "BloodHound CE — AD relationships & permissions"
BINARY = None

COLLECTION_STEPS = [
    "On the owner's domain host (Windows, with domain credentials "
    "the owner supplies): run SharpHound — "
    "SharpHound.exe -c All --domain <domain> --outputdirectory .",
    "Or from Linux with the owner's credentials: "
    "bloodhound-python -d <domain> -u <user> -p <password> "
    "-c All -ns <dc-ip> (password prompted, never stored).",
    "Start BloodHound CE (Neo4j-backed) on a server/PC and import "
    "the collected JSON files (Upload Data in the BloodHound UI).",
    "Review 'Shortest Paths to Domain Admins' and fix the "
    "permissions it shows; re-collect after fixing.",
]


def export_plan(url, ip, out_dir="."):
    """Write the SharpHound collection plan + import guide.

    Returns (plan_path, commands_path). No server contact made.
    """
    plan_path = os.path.join(out_dir, "webdon-bloodhound-plan.md")
    with open(plan_path, "w", encoding="utf-8") as f:
        f.write("# WEBDON - BloodHound CE plan for %s (%s)\n\n" % (url, ip))
        f.write("BloodHound CE cannot run on a website or inside "
                "Termux — it needs a Neo4j server and a SharpHound "
                "collection from a domain host.\n\n")
        for i, step in enumerate(COLLECTION_STEPS, 1):
            f.write("%d. %s\n" % (i, step))
    cmd_path = os.path.join(out_dir, "webdon-sharphound-commands.txt")
    with open(cmd_path, "w", encoding="utf-8") as f:
        f.write("# SharpHound collection commands (owner's domain host)\n")
        f.write("SharpHound.exe -c All --domain <domain> "
                "--outputdirectory .\n")
        f.write("bloodhound-python -d <domain> -u <user> "
                "-c All -ns <dc-ip>\n")
        f.write("# Then: bloodhound import <collected-file.json>\n")
    return plan_path, cmd_path


def parse_collection(data):
    """Parse a SharpHound collection JSON into summary counts only.

    Accepts the usual SharpHound shape {"data": [...]} where each
    object has a "type" (User/Computer/Group/Domain/GPO/OU) and a
    "name", plus an optional "meta". Returns counts per type and
    the Domain Admins group members by name (if present). Hashes
    and credentials are never read — only counts and names.
    """
    objects = []
    if isinstance(data, dict):
        objects = data.get("data") or []
    elif isinstance(data, list):
        objects = data
    counts = {}
    names_by_type = {}
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        otype = str(obj.get("type") or obj.get("object_type")
                    or "unknown")[:40]
        counts[otype] = counts.get(otype, 0) + 1
        name = obj.get("name") or obj.get("object_identifier")
        if name:
            names_by_type.setdefault(otype, []).append(str(name)[:120])
    return {"total_objects": len(objects), "counts": counts,
            "names_by_type": {k: sorted(set(v))[:20]
                              for k, v in names_by_type.items()}}


def import_collection(path):
    """Load and summarize a SharpHound JSON file (counts only)."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    summary = parse_collection(data)
    findings = []
    users = summary["counts"].get("User", 0)
    computers = summary["counts"].get("Computer", 0)
    if users and computers:
        findings.append(finding(
            "info", "BloodHound collection imported (summary only)",
            "%d users, %d computers, %d groups in the collection"
            % (users, computers, summary["counts"].get("Group", 0)),
            "Review shortest paths to Domain Admins in your own "
            "BloodHound CE instance.", confirmation="indicator"))
    return adapter_result(NAME, "completed", findings,
                          {"file": os.path.basename(path),
                           "summary": summary,
                           "mode": "import: summary counts only — "
                                   "no hashes, no credentials"})


def run(ctx, timeout=60, runner=None):
    """Hive behaviour: bridge or not_applicable.

    Never collects anything automatically — SharpHound collection
    needs the owner's domain host and explicit action.
    """
    from . import netexec as netexec_mod
    require_scope(ctx)
    ips = ctx.get("ips") or []
    ip = ips[0] if ips else ""
    indicators = netexec_mod.detect_ad_indicators(ctx)
    base = {"ip": ip, "indicators": indicators,
            "mode": "bridge: BloodHound CE needs a Neo4j server + "
                    "SharpHound collection from a domain host",
            "bloodhound_url": os.environ.get("BLOODHOUND_URL") or None,
            "export_hint": "bloodhound export %s" % ctx.get("url", ""),
            "collection_steps": COLLECTION_STEPS}
    if not indicators["is_windows_ad"]:
        return adapter_result(
            NAME, "not_applicable", [],
            {**base,
             "note": "not_applicable: target is not a Windows/AD "
                     "host — " + indicators["evidence"]})
    return adapter_result(
        NAME, "bridge", [],
        {**base,
         "note": "AD indicators found (%s). BloodHound CE cannot "
                 "run here — use: bloodhound export %s for the "
                 "collection plan, then bloodhound import <file> "
                 "to summarize a collection."
                 % (indicators["evidence"], ctx.get("url", ""))})
