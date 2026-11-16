#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Neo cloud hook — export findings for the external platform (v3.00).

  * `neo export` always works: writes findings JSON for upload to
    the Neo platform (external / cloud).
  * `neo push` ONLY with a user-provided API key from the
    NEO_API_KEY environment variable and an endpoint from
    NEO_API_URL. The key is never stored in any file, never
    logged, and push is never automatic. Without either variable
    the push is refused honestly — never a fake "pushed".
"""
import json
import os
import urllib.request

from . import adapter_result, require_scope

NAME = "neo"
TITLE = "Neo cloud hook"
BINARY = None


def export_findings(scan, out_path="webdon-neo-export.json"):
    """Write a sanitized findings export. Returns the path."""
    from . import sanitize
    payload = sanitize({
        "tool": "WEBDON v3.00 HIVE",
        "target": scan.get("target"),
        "score": scan.get("score"),
        "grade": scan.get("grade"),
        "coverage": (scan.get("coverage") or {}).get("percent"),
        "findings": scan.get("findings") or [],
    })
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    return out_path


def push(scan, opener=None):
    """Push findings to Neo. Requires NEO_API_KEY + NEO_API_URL env.

    Returns an adapter result; the key is read from the environment
    only and is never written anywhere.
    """
    key = os.environ.get("NEO_API_KEY")
    endpoint = os.environ.get("NEO_API_URL")
    if not key:
        return adapter_result(NAME, "refused", [],
                              {"error": "NEO_API_KEY is not set — set it "
                                        "in the environment to push; "
                                        "export only was performed"})
    if not endpoint:
        return adapter_result(NAME, "refused", [],
                              {"error": "NEO_API_URL is not set — set the "
                                        "Neo endpoint URL in the "
                                        "environment"})
    from . import sanitize
    payload = json.dumps(sanitize({
        "tool": "WEBDON v3.00 HIVE", "target": scan.get("target"),
        "score": scan.get("score"), "grade": scan.get("grade"),
        "findings": scan.get("findings") or [],
    }), ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        endpoint, data=payload, method="POST",
        headers={"Content-Type": "application/json",
                 "Authorization": "Bearer %s" % key})
    opener = opener or urllib.request.urlopen
    try:
        with opener(req, timeout=30) as resp:
            return adapter_result(NAME, "completed", [],
                                  {"endpoint": endpoint,
                                   "http_status": resp.status})
    except Exception as exc:
        return adapter_result(NAME, "error", [],
                              {"error": "push failed: %s" % str(exc)[:200]})
