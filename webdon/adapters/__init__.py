#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Shared adapter layer — wraps real professional tools (v3.00 HIVE).

Every adapter follows the same contract:
  * scope-gated: refuse without a signed scope (PermissionError).
  * detection-only: never destructive, never brute force, never
    login bypass, never auth bypass.
  * honest fallback: when the external binary is not installed the
    adapter returns status "not_installed (fallback)" and runs the
    built-in stdlib equivalent — it never invents results.
  * value-free: raw request/response bodies and any credential,
    cookie or session value are stripped before anything is stored
    or returned (see sanitize()).

Adapters never shell out with unsanitized input: argv lists only,
no shell=True, and every run has a timeout.
"""
import json
import os
import re
import shutil
import subprocess

NOT_INSTALLED = "not_installed (fallback)"

# Keys whose values must never be stored, shown or logged.
SENSITIVE_KEYS = {
    "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
    "auth", "authorization", "cookie", "set-cookie", "session",
    "sessionid", "session_id", "csrf", "private_key", "access_key",
}

# Value patterns redacted inside strings (v4.00): a credential or
# session value embedded in an evidence string must be scrubbed
# even when it is not under a sensitive key — e.g. a Set-Cookie
# header line or a `DB_PASSWORD=...` assignment pasted into
# evidence. Placeholder values such as `<value>` in remediation
# templates are NOT redacted (a value must not start with `<`).
_VALUE_PATTERNS = [
    # Authorization: Bearer/Basic <token>
    (re.compile(r"(authorization\s*:\s*(?:bearer|basic)\s+)\S+",
                re.IGNORECASE), r"\1[REDACTED]"),
    # Set-Cookie: <name>=<value>
    (re.compile(r"(set-cookie\s*:\s*[^\s=;]+)=([^<\s;,][^\s;,]*)",
                re.IGNORECASE), r"\1=[REDACTED]"),
    # sensitive-name = value  (sessionid, token, password, secret,
    # api_key, auth, csrf, access_key, ...)
    (re.compile(r"((?:sessionid|session_id|session|token|password|"
                r"passwd|pwd|secret|api[_-]?key|apikey|auth|csrf|"
                r"access[_-]?key|private[_-]?key)\s*[:=]\s*)"
                r"[^<\s;,\"'}&]+", re.IGNORECASE), r"\1[REDACTED]"),
    # env-style assignments: DB_PASSWORD=... / API_TOKEN=...
    (re.compile(r"((?:[A-Z0-9_]*?(?:PASSWORD|SECRET|TOKEN|"
                r"API[_-]?KEY))\s*=\s*)[^<\s;,\"'}&]+",
                re.IGNORECASE), r"\1[REDACTED]"),
]


def _redact_values(text):
    """Scrub credential/session values out of a free-text string."""
    for pattern, repl in _VALUE_PATTERNS:
        text = pattern.sub(repl, text)
    return text

# Keys that may carry raw bodies / full requests — dropped entirely.
BODY_KEYS = {"request", "response", "raw", "body", "raw_response",
             "raw_request", "snippet", "matched_at_response"}


def which(binary):
    """Absolute path of a binary, or None."""
    try:
        return shutil.which(binary)
    except Exception:
        return None


def is_installed(binary):
    return which(binary) is not None


def run_cmd(argv, timeout=60, cwd=None, env=None):
    """Run argv (list, no shell). Returns (rc, stdout, stderr).

    Never raises; a timeout returns rc=-1 with an error note.
    stdout is capped at 2 MB so a chatty tool cannot flood memory.
    """
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout,
            cwd=cwd, env=env)
        out = (proc.stdout or "")[:2000000]
        err = (proc.stderr or "")[:200000]
        return proc.returncode, out, err
    except subprocess.TimeoutExpired:
        return -1, "", "timeout after %ss" % timeout
    except FileNotFoundError:
        return -1, "", "binary not found: %s" % argv[0]
    except Exception as exc:
        return -1, "", str(exc)


def version_of(binary, args=("--version",), timeout=20):
    """Run `<binary> <args>` and return the first version line, or None."""
    if not is_installed(binary):
        return None
    rc, out, _err = run_cmd([binary] + list(args), timeout=timeout)
    if rc != 0 and not out.strip():
        return None
    for line in (out or "").splitlines():
        line = line.strip()
        if line:
            return line[:160]
    return None


def sanitize(obj):
    """Recursively strip sensitive values and raw bodies from data.

    Drops any key in SENSITIVE_KEYS or BODY_KEYS (any depth),
    redacts credential/session values embedded in strings
    (Set-Cookie values, `name=value` for sensitive names,
    `Authorization: Bearer ...`, `DB_PASSWORD=...`), and truncates
    long strings. Returns a clean copy; the input is never mutated.
    """
    if isinstance(obj, dict):
        clean = {}
        for key, val in obj.items():
            kl = str(key).lower()
            if kl in SENSITIVE_KEYS or kl in BODY_KEYS:
                continue
            clean[key] = sanitize(val)
        return clean
    if isinstance(obj, (list, tuple)):
        return [sanitize(v) for v in obj]
    if isinstance(obj, str):
        return _redact_values(obj[:500])
    return obj


def finding(severity, name, evidence, fix, confirmation="indicator"):
    """One unified finding (evidence only, never a value or body)."""
    return {"severity": severity, "confirmation": confirmation,
            "name": str(name)[:200],
            "evidence": str(evidence or "")[:300],
            "fix": str(fix or "")[:300]}


def adapter_result(name, status, findings=None, data=None):
    """Standard adapter result dict, sanitized before return."""
    return {"adapter": name, "status": status,
            "findings": sanitize(findings or []),
            "data": sanitize(data or {})}


def require_scope(ctx):
    """Raise PermissionError unless the target has a signed scope."""
    if not ctx.get("authorized"):
        raise PermissionError(
            "No signed scope for %s — run: scope create %s"
            % (ctx.get("url", ""), ctx.get("url", "")))
