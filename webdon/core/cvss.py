#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVSS v3.1 base-score calculator (WEBDON v4.00 EVIDENCE).

The score is COMPUTED from the vector string using the official
FIRST CVSS v3.1 equations — it is never hardcoded:

    ISS  = 1 - [(1-C) * (1-I) * (1-A)]
    Impact (Scope Unchanged) = 6.42 * ISS
    Impact (Scope Changed)   = 7.52 * (ISS - 0.029)
                               - 3.25 * (ISS - 0.02) ** 15
    Exploitability = 8.22 * AV * AC * PR * UI
    If Impact <= 0: BaseScore = 0
    If Scope Unchanged: BaseScore = Roundup(min(Impact + Exploit, 10))
    If Scope Changed:   BaseScore = Roundup(min(1.08 * (Impact +
                        Exploit), 10))
    Roundup = smallest number >= input, to one decimal place.

Reference anchors (verified against NVD / FIRST):
    CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H -> 10.0 (Log4Shell)
    CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H -> 9.8
    CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N -> 5.3
    CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N -> 3.4 (POODLE,
        CVE-2014-3566, NVD)
    CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N -> 0.0

Optional enrichment: a CVE id can be looked up on the public NVD
API (no key, 6s timeout). Offline or unknown -> None, never a
guessed score.
"""
import json
import math
import urllib.request

# Metric values, CVSS v3.1 specification (FIRST).
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
# Privileges Required depends on Scope.
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}

_SEVERITY_BANDS = (
    (0.0, 0.0, "None"),
    (0.1, 3.9, "Low"),
    (4.0, 6.9, "Medium"),
    (7.0, 8.9, "High"),
    (9.0, 10.0, "Critical"),
)

_NVD_CACHE = {}


def roundup(value):
    """Smallest number >= value, to one decimal place.

    Integer math avoids float artefacts (e.g. 5.3 must stay 5.3,
    never become 5.4).
    """
    scaled = value * 10.0
    # Tiny epsilon so an exact 5.3 does not round up to 5.4.
    return math.ceil(scaled - 1e-9) / 10.0


def parse_vector(vector):
    """Parse a CVSS v3.x vector string into a metric dict.

    Accepts "CVSS:3.1/AV:N/AC:L/..." and bare "AV:N/AC:L/...".
    Raises ValueError on a malformed vector.
    """
    if not vector or not isinstance(vector, str):
        raise ValueError("empty CVSS vector")
    text = vector.strip()
    if text.upper().startswith("CVSS:"):
        parts = text.split("/", 1)
        if len(parts) != 2:
            raise ValueError("malformed CVSS vector: %s" % vector[:80])
        text = parts[1]
    metrics = {}
    for piece in text.split("/"):
        if ":" not in piece:
            raise ValueError("malformed CVSS metric: %s" % piece)
        key, val = piece.split(":", 1)
        metrics[key.strip().upper()] = val.strip().upper()
    for key in ("AV", "AC", "PR", "UI", "S", "C", "I", "A"):
        if key not in metrics:
            raise ValueError("CVSS vector missing %s" % key)
    if metrics["AV"] not in _AV:
        raise ValueError("bad AV: %s" % metrics["AV"])
    if metrics["AC"] not in _AC:
        raise ValueError("bad AC: %s" % metrics["AC"])
    if metrics["PR"] not in _PR_U:
        raise ValueError("bad PR: %s" % metrics["PR"])
    if metrics["UI"] not in _UI:
        raise ValueError("bad UI: %s" % metrics["UI"])
    if metrics["S"] not in ("U", "C"):
        raise ValueError("bad S: %s" % metrics["S"])
    for key in ("C", "I", "A"):
        if metrics[key] not in _CIA:
            raise ValueError("bad %s: %s" % (key, metrics[key]))
    return metrics


def base_score(vector):
    """Compute the CVSS v3.1 base score (0.0-10.0) from a vector.

    Returns a float rounded to one decimal. Raises ValueError on a
    malformed vector.
    """
    m = parse_vector(vector)
    scope_changed = m["S"] == "C"
    pr_table = _PR_C if scope_changed else _PR_U
    c = _CIA[m["C"]]
    i = _CIA[m["I"]]
    a = _CIA[m["A"]]
    iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a)
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss
    exploit = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr_table[m["PR"]] \
        * _UI[m["UI"]]
    if impact <= 0:
        return 0.0
    if scope_changed:
        raw = min(1.08 * (impact + exploit), 10.0)
    else:
        raw = min(impact + exploit, 10.0)
    return round(roundup(raw), 1)


def severity_for(score):
    """CVSS severity band for a base score (None -> 'None')."""
    if score is None:
        return "None"
    for low, high, name in _SEVERITY_BANDS:
        if low <= score <= high:
            return name
    return "None"


def score_vector(vector):
    """Full result for a vector: score + severity band.

    Returns {"vector", "score", "severity"} or None if the vector
    is malformed (never raises for bad input from a template).
    """
    try:
        score = base_score(vector)
    except ValueError:
        return None
    return {"vector": vector, "score": score,
            "severity": severity_for(score)}


def nvd_lookup(cve_id, timeout=6):
    """Look up a CVE on the public NVD API (no key).

    Returns {"cve_id", "vector", "score", "severity", "cwe_ids"}
    or None when offline, unknown, or the response has no CVSS
    v3.1 data. Results are cached in-memory for the process.
    Never raises.
    """
    cve_id = (cve_id or "").strip().upper()
    if not cve_id.startswith("CVE-"):
        return None
    if cve_id in _NVD_CACHE:
        return _NVD_CACHE[cve_id]
    result = None
    try:
        url = ("https://services.nvd.nist.gov/rest/json/cves/2.0"
               "?cveId=" + cve_id)
        req = urllib.request.Request(
            url, headers={"User-Agent": "WEBDON/5.00 (defensive audit)"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        vulns = data.get("vulnerabilities") or []
        if not vulns:
            _NVD_CACHE[cve_id] = None
            return None
        cve = (vulns[0].get("cve") or {})
        metrics = cve.get("metrics") or {}
        entries = metrics.get("cvssMetricV31") or []
        if not entries:
            _NVD_CACHE[cve_id] = None
            return None
        cvss = (entries[0].get("cvssData") or {})
        vector = cvss.get("vectorString")
        score = cvss.get("baseScore")
        if vector:
            computed = score_vector(vector)
            if computed is not None:
                score = computed["score"]
        cwe_ids = []
        for weak in cve.get("weaknesses") or []:
            for desc in weak.get("description") or []:
                val = desc.get("value") or ""
                if val.startswith("CWE-"):
                    cwe_ids.append(val)
        result = {"cve_id": cve_id, "vector": vector,
                  "score": score,
                  "severity": severity_for(score) if score is not None
                              else "None",
                  "cwe_ids": sorted(set(cwe_ids))}
    except Exception:
        result = None
    _NVD_CACHE[cve_id] = result
    return result
