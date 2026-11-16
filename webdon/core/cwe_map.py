#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CWE + CVSS mapping for every WEBDON finding type (v4.00 EVIDENCE).

Each rule maps a finding (matched by case-insensitive substrings
of its name) to a CWE id + name + a CVSS v3.1 vector. The vector's
metric values are justified in the `rationale` — e.g. a missing
HSTS header is AV:N (network attacker) / AC:H (needs a hostile
network position) / PR:N / UI:N / S:U / C:L + I:L (SSL stripping
can expose and alter traffic) / A:N. The score is COMPUTED from
the vector by webdon.core.cvss — never hardcoded.

Rules are ordered specific-first; the first rule whose patterns
all appear in the finding name wins. A finding type with no
defensible mapping returns None: its CVSS stays null and its
severity comes from the existing WEBDON scoring — never an
invented number. Informational findings (severity "info") never
get a CVSS.
"""
from . import cvss as cvss_mod

CWE_URL = "https://cwe.mitre.org/data/definitions/%s.html"


def _rule(key, patterns, cwe_id, cwe_name, vector, rationale):
    return {"key": key, "patterns": tuple(p.lower() for p in patterns),
            "cwe_id": cwe_id, "cwe_name": cwe_name,
            "vector": vector, "rationale": rationale}


# Each vector below was chosen so its computed score matches the
# engine severity of the finding (low ~3.x, medium ~4-6.x,
# high ~7.x, critical ~9.x). See tests/test_evidence.py for the
# computed scores.
RULES = [
    _rule("cors-wildcard-credentials",
          ("cors", "wildcard", "credentials"),
          "CWE-942", "Permissive Cross-domain Policy with Untrusted Domains",
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
          "Any website can read authenticated responses (AC:L, no "
          "interaction needed); full read/write of the victim session."),
    _rule("cors-wildcard",
          ("cors", "wildcard"),
          "CWE-942", "Permissive Cross-domain Policy with Untrusted Domains",
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
          "Any website can call the API (AC:L); without credentials "
          "the impact is limited to unauthenticated data."),
    _rule("cors-credentials-origin",
          ("cors", "credentials"),
          "CWE-942", "Permissive Cross-domain Policy with Untrusted Domains",
          "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
          "Credentials are shared with one origin: only harmful if "
          "that origin is compromised or the victim is tricked "
          "(AC:H, UI:R)."),
    _rule("config-exposed-env",
          (".env",),
          "CWE-538", "Insertion of Sensitive Information into "
                     "Externally-Accessible File or Directory",
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
          "A reachable .env can expose live secrets (AC:L, no auth); "
          "confidentiality and integrity of the application at stake."),
    _rule("config-exposed-wp",
          ("wp-config",),
          "CWE-538", "Insertion of Sensitive Information into "
                     "Externally-Accessible File or Directory",
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
          "wp-config.php exposes database credentials; full site "
          "takeover is possible from the leaked values."),
    _rule("config-exposed-generic",
          ("config", "reachable"),
          "CWE-538", "Insertion of Sensitive Information into "
                     "Externally-Accessible File or Directory",
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
          "A reachable config file can expose credentials; the "
          "validator confirmed HTTP 200 by HEAD, body never read."),
    _rule("config-exposed-backup",
          ("backup", "reachable"),
          "CWE-538", "Insertion of Sensitive Information into "
                     "Externally-Accessible File or Directory",
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
          "A reachable backup archive can contain source code and "
          "secrets in one download."),
    _rule("config-exposed-db",
          ("database dump", "reachable"),
          "CWE-538", "Insertion of Sensitive Information into "
                     "Externally-Accessible File or Directory",
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
          "A reachable database dump exposes every stored record, "
          "including password hashes."),
    _rule("config-exposed-phpinfo",
          ("phpinfo", "reachable"),
          "CWE-200", "Exposure of Sensitive Information to an "
                     "Unauthorized Actor",
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
          "phpinfo() discloses versions, paths and environment — "
          "useful for targeting, no secrets directly (C:L only)."),
    _rule("git-exposed",
          (".git",),
          "CWE-538", "Insertion of Sensitive Information into "
                     "Externally-Accessible File or Directory",
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
          "A public .git exposes full source history, often with "
          "old secrets and credentials in past commits."),
    _rule("svn-exposed",
          (".svn",),
          "CWE-538", "Insertion of Sensitive Information into "
                     "Externally-Accessible File or Directory",
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
          "Public Subversion metadata exposes source paths and "
          "history."),
    _rule("ds-store",
          (".ds_store",),
          "CWE-200", "Exposure of Sensitive Information to an "
                     "Unauthorized Actor",
          "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
          ".DS_Store only leaks file names (AC:H, C:L); it aids "
          "targeting but exposes no content by itself."),
    _rule("chain-xss-session",
          ("xss", "session-theft"),
          "CWE-79", "Improper Neutralization of Input During Web Page "
                    "Generation ('Cross-site Scripting')",
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
          "No CSP lets injected scripts run; without HttpOnly they "
          "read session cookies — scope changes to the victim "
          "browser (S:C)."),
    _rule("chain-session-hijack",
          ("session hijack chain",),
          "CWE-614", "Sensitive Cookie in HTTPS Session Without "
                     "'Secure' Attribute",
          "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N",
          "Cookie without Secure plus no HSTS/plain HTTP lets a "
          "network attacker steal the session (AC:H: hostile "
          "network needed)."),
    _rule("chain-source-secrets",
          ("source + secrets exposure chain",),
          "CWE-538", "Insertion of Sensitive Information into "
                     "Externally-Accessible File or Directory",
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
          "Public .git plus public config files together expose "
          "source code and credentials."),
    _rule("missing-csp",
          ("content-security-policy",),
          "CWE-693", "Protection Mechanism Failure",
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
          "Without CSP, an injection runs in the victim browser "
          "(UI:R); it can read and alter page content (C:L/I:L)."),
    _rule("missing-hsts",
          ("strict-transport-security",),
          "CWE-319", "Cleartext Transmission of Sensitive Information",
          "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
          "Without HSTS the first visit can be SSL-stripped on a "
          "hostile network (AC:H); traffic can be read and altered."),
    _rule("short-hsts",
          ("short hsts",),
          "CWE-319", "Cleartext Transmission of Sensitive Information",
          "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
          "A short max-age leaves a window where stripping works "
          "(I:L only — confidentiality is mostly protected)."),
    _rule("missing-xfo",
          ("x-frame-options",),
          "CWE-1021", "Improper Restriction of Rendered UI Layers or "
                      "Frames",
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
          "Without frame protection the site can be clickjacked "
          "(UI:R); the victim's clicks are hijacked (I:L)."),
    _rule("missing-xcto",
          ("x-content-type-options",),
          "CWE-693", "Protection Mechanism Failure",
          "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N",
          "MIME sniffing needs attacker-controlled content served "
          "from the site plus a victim click (AC:H, UI:R)."),
    _rule("missing-referrer-policy",
          ("referrer-policy",),
          "CWE-359", "Exposure of Personal Data to an Unauthorized Actor",
          "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
          "Full referrer URLs can leak private paths/tokens to "
          "third parties (AC:H, UI:R, C:L)."),
    _rule("missing-permissions-policy",
          ("permissions-policy",),
          "CWE-693", "Protection Mechanism Failure",
          "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N",
          "Without the policy, embedded content could use powerful "
          "features (camera/mic) if the page ever grants them."),
    _rule("missing-coop",
          ("cross-origin-opener-policy",),
          "CWE-693", "Protection Mechanism Failure",
          "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N",
          "Without COOP, a cross-origin page can keep a window "
          "reference and probe the opener (AC:H, UI:R)."),
    _rule("missing-corp",
          ("cross-origin-resource-policy",),
          "CWE-693", "Protection Mechanism Failure",
          "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N",
          "Without CORP, other origins can load the site's "
          "resources and exploit Spectre-class leaks (AC:H)."),
    _rule("plain-http",
          ("plain http",),
          "CWE-319", "Cleartext Transmission of Sensitive Information",
          "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
          "Everything (including logins and session tokens) travels "
          "in cleartext on a hostile network (AC:H, C:H/I:H)."),
    _rule("no-tls",
          ("no tls",),
          "CWE-319", "Cleartext Transmission of Sensitive Information",
          "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
          "No TLS at all: same cleartext exposure as plain HTTP."),
    _rule("weak-tls",
          ("weak tls",),
          "CWE-327", "Use of a Broken or Risky Cryptographic Algorithm",
          "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
          "TLS 1.0/1.1 are broken (BEAST/POODLE-era); a network "
          "attacker can decrypt sessions (AC:H, C:H)."),
    _rule("no-modern-tls",
          ("no modern tls",),
          "CWE-327", "Use of a Broken or Risky Cryptographic Algorithm",
          "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
          "Only obsolete TLS versions answered the handshake."),
    _rule("tls-expired",
          ("certificate expired",),
          "CWE-295", "Improper Certificate Validation",
          "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
          "An expired certificate breaks trust; users trained to "
          "click through warnings enable MITM (I:H)."),
    _rule("tls-chain",
          ("certificate chain issue",),
          "CWE-295", "Improper Certificate Validation",
          "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
          "A broken chain means clients cannot verify the server — "
          "same MITM exposure as an expired certificate."),
    _rule("tls-expires-soon",
          ("certificate expires soon",),
          "CWE-295", "Improper Certificate Validation",
          "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L",
          "Operational: the certificate will lapse soon and the "
          "site will break (A:L only)."),
    _rule("cookie-no-secure",
          ("cookie without secure",),
          "CWE-614", "Sensitive Cookie in HTTPS Session Without "
                     "'Secure' Attribute",
          "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
          "The cookie can be sent over plain HTTP on a hostile "
          "network (AC:H) and then used as the victim (C:L/I:L)."),
    _rule("cookie-no-httponly",
          ("cookie without httponly",),
          "CWE-1004", "Sensitive Cookie Without 'HttpOnly' Flag",
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
          "Any injected script can read the cookie (needs an XSS "
          "hole + a victim visit: UI:R, C:L)."),
    _rule("cookie-no-samesite",
          ("cookie without samesite",),
          "CWE-1275", "Sensitive Cookie with Improper SameSite Attribute",
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
          "The cookie is sent on cross-site requests, enabling "
          "CSRF (UI:R, I:L)."),
    _rule("server-version",
          ("server version disclosed",),
          "CWE-200", "Exposure of Sensitive Information to an "
                     "Unauthorized Actor",
          "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
          "A version string alone grants nothing; it only helps an "
          "attacker pick a known exploit (AC:H, C:L)."),
    _rule("x-powered-by",
          ("x-powered-by",),
          "CWE-200", "Exposure of Sensitive Information to an "
                     "Unauthorized Actor",
          "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
          "The framework version helps targeting only (AC:H, C:L)."),
    _rule("dnssec",
          ("dnssec not enabled",),
          "CWE-353", "Missing Support for Integrity Check",
          "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
          "Without DNSSEC, DNS answers can be spoofed on the path "
          "(AC:H, I:L)."),
    _rule("no-spf",
          ("no spf record",),
          "CWE-290", "Authentication Bypass by Spoofing",
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
          "Anyone can send mail as the domain (AC:L); receivers "
          "cannot tell it is forged (I:L)."),
    _rule("no-dmarc",
          ("no dmarc record",),
          "CWE-290", "Authentication Bypass by Spoofing",
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
          "Without DMARC, spoofed mail is not quarantined or "
          "rejected (I:L)."),
    _rule("sensitive-service",
          ("sensitive service",),
          "CWE-200", "Exposure of Sensitive Information to an "
                     "Unauthorized Actor",
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
          "A sensitive service (database, admin panel) is reachable "
          "from the internet (C:L/I:L)."),
    _rule("no-rate-limit",
          ("no rate-limit",),
          "CWE-770", "Allocation of Resources Without Limits",
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
          "No rate-limit headers: the endpoint can be flooded or "
          "credential-stuffed without slowing down (A:L)."),
    _rule("outdated-service",
          ("outdated service",),
          "CWE-1104", "Use of Unmaintained Third-Party Components",
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
          "An end-of-life service banner means known, unpatched "
          "vulnerabilities may apply (C:L/I:L)."),
    _rule("outdated-tls-traffic",
          ("outdated tls version seen in traffic",),
          "CWE-327", "Use of a Broken or Risky Cryptographic Algorithm",
          "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
          "Obsolete TLS was actually observed on the wire, not "
          "just offered (C:H)."),
    _rule("plaintext-traffic",
          ("plaintext http traffic",),
          "CWE-319", "Cleartext Transmission of Sensitive Information",
          "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
          "Cleartext HTTP traffic to the target was observed on "
          "the wire (C:H/I:H)."),
]


def lookup(name, severity="medium"):
    """Map a finding name to its CWE + computed CVSS.

    Returns {"key", "cwe_id", "cwe_name", "cwe_url", "vector",
    "cvss_score", "cvss_severity", "rationale", "source"} or None
    when no defensible mapping exists (info findings included).
    The score is computed from the vector, never hardcoded.
    """
    if (severity or "").lower() == "info":
        return None
    text = (name or "").lower()
    for rule in RULES:
        if all(p in text for p in rule["patterns"]):
            scored = cvss_mod.score_vector(rule["vector"])
            if scored is None:
                return None
            return {
                "key": rule["key"],
                "cwe_id": rule["cwe_id"],
                "cwe_name": rule["cwe_name"],
                "cwe_url": CWE_URL % rule["cwe_id"].split("-")[1],
                "vector": rule["vector"],
                "cvss_score": scored["score"],
                "cvss_severity": scored["severity"],
                "rationale": rule["rationale"],
                "source": "webdon-mapping",
            }
    return None


def enrich(finding):
    """Attach CWE/CVSS to a finding dict, in place.

    Nuclei classification (cve_id / cwe_id / cvss_vector, when the
    template provided them) wins over the mapping table; an NVD
    lookup enriches a CVE id when reachable. A finding with no
    defensible mapping gets cvss=None / cwe=None — never an
    invented number.
    Returns the finding.
    """
    cve_id = finding.get("cve_id")
    cwe_id = finding.get("cwe_id")
    vector = finding.get("cvss_vector")
    if vector:
        scored = cvss_mod.score_vector(vector)
        if scored is not None:
            finding["cvss"] = {
                "vector": vector, "score": scored["score"],
                "severity": scored["severity"], "source": "template"}
            finding["cwe"] = {
                "id": cwe_id or "UNKNOWN",
                "name": "See template classification",
                "url": (CWE_URL % cwe_id.split("-")[1]
                        if cwe_id and cwe_id.startswith("CWE-") else None)}
            if cve_id:
                finding["cve_id"] = cve_id
            return finding
    if cve_id:
        nvd = cvss_mod.nvd_lookup(cve_id)
        if nvd and nvd.get("vector"):
            scored = cvss_mod.score_vector(nvd["vector"])
            if scored is not None:
                finding["cvss"] = {
                    "vector": nvd["vector"], "score": scored["score"],
                    "severity": scored["severity"], "source": "nvd"}
                cwe_ids = nvd.get("cwe_ids") or []
                finding["cwe"] = {
                    "id": cwe_ids[0] if cwe_ids else "UNKNOWN",
                    "name": "See NVD record",
                    "url": (CWE_URL % cwe_ids[0].split("-")[1]
                            if cwe_ids else None)}
                finding["cve_id"] = cve_id
                return finding
    mapped = lookup(finding.get("name", ""),
                    finding.get("severity", "medium"))
    if mapped is None:
        finding["cvss"] = None
        finding["cwe"] = None
        if cve_id:
            finding["cve_id"] = cve_id
        return finding
    finding["cvss"] = {"vector": mapped["vector"],
                       "score": mapped["cvss_score"],
                       "severity": mapped["cvss_severity"],
                       "source": mapped["source"]}
    finding["cwe"] = {"id": mapped["cwe_id"],
                      "name": mapped["cwe_name"],
                      "url": mapped["cwe_url"]}
    if cve_id:
        finding["cve_id"] = cve_id
    return finding
