#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Technology fingerprinting — server, frameworks, CMS, JS libs.

From response headers and HTML meta/generator tags only. A
technology is reported only when actually seen — never guessed.
"""
import re

NAME = "tech"
TITLE = "Technology Fingerprinting"

PHASES = ["headers fingerprint", "HTML meta fingerprint"]

CMS_SIGNS = [
    ("wp-content", "WordPress"), ("wp-includes", "WordPress"),
    ("Joomla", "Joomla"), ("Drupal", "Drupal"),
    ("/sites/default/files", "Drupal"),
    ("Shopify", "Shopify"), ("Magento", "Magento"),
    ("PrestaShop", "PrestaShop"), ("Wix", "Wix"),
    ("Squarespace", "Squarespace"),
]

LIB_PATTERNS = [
    (r"jquery[-.](\d+\.\d+\.\d+)", "jQuery"),
    (r"react(?:\.min)?\.js", "React"),
    (r"vue(?:\.min)?\.js", "Vue.js"),
    (r"angular(?:\.min)?\.js", "Angular"),
    (r"bootstrap[-.](\d+\.\d+\.\d+)", "Bootstrap"),
]


def run(ctx):
    headers = ctx.get("headers") or {}
    html = ctx.get("html") or ""
    findings = []
    techs = []
    server = headers.get("server", "")
    if server:
        techs.append("server: %s" % server[:80])
    powered = headers.get("x-powered-by", "")
    if powered:
        techs.append("x-powered-by: %s" % powered[:80])
    generator = ""
    m = re.search(r'<meta[^>]+name\s*=\s*["\']generator["\'][^>]+'
                  r'content\s*=\s*["\']([^"\']+)', html, re.I)
    if not m:
        m = re.search(r'<meta[^>]+content\s*=\s*["\']([^"\']+)["\'][^>]+'
                      r'name\s*=\s*["\']generator["\']', html, re.I)
    if m:
        generator = m.group(1)
        techs.append("generator: %s" % generator[:80])
    cms = None
    for sign, name in CMS_SIGNS:
        if sign.lower() in html.lower() or sign in server:
            cms = name
            techs.append("cms: %s" % name)
            break
    libs = []
    for pat, name in LIB_PATTERNS:
        if re.search(pat, html, re.I):
            libs.append(name)
    if libs:
        techs.append("js_libs: %s" % ", ".join(sorted(set(libs))))
    data = {"server": server, "x_powered_by": powered,
            "generator": generator, "cms": cms,
            "technologies": techs, "js_libraries": sorted(set(libs))}
    if server and re.search(r"/\d", server):
        findings.append({"severity": "low",
                         "name": "Server version disclosed",
                         "evidence": "Server: %s" % server[:80],
                         "fix": "Hide the server version in the Server "
                                "header."})
    return {"engine": NAME, "status": "completed",
            "findings": findings, "data": data}
