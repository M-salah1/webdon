#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Engine registry: every engine in WEBDON, in run order."""
from . import cookies, cors, crawl, dns, headers, ipintel, paths
from . import ports, protect, tech, timeline, tls, whois
from . import httpx, katana, naabu, nuclei, schemathesis, subfinder

ENGINES = [crawl, headers, tls, tech, dns, whois, cookies, cors,
           protect, paths, ports, ipintel, timeline,
           httpx, subfinder, katana, nuclei, naabu, schemathesis]

BY_NAME = {e.NAME: e for e in ENGINES}

# Phases per engine — the "heavy" measure. DEEP and FORENSIC run
# 25+ phases in total (see total_phases in core/engine.py).
PHASES = {e.NAME: list(getattr(e, "PHASES", [e.NAME])) for e in ENGINES}

# Profiles: which engines run.
PROFILES = {
    # quick: site surface only — 6 engines, 12 phases.
    "quick": ["crawl", "headers", "tls", "tech", "cookies", "cors"],
    # deep: everything except the slowest follow-ups — 11 engines.
    "deep": ["crawl", "headers", "tls", "tech", "dns", "whois",
             "cookies", "cors", "protect", "paths", "ports", "ipintel"],
    # forensic: everything — 13 engines, 28 phases.
    "forensic": ["crawl", "headers", "tls", "tech", "dns", "whois",
                 "cookies", "cors", "protect", "paths", "ports",
                 "ipintel", "timeline"],
    # hive: everything + the 6 external adapters — 19 engines,
    # 45 phases, five waves (see webdon/core/hive.py).
    "hive": ["crawl", "headers", "tls", "tech", "httpx", "subfinder",
             "dns", "whois", "cookies", "cors", "protect", "paths",
             "katana", "nuclei", "ports", "naabu", "schemathesis",
             "ipintel", "timeline"],
}
