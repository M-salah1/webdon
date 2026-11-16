#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Engine registry: every engine in WEBDON, in run order."""
from . import cookies, cors, crawl, dns, headers, ipintel, paths
from . import ports, protect, tech, timeline, tls, whois
from . import httpx, katana, naabu, nuclei, schemathesis, subfinder
from . import bloodhound, netexec, nmap, openvas, wireshark

ENGINES = [crawl, headers, tls, tech, dns, whois, cookies, cors,
           protect, paths, ports, ipintel, timeline,
           httpx, subfinder, katana, nuclei, naabu, schemathesis,
           nmap, wireshark, openvas, netexec, bloodhound]

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
    # hive: everything + the 11 external adapters — 24 engines,
    # 56 phases, six waves (see webdon/core/hive.py).
    "hive": ["crawl", "headers", "tls", "tech", "httpx", "subfinder",
             "dns", "whois", "cookies", "cors", "protect", "paths",
             "katana", "nuclei", "ports", "naabu", "schemathesis",
             "ipintel", "timeline",
             # v3.00 NET — Wave 6: network & systems tools.
             "nmap", "wireshark", "openvas", "netexec", "bloodhound"],
}
