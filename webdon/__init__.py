#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WEBDON v5.00 DEEP-DIVE — Heavy Website Investigation System.

Developer: Hafed Mehdi Salah Eddine — Algeria
FOX COMPANY — Copyright (c) 2026

A heavy, modular, defensive website audit tool for Termux:
24 engines, 4 profiles (QUICK / DEEP / FORENSIC / HIVE), 56
phases in HIVE, SQLite history, JSON/HTML/PDF reports,
interactive Metasploit-style console, Arabic / English / French.

HIVE: one command (`hive <url>`) runs everything in six
parallel waves like a beehive — recon, web, vuln-detection,
IP follow-up alone, network & systems (Nmap, Wireshark,
OpenVAS bridge, NetExec, BloodHound CE bridge), report — with
professional-tool adapters (Nuclei, httpx, Subfinder, Katana,
Naabu, Schemathesis, ZAP bridge, Neo cloud hook, built-in
Burp-like).

v5.00 DEEP-DIVE: when a scan finds a result, WEBDON follows it
up with deeper probes on that exact result — and when those
probes find more, it goes deeper again (max depth 3 by default,
probe + time budgets, full dedup). Every finding gains depth /
parent / chain; chains survive in SQLite and in the reports.

Python standard library only. Authorized-only: every scan requires
a signed authorization scope (your own site or a site with written
permission). Passive / presence-only checks. No exploitation, no
payloads, no bypass testing, no brute force, no login bypass, and
no secret or password value is ever collected, stored or shown.
"""
__version__ = "5.00"
__author__ = "Hafed Mehdi Salah Eddine"
__org__ = "FOX COMPANY"
