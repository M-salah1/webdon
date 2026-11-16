#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WEBDON v4.00 EVIDENCE tests — run: python3 -m unittest discover -s tests -v

Covers: hive now 6 waves / >=55 phases / 24 engines, Nmap XML
parsing (identified only when a banner/version was read) and
no -O flag, Wireshark capture filter limited to the target IP
plus the own-request-log fallback, OpenVAS bridge status and
outdated-service heuristic labelling, NetExec not_applicable
without AD indicators and refusal of spraying/brute-force
flags, BloodHound bridge + import summary counts only (no
hashes), scope enforcement for Wave 6, the tool manager's five
new tools, the report's Network & Systems section, and a full
HIVE run against the local lab server.
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_webdon import FAKE_COOKIE_VALUE, FAKE_ENV_SECRET, LabServer  # noqa: E402
from webdon import __version__  # noqa: E402
from webdon.adapters import bloodhound as bloodhound_mod  # noqa: E402
from webdon.adapters import manager as manager_mod  # noqa: E402
from webdon.adapters import netexec as netexec_mod  # noqa: E402
from webdon.adapters import nmap as nmap_mod  # noqa: E402
from webdon.adapters import openvas as openvas_mod  # noqa: E402
from webdon.adapters import sanitize  # noqa: E402
from webdon.adapters import wireshark as wireshark_mod  # noqa: E402
from webdon.core import hive as hive_mod  # noqa: E402
from webdon.core import report as report_mod  # noqa: E402
from webdon.core.scope import Scope  # noqa: E402
from webdon.engines import PROFILES  # noqa: E402


def _ctx(url="http://127.0.0.1:9", authorized=True, **extra):
    ctx = {"url": url, "host": "127.0.0.1", "domain": "127.0.0.1",
           "authorized": authorized, "ips": ["127.0.0.1"],
           "pages": [], "scripts": [], "tls": {}, "whois": {},
           "ports_data": {"open_ports": []}, "nmap_data": {}}
    ctx.update(extra)
    return ctx


class TestVersionAndHiveStructure(unittest.TestCase):
    def test_version_is_3_00(self):
        self.assertEqual(__version__, "5.00")

    def test_hive_has_6_waves_55_plus_phases_24_engines(self):
        self.assertEqual(len(hive_mod.wave_names()), 6)
        self.assertIn("wave5-net", hive_mod.wave_names())
        self.assertEqual(len(PROFILES["hive"]), 24)
        self.assertGreaterEqual(hive_mod.total_phases(), 55)
        self.assertEqual(hive_mod.total_phases(), 56)

    def test_hive_refuses_without_scope(self):
        with tempfile.TemporaryDirectory() as d:
            scope = Scope(base_dir=d)
            with self.assertRaises(PermissionError):
                hive_mod.run_hive("https://example.com", scope=scope)

    def test_old_profiles_unchanged(self):
        from webdon.core import engine as engine_mod
        self.assertEqual(engine_mod.total_phases("quick"), 13)
        self.assertEqual(engine_mod.total_phases("deep"), 31)
        self.assertEqual(engine_mod.total_phases("forensic"), 33)


class TestNmapAdapter(unittest.TestCase):
    SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun><host><status state="up"/>
<ports>
<port protocol="tcp" portid="22"><state state="open"/>
<service name="ssh" product="OpenSSH" version="8.9"/></port>
<port protocol="tcp" portid="80"><state state="open"/>
<service name="http"/></port>
<port protocol="tcp" portid="443"><state state="closed"/></port>
<port protocol="tcp" portid="445"><state state="open"/></port>
</ports></host></nmaprun>"""

    def test_args_have_no_os_detection(self):
        args = nmap_mod.build_args("1.2.3.4")
        self.assertIn("-sV", args)
        self.assertIn("--top-ports", args)
        self.assertEqual(args[args.index("--top-ports") + 1], "100")
        self.assertIn("-oX", args)
        self.assertNotIn("-O", args)
        self.assertNotIn("-A", args)
        self.assertEqual(args[-1], "1.2.3.4")

    def test_parse_identified_only_when_banner_read(self):
        ports = nmap_mod.parse_xml(self.SAMPLE_XML)
        self.assertEqual([p["port"] for p in ports], [22, 80, 445])
        ssh = ports[0]
        self.assertEqual(ssh["state"], "service_identified")
        self.assertTrue(ssh["identified"])
        self.assertIn("OpenSSH", ssh["service"])
        # Port 80 has a service name but no product/version: it is
        # identified by name only; port 445 has nothing at all.
        self.assertEqual(ports[2]["state"], "tcp_open")
        self.assertFalse(ports[2]["identified"])

    def test_parse_garbage_is_empty(self):
        self.assertEqual(nmap_mod.parse_xml("not xml at all"), [])
        self.assertEqual(nmap_mod.parse_xml(""), [])

    def test_run_falls_back_when_not_installed(self):
        res = nmap_mod.run(_ctx())
        self.assertEqual(res["status"], "not_installed (fallback)")
        self.assertIn("connect scan", res["data"]["mode"])

    def test_run_refuses_without_scope(self):
        with self.assertRaises(PermissionError):
            nmap_mod.run(_ctx(authorized=False))


class TestWiresharkAdapter(unittest.TestCase):
    def test_args_filter_limited_to_target_ip(self):
        args = wireshark_mod.build_args("203.0.113.7")
        self.assertIn("-f", args)
        self.assertEqual(args[args.index("-f") + 1], "host 203.0.113.7")
        self.assertIn("-c", args)
        self.assertEqual(args[args.index("-c") + 1], "200")
        self.assertNotIn("host 203.0.113.7 or", " ".join(args))

    def test_parse_fields_counts_only(self):
        text = ("1\t6\t\t0x0303\tGET\texample.com\n"
                "2\t17\texample.com\t\t\t\n"
                "3\t6\t\t0x0301\t\t\n")
        summary = wireshark_mod.parse_fields(text)
        self.assertEqual(summary["packets"], 3)
        self.assertEqual(summary["dns_queries"], ["example.com"])
        self.assertIn("0x0303", summary["tls_versions"])
        self.assertEqual(summary["http_methods"], ["GET"])
        self.assertNotIn("payload", json.dumps(summary))

    def test_run_falls_back_when_tshark_missing(self):
        res = wireshark_mod.run(_ctx())
        self.assertIn(res["status"],
                      ("not_installed (fallback)", "fallback"))
        self.assertIn("own-request-log", res["data"]["mode"])
        self.assertEqual(
            res["data"]["capture"]["source"], "own-request-log")

    def test_fallback_ignores_failed_tls_attempts(self):
        # The TLS engine records {label: bool}; False means the
        # handshake was attempted and FAILED (e.g. behind an
        # intercepting proxy). Failed attempts are NOT observed
        # versions and must not produce an outdated-TLS finding.
        ctx = _ctx(tls={"versions": {"TLSv1.0": False,
                                     "TLSv1.1": False,
                                     "TLSv1.2": False,
                                     "TLSv1.3": False},
                        "note": "TLS handshake failed for all versions"})
        res = wireshark_mod.run(ctx)
        self.assertEqual(
            res["data"]["capture"]["tls_versions"], [])
        self.assertFalse(any("Outdated TLS" in f["name"]
                             for f in res["findings"]))
        # ...while a version that really succeeded IS reported.
        ctx2 = _ctx(tls={"versions": {"TLSv1.0": True,
                                      "TLSv1.2": True}})
        res2 = wireshark_mod.run(ctx2)
        self.assertEqual(
            res2["data"]["capture"]["tls_versions"],
            ["TLSv1.0", "TLSv1.2"])
        self.assertTrue(any("Outdated TLS" in f["name"]
                            for f in res2["findings"]))

    def test_run_refuses_without_scope(self):
        with self.assertRaises(PermissionError):
            wireshark_mod.run(_ctx(authorized=False))


class TestOpenvasAdapter(unittest.TestCase):
    def test_heuristic_labels_outdated_tls(self):
        ctx = _ctx(tls={"version": "TLSv1.0"})
        findings = openvas_mod.check_outdated(ctx)
        self.assertTrue(any("TLS 1.0" in f["name"]
                            or "Outdated service" in f["name"]
                            for f in findings))
        self.assertTrue(all("banner-based heuristic" in f["evidence"]
                            for f in findings))
        self.assertTrue(any("not a full OpenVAS scan" in f["evidence"]
                            for f in findings))

    def test_heuristic_labels_old_openssh_banner(self):
        ctx = _ctx(ports_data={"open_ports": [
            {"port": 22, "service": "ssh",
             "banner": "SSH-2.0-OpenSSH_5.9", "state": "service_identified"}]})
        findings = openvas_mod.check_outdated(ctx)
        self.assertTrue(any("openssh" in f["name"] for f in findings))

    def test_heuristic_clean_for_modern_versions(self):
        ctx = _ctx(tls={"version": "TLSv1.3"},
                   ports_data={"open_ports": [
                       {"port": 22, "service": "ssh",
                        "banner": "SSH-2.0-OpenSSH_9.6",
                        "state": "service_identified"}]})
        self.assertEqual(openvas_mod.check_outdated(ctx), [])

    def test_run_is_bridge_not_a_real_scan(self):
        res = openvas_mod.run(_ctx())
        self.assertEqual(res["status"], "bridge")
        self.assertIn("server/PC", res["data"]["mode"])
        self.assertIn("openvas export", res["data"]["export_hint"])

    def test_export_writes_task_and_plan(self):
        with tempfile.TemporaryDirectory() as d:
            task_path, plan_path = openvas_mod.export_task(
                "https://example.com", "93.184.216.34", out_dir=d)
            with open(task_path, encoding="utf-8") as f:
                task = json.load(f)
            self.assertEqual(task["hosts"], ["93.184.216.34"])
            self.assertEqual(task["scan_config"], "Full and fast")
            with open(plan_path, encoding="utf-8") as f:
                self.assertIn("Greenbone", f.read())

    def test_gvm_task_flow_with_mocked_runner(self):
        calls = []

        def fake_runner(argv, timeout=120):
            calls.append(argv)
            if "<get_version/>" in argv[-1]:
                return 0, "<get_version_response status='200'/>", ""
            if "<create_target>" in argv[-1]:
                return 0, ('<create_target_response status="201" '
                           'id="11111111-1111-1111-1111-111111111111"/>'), ""
            return 0, ('<create_task_response status="201" '
                       'id="22222222-2222-2222-2222-222222222222"/>'), ""

        res = openvas_mod.run_gvm_task(
            "192.168.1.10", "admin", "s3cr3t-fake", "10.0.0.5",
            runner=fake_runner)
        self.assertEqual(res["status"], "completed")
        self.assertEqual(res["data"]["task_id"],
                         "22222222-2222-2222-2222-222222222222")
        blob = json.dumps(res)
        self.assertNotIn("s3cr3t-fake", blob)

    def test_run_refuses_without_scope(self):
        with self.assertRaises(PermissionError):
            openvas_mod.run(_ctx(authorized=False))


class TestNetexecAdapter(unittest.TestCase):
    def test_detect_indicators_from_ad_ports(self):
        ind = netexec_mod.detect_ad_indicators(
            _ctx(ports_data={"open_ports": [
                {"port": 445, "service": "smb"},
                {"port": 389, "service": "ldap"},
                {"port": 443, "service": "https"}]}))
        self.assertTrue(ind["is_windows_ad"])
        self.assertEqual(ind["ad_ports_open"], [389, 445])
        self.assertIn("smb", ind["ad_services"])

    def test_detect_no_indicators_for_plain_website(self):
        ind = netexec_mod.detect_ad_indicators(
            _ctx(ports_data={"open_ports": [
                {"port": 80, "service": "http"},
                {"port": 443, "service": "https"}]}))
        self.assertFalse(ind["is_windows_ad"])
        self.assertEqual(ind["ad_ports_open"], [])

    def test_build_args_are_anonymous_only(self):
        args = netexec_mod.build_args("10.0.0.5", "shares")
        self.assertEqual(args[:3], ["nxc", "smb", "10.0.0.5"])
        self.assertIn("--shares", args)
        for forbidden in ("--spray", "--brute", "--hash", "--pass",
                          "--password", "--passwords", "--pth",
                          "--wordlist"):
            self.assertNotIn(forbidden, args)
        with self.assertRaises(ValueError):
            netexec_mod.build_args("10.0.0.5", "spray")

    def test_run_not_applicable_without_indicators(self):
        res = netexec_mod.run(_ctx())
        self.assertEqual(res["status"], "not_applicable")
        self.assertIn("not a Windows/AD host", res["data"]["note"])

    def test_run_refuses_without_scope(self):
        with self.assertRaises(PermissionError):
            netexec_mod.run(_ctx(authorized=False))

    def test_run_explicit_refuses_without_indicators(self):
        res = netexec_mod.run_explicit(_ctx())
        self.assertEqual(res["status"], "not_applicable")


class TestBloodhoundAdapter(unittest.TestCase):
    FAKE_HASH = "aad3b435b51404eeaad3b435b51404ee"
    SAMPLE = {"data": [
        {"type": "User", "name": "alice@EXAMPLE.LOCAL",
         "hash": FAKE_HASH},
        {"type": "User", "name": "bob@EXAMPLE.LOCAL"},
        {"type": "Computer", "name": "WS01.EXAMPLE.LOCAL"},
        {"type": "Group", "name": "DOMAIN ADMINS@EXAMPLE.LOCAL"},
        {"type": "Domain", "name": "EXAMPLE.LOCAL"},
    ]}

    def test_parse_counts_only_no_hashes(self):
        summary = bloodhound_mod.parse_collection(self.SAMPLE)
        self.assertEqual(summary["total_objects"], 5)
        self.assertEqual(summary["counts"]["User"], 2)
        self.assertEqual(summary["counts"]["Computer"], 1)
        blob = json.dumps(summary)
        self.assertNotIn("hash", blob.lower())
        self.assertNotIn("password", blob.lower())
        self.assertIn("alice@EXAMPLE.LOCAL",
                      summary["names_by_type"]["User"])

    def test_import_summary_counts(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "collection.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.SAMPLE, f)
            res = bloodhound_mod.import_collection(path)
            self.assertEqual(res["status"], "completed")
            self.assertEqual(
                res["data"]["summary"]["counts"]["Group"], 1)
            # The fake hash value from the collection must never
            # appear in the output (only counts and names do).
            self.assertNotIn(self.FAKE_HASH, json.dumps(res))

    def test_run_not_applicable_without_indicators(self):
        res = bloodhound_mod.run(_ctx())
        self.assertEqual(res["status"], "not_applicable")
        self.assertIn("not a Windows/AD host", res["data"]["note"])

    def test_run_is_bridge_with_indicators(self):
        ctx = _ctx(ports_data={"open_ports": [
            {"port": 445, "service": "smb"}]})
        res = bloodhound_mod.run(ctx)
        self.assertEqual(res["status"], "bridge")
        self.assertIn("bloodhound export", res["data"]["note"])

    def test_export_writes_plan_and_commands(self):
        with tempfile.TemporaryDirectory() as d:
            plan_path, cmd_path = bloodhound_mod.export_plan(
                "https://example.com", "10.0.0.5", out_dir=d)
            with open(plan_path, encoding="utf-8") as f:
                self.assertIn("SharpHound", f.read())
            with open(cmd_path, encoding="utf-8") as f:
                self.assertIn("SharpHound.exe", f.read())

    def test_run_refuses_without_scope(self):
        with self.assertRaises(PermissionError):
            bloodhound_mod.run(_ctx(authorized=False))


class TestNetToolManager(unittest.TestCase):
    def test_five_new_tools_listed(self):
        names = [row["name"] for row in manager_mod.list_all()]
        for name in ("nmap", "tshark", "openvas", "netexec", "bloodhound"):
            self.assertIn(name, names)
        self.assertEqual(len(names), 14)

    def test_install_cmds(self):
        self.assertEqual(manager_mod.install_cmd("nmap"),
                         "pkg install nmap")
        self.assertEqual(manager_mod.install_cmd("tshark"),
                         "pkg install tshark")
        self.assertEqual(manager_mod.install_cmd("netexec"),
                         "pip install netexec")
        self.assertIsNone(manager_mod.install_cmd("openvas"))
        self.assertIsNone(manager_mod.install_cmd("bloodhound"))

    def test_bridges_not_installable(self):
        self.assertFalse(manager_mod.install("openvas")["installed"])
        self.assertFalse(manager_mod.install("bloodhound")["installed"])
        self.assertIn("bridge", manager_mod.install("openvas")["error"])

    def test_bridge_check_status(self):
        self.assertEqual(manager_mod.check("openvas")["status"],
                         "bridge (server)")
        self.assertEqual(manager_mod.check("bloodhound")["status"],
                         "bridge (server)")


class TestNetReportSection(unittest.TestCase):
    def test_net_section_lists_wave6_statuses(self):
        scan = {"engines": ["nmap", "wireshark", "openvas", "netexec",
                            "bloodhound"],
                "engine_status": {
                    "nmap": {"status": "completed"},
                    "wireshark": {"status": "not_installed (fallback)"},
                    "openvas": {"status": "bridge"},
                    "netexec": {"status": "not_applicable"},
                    "bloodhound": {"status": "not_applicable"}},
                "results": {
                    "nmap": {"status": "completed",
                             "data": {"mode": "nmap -sV"}},
                    "wireshark": {"status": "not_installed (fallback)",
                                  "data": {"mode": "fallback"}},
                    "openvas": {"status": "bridge",
                                "data": {"mode": "bridge"}},
                    "netexec": {"status": "not_applicable", "data": {}},
                    "bloodhound": {"status": "not_applicable",
                                   "data": {}}}}
        rows = report_mod.net_section(scan)
        self.assertEqual(len(rows), 5)
        self.assertEqual(dict((n, s) for n, s, _ in rows)["openvas"],
                         "bridge")
        self.assertEqual(dict((n, s) for n, s, _ in rows)["netexec"],
                         "not_applicable")

    def test_html_contains_net_section(self):
        scan = {"target": "https://example.com", "profile": "hive",
                "score": 43, "grade": "F", "confidence": 50,
                "coverage": {"percent": 100}, "duration_s": 1.0,
                "metrics": {"verification_rate": 0},
                "engines": ["nmap", "netexec"],
                "engine_status": {"nmap": {"status": "completed",
                                           "duration_s": 0.1},
                                  "netexec": {"status": "not_applicable",
                                              "duration_s": 0.1}},
                "results": {"nmap": {"status": "completed",
                                     "data": {"mode": "nmap -sV"}},
                            "netexec": {"status": "not_applicable",
                                        "data": {}}},
                "findings": [], "limits": {},
                "recommendations": []}
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "report.html")
            report_mod.to_html(scan, path)
            with open(path, encoding="utf-8") as f:
                html = f.read()
            self.assertIn("Network &amp; Systems", html)
            self.assertIn("not_applicable", html)


class TestHiveLabNet(unittest.TestCase):
    def test_full_hive_on_lab_server_wave6(self):
        with LabServer() as base, tempfile.TemporaryDirectory() as d:
            scope = Scope(base_dir=d)
            scope.authorize(base)
            scan = hive_mod.run_hive(
                base, scope=scope,
                settings={"scan_budget_s": 240})
            self.assertEqual(scan["tool"], "WEBDON v5.00")
            self.assertEqual(scan["kind"], "webdon-hive")
            self.assertEqual(scan["profile"], "hive")
            self.assertIsNotNone(scan["score"])
            self.assertGreaterEqual(
                scan["coverage"]["phases_done"], 55)
            self.assertEqual(scan["hive"]["phases"], 56)
            self.assertEqual(len(scan["hive"]["waves"]), 6)
            adapters = scan["hive"]["adapters"]
            for name in ("nmap", "wireshark", "openvas", "netexec",
                         "bloodhound"):
                self.assertIn(name, adapters)
            # The lab server is a plain website, not a Windows/AD host.
            self.assertEqual(
                (scan["results"].get("netexec") or {}).get("status"),
                "not_applicable")
            self.assertEqual(
                (scan["results"].get("bloodhound") or {}).get("status"),
                "not_applicable")
            self.assertEqual(
                (scan["results"].get("openvas") or {}).get("status"),
                "bridge")
            blob = json.dumps(scan, ensure_ascii=False)
            self.assertNotIn(FAKE_COOKIE_VALUE, blob)
            self.assertNotIn(FAKE_ENV_SECRET, blob)
            self.assertNotIn("DB_PASSWORD", blob)
            rows = report_mod.net_section(scan)
            self.assertEqual(len(rows), 5)


if __name__ == "__main__":
    unittest.main()
