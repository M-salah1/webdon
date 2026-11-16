#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WEBDON v5.00 DEEP-DIVE tests — run: python3 -m unittest discover -s tests -v

Covers: depth clamp + depth limit, probe/time budget stops with
the exact reason recorded, dedup (same probe never twice, same
finding_key counts once across depths), parent/child linkage +
chain paths, playbook coverage for all 11 chains on lab data,
no-new-finding branches ending, scope enforcement for the dive,
sanitizer stripping secrets from follow-up results, scoring
without inflation, and report chains output (terminal/JSON/HTML).
"""
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_webdon import FAKE_COOKIE_VALUE, LabServer  # noqa: E402
from webdon import __version__  # noqa: E402
from webdon.core import deepdive as dd  # noqa: E402
from webdon.core import enrich as enrich_mod  # noqa: E402
from webdon.core import hive as hive_mod  # noqa: E402
from webdon.core import report as report_mod  # noqa: E402
from webdon.core import scoring as scoring_mod  # noqa: E402
from webdon.core.scope import Scope  # noqa: E402


def _ctx():
    return {"url": "http://127.0.0.1:9", "host": "127.0.0.1",
            "domain": "127.0.0.1", "authorized": True,
            "ips": ["127.0.0.1"],
            "pages": [{"url": "http://127.0.0.1:9"},
                      {"url": "http://127.0.0.1:9/page2"}],
            "scripts": [], "subdomains": ["api.example.test"],
            "tls": {}, "whois": {}}


def _finding(name, engine="headers", fid="F-001", depth=0, **kw):
    f = {"severity": kw.pop("severity", "medium"),
         "name": name, "evidence": kw.pop("evidence", "lab evidence"),
         "fix": "fix it", "confirmation": kw.pop("confirmation",
                                                  "indicator"),
         "engine": engine, "finding_id": fid, "depth": depth,
         "parent_id": None, "follow_ups": [], "chain": fid}
    f.update(kw)
    return f


def _scope_for(url="http://127.0.0.1:9"):
    d = tempfile.mkdtemp()
    scope = Scope(base_dir=d)
    scope.authorize(url)
    return scope


def _scan(findings, base="http://127.0.0.1:9"):
    enriched = enrich_mod.enrich_all(findings, _ctx())
    return {"tool": "WEBDON v%s" % __version__, "target": base,
            "profile": "hive", "kind": "webdon-hive",
            "coverage": {"percent": 100}, "unreachable": False,
            "findings": enriched, "false_positives": [], "chains": [],
            "results": {"crawl": {"data": {"pages": [
                {"url": base}, {"url": base + "/page2"}]}}},
            "ips": ["127.0.0.1"], "host": "127.0.0.1",
            "domain": "127.0.0.1",
            "validation": {"verified": 0,
                           "observed": len(enriched),
                           "false_positive": 0},
            "metrics": {"security_score": None, "confidence": 0,
                        "verification_rate": 0},
            "severity_distribution": {}, "recommendations": []}


# Header chain used by the fake runner: each header_audit probe
# returns the NEXT missing header, so the dive keeps going until
# the depth limit stops it.
HEADER_CHAIN = {
    "content-security-policy": "Missing X-Frame-Options",
    "x-frame-options": "Missing Referrer-Policy",
    "referrer-policy": "Missing Permissions-Policy",
    "permissions-policy": "Missing Cross-Origin-Opener-Policy",
    "cross-origin-opener-policy": "Missing Content-Security-Policy",
}


def header_chain_runner(probe, ctx):
    if probe["type"] != "header_audit":
        return []
    nxt = HEADER_CHAIN.get((probe["params"] or {}).get("header"))
    if not nxt:
        return []
    return [_finding(nxt, engine="deepdive", severity="low")]


class TestDepthClamp(unittest.TestCase):
    def test_valid_depth_unchanged(self):
        self.assertEqual(dd.clamp_depth(3), (3, False))
        self.assertEqual(dd.clamp_depth(1), (1, False))
        self.assertEqual(dd.clamp_depth(5), (5, False))

    def test_out_of_range_clamps_with_warning(self):
        self.assertEqual(dd.clamp_depth(0), (1, True))
        self.assertEqual(dd.clamp_depth(9), (5, True))
        self.assertEqual(dd.clamp_depth(-2), (1, True))

    def test_garbage_clamps_to_default_with_warning(self):
        self.assertEqual(dd.clamp_depth("nope"), (3, True))
        self.assertEqual(dd.clamp_depth(None), (3, True))


class TestPlaybookCoverage(unittest.TestCase):
    """Each of the 11 chains produces its follow-ups on lab data."""

    def test_missing_header_audits_all_pages_plus_related(self):
        probes = dd.plan_follow_ups(
            _finding("Missing Content-Security-Policy"), _ctx())
        self.assertEqual(len(probes), 1)
        self.assertEqual(probes[0]["type"], "header_audit")
        self.assertEqual(probes[0]["params"]["header"],
                         "content-security-policy")
        self.assertEqual(len(probes[0]["params"]["pages"]), 2)
        self.assertIn("strict-transport-security",
                      probes[0]["params"]["related"])

    def test_open_port_banner_neighbours(self):
        probes = dd.plan_follow_ups(
            _finding("Port 22 open but service unidentified",
                     engine="ports",
                     evidence="port 22 answered TCP"),
            _ctx())
        types = [p["type"] for p in probes]
        self.assertIn("port_banner", types)
        self.assertIn("port_neighbours", types)
        nb = next(p for p in probes if p["type"] == "port_neighbours")
        self.assertEqual(nb["params"]["neighbours"], [20, 21, 23, 24])

    def test_subdomain_miniscan(self):
        probes = dd.plan_follow_ups(
            _finding("Subdomain found: api.example.test",
                     engine="subfinder",
                     evidence="api.example.test"),
            _ctx())
        self.assertEqual([p["type"] for p in probes],
                         ["subdomain_miniscan"])
        self.assertEqual(probes[0]["target"], "api.example.test")

    def test_exposed_config_siblings_head_only_plus_robots(self):
        probes = dd.plan_follow_ups(
            _finding("Environment file reachable (.env)",
                     engine="paths", evidence="/.env -> HTTP 200"),
            _ctx())
        types = [p["type"] for p in probes]
        self.assertIn("config_siblings", types)
        self.assertIn("config_robots_ref", types)
        sib = next(p for p in probes if p["type"] == "config_siblings")
        self.assertIn("/.env.local", sib["params"]["siblings"])
        self.assertIn("/config/.env", sib["params"]["siblings"])

    def test_cookie_flag_audits_all_pages(self):
        probes = dd.plan_follow_ups(
            _finding("Cookie without Secure flag", engine="cookies",
                     evidence="cookie sessionid"),
            _ctx())
        self.assertEqual([p["type"] for p in probes], ["cookie_audit"])
        self.assertEqual(probes[0]["params"]["flag"], "Secure")
        self.assertEqual(len(probes[0]["params"]["pages"]), 2)

    def test_weak_tls_enumerates_versions_and_chain(self):
        probes = dd.plan_follow_ups(
            _finding("Weak TLS version: TLS 1.0", engine="tls"), _ctx())
        self.assertEqual({p["type"] for p in probes},
                         {"tls_enumerate", "tls_cert_chain"})

    def test_tech_wordpress_version_and_plugins(self):
        probes = dd.plan_follow_ups(
            _finding("WordPress detected", engine="tech",
                     evidence="cms: WordPress"),
            _ctx())
        types = [p["type"] for p in probes]
        self.assertIn("tech_version", types)
        self.assertIn("tech_plugins", types)

    def test_tech_version_finding_gets_nvd_lookup(self):
        probes = dd.plan_follow_ups(
            _finding("WordPress version detected: 6.5", engine="deepdive",
                     tech_name="wordpress", tech_version="6.5"),
            _ctx())
        self.assertEqual([p["type"] for p in probes],
                         ["nvd_tech_lookup"])
        self.assertEqual(probes[0]["params"]["version"], "6.5")

    def test_whois_rdap_and_asn(self):
        ctx = _ctx()
        ctx["domain"] = "example.test"
        probes = dd.plan_follow_ups(
            _finding("Domain registration expires soon", engine="whois"),
            ctx)
        self.assertEqual({p["type"] for p in probes},
                         {"whois_rdap", "whois_asn"})

    def test_cors_wildcard_preflight_on_api_paths(self):
        probes = dd.plan_follow_ups(
            _finding("CORS: wildcard origin allows any site",
                     engine="cors"),
            _ctx())
        self.assertTrue(probes)
        self.assertTrue(all(p["type"] == "cors_preflight"
                            for p in probes))

    def test_nuclei_reprobe_and_family(self):
        probes = dd.plan_follow_ups(
            _finding("Nuclei: http/missing-headers", engine="nuclei",
                     cwe={"id": "CWE-693", "name": "x"}),
            _ctx())
        types = [p["type"] for p in probes]
        self.assertIn("nuclei_reprobe", types)
        self.assertIn("nuclei_family", types)

    def test_ip_reverse_asn_and_other_ips(self):
        probes = dd.plan_follow_ups(
            _finding("IP 127.0.0.1 located in Nowhere (AS1), hosted "
                     "by Lab", engine="ipintel",
                     evidence="reverse DNS: none"),
            _ctx())
        self.assertEqual({p["type"] for p in probes},
                         {"ip_reverse", "ip_asn_geo", "ip_other_ips"})

    def test_unknown_finding_has_no_follow_ups(self):
        probes = dd.plan_follow_ups(
            _finding("Something entirely unrelated", engine="timeline"),
            _ctx())
        self.assertEqual(probes, [])


    def test_neighbour_finding_spawns_no_further_probes(self):
        # A neighbour finding must not walk the port range.
        probes = dd.plan_follow_ups(
            _finding("Neighbour port 81 open next to 80 (http)",
                     engine="deepdive",
                     evidence="port 81 service_identified"),
            _ctx())
        self.assertEqual(probes, [])
        probes = dd.plan_follow_ups(
            _finding("Open port 22: ssh (service_confirmed)",
                     engine="deepdive", evidence="port 22 ssh"),
            _ctx())
        self.assertEqual(probes, [])

    def test_tcp_open_banner_is_not_a_finding(self):
        # A bare TCP answer with no banner (firewall / egress
        # proxy answering SYNs) adds nothing new.
        fake = {"port": 22, "service": "?", "state": "tcp_open",
                "banner": "muse: Other TCP connections is turned off"}
        with mock.patch("webdon.engines.ports.check_port",
                        return_value=fake):
            probe = {"probe_id": "P-x", "type": "port_banner",
                     "target": "127.0.0.1:22",
                     "params": {"ip": "127.0.0.1", "port": 22}}
            self.assertEqual(dd._run_probe(probe, _ctx()), [])
            probe = {"probe_id": "P-y", "type": "port_neighbours",
                     "target": "127.0.0.1:22",
                     "params": {"ip": "127.0.0.1", "port": 22,
                                "neighbours": [21, 23]}}
            self.assertEqual(dd._run_probe(probe, _ctx()), [])
        identified = dict(fake, state="service_confirmed",
                          service="ssh", banner="SSH-2.0-OpenSSH_9.0")
        with mock.patch("webdon.engines.ports.check_port",
                        return_value=identified):
            probe = {"probe_id": "P-x", "type": "port_banner",
                     "target": "127.0.0.1:22",
                     "params": {"ip": "127.0.0.1", "port": 22}}
            out = dd._run_probe(probe, _ctx())
            self.assertEqual(len(out), 1)
            self.assertIn("Open port 22", out[0]["name"])


class TestRunnerBounds(unittest.TestCase):
    def test_depth_limit_enforced_and_recorded(self):
        dive = dd.DeepDive(_scope_for(), _ctx(),
                            settings={"depth": 2},
                            runner=header_chain_runner)
        new, stats = dive.run([_finding("Missing Content-Security-Policy")])
        self.assertTrue(all(f["depth"] <= 2 for f in new))
        self.assertEqual(stats["deepest"], 2)
        self.assertEqual(stats["stop_reason"], "depth_limit")
        self.assertEqual(stats["new_findings_by_depth"], {"1": 1, "2": 1})

    def test_depth_1_caps_at_one_level(self):
        dive = dd.DeepDive(_scope_for(), _ctx(),
                            settings={"depth": 1},
                            runner=header_chain_runner)
        new, stats = dive.run([_finding("Missing Content-Security-Policy")])
        self.assertEqual(len(new), 1)
        self.assertEqual(new[0]["depth"], 1)

    def test_no_new_finding_branch_ends(self):
        dive = dd.DeepDive(_scope_for(), _ctx(),
                            settings={"depth": 3},
                            runner=lambda p, c: [])
        new, stats = dive.run([_finding("Missing Content-Security-Policy")])
        self.assertEqual(new, [])
        self.assertEqual(stats["deepest"], 0)
        self.assertIsNone(stats["stop_reason"])
        self.assertEqual(stats["probes_run"], 1)

    def test_probe_budget_stops_with_exact_reason(self):
        calls = []

        def counting_runner(probe, ctx):
            calls.append(probe["probe_id"])
            return header_chain_runner(probe, ctx)

        dive = dd.DeepDive(_scope_for(), _ctx(),
                            settings={"depth": 5, "deepdive_probe_budget": 2},
                            runner=counting_runner)
        new, stats = dive.run([_finding("Missing Content-Security-Policy")])
        self.assertEqual(stats["stop_reason"], "probe_budget")
        self.assertLessEqual(stats["probes_run"], 2)
        self.assertEqual(len(calls), stats["probes_run"])

    def test_time_budget_stops_with_exact_reason(self):
        dive = dd.DeepDive(_scope_for(), _ctx(),
                            settings={"depth": 3,
                                      "deepdive_time_budget_s": 0},
                            runner=header_chain_runner)
        new, stats = dive.run([_finding("Missing Content-Security-Policy")])
        self.assertEqual(stats["stop_reason"], "time_budget")
        self.assertEqual(stats["probes_run"], 0)
        self.assertEqual(new, [])

    def test_same_probe_never_runs_twice(self):
        calls = []

        def counting_runner(probe, ctx):
            calls.append(probe["probe_id"])
            return []

        dive = dd.DeepDive(_scope_for(), _ctx(),
                            settings={"depth": 3},
                            runner=counting_runner)
        # Two identical L0 findings plan the identical probe.
        l0 = [_finding("Missing Content-Security-Policy", fid="F-001"),
              _finding("Missing Content-Security-Policy", fid="F-002")]
        dive.run(l0)
        self.assertEqual(len(calls), 1)
        self.assertEqual(len(set(calls)), 1)
        self.assertEqual(dive.probes_deduped, 1)

    def test_scope_enforced_for_deepdive(self):
        with tempfile.TemporaryDirectory() as d:
            scope = Scope(base_dir=d)  # nothing authorized
            dive = dd.DeepDive(scope, _ctx(), settings={"depth": 2},
                                runner=header_chain_runner)
            with self.assertRaises(PermissionError):
                dive.run([_finding("Missing Content-Security-Policy")])

    def test_identical_finding_key_deduped_across_depths(self):
        def echo_runner(probe, ctx):
            # The probe "finds" the very same problem again.
            return [_finding("Missing Content-Security-Policy",
                             engine="deepdive", severity="high")]

        dive = dd.DeepDive(_scope_for(), _ctx(),
                            settings={"depth": 3}, runner=echo_runner)
        new, stats = dive.run([_finding("Missing Content-Security-Policy")])
        self.assertEqual(new, [])
        self.assertEqual(len(stats["deduped_findings"]), 1)
        self.assertEqual(stats["deduped_findings"][0]["finding_key"],
                         "missing content security policy")


class TestApplyToScan(unittest.TestCase):
    def test_parent_child_linkage_and_chain_paths(self):
        scan = _scan([_finding("Missing Content-Security-Policy")])
        dd.apply_to_scan(scan, _scope_for(),
                         settings={"depth": 2},
                         runner=header_chain_runner)
        by_id = {f["finding_id"]: f for f in scan["findings"]}
        self.assertEqual(len(scan["findings"]), 3)
        child = by_id["F-002"]
        grand = by_id["F-003"]
        self.assertEqual(child["depth"], 1)
        self.assertEqual(child["parent_id"], "F-001")
        self.assertEqual(child["chain"], "F-001/F-002")
        self.assertEqual(grand["depth"], 2)
        self.assertEqual(grand["parent_id"], "F-002")
        self.assertEqual(grand["chain"], "F-001/F-002/F-003")
        self.assertEqual(by_id["F-001"]["depth"], 0)
        self.assertIsNone(by_id["F-001"]["parent_id"])
        self.assertEqual(by_id["F-001"]["chain"], "F-001")
        self.assertIn("P-", by_id["F-001"]["follow_ups"][0])
        self.assertEqual(scan["deepdive"]["deepest"], 2)
        self.assertEqual(scan["deepdive"]["stop_reason"], "depth_limit")

    def test_score_counts_each_finding_once_no_inflation(self):
        l0 = [_finding("Missing Content-Security-Policy", severity="low",
                       confirmation="indicator")]
        scan = _scan(l0)
        before = scoring_mod.score_findings(scan["findings"])[0]
        self.assertEqual(before, 99)  # one low indicator = -1

        def one_child(probe, ctx):
            return [_finding("Child medium issue", engine="deepdive",
                             severity="medium",
                             confirmation="indicator")]

        dd.apply_to_scan(scan, _scope_for(), settings={"depth": 1},
                         runner=one_child)
        self.assertEqual(len(scan["findings"]), 2)
        # Low indicator (1) + medium indicator (4) = 95, once each.
        self.assertEqual(scan["score"], 95)
        # A duplicate child must not move the score again.
        dd2 = dd.DeepDive(_scope_for(), _ctx(), settings={"depth": 1},
                          runner=one_child)
        self.assertEqual(dd2.run(scan["findings"])[1]["new_findings"], 0)

    def test_sanitizer_strips_secrets_from_follow_up_results(self):
        def leaky_runner(probe, ctx):
            return [_finding("Leaky follow-up", engine="deepdive",
                             evidence="Set-Cookie: sessionid=%s"
                                      % FAKE_COOKIE_VALUE)]

        scan = _scan([_finding("Missing Content-Security-Policy")])
        dd.apply_to_scan(scan, _scope_for(), settings={"depth": 1},
                         runner=leaky_runner)
        blob = json.dumps(scan, ensure_ascii=False)
        self.assertNotIn(FAKE_COOKIE_VALUE, blob)

    def test_header_audit_reuses_canonical_title_and_promotes(self):
        # The audit finding has the SAME finding_key as the L0
        # finding: it dedups (counts once) and promotes the
        # shallow finding to confirmed instead of double-counting.
        with LabServer() as base:
            ctx = _ctx()
            ctx["url"] = base
            ctx["host"] = "127.0.0.1"
            probes = dd.plan_follow_ups(
                _finding("Missing Content-Security-Policy"), ctx)
            out = dd._run_probe(probes[0], ctx)
            self.assertTrue(out)
            self.assertEqual(out[0]["name"],
                             "Missing Content-Security-Policy")
            self.assertEqual(out[0]["confirmation"], "confirmed")
            # Every audit finding reuses a canonical engine title.
            self.assertTrue(all(
                o["name"] in dd.HEADER_TITLES.values() for o in out))
        scan = _scan([_finding("Missing Content-Security-Policy",
                               severity="high",
                               confirmation="indicator")])

        def audit_runner(probe, ctx):
            return [_finding("Missing Content-Security-Policy",
                             engine="deepdive", severity="high",
                             confirmation="confirmed")]

        dd.apply_to_scan(scan, _scope_for(), settings={"depth": 1},
                         runner=audit_runner)
        self.assertEqual(len(scan["findings"]), 1)
        self.assertEqual(scan["findings"][0]["confirmation"],
                         "confirmed")
        # One high confirmed = 15 -> score 85 (counted once).
        self.assertEqual(scan["score"], 85)
        self.assertEqual(len(scan["deepdive"]["deduped_findings"]), 1)

    def test_nvd_offline_is_cve_unknown_never_invented(self):
        with mock.patch("webdon.core.http.fetch_json",
                        return_value=(None, "boom")):
            res = dd.nvd_lookup_product("WordPress", "6.5")
        self.assertEqual(res["status"], "cve_unknown")
        self.assertEqual(res["cves"], [])

    def test_real_config_probes_use_head_only_on_lab(self):
        with LabServer() as base:
            ctx = _ctx()
            ctx["url"] = base
            ctx["host"] = "127.0.0.1"
            probes = dd.plan_follow_ups(
                _finding("Environment file reachable (.env)",
                         engine="paths", evidence="/.env -> HTTP 200"),
                ctx)
            sib = next(p for p in probes
                       if p["type"] == "config_siblings")
            # Lab exposes no sibling: HEAD 404 everywhere, and the
            # GET body (with the fake secret) is never fetched.
            out = dd._run_probe(sib, ctx)
            self.assertEqual(out, [])
            ref = next(p for p in probes
                       if p["type"] == "config_robots_ref")
            self.assertEqual(dd._run_probe(ref, ctx), [])

    def test_report_chains_output(self):
        scan = _scan([_finding("Missing Content-Security-Policy")])
        dd.apply_to_scan(scan, _scope_for(),
                         settings={"depth": 2},
                         runner=header_chain_runner)
        buf = io.StringIO()
        with redirect_stdout(buf):
            report_mod.print_chains(scan)
        text = buf.getvalue()
        self.assertIn("F-001/F-002/F-003", text)
        self.assertIn("depth 2", text)
        self.assertIn("depth_limit", text)
        buf = io.StringIO()
        with redirect_stdout(buf):
            ok = report_mod.print_finding_chain(scan, "F-002")
        self.assertTrue(ok)
        self.assertIn("F-001/F-002", buf.getvalue())
        self.assertFalse(report_mod.print_finding_chain(scan, "F-999"))
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "r.json")
            report_mod.to_json_report(scan, path)
            with open(path, encoding="utf-8") as f:
                rep = json.load(f)
            self.assertEqual(rep["report_version"], "5.1")
            self.assertEqual(rep["deepdive"]["deepest"], 2)
            self.assertEqual(rep["deepdive"]["stop_reason"],
                             "depth_limit")
            self.assertTrue(rep["finding_chains"])
            self.assertEqual(
                rep["finding_chains"][0]["children"][0]["children"][0]
                ["finding_id"], "F-003")
            self.assertTrue(all(
                "depth" in f and "parent_id" in f and "chain" in f
                for f in rep["findings"]))
            html_path = os.path.join(d, "r.html")
            report_mod.to_html(scan, html_path)
            with open(html_path, encoding="utf-8") as f:
                html = f.read()
            self.assertIn("Investigation chains", html)
            self.assertIn("F-001/F-002/F-003", html)


class TestHiveDeepDiveLab(unittest.TestCase):
    def test_hive_lab_with_deepdive_and_depth_cap(self):
        with LabServer() as base, tempfile.TemporaryDirectory() as d:
            scope = Scope(base_dir=d)
            scope.authorize(base)
            scan = hive_mod.run_hive(
                base, scope=scope,
                settings={"scan_budget_s": 180}, depth=2)
            self.assertEqual(scan["deepdive"]["status"], "completed")
            self.assertEqual(scan["deepdive"]["max_depth"], 2)
            self.assertTrue(all(f.get("depth", 0) <= 2
                                for f in scan["findings"]))
            self.assertTrue(all(f.get("chain")
                                for f in scan["findings"]))
            blob = json.dumps(scan, ensure_ascii=False)
            self.assertNotIn(FAKE_COOKIE_VALUE, blob)
            with tempfile.TemporaryDirectory() as d2:
                path = os.path.join(d2, "r.json")
                report_mod.to_json_report(scan, path)
                with open(path, encoding="utf-8") as f:
                    rep = json.load(f)
                self.assertIn("deepdive", rep)
                self.assertIn("finding_chains", rep)


if __name__ == "__main__":
    unittest.main()
