#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WEBDON v4.00 EVIDENCE tests — run: python3 -m unittest discover -s tests -v

Covers: hive phase counts and scope enforcement, adapter
argument construction (Nuclei excludes dos, Naabu fallback flag,
Schemathesis read-only checks), ZAP honest not-installed,
Neo refusing without an env key, tool-manager detection with a
mocked version check, Burp-like proxy/repeater/sitemap/scanner,
adapter-output sanitizing (no secret value ever leaves), and a
full HIVE run against the local lab server.
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_webdon import FAKE_COOKIE_VALUE, FAKE_ENV_SECRET, LabServer  # noqa: E402
from webdon import __version__  # noqa: E402
from webdon.adapters import burp as burp_mod  # noqa: E402
from webdon.adapters import manager as manager_mod  # noqa: E402
from webdon.adapters import naabu as naabu_mod  # noqa: E402
from webdon.adapters import neo as neo_mod  # noqa: E402
from webdon.adapters import nuclei as nuclei_mod  # noqa: E402
from webdon.adapters import schemathesis as schema_mod  # noqa: E402
from webdon.adapters import zap as zap_mod  # noqa: E402
from webdon.adapters import sanitize  # noqa: E402
from webdon.core import engine as engine_mod  # noqa: E402
from webdon.core import hive as hive_mod  # noqa: E402
from webdon.core.scope import Scope  # noqa: E402
from webdon.engines import PROFILES  # noqa: E402


def _ctx(url="http://127.0.0.1:9", authorized=True):
    return {"url": url, "host": "127.0.0.1", "domain": "127.0.0.1",
            "authorized": authorized, "ips": ["127.0.0.1"],
            "pages": [], "scripts": []}


class TestVersion(unittest.TestCase):
    def test_version_is_2_00(self):
        self.assertEqual(__version__, "5.1")


class TestHiveStructure(unittest.TestCase):
    def test_hive_has_40_plus_phases(self):
        self.assertGreaterEqual(hive_mod.total_phases(), 55)
        self.assertEqual(len(PROFILES["hive"]), 24)
        self.assertEqual(len(hive_mod.wave_names()), 6)

    def test_hive_refuses_without_scope(self):
        with tempfile.TemporaryDirectory() as d:
            scope = Scope(base_dir=d)
            with self.assertRaises(PermissionError):
                hive_mod.run_hive("https://example.com", scope=scope)

    def test_old_profiles_unchanged(self):
        self.assertEqual(engine_mod.total_phases("quick"), 15)
        self.assertEqual(engine_mod.total_phases("deep"), 33)
        self.assertEqual(engine_mod.total_phases("forensic"), 35)


class TestNucleiAdapter(unittest.TestCase):
    def test_args_exclude_dos_and_limit_rate(self):
        args = nuclei_mod.build_args("https://example.com")
        self.assertIn("-exclude-tags", args)
        self.assertEqual(args[args.index("-exclude-tags") + 1], "dos")
        self.assertIn("low,medium,high,critical", args)
        sev_value = args[args.index("-severity") + 1]
        self.assertNotIn("dos", sev_value)
        self.assertEqual(args[args.index("-rate-limit") + 1], "50")

    def test_parse_strips_request_response_bodies(self):
        line = json.dumps({
            "template-id": "http/missing-headers",
            "info": {"name": "Missing headers", "severity": "medium"},
            "host": "https://example.com",
            "request": "GET / HTTP/1.1\r\nCookie: session=%s"
                       % FAKE_COOKIE_VALUE,
            "response": "HTTP/1.1 200 OK\r\nSet-Cookie: a=%s"
                        % FAKE_COOKIE_VALUE})
        findings, templates = nuclei_mod.parse_jsonl(line)
        self.assertEqual(templates, ["http/missing-headers"])
        blob = json.dumps(findings)
        self.assertNotIn(FAKE_COOKIE_VALUE, blob)
        self.assertNotIn("Cookie:", blob)
        self.assertEqual(findings[0]["severity"], "medium")

    def test_run_falls_back_when_not_installed(self):
        res = nuclei_mod.run(_ctx())
        self.assertEqual(res["status"], "not_installed (fallback)")
        self.assertIn("fallback", res["data"]["note"].lower())

    def test_run_refuses_without_scope(self):
        with self.assertRaises(PermissionError):
            nuclei_mod.run(_ctx(authorized=False))


class TestNaabuAdapter(unittest.TestCase):
    def test_args_use_top_ports(self):
        args = naabu_mod.build_args("1.2.3.4")
        self.assertIn("-top-ports", args)
        self.assertEqual(args[args.index("-top-ports") + 1], "100")

    def test_fallback_reports_connect_scan_honestly(self):
        # Naabu is not installed here, so the adapter must fall back
        # to the connect scan and say SYN is unavailable without root.
        res = naabu_mod.run(_ctx())
        self.assertIn(res["status"],
                      ("not_installed (fallback)", "fallback"))
        self.assertIn("connect-scan fallback", res["data"]["mode"])
        self.assertIn("SYN unavailable without root",
                      res["data"]["mode"])


class TestSchemathesisAdapter(unittest.TestCase):
    def test_args_are_read_only_checks(self):
        args = schema_mod.build_args("api.yaml")
        self.assertIn("--checks", args)
        self.assertEqual(args[args.index("--checks") + 1],
                         "not_a_server_error")
        self.assertEqual(args[args.index("--hypothesis-max-examples") + 1],
                         "20")

    def test_skipped_without_schema(self):
        res = schema_mod.run(_ctx())
        self.assertEqual(res["status"], "skipped_no_schema")

    def test_parse_counts(self):
        passed, failed = schema_mod.parse_summary(
            "8 passed, 2 failed in 1.2s")
        self.assertEqual((passed, failed), (8, 2))


class TestZapBridge(unittest.TestCase):
    def test_run_reports_not_installed_honestly(self):
        res = zap_mod.run(_ctx())
        self.assertEqual(res["status"], "not_installed")
        self.assertTrue(res["data"]["pc_steps"])
        blob = json.dumps(res)
        self.assertNotIn("completed", blob.split('"status"')[0])

    def test_export_writes_context_and_plan(self):
        with tempfile.TemporaryDirectory() as d:
            ctx_path, plan_path = zap_mod.export_plan(
                "https://example.com", out_dir=d)
            with open(ctx_path, encoding="utf-8") as f:
                ctx = json.load(f)
            self.assertEqual(ctx["target"], "https://example.com")
            with open(plan_path, encoding="utf-8") as f:
                self.assertIn("ZAP", f.read())


class TestNeoHook(unittest.TestCase):
    def test_push_refuses_without_env_key(self):
        os.environ.pop("NEO_API_KEY", None)
        os.environ.pop("NEO_API_URL", None)
        res = neo_mod.push({"target": "https://example.com",
                            "score": 50, "grade": "F", "findings": []})
        self.assertEqual(res["status"], "refused")
        self.assertIn("NEO_API_KEY", res["data"]["error"])

    def test_export_writes_sanitized_json(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "neo.json")
            neo_mod.export_findings(
                {"target": "https://example.com", "score": 50,
                 "grade": "F", "coverage": {"percent": 100},
                 "findings": [{"name": "x", "severity": "low"}]}, path)
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(data["target"], "https://example.com")


class TestToolManager(unittest.TestCase):
    def test_unknown_tool(self):
        self.assertEqual(manager_mod.check("nosuchtool")["status"],
                         "unknown_tool")
        self.assertIsNone(manager_mod.install_cmd("nosuchtool"))

    def test_install_cmds_are_go_or_pip(self):
        self.assertTrue(manager_mod.install_cmd("nuclei").startswith(
            "go install github.com/projectdiscovery/nuclei"))
        self.assertTrue(manager_mod.install_cmd("naabu").startswith(
            "go install github.com/projectdiscovery/naabu"))
        self.assertEqual(manager_mod.install_cmd("schemathesis"),
                         "pip install schemathesis")

    def test_detection_with_mocked_version(self):
        orig = manager_mod.version_of
        manager_mod.version_of = lambda b, a=(), timeout=20: (
            "nuclei version 3.4.0" if b == "nuclei" else None)
        try:
            row = manager_mod.check("nuclei")
            self.assertEqual(row["status"], "installed")
            self.assertIn("3.4.0", row["version"])
            self.assertEqual(manager_mod.check("httpx")["status"],
                             "not_installed")
        finally:
            manager_mod.version_of = orig

    def test_install_verified_by_version_check(self):
        orig_check = manager_mod.check
        calls = []

        def fake_check(name):
            calls.append(name)
            return {"name": name, "status": "installed",
                    "version": "9.9.9", "note": ""}

        manager_mod.check = fake_check
        try:
            res = manager_mod.install(
                "httpx", runner=lambda argv, timeout=600: (0, "", ""))
            self.assertTrue(res["installed"])
            self.assertEqual(res["version"], "9.9.9")
        finally:
            manager_mod.check = orig_check

    def test_install_reports_failure_honestly(self):
        orig_check = manager_mod.check
        manager_mod.check = lambda name: {"name": name,
                                          "status": "not_installed",
                                          "version": None, "note": ""}
        try:
            res = manager_mod.install(
                "httpx",
                runner=lambda argv, timeout=600: (1, "", "go: boom"))
            self.assertFalse(res["installed"])
            self.assertIn("go install", res["manual_command"])
        finally:
            manager_mod.check = orig_check

    def test_builtin_and_bridge_not_installable(self):
        self.assertFalse(manager_mod.install("burp")["installed"])
        self.assertFalse(manager_mod.install("zap")["installed"])


class TestSanitize(unittest.TestCase):
    def test_sensitive_keys_dropped_at_any_depth(self):
        dirty = {"ok": 1, "password": "hunter2",
                 "nested": {"cookie": "abc=%s" % FAKE_COOKIE_VALUE,
                            "request": "GET /", "keep": "yes"}}
        clean = sanitize(dirty)
        blob = json.dumps(clean)
        self.assertNotIn("hunter2", blob)
        self.assertNotIn(FAKE_COOKIE_VALUE, blob)
        self.assertNotIn("GET /", blob)
        self.assertEqual(clean["nested"]["keep"], "yes")


class TestBurpLike(unittest.TestCase):
    def test_proxy_log_stores_names_only(self):
        log = burp_mod.ProxyLog()
        e = log.record("GET", "https://example.com/", 200,
                       ["Server", "Set-Cookie"])
        self.assertEqual(e["id"], 1)
        self.assertEqual(e["headers"], ["Server", "Set-Cookie"])
        self.assertNotIn(FAKE_COOKIE_VALUE, json.dumps(log.list()))

    def test_repeater_refuses_without_scope(self):
        log = burp_mod.ProxyLog()
        log.record("GET", "https://example.com/", 200)
        with tempfile.TemporaryDirectory() as d:
            scope = Scope(base_dir=d)
            res = burp_mod.repeater(log, 1, scope)
            self.assertIn("error", res)
            self.assertIn("scope", res["error"])

    def test_sitemap_and_scanner(self):
        tree = burp_mod.sitemap([{"url": "https://example.com/a/b"},
                                 {"url": "https://example.com/a/c"},
                                 {"url": "https://example.com/"}])
        self.assertIn("/a", tree)
        self.assertIn("/a/b", tree["/a"])
        summ = burp_mod.scanner_summary(
            {"score": 50, "grade": "F",
             "findings": [{"engine": "headers", "severity": "high"},
                          {"engine": "nuclei", "severity": "medium"}]})
        self.assertEqual(summ["total_findings"], 2)
        self.assertEqual(summ["findings_by_area"]["headers"], 1)
        self.assertEqual(summ["findings_by_area"]["nuclei"], 1)


class TestHiveLab(unittest.TestCase):
    def test_full_hive_on_lab_server(self):
        with LabServer() as base, tempfile.TemporaryDirectory() as d:
            scope = Scope(base_dir=d)
            scope.authorize(base)
            scan = hive_mod.run_hive(
                base, scope=scope,
                settings={"scan_budget_s": 180})
            self.assertEqual(scan["tool"], "WEBDON v5.1")
            self.assertEqual(scan["kind"], "webdon-hive")
            self.assertEqual(scan["profile"], "hive")
            self.assertIsNotNone(scan["score"])
            self.assertGreaterEqual(
                scan["coverage"]["phases_done"], 55)
            self.assertEqual(scan["hive"]["phases"], 58)
            self.assertEqual(len(scan["hive"]["waves"]), 6)
            adapters = scan["hive"]["adapters"]
            self.assertEqual(adapters["nuclei"]["status"],
                             "not_installed (fallback)")
            self.assertIn("connect-scan fallback",
                          adapters["naabu"]["mode"])
            self.assertEqual(
                (scan["results"].get("schemathesis") or {}).get(
                    "status"), "skipped_no_schema")
            blob = json.dumps(scan, ensure_ascii=False)
            self.assertNotIn(FAKE_COOKIE_VALUE, blob)
            self.assertNotIn(FAKE_ENV_SECRET, blob)
            self.assertNotIn("DB_PASSWORD", blob)
            names = [f["name"] for f in scan["findings"]]
            self.assertTrue(any(".env" in n for n in names))


if __name__ == "__main__":
    unittest.main()
