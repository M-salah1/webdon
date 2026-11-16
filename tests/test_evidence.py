#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WEBDON v4.00 EVIDENCE tests — run: python3 -m unittest discover -s tests -v

Covers: the CVSS v3.1 calculator against independently verified
vectors, CWE mapping completeness for every finding type,
evidence-required rejection, the validation stage
(promotion / demotion / corroboration), persistent false-positive
marking with score recompute, precise remediation for every
finding type, interactive HTML, professional PDF, the JSON report
schema, scan comparison, and the per-target timeline.
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_webdon import FAKE_COOKIE_VALUE, FAKE_ENV_SECRET, LabServer  # noqa: E402
from webdon.core import cwe_map as cwe_map_mod  # noqa: E402
from webdon.core import cvss as cvss_mod  # noqa: E402
from webdon.core import engine as engine_mod  # noqa: E402
from webdon.core import enrich as enrich_mod  # noqa: E402
from webdon.core import evidence as evidence_mod  # noqa: E402
from webdon.core import pdf as pdf_mod  # noqa: E402
from webdon.core import remediation as remediation_mod  # noqa: E402
from webdon.core import report as report_mod  # noqa: E402
from webdon.core import storage as storage_mod  # noqa: E402
from webdon.core import validation as validation_mod  # noqa: E402
from webdon.core.scope import Scope  # noqa: E402


def _finding(name, severity="medium", evidence="observed: test",
             engine="headers", confirmation="indicator"):
    return {"severity": severity, "name": name, "evidence": evidence,
            "fix": "fix it", "engine": engine,
            "confirmation": confirmation,
            "validation": {"status": "observed", "confidence": 60,
                           "reason": "single observation"}}


def _ctx(url="https://example.com/"):
    return {"url": url, "host": "example.com", "domain": "example.com",
            "authorized": True, "timeout": 8, "profile": "deep",
            "html": "", "headers": {}, "cookie_headers": [],
            "status": 200, "ips": [], "pages": [], "scripts": [],
            "subdomains": [], "tls": {}, "whois": {}, "ports_data": {}}


class TestCVSSCalculator(unittest.TestCase):
    def test_critical_scope_changed_10(self):
        self.assertEqual(
            cvss_mod.base_score(
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 10.0)

    def test_critical_scope_unchanged_9_8(self):
        self.assertEqual(
            cvss_mod.base_score(
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)

    def test_medium_5_3(self):
        self.assertEqual(
            cvss_mod.base_score(
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"), 5.3)

    def test_poodle_3_4(self):
        # CVE-2014-3566 (POODLE) — NVD published score 3.4.
        self.assertEqual(
            cvss_mod.base_score(
                "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N"), 3.4)

    def test_all_none_is_zero(self):
        self.assertEqual(
            cvss_mod.base_score(
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"), 0.0)

    def test_bare_vector_without_prefix(self):
        self.assertEqual(
            cvss_mod.base_score("AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
            5.3)

    def test_malformed_vectors_raise(self):
        # base_score raises ValueError on a malformed vector;
        # score_vector (the safe entry point) returns None instead.
        for bad in ("", "garbage", "CVSS:3.1/AV:N/AC:L",
                    "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N",
                    None, 42):
            with self.assertRaises(ValueError, msg=repr(bad)):
                cvss_mod.base_score(bad)
            self.assertIsNone(cvss_mod.score_vector(bad), bad)

    def test_severity_bands(self):
        cases = [(0.0, "None"), (0.1, "Low"), (3.9, "Low"),
                 (4.0, "Medium"), (6.9, "Medium"), (7.0, "High"),
                 (8.9, "High"), (9.0, "Critical"), (10.0, "Critical")]
        for score, band in cases:
            self.assertEqual(cvss_mod.severity_for(score), band, score)
        self.assertEqual(cvss_mod.severity_for(None), "None")

    def test_score_vector_returns_score_and_band(self):
        result = cvss_mod.score_vector(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertEqual(result["score"], 9.8)
        self.assertEqual(result["severity"], "Critical")
        self.assertEqual(cvss_mod.score_vector("garbage"), None)

    def test_nvd_lookup_never_raises_offline(self):
        # No key, short timeout; offline or unknown CVE -> None, no raise.
        self.assertIsNone(cvss_mod.nvd_lookup("CVE-0000-00000"))


class TestCWEMap(unittest.TestCase):
    def test_every_rule_has_valid_cwe_and_vector(self):
        self.assertTrue(cwe_map_mod.RULES)
        for rule in cwe_map_mod.RULES:
            self.assertTrue(rule["cwe_id"], rule)
            self.assertTrue(rule["cwe_name"], rule)
            self.assertTrue(rule["vector"], rule)
            score = cvss_mod.base_score(rule["vector"])
            self.assertIsNotNone(score, rule)
            self.assertTrue(0.0 <= score <= 10.0, rule)
            self.assertIn(rule["key"], remediation_mod.REMEDIATIONS,
                          rule["key"])

    def test_representative_mappings(self):
        cases = [
            ("Missing Strict-Transport-Security (HSTS)", "CWE-319"),
            ("Missing X-Content-Type-Options", "CWE-693"),
            ("Missing Content-Security-Policy", "CWE-693"),
            ("Cookie without Secure flag", "CWE-614"),
            ("Exposed .env configuration file", "CWE-538"),
            ("Exposed .git directory", "CWE-538"),
            ("CORS: wildcard origin with credentials", "CWE-942"),
            ("Server version disclosed", "CWE-200"),
            ("Plain HTTP (no TLS)", "CWE-319"),
            ("Missing X-Frame-Options (clickjacking protection)",
             "CWE-1021"),
            ("Missing Referrer-Policy header", "CWE-359"),
        ]
        for name, cwe_id in cases:
            result = cwe_map_mod.lookup(name)
            self.assertIsNotNone(result, name)
            self.assertEqual(result["cwe_id"], cwe_id, name)
            self.assertTrue(result["cwe_url"].endswith(
                "definitions/%s.html" % cwe_id.split("-")[1]), name)
            self.assertIsNotNone(result["cvss_score"], name)

    def test_hsts_vector_scores_medium(self):
        result = cwe_map_mod.lookup(
            "Missing Strict-Transport-Security header")
        self.assertEqual(result["cvss_severity"], "Medium")
        self.assertAlmostEqual(result["cvss_score"], 4.8, places=1)

    def test_unmapped_name_returns_none(self):
        self.assertIsNone(
            cwe_map_mod.lookup("Totally unknown finding xyzqq"))

    def test_info_severity_has_no_cvss(self):
        result = cwe_map_mod.lookup("robots.txt present", "info")
        self.assertIsNone(result)

    def test_enrich_adds_cwe_cvss_and_remediation(self):
        f = _finding("Missing Strict-Transport-Security (HSTS)",
                     severity="medium")
        enrich_mod.enrich_finding(f, _ctx())
        self.assertEqual(f["cwe"]["id"], "CWE-319")
        self.assertAlmostEqual(f["cvss"]["score"], 4.8, places=1)
        self.assertEqual(f["cvss"]["severity"], "Medium")
        self.assertTrue(f["cvss"]["vector"].startswith("CVSS:3.1/"))
        self.assertIn("remediation", f)
        self.assertIn("Strict-Transport-Security",
                      f["remediation"]["summary"])

    def test_enrich_never_invents_cvss_for_unmapped(self):
        f = _finding("Totally unknown finding xyzqq")
        cwe_map_mod.enrich(f)
        self.assertIsNone(f["cvss"])
        self.assertIsNone(f["cwe"])

    def test_nuclei_classification_wins_over_table(self):
        f = _finding("Nuclei: CVE-2014-3566", severity="medium")
        f["cve_id"] = "CVE-2014-3566"
        f["cwe_id"] = "CWE-338"
        f["cvss_vector"] = ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/"
                            "C:L/I:N/A:N")
        cwe_map_mod.enrich(f)
        self.assertEqual(f["cwe"]["id"], "CWE-338")
        self.assertEqual(f["cvss"]["score"], 3.4)
        self.assertEqual(f["cvss"]["source"], "template")


class TestEvidenceRequired(unittest.TestCase):
    def test_finding_without_evidence_is_rejected(self):
        f = {"severity": "medium", "name": "No evidence here",
             "fix": "fix it", "engine": "headers"}
        with self.assertRaises(ValueError):
            evidence_mod.require_evidence(f)

    def test_finding_with_evidence_obj_passes(self):
        f = _finding("Missing Strict-Transport-Security (HSTS)")
        f["evidence_obj"] = evidence_mod.build_evidence_obj(f, _ctx())
        evidence_mod.require_evidence(f)
        self.assertEqual(f["evidence_obj"]["engine"], "headers")
        self.assertIn("https://example.com", f["evidence_obj"]["location"])

    def test_empty_evidence_string_is_rejected(self):
        f = _finding("X", evidence="")
        with self.assertRaises(ValueError):
            evidence_mod.require_evidence(f)

    def test_migrate_old_finding_adds_evidence_obj(self):
        old = {"severity": "medium", "name": "Old finding",
               "evidence": "header missing on /", "fix": "fix it",
               "engine": "headers"}
        evidence_mod.migrate_finding(old, "https://example.com/")
        self.assertIn("evidence_obj", old)
        self.assertEqual(old["evidence_obj"]["observed"],
                         "header missing on /")

    def test_sanitizer_strips_secrets_from_evidence(self):
        f = _finding("Cookie without Secure flag")
        f["evidence"] = ("Set-Cookie: sessionid=%s; Path=/"
                         % FAKE_COOKIE_VALUE)
        obj = evidence_mod.build_evidence_obj(f, _ctx())
        self.assertNotIn(FAKE_COOKIE_VALUE, obj["observed"])
        self.assertNotIn(FAKE_COOKIE_VALUE, obj["observation"])
        blob = json.dumps(obj)
        self.assertNotIn(FAKE_COOKIE_VALUE, blob)
        self.assertIn("[REDACTED]", blob)

    def test_env_secret_never_in_evidence(self):
        f = _finding("Exposed .env configuration file")
        f["evidence"] = "GET /.env body: DB_PASSWORD=%s" % FAKE_ENV_SECRET
        obj = evidence_mod.build_evidence_obj(f, _ctx())
        blob = json.dumps(obj)
        self.assertNotIn(FAKE_ENV_SECRET, blob)
        self.assertIn("[REDACTED]", blob)


class TestValidationStage(unittest.TestCase):
    def test_known_fp_rule_200_alone(self):
        # apply_fp_rules returns a reason string (or None); the
        # caller (validation.run) turns it into the FP verdict.
        ev = _finding("Suspicious response", evidence="HTTP 200")
        ev["evidence_obj"] = {"observed": "HTTP 200"}
        reason = validation_mod.apply_fp_rules(ev, _ctx())
        self.assertIsNotNone(reason)
        self.assertIn("200", reason)

    def test_known_fp_rule_403_is_not_a_finding(self):
        ev = _finding("Possible vulnerability (403)",
                      evidence="HTTP 403 on /admin")
        reason = validation_mod.apply_fp_rules(ev, _ctx())
        self.assertIsNotNone(reason)
        self.assertIn("403", reason)

    def test_known_fp_rule_cloudflare_server_header(self):
        ev = _finding("Server version disclosed",
                      evidence="Server: cloudflare")
        ev["evidence_obj"] = {"observed": "Server: cloudflare"}
        reason = validation_mod.apply_fp_rules(ev, _ctx())
        self.assertIsNotNone(reason)
        self.assertIn("cloudflare", reason)

    def test_no_fp_rule_for_real_finding(self):
        ev = _finding("Missing Strict-Transport-Security (HSTS)",
                      evidence="Strict-Transport-Security: absent")
        ev["evidence_obj"] = {"observed": "Strict-Transport-Security: "
                                           "absent"}
        self.assertIsNone(validation_mod.apply_fp_rules(ev, _ctx()))

    def test_corrobation_promotes_two_engine_finding(self):
        ev1 = _finding("Plain HTTP (no TLS)", engine="headers")
        ev2 = _finding("Plain HTTP (no TLS)", engine="tls")
        validation_mod.corroborate([ev1, ev2])
        self.assertEqual(ev1["validation"]["status"], "verified")
        self.assertIn("tls", ev1["corroborated_by"])
        self.assertGreaterEqual(ev1["validation"]["confidence"], 85)

    def test_single_signal_stays_observed(self):
        ev = _finding("Plain HTTP (no TLS)", engine="headers")
        validation_mod.corroborate([ev])
        self.assertEqual(ev["validation"]["status"], "observed")

    def test_validation_run_reprobes_and_keeps_evidence(self):
        ev = _finding("Missing Strict-Transport-Security (HSTS)",
                      evidence="Strict-Transport-Security: absent")
        out = validation_mod.run([ev], _ctx())
        self.assertEqual(len(out), 1)
        self.assertIn("validation", out[0])
        self.assertIn(out[0]["validation"]["status"],
                      ("verified", "observed", "false_positive"))

    def test_validation_never_overrides_false_positive(self):
        ev1 = _finding("Server version disclosed",
                       evidence="Server: cloudflare", engine="headers")
        ev2 = _finding("Server version disclosed",
                       evidence="Server: cloudflare", engine="tech")
        ev1["evidence_obj"] = {"observed": "Server: cloudflare"}
        ev2["evidence_obj"] = {"observed": "Server: cloudflare"}
        out = validation_mod.run([ev1, ev2], _ctx())
        self.assertEqual(out[0]["validation"]["status"], "false_positive")
        self.assertEqual(out[1]["validation"]["status"], "false_positive")


class TestRemediation(unittest.TestCase):
    def test_every_rule_has_precise_remediation(self):
        for rule in cwe_map_mod.RULES:
            rem = remediation_mod.REMEDIATIONS[rule["key"]]
            self.assertTrue(rem["summary"], rule["key"])
            self.assertTrue(rem["verify"], rule["key"])
            # Not generic advice: a fix must name a header, a
            # config snippet, a file, or a command.
            self.assertTrue(
                rem.get("header") or rem.get("nginx")
                or rem.get("apache") or rem.get("file"),
                rule["key"])

    def test_remediation_references_observed_evidence(self):
        ctx = _ctx("https://example.com/login")
        f = _finding("Missing Strict-Transport-Security (HSTS)")
        f["evidence_obj"] = evidence_mod.build_evidence_obj(f, ctx)
        rem = remediation_mod.build(f, ctx)
        self.assertIn("Strict-Transport-Security",
                      rem["header"])
        self.assertIn("max-age=31536000", rem["header"])
        self.assertIn("example.com", rem["verify"])
        self.assertIn("nginx", rem)
        self.assertIn("apache", rem)
        blob = json.dumps(rem)
        self.assertIn("example.com", blob)

    def test_hsts_fix_has_both_server_snippets(self):
        f = _finding("Missing Strict-Transport-Security (HSTS)")
        rem = remediation_mod.build(f, _ctx())
        self.assertIn("add_header", rem["nginx"])
        self.assertIn("Header always set", rem["apache"])

    def test_cookie_fix_names_flag_and_scope(self):
        f = _finding("Cookie without Secure flag")
        rem = remediation_mod.build(f, _ctx())
        self.assertIn("Secure", rem["summary"])
        self.assertIn("set-cookie", rem["verify"].lower())

    def test_unmapped_finding_keeps_own_fix_with_verify(self):
        f = _finding("Totally unknown finding xyzqq")
        f["fix"] = "Check it manually on the server."
        rem = remediation_mod.build(f, _ctx())
        self.assertIn("Check it manually", rem["summary"])
        self.assertTrue(rem["verify"])


class TestLabScanEvidence(unittest.TestCase):
    def test_lab_scan_findings_carry_evidence_cvss_cwe(self):
        with LabServer() as base, tempfile.TemporaryDirectory() as d:
            scope = Scope(base_dir=d)
            scope.authorize(base)
            scan = engine_mod.run_scan(
                base, profile="deep", scope=scope,
                settings={"scan_budget_s": 120})
            self.assertTrue(scan["findings"])
            for f in scan["findings"]:
                self.assertIn("finding_id", f)
                self.assertIn("evidence_obj", f)
                ev = f["evidence_obj"]
                self.assertTrue(ev["observed"])
                self.assertTrue(ev["location"])
                self.assertTrue(ev["timestamp"])
                self.assertTrue(ev["engine"])
                self.assertTrue(ev["method"])
                self.assertIn("cvss", f)
                self.assertIn("cwe", f)
                self.assertIn("remediation", f)
                if f["severity"] == "info":
                    # Info findings have nothing to fix.
                    self.assertIsNone(f["remediation"])
                else:
                    self.assertTrue(f["remediation"]["summary"])
                    self.assertTrue(f["remediation"]["verify"])
            blob = json.dumps(scan, ensure_ascii=False)
            self.assertNotIn(FAKE_COOKIE_VALUE, blob)
            self.assertNotIn(FAKE_ENV_SECRET, blob)
            self.assertNotIn("DB_PASSWORD", blob)
            # .env finding: CWE-538, Critical CVSS.
            env_f = next(f for f in scan["findings"]
                         if ".env" in f["name"])
            self.assertEqual(env_f["cwe"]["id"], "CWE-538")
            self.assertEqual(env_f["cvss"]["severity"], "Critical")
            # Missing HSTS: CWE-319.
            hsts = next(f for f in scan["findings"]
                        if "Strict-Transport-Security" in f["name"])
            self.assertEqual(hsts["cwe"]["id"], "CWE-319")
            # Validation counts present.
            self.assertIn("verified", scan["validation"])
            self.assertIn("false_positive", scan["validation"])

    def test_fp_marking_recomputes_score(self):
        with LabServer() as base, tempfile.TemporaryDirectory() as d:
            scope = Scope(base_dir=d)
            scope.authorize(base)
            scan = engine_mod.run_scan(
                base, profile="quick", scope=scope,
                settings={"scan_budget_s": 60})
            db = os.path.join(d, "webdon-scans.db")
            scan_id = storage_mod.save_scan(db, scan)
            before = storage_mod.get_scan(db, scan_id)
            self.assertTrue(before["findings"])
            score_before = before["score"]
            fid = before["findings"][0]["finding_id"]
            ok, _msg = storage_mod.mark_fp(
                db, scan_id, fid, "lab test: known false positive")
            self.assertTrue(ok)
            after = storage_mod.get_scan(db, scan_id)
            self.assertEqual(len(after["findings"]),
                             len(before["findings"]) - 1)
            self.assertEqual(len(after["false_positives"]), 1)
            self.assertEqual(after["false_positives"][0]["fp_reason"],
                             "lab test: known false positive")
            # Score recomputed: excluding a finding can only raise
            # the security score (fewer real findings = more secure),
            # never lower it.
            if score_before is not None:
                self.assertGreaterEqual(after["score"], score_before)
            # Unmark restores it.
            ok, _msg = storage_mod.unmark_fp(db, scan_id, fid)
            self.assertTrue(ok)
            restored = storage_mod.get_scan(db, scan_id)
            self.assertEqual(len(restored["findings"]),
                             len(before["findings"]))
            self.assertEqual(restored["score"], score_before)

    def test_fp_marking_unknown_finding_fails(self):
        with LabServer() as base, tempfile.TemporaryDirectory() as d:
            scope = Scope(base_dir=d)
            scope.authorize(base)
            scan = engine_mod.run_scan(
                base, profile="quick", scope=scope,
                settings={"scan_budget_s": 60})
            db = os.path.join(d, "webdon-scans.db")
            scan_id = storage_mod.save_scan(db, scan)
            ok, msg = storage_mod.mark_fp(db, scan_id, "F-999",
                                          "nope")
            self.assertFalse(ok)
            self.assertIn("not found", msg)


class TestReports(unittest.TestCase):
    def _scan(self):
        with LabServer() as base, tempfile.TemporaryDirectory() as d:
            scope = Scope(base_dir=d)
            scope.authorize(base)
            scan = engine_mod.run_scan(
                base, profile="quick", scope=scope,
                settings={"scan_budget_s": 60})
            return scan, d

    def test_html_is_interactive_with_evidence(self):
        with LabServer() as base, tempfile.TemporaryDirectory() as d:
            scope = Scope(base_dir=d)
            scope.authorize(base)
            scan = engine_mod.run_scan(
                base, profile="quick", scope=scope,
                settings={"scan_budget_s": 60})
            path = os.path.join(d, "r.html")
            report_mod.to_html(scan, path)
            with open(path, encoding="utf-8") as f:
                html = f.read()
            self.assertIn("<svg", html)
            self.assertIn("sortTable", html)
            self.assertIn("filterRows", html)
            self.assertIn("evidence", html)
            self.assertIn("CVSS", html)
            self.assertIn("CWE", html)
            self.assertIn("remediation", html)
            self.assertIn("Executive summary", html)
            self.assertIn("Scope and methodology", html)
            self.assertIn("What cannot be known", html)
            self.assertNotIn(FAKE_COOKIE_VALUE, html)

    def test_pdf_starts_with_magic_and_has_title(self):
        with LabServer() as base, tempfile.TemporaryDirectory() as d:
            scope = Scope(base_dir=d)
            scope.authorize(base)
            scan = engine_mod.run_scan(
                base, profile="quick", scope=scope,
                settings={"scan_budget_s": 60})
            path = os.path.join(d, "r.pdf")
            report_mod.to_pdf(scan, path)
            with open(path, "rb") as f:
                data = f.read()
            self.assertTrue(data.startswith(b"%PDF"))
            self.assertGreater(len(data), 1000)
            self.assertIn(b"WEBDON", data)
            self.assertIn(b"Executive Summary", data)

    def test_pdf_writer_is_stdlib_only(self):
        data = pdf_mod.report_pdf(
            {"target": "https://example.com", "profile": "quick",
             "score": 80, "grade": "B", "confidence": 90,
             "coverage": {"percent": 100}, "metrics": {},
             "findings": [], "false_positives": [],
             "recommendations": [], "limits": {},
             "severity_distribution": {}, "validation": {},
             "duration_s": 1},
            os.path.join(tempfile.gettempdir(), "webdon-test.pdf"))
        self.assertTrue(os.path.exists(data))
        with open(data, "rb") as f:
            self.assertTrue(f.read().startswith(b"%PDF"))

    def test_json_report_schema(self):
        with LabServer() as base, tempfile.TemporaryDirectory() as d:
            scope = Scope(base_dir=d)
            scope.authorize(base)
            scan = engine_mod.run_scan(
                base, profile="quick", scope=scope,
                settings={"scan_budget_s": 60})
            path = os.path.join(d, "r.json")
            report_mod.to_json_report(scan, path)
            with open(path, encoding="utf-8") as f:
                rep = json.load(f)
            self.assertEqual(rep["report_version"], "5.1")
            self.assertIn("findings", rep)
            self.assertIn("scores", rep)
            self.assertIn("coverage", rep)
            self.assertIn("validation", rep)
            self.assertIn("false_positives_suppressed", rep)
            self.assertIn("timeline_refs", rep)
            f0 = rep["findings"][0]
            for key in ("finding_id", "evidence_obj", "cvss", "cwe",
                        "remediation", "validation"):
                self.assertIn(key, f0, key)
            self.assertNotIn(FAKE_COOKIE_VALUE,
                             json.dumps(rep, ensure_ascii=False))

    def test_compare_new_fixed_persisting(self):
        with LabServer() as base, tempfile.TemporaryDirectory() as d:
            scope = Scope(base_dir=d)
            scope.authorize(base)
            a = engine_mod.run_scan(
                base, profile="quick", scope=scope,
                settings={"scan_budget_s": 60})
            b = engine_mod.run_scan(
                base, profile="quick", scope=scope,
                settings={"scan_budget_s": 60})
            db = os.path.join(d, "webdon-scans.db")
            ida = storage_mod.save_scan(db, a)
            idb = storage_mod.save_scan(db, b)
            sa = storage_mod.get_scan(db, ida)
            sb = storage_mod.get_scan(db, idb)
            diff = storage_mod.compare_scans(sa, sb)
            self.assertIn("new", diff)
            self.assertIn("fixed", diff)
            self.assertIn("persisting", diff)
            self.assertIn("changed", diff)
            self.assertIn("fp_suppressed", diff)
            self.assertIn("score_delta", diff)
            # Same lab target twice: everything persists, nothing new.
            self.assertEqual(diff["new"], [])
            self.assertEqual(diff["fixed"], [])
            self.assertTrue(diff["persisting"])
            # Compare a scan with itself: score delta 0.
            self.assertEqual(diff["score_delta"], 0)

    def test_compare_detects_fixed_finding(self):
        with LabServer() as base, tempfile.TemporaryDirectory() as d:
            scope = Scope(base_dir=d)
            scope.authorize(base)
            a = engine_mod.run_scan(
                base, profile="quick", scope=scope,
                settings={"scan_budget_s": 60})
            db = os.path.join(d, "webdon-scans.db")
            ida = storage_mod.save_scan(db, a)
            # Second scan with the first finding removed = fixed.
            b = json.loads(json.dumps(a))
            removed = b["findings"].pop(0)
            idb = storage_mod.save_scan(db, b)
            sa = storage_mod.get_scan(db, ida)
            sb = storage_mod.get_scan(db, idb)
            diff = storage_mod.compare_scans(sa, sb)
            fixed_names = [f["name"] for f in diff["fixed"]]
            self.assertIn(removed["name"], fixed_names)

    def test_timeline_ordering_and_first_last_seen(self):
        with LabServer() as base, tempfile.TemporaryDirectory() as d:
            scope = Scope(base_dir=d)
            scope.authorize(base)
            db = os.path.join(d, "webdon-scans.db")
            a = engine_mod.run_scan(
                base, profile="quick", scope=scope,
                settings={"scan_budget_s": 60})
            ida = storage_mod.save_scan(db, a)
            b = engine_mod.run_scan(
                base, profile="quick", scope=scope,
                settings={"scan_budget_s": 60})
            idb = storage_mod.save_scan(db, b)
            tl = storage_mod.timeline(db, base)
            self.assertEqual(tl["target"], base)
            ids = [s["id"] for s in tl["scans"]]
            self.assertEqual(ids, sorted(ids))
            self.assertIn(ida, ids)
            self.assertIn(idb, ids)
            self.assertTrue(tl["findings"])
            for f in tl["findings"]:
                self.assertTrue(f["first_seen"])
                self.assertTrue(f["last_seen"])
                self.assertLessEqual(f["first_seen"], f["last_seen"])
            # First scan opens everything, second opens nothing.
            self.assertTrue(tl["scans"][0]["opened"])
            self.assertEqual(tl["scans"][1]["opened"], [])
            self.assertEqual(tl["scans"][1]["closed"], [])

    def test_backfill_history_migrates_old_rows(self):
        with LabServer() as base, tempfile.TemporaryDirectory() as d:
            scope = Scope(base_dir=d)
            scope.authorize(base)
            db = os.path.join(d, "webdon-scans.db")
            scan = engine_mod.run_scan(
                base, profile="quick", scope=scope,
                settings={"scan_budget_s": 60})
            scan_id = storage_mod.save_scan(db, scan)
            # Wipe history and backfill: first_seen = scan date.
            import sqlite3
            conn = sqlite3.connect(db)
            conn.execute("DELETE FROM finding_history")
            conn.commit()
            conn.close()
            storage_mod.backfill_history(db, base)
            hist = storage_mod.get_finding_history(db, base)
            self.assertTrue(hist)
            for row in hist:
                self.assertEqual(row["first_seen"],
                                 scan["finished_at"])
                self.assertEqual(row["last_scan_id"], scan_id)

    def test_enrich_assigns_stable_ids(self):
        findings = [_finding("Missing Strict-Transport-Security header"),
                    _finding("Cookie sessionid without Secure flag")]
        out = enrich_mod.enrich_all(findings, _ctx())
        self.assertEqual(out[0]["finding_id"], "F-001")
        self.assertEqual(out[1]["finding_id"], "F-002")
        self.assertTrue(out[0]["finding_key"])
        self.assertNotEqual(out[0]["finding_key"],
                            out[1]["finding_key"])
        # Ids continue across lists: no duplicates in one scan
        # (findings + false positives + chains share the sequence,
        # so mark-fp / unmark can never hit the wrong finding).
        more = enrich_mod.enrich_all(
            [_finding("Server version disclosed")], _ctx(), start=3)
        self.assertEqual(more[0]["finding_id"], "F-003")
        ids = [f["finding_id"] for f in out + more]
        self.assertEqual(len(ids), len(set(ids)))


if __name__ == "__main__":
    unittest.main()
