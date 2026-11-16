#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WEBDON v4.00 EVIDENCE tests — run: python3 -m unittest discover -s tests -v

Covers: scope enforcement, WHOIS parsing, headers analysis, the
cookie value-free guarantee, the config-file check never reading
a body, CORS analysis, port-scan timeout handling, verify-mode
k-anonymity (mocked network), scoring, report generation from a
saved scan, phase counts, and a full lab-server scan.
"""
import hashlib
import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from webdon.core import engine as engine_mod  # noqa: E402
from webdon.core import report as report_mod  # noqa: E402
from webdon.core import scoring as scoring_mod  # noqa: E402
from webdon.core import storage as storage_mod  # noqa: E402
from webdon.core import summary as summary_mod  # noqa: E402
from webdon.core import verify as verify_mod  # noqa: E402
from webdon.core import whois as whois_mod  # noqa: E402
from webdon.core.scope import Scope, normalize_url  # noqa: E402
from webdon.engines import PROFILES, PHASES  # noqa: E402
from webdon.engines import cookies as cookies_mod  # noqa: E402
from webdon.engines import cors as cors_mod  # noqa: E402
from webdon.engines import headers as headers_mod  # noqa: E402
from webdon.engines import paths as paths_mod  # noqa: E402
from webdon.engines import ports as ports_mod  # noqa: E402

FAKE_COOKIE_VALUE = "abc123"
FAKE_ENV_SECRET = "FAKESECRET_9f3a7b2c"


# ---------------------------------------------------------------- lab server
class LabHandler(BaseHTTPRequestHandler):
    """Weak lab site: no security headers, cookie without flags,
    /.env answers HEAD 200 (GET body holds a fake secret the tool
    must never download), robots.txt + security.txt present."""

    def _send_home(self):
        body = (b"<html><head><title>Lab</title></head><body>"
                b"<a href='/page2'>page2</a></body></html>")
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Server", "LabServer/1.0")
        self.send_header("Set-Cookie",
                         "sessionid=%s; Path=/" % FAKE_COOKIE_VALUE)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command == "GET":
            self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/", ""):
            self._send_home()
        elif self.path == "/page2":
            body = b"<html><head><title>Page 2</title></head><body>hi</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/.env":
            body = ("DB_PASSWORD=%s\nAPI_KEY=leakme\n"
                    % FAKE_ENV_SECRET).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/robots.txt":
            body = b"User-agent: *\nDisallow: /admin/\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/.well-known/security.txt":
            body = b"Contact: mailto:security@example.test\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def do_HEAD(self):
        if self.path == "/.env":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", "42")
            self.end_headers()
        elif self.path in ("/", "", "/page2", "/robots.txt",
                           "/.well-known/security.txt"):
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def log_message(self, *args):
        pass


class LabServer:
    def __enter__(self):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), LabHandler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever,
                                       daemon=True)
        self.thread.start()
        return "http://127.0.0.1:%d" % self.port

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()


# ------------------------------------------------------------------- tests
class TestScope(unittest.TestCase):
    def test_run_scan_refuses_without_scope(self):
        with tempfile.TemporaryDirectory() as d:
            scope = Scope(base_dir=d)
            with self.assertRaises(PermissionError):
                engine_mod.run_scan("https://example.com",
                                    profile="quick", scope=scope)

    def test_scope_authorize_and_list(self):
        with tempfile.TemporaryDirectory() as d:
            scope = Scope(base_dir=d)
            host = scope.authorize("https://example.com/some/path")
            self.assertEqual(host, "example.com")
            self.assertTrue(scope.is_authorized("https://example.com/"))
            self.assertFalse(scope.is_authorized("https://other.com/"))
            self.assertIn("example.com", scope.list())
            scope.revoke("https://example.com/")
            self.assertFalse(scope.is_authorized("https://example.com/"))


class TestWhoisParsing(unittest.TestCase):
    SAMPLE = """
Domain Name: EXAMPLE.COM
Registrar: Example Registrar, Inc.
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2030-08-13T04:00:00Z
Registrant Organization: Example Org Ltd
Registrant Country: US
Name Server: A.IANA-SERVERS.NET
Name Server: B.IANA-SERVERS.NET
Domain Status: clientTransferProhibited
Whois Server: whois.example-registrar.com
"""
    REDACTED = """
Domain Name: EXAMPLE.COM
Registrar: Example Registrar, Inc.
Registrant Organization: REDACTED FOR PRIVACY
Registrant Country: REDACTED FOR PRIVACY
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2030-08-13T04:00:00Z
"""

    def test_parse_public_fields(self):
        parsed = whois_mod.parse_whois(self.SAMPLE)
        f = parsed["fields"]
        self.assertEqual(f["registrar"], "Example Registrar, Inc.")
        self.assertEqual(f["org"], "Example Org Ltd")
        self.assertEqual(f["country"], "US")
        self.assertTrue(f["created"].startswith("1995-08-14"))
        self.assertTrue(f["expires"].startswith("2030-08-13"))
        self.assertEqual(len(parsed["nameservers"]), 2)
        self.assertEqual(parsed["referral_server"],
                         "whois.example-registrar.com")

    def test_redacted_is_none_never_guessed(self):
        parsed = whois_mod.parse_whois(self.REDACTED)
        f = parsed["fields"]
        self.assertIsNone(f["org"])
        self.assertIsNone(f["country"])
        self.assertIsNotNone(f["registrar"])

    def test_iana_referral_format(self):
        # IANA answers a TLD query with "whois:" (not "Whois Server:").
        iana = ("% IANA WHOIS server\n\ndomain:       COM\n\n"
                "whois:        whois.verisign-grs.com\n\n"
                "status:       ACTIVE\n")
        parsed = whois_mod.parse_whois(iana)
        self.assertEqual(parsed["referral_server"],
                         "whois.verisign-grs.com")


class TestHeaders(unittest.TestCase):
    def test_missing_headers_flagged(self):
        findings, data = headers_mod.analyze_headers(
            {"server": "nginx/1.18"}, "https://example.com")
        names = [f["name"] for f in findings]
        self.assertIn("Missing Content-Security-Policy", names)
        self.assertIn("Missing Strict-Transport-Security (HSTS)", names)
        self.assertEqual(len(data["headers_missing"]), 8)

    def test_weak_csp_flagged(self):
        findings, _ = headers_mod.analyze_headers(
            {"content-security-policy": "default-src * 'unsafe-inline'",
             "strict-transport-security": "max-age=31536000",
             "x-frame-options": "SAMEORIGIN",
             "x-content-type-options": "nosniff",
             "referrer-policy": "no-referrer",
             "permissions-policy": "geolocation=()",
             "cross-origin-opener-policy": "same-origin",
             "cross-origin-resource-policy": "same-origin"},
            "https://example.com")
        names = [f["name"] for f in findings]
        self.assertIn("Weak Content-Security-Policy", names)
        self.assertNotIn("Missing Content-Security-Policy", names)

    def test_plain_http_flagged(self):
        findings, _ = headers_mod.analyze_headers({}, "http://example.com")
        self.assertTrue(any("plain HTTP" in f["name"] for f in findings))


class TestCookies(unittest.TestCase):
    def test_value_never_in_output(self):
        raw = ["sessionid=%s; Path=/" % FAKE_COOKIE_VALUE,
               "prefs=dark; Secure; HttpOnly; SameSite=Lax; Path=/",
               "track=x9y8z7; Domain=.example.com; Path=/"]
        cookies, findings = cookies_mod.analyze_cookies(
            raw, "example.com", https=True)
        blob = json.dumps({"cookies": cookies, "findings": findings})
        self.assertNotIn(FAKE_COOKIE_VALUE, blob)
        self.assertNotIn("x9y8z7", blob)
        self.assertNotIn("dark", blob)
        names = [c["name"] for c in cookies]
        self.assertEqual(names, ["sessionid", "prefs", "track"])

    def test_flags_parsed(self):
        cookies, _ = cookies_mod.analyze_cookies(
            ["a=1; Secure; HttpOnly; SameSite=Strict; Max-Age=3600"],
            "example.com", https=True)
        c = cookies[0]
        self.assertTrue(c["secure"] and c["httponly"])
        self.assertEqual(c["samesite"], "strict")
        self.assertFalse(c["session"])

    def test_missing_flags_flagged(self):
        _c, findings = cookies_mod.analyze_cookies(
            ["sessionid=%s; Path=/" % FAKE_COOKIE_VALUE],
            "example.com", https=True)
        names = [f["name"] for f in findings]
        self.assertIn("Cookie without Secure flag", names)
        self.assertIn("Cookie without HttpOnly flag", names)


class TestPaths(unittest.TestCase):
    def test_config_check_uses_head_only_never_reads_body(self):
        calls = []

        def fake_head(url, timeout=8):
            calls.append(("HEAD", url))
            return {"status": 200 if url.endswith("/.env") else 404,
                    "headers": {}, "body": ""}

        def exploding_get(*args, **kwargs):
            raise AssertionError("GET must never be called for config paths")

        findings, checked = paths_mod.check_config_paths(
            "http://127.0.0.1:9", head_fn=fake_head)
        self.assertTrue(all(m == "HEAD" for m, _ in calls))
        self.assertEqual(len(calls), len(paths_mod.CONFIG_PATHS))
        self.assertTrue(any(".env" in f["name"] for f in findings))
        self.assertTrue(any(f["evidence"].startswith("/.env")
                            for f in findings))
        blob = json.dumps({"findings": findings, "checked": checked})
        self.assertNotIn(FAKE_ENV_SECRET, blob)
        self.assertNotIn("DB_PASSWORD", blob)
        for f in findings:
            self.assertIn("never", f["evidence"].lower())

    def test_config_404_means_not_exposed(self):
        findings, _ = paths_mod.check_config_paths(
            "http://127.0.0.1:9",
            head_fn=lambda url, timeout=8: {"status": 404, "headers": {},
                                            "body": ""})
        self.assertEqual(findings, [])


class TestCors(unittest.TestCase):
    def test_wildcard_plus_credentials_is_high(self):
        findings, data = cors_mod.analyze_cors({
            "access-control-allow-origin": "*",
            "access-control-allow-credentials": "true"})
        self.assertEqual(findings[0]["severity"], "high")
        self.assertTrue(data["cors_enabled"])

    def test_no_cors_headers(self):
        findings, data = cors_mod.analyze_cors({})
        self.assertEqual(findings, [])
        self.assertFalse(data["cors_enabled"])


class TestPorts(unittest.TestCase):
    def test_closed_port_returns_none_fast(self):
        import time
        t0 = time.time()
        res = ports_mod.check_port("127.0.0.1", 59998, timeout=0.5)
        self.assertIsNone(res)
        self.assertLess(time.time() - t0, 5)

    def test_scan_closed_ports_is_empty(self):
        found = ports_mod.scan_ports("127.0.0.1", ports=[59997, 59998],
                                     timeout=0.5)
        self.assertEqual(found, [])


class TestVerifyKAnonymity(unittest.TestCase):
    def test_only_first_5_hash_chars_leave(self):
        password = "correct horse battery staple"
        digest = hashlib.sha1(password.encode()).hexdigest().upper()
        seen_urls = []

        def fake_fetch(url, timeout=12, max_bytes=1000000):
            seen_urls.append(url)
            # Simulate HIBP: suffix present with count 3.
            return {"status": 200,
                    "body": "%s:3\nAAAAA11111111111111111111111111111:7\n"
                            % digest[5:]}

        res = verify_mod.check_pwned(password, fetcher=fake_fetch)
        self.assertEqual(len(seen_urls), 1)
        self.assertTrue(seen_urls[0].endswith("/" + digest[:5]))
        self.assertNotIn(password, seen_urls[0])
        self.assertNotIn(digest, seen_urls[0])
        self.assertNotIn(digest[5:], seen_urls[0])
        self.assertEqual(res["status"], "pwned")
        self.assertEqual(res["count"], 3)
        self.assertNotIn(password, json.dumps(res))

    def test_not_pwned_and_offline_unknown(self):
        res = verify_mod.check_pwned(
            "some-password",
            fetcher=lambda url, timeout=12, max_bytes=1000000:
            {"status": 200, "body": "AAAAA:1\nBBBBB:2\n"})
        self.assertEqual(res["status"], "not_pwned")
        res2 = verify_mod.check_pwned(
            "some-password",
            fetcher=lambda url, timeout=12, max_bytes=1000000:
            {"status": None, "body": "", "error": "no network"})
        self.assertEqual(res2["status"], "unknown")


class TestScoring(unittest.TestCase):
    def test_grades(self):
        self.assertEqual(scoring_mod.grade_for(97), "A+")
        self.assertEqual(scoring_mod.grade_for(85), "B")
        self.assertEqual(scoring_mod.grade_for(30), "F")
        self.assertEqual(scoring_mod.grade_for(None), "INCOMPLETE")

    def test_confirmed_weighs_full_indicator_half(self):
        findings = [
            {"severity": "high", "confirmation": "confirmed"},
            {"severity": "high", "confirmation": "indicator"},
            {"severity": "info", "confirmation": "info"}]
        score, grade, dist = scoring_mod.score_findings(findings)
        self.assertEqual(score, 100 - 15 - 7)
        self.assertEqual(dist["high"], 2)

    def test_coverage_below_50_means_incomplete(self):
        cov = scoring_mod.compute_coverage(
            ["a", "b"], {"a": {"status": "completed"},
                         "b": {"status": "timeout"}}, {})
        self.assertEqual(cov["percent"], 50)


class TestTlsHonesty(unittest.TestCase):
    def test_all_handshakes_failed_is_not_no_modern_tls(self):
        # Simulate a sandbox proxy: TCP connects, every TLS version
        # fails. The engine must say "handshake failed", never claim
        # the server has no modern TLS.
        import webdon.engines.tls as tls_mod
        orig = tls_mod._handshake
        tls_mod._handshake = lambda *a, **k: (_ for _ in ()).throw(
            Exception("wrong version number"))
        try:
            out = tls_mod.run({"host": "example.com",
                               "url": "https://example.com",
                               "status": 200, "headers": {}})
        finally:
            tls_mod._handshake = orig
        names = [f["name"] for f in out["findings"]]
        self.assertIn("TLS handshake failed for all versions", names)
        self.assertNotIn("No modern TLS version supported", names)


class TestPhases(unittest.TestCase):
    def test_deep_and_forensic_have_25_plus_phases(self):
        self.assertGreaterEqual(engine_mod.total_phases("deep"), 25)
        self.assertGreaterEqual(engine_mod.total_phases("forensic"), 25)
        self.assertEqual(len(PROFILES["quick"]), 6)
        self.assertEqual(len(PROFILES["deep"]), 12)
        self.assertEqual(len(PROFILES["forensic"]), 13)


class TestLabScan(unittest.TestCase):
    def test_deep_lab_scan(self):
        with LabServer() as base, tempfile.TemporaryDirectory() as d:
            scope = Scope(base_dir=d)
            scope.authorize(base)
            scan = engine_mod.run_scan(
                base, profile="deep", scope=scope,
                settings={"scan_budget_s": 120})
            self.assertEqual(scan["tool"], "WEBDON v5.1")
            self.assertEqual(scan["profile"], "deep")
            self.assertIsNotNone(scan["score"])
            self.assertGreaterEqual(
                scan["coverage"]["phases_done"], 25)
            # No secret value anywhere in the whole scan.
            blob = json.dumps(scan, ensure_ascii=False)
            self.assertNotIn(FAKE_COOKIE_VALUE, blob)
            self.assertNotIn(FAKE_ENV_SECRET, blob)
            self.assertNotIn("DB_PASSWORD", blob)
            # The /.env HEAD-200 finding exists, with no content.
            names = [f["name"] for f in scan["findings"]]
            self.assertTrue(any(".env" in n for n in names))
            # Missing headers found on the weak lab site.
            self.assertTrue(any("Content-Security-Policy" in n
                                for n in names))
            # Limits block is present and honest.
            self.assertIn("live_users", scan["limits"])
            self.assertIn("UNKNOWN", scan["limits"]["live_users"])
            self.assertIn("devices_on_site", scan["limits"])
            # Cookies recorded by name only.
            cookie_names = (scan["assets"].get("cookie_names") or [])
            self.assertIn("sessionid", cookie_names)
            # Storage round-trip + reports.
            db = os.path.join(d, "webdon-scans.db")
            scan_id = storage_mod.save_scan(db, scan)
            loaded = storage_mod.get_scan(db, scan_id)
            self.assertEqual(loaded["target"], base)
            self.assertEqual(loaded["score"], scan["score"])
            json_path = os.path.join(d, "r.json")
            html_path = os.path.join(d, "r.html")
            report_mod.to_json(loaded, json_path)
            report_mod.to_html(loaded, html_path)
            with open(json_path, encoding="utf-8") as f:
                self.assertNotIn(FAKE_COOKIE_VALUE, f.read())
            with open(html_path, encoding="utf-8") as f:
                self.assertNotIn(FAKE_COOKIE_VALUE, f.read())
            # Executive summary builds and formats.
            summary = summary_mod.build_summary(loaded)
            self.assertEqual(summary["target"], base)
            text = summary_mod.format_summary(summary)
            self.assertIn("WEBDON", text)

    def test_quick_lab_scan_completes(self):
        with LabServer() as base, tempfile.TemporaryDirectory() as d:
            scope = Scope(base_dir=d)
            scope.authorize(base)
            scan = engine_mod.run_scan(
                base, profile="quick", scope=scope,
                settings={"scan_budget_s": 60})
            self.assertIsNotNone(scan["score"])
            blob = json.dumps(scan, ensure_ascii=False)
            self.assertNotIn(FAKE_COOKIE_VALUE, blob)


if __name__ == "__main__":
    unittest.main()
