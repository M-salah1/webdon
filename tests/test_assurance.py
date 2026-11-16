#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WEBDON v5.1 PROFESSIONAL ASSURANCE tests.

Covers the 7 v5.1 items: standalone evidence bundles (request +
response, redacted, verified_at; null + reason when none; legacy
migration), the evidence-sufficiency gate (per-type minimums,
suspected + named gap, never confirmed with sufficiency fail),
TLS deep validation (chain, expiry, SAN, protocols, weak
ciphers), port two-tier classification, cookie context analysis,
WAF likelihood, and per-engine coverage transparency.
Run: python3 -m unittest discover -s tests -v
"""
import io
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_webdon import FAKE_COOKIE_VALUE, LabServer  # noqa: E402
from webdon import __version__  # noqa: E402
from webdon.adapters import nmap as nmap_mod  # noqa: E402
from webdon.core import assurance as assurance_mod  # noqa: E402
from webdon.core import engine as engine_mod  # noqa: E402
from webdon.core import report as report_mod  # noqa: E402
from webdon.core import scoring as scoring_mod  # noqa: E402
from webdon.core import storage as storage_mod  # noqa: E402
from webdon.core.scope import Scope  # noqa: E402
from webdon.engines import cookies as cookies_mod  # noqa: E402
from webdon.engines import ports as ports_mod  # noqa: E402
from webdon.engines import protect as protect_mod  # noqa: E402
from webdon.engines import tls as tls_mod  # noqa: E402

FAKE_TOKEN = "tok-9f8e7d6c5b4a"


def _finding(name, engine="headers", severity="medium",
             validation="observed", **kw):
    f = {"severity": severity, "name": name, "evidence": "observed: test",
         "fix": "fix it", "engine": engine, "finding_id": "F-001",
         "confirmation": kw.pop("confirmation", "indicator"),
         "validation": {"status": validation, "confidence": 60}}
    f["evidence_obj"] = {
        "observed": "observed: test",
        "location": "https://example.com/",
        "timestamp": "2026-11-16T00:00:00Z",
        "engine": engine, "method": "GET https://example.com/",
        "observation": "observed: test"}
    f.update(kw)
    return f


def _insufficient_fixtures():
    """One insufficient-evidence finding per sufficiency type."""
    return {
        "header": _finding("Missing Content-Security-Policy"),
        "cookie": _finding("Cookie without Secure flag",
                           engine="cookies"),
        "tls": _finding("Weak TLS protocol supported: TLSv1.0",
                        engine="tls",
                        tls_detail={"handshake": True,
                                    "cert_parsed": False}),
        "port": _finding("Port 3306 open but service unidentified",
                         engine="ports", port_state="tcp_open"),
        "config": _finding("Environment file reachable (.env)",
                           engine="paths"),
        "dns": _finding("No SPF record", engine="dns"),
        "whois": _finding("WHOIS privacy redacted", engine="whois"),
        "cors": _finding("CORS wildcard origin", engine="cors"),
        "tech": _finding("Server version disclosed", engine="tech"),
        "generic": _finding("Something odd seen", engine="crawl"),
    }


def _sufficient_fixtures():
    """Same types with sufficient evidence."""
    out = _insufficient_fixtures()
    out["header"]["validation"] = {"status": "verified",
                                   "confidence": 90}
    out["cookie"]["validation"] = {"status": "verified",
                                   "confidence": 80}
    out["tls"]["tls_detail"] = {"handshake": True, "cert_parsed": True,
                                "chain_valid": True}
    out["port"] = _finding("Sensitive service confirmed: mysql "
                           "on port 3306", engine="ports",
                           severity="high", validation="verified",
                           port_state="service_confirmed",
                           banner="mysql_native_password")
    out["config"]["validation"] = {"status": "verified",
                                   "confidence": 90}
    out["dns"]["validation"] = {"status": "verified",
                                "confidence": 80}
    out["whois"]["validation"] = {"status": "verified",
                                  "confidence": 80}
    out["cors"]["validation"] = {"status": "verified",
                                 "confidence": 75}
    out["tech"]["validation"] = {"status": "verified",
                                 "confidence": 75}
    out["generic"]["validation"] = {"status": "verified",
                                    "confidence": 80}
    return out


class TestVersion51(unittest.TestCase):
    def test_version_is_5_1(self):
        self.assertEqual(__version__, "5.1")

    def test_json_report_version_5_1(self):
        scan = {"tool": "WEBDON v5.1", "target": "https://example.com/",
                "profile": "deep", "score": 90, "grade": "A",
                "confidence": 80, "coverage": {"percent": 100},
                "metrics": {"verification_rate": 50},
                "validation": {}, "severity_distribution": {},
                "findings": [], "false_positives": [], "chains": [],
                "contradictions": [], "assets": {}, "limits": {},
                "recommendations": [], "summary": {}, "engines": [],
                "engine_status": {}, "results": {}}
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "r.json")
            report_mod.to_json_report(scan, path)
            with open(path, encoding="utf-8") as f:
                rep = json.load(f)
        self.assertEqual(rep["report_version"], "5.1")
        self.assertIn("coverage_table", rep)
        self.assertIn("ports_summary", rep)
        self.assertIn("waf_summary", rep)
        self.assertIn("evidence_bundles", rep)


class TestEvidenceBundles(unittest.TestCase):
    def test_bundle_stores_request_and_response_and_verified_at(self):
        f = _finding("Missing Content-Security-Policy")
        req = {"method": "GET", "url": "https://example.com/",
               "headers": {"User-Agent": "WEBDON"}, "body_excerpt": ""}
        resp = {"status": 200,
                "headers": {"Content-Type": "text/html",
                            "Server": "LabServer/1.0"},
                "body_excerpt": "<html>hello</html>"}
        b = assurance_mod.build_bundle(f, request=req, response=resp)
        self.assertTrue(b["request_response"])
        self.assertEqual(b["request"]["method"], "GET")
        self.assertEqual(b["request"]["url"], "https://example.com/")
        self.assertEqual(b["response"]["status"], 200)
        self.assertEqual(b["response"]["body_excerpt"],
                         "<html>hello</html>")
        self.assertTrue(b["verified_at"])
        self.assertEqual(b["finding_id"], "F-001")
        self.assertEqual(b["engine"], "headers")

    def test_bundle_redacts_secrets_in_request_and_response(self):
        f = _finding("Missing Content-Security-Policy")
        req = {"method": "GET", "url": "https://example.com/",
               "headers": {"Authorization": "Bearer " + FAKE_TOKEN,
                           "Cookie": "sessionid=" + FAKE_COOKIE_VALUE},
               "body_excerpt": ""}
        resp = {"status": 200,
                "headers": {"Set-Cookie":
                            "sessionid=" + FAKE_COOKIE_VALUE + "; Path=/"},
                "body_excerpt": "Set-Cookie: sessionid="
                                + FAKE_COOKIE_VALUE + "; Path=/\n"
                                "DB_PASSWORD=hunter2-secret"}
        b = assurance_mod.build_bundle(f, request=req, response=resp)
        blob = json.dumps(b, ensure_ascii=False)
        self.assertNotIn(FAKE_COOKIE_VALUE, blob)
        self.assertNotIn(FAKE_TOKEN, blob)
        self.assertNotIn("hunter2-secret", blob)
        self.assertIn("[REDACTED]", blob)

    def test_dns_finding_has_null_request_response_with_reason(self):
        f = _finding("No SPF record", engine="dns")
        b = assurance_mod.build_bundle(f, ctx={"url": "https://x/"})
        self.assertIsNone(b["request_response"])
        self.assertIsNone(b["request"])
        self.assertIsNone(b["response"])
        self.assertIn("DNS", b["reason"])

    def test_tls_finding_has_null_request_response_with_reason(self):
        f = _finding("TLS certificate EXPIRED", engine="tls")
        b = assurance_mod.build_bundle(f, ctx={"url": "https://x/"})
        self.assertIsNone(b["request_response"])
        self.assertIn("TLS", b["reason"])

    def test_head_only_config_finding_has_no_response_body(self):
        f = _finding("Environment file reachable (.env)", engine="paths")
        b = assurance_mod.build_bundle(f, ctx={"url": "https://x/"})
        self.assertIsNone(b["request_response"])
        self.assertEqual(b["request"]["method"], "HEAD")
        self.assertIn("HEAD-only", b["reason"])

    def test_legacy_migration_marks_legacy_evidence(self):
        f = _finding("Missing Content-Security-Policy")
        b = assurance_mod.migrate_bundle(f, "https://example.com/")
        self.assertTrue(b["legacy"])
        self.assertIsNone(b["request_response"])
        self.assertIn("legacy_evidence", b["reason"])

    def test_storage_round_trip_bundles(self):
        f = _finding("Missing Content-Security-Policy")
        bundle = assurance_mod.build_bundle(
            f, request={"method": "GET", "url": "https://example.com/",
                        "headers": {}, "body_excerpt": ""},
            response={"status": 200, "headers": {},
                      "body_excerpt": "hi"})
        scan = {"target": "https://example.com/", "profile": "deep",
                "started_at": "2026-11-16T00:00:00Z",
                "finished_at": "2026-11-16T00:01:00Z",
                "duration_s": 1.0, "score": 90, "grade": "A",
                "coverage": {"percent": 100}, "findings": [f],
                "false_positives": [], "engine_status": {},
                "evidence_bundles": [bundle]}
        with tempfile.TemporaryDirectory() as d:
            db = os.path.join(d, "webdon-scans.db")
            scan_id = storage_mod.save_scan(db, scan)
            got = storage_mod.get_evidence_bundle(db, scan_id, "F-001")
            self.assertIsNotNone(got)
            self.assertEqual(got["response"]["status"], 200)
            self.assertEqual(got["request"]["method"], "GET")
            loaded = storage_mod.get_scan(db, scan_id)
            self.assertEqual(len(loaded["evidence_bundles"]), 1)

    def test_storage_old_scan_gets_legacy_bundles(self):
        f = _finding("Missing Content-Security-Policy")
        scan = {"target": "https://example.com/", "profile": "deep",
                "started_at": "2026-11-16T00:00:00Z",
                "finished_at": "2026-11-16T00:01:00Z",
                "duration_s": 1.0, "score": 90, "grade": "A",
                "coverage": {"percent": 100}, "findings": [f],
                "false_positives": [], "engine_status": {}}
        with tempfile.TemporaryDirectory() as d:
            db = os.path.join(d, "webdon-scans.db")
            scan_id = storage_mod.save_scan(db, scan)
            loaded = storage_mod.get_scan(db, scan_id)
            self.assertTrue(loaded["evidence_bundles"])
            self.assertTrue(loaded["evidence_bundles"][0]["legacy"])
            self.assertIn("legacy_evidence",
                          loaded["evidence_bundles"][0]["reason"])


class TestSufficiencyGate(unittest.TestCase):
    def test_insufficient_evidence_stays_suspected_with_named_gap(self):
        for ftype, f in _insufficient_fixtures().items():
            with self.subTest(ftype=ftype):
                res = assurance_mod.assess(f)
                self.assertFalse(res["sufficiency"], ftype)
                self.assertIsNotNone(res["evidence_gap"], ftype)
                self.assertTrue(0 <= res["evidence_score"] <= 100)
                out = assurance_mod.apply_assurance([dict(f)])
                self.assertEqual(out[0]["confirmation"], "suspected",
                                 ftype)
                self.assertEqual(out[0]["evidence_gap"],
                                 res["evidence_gap"])

    def test_sufficient_evidence_reaches_confirmed(self):
        for ftype, f in _sufficient_fixtures().items():
            with self.subTest(ftype=ftype):
                res = assurance_mod.assess(f)
                self.assertTrue(res["sufficiency"], ftype)
                out = assurance_mod.apply_assurance([dict(f)])
                self.assertEqual(out[0]["confirmation"], "confirmed",
                                 ftype)

    def test_no_finding_confirmed_with_sufficiency_fail(self):
        # Regression: over ALL finding types, insufficient evidence
        # can never produce `confirmed`.
        for ftype, f in _insufficient_fixtures().items():
            out = assurance_mod.apply_assurance([dict(f)])
            self.assertNotEqual(out[0]["confirmation"], "confirmed",
                                ftype)
            self.assertFalse(out[0]["sufficiency"]["pass"], ftype)

    def test_header_needs_two_urls_or_one_plus_reprobe(self):
        f = _finding("Missing Content-Security-Policy")
        self.assertFalse(assurance_mod.assess(f)["sufficiency"])
        f2 = _finding("Missing Content-Security-Policy",
                      observed_urls=["https://example.com/",
                                     "https://example.com/page2"])
        self.assertTrue(assurance_mod.assess(f2)["sufficiency"])
        f3 = _finding("Missing Content-Security-Policy",
                      validation="verified")
        self.assertTrue(assurance_mod.assess(f3)["sufficiency"])

    def test_port_needs_banner_never_bare_tcp(self):
        f = _finding("Port 3306 open but service unidentified",
                     engine="ports", port_state="tcp_open")
        res = assurance_mod.assess(f)
        self.assertFalse(res["sufficiency"])
        self.assertEqual(res["evidence_gap"], "needs banner")
        f2 = _finding("Sensitive service confirmed: mysql on port 3306",
                      engine="ports", port_state="service_confirmed",
                      banner="mysql_native_password")
        self.assertTrue(assurance_mod.assess(f2)["sufficiency"])

    def test_tls_needs_handshake_and_cert(self):
        f = _finding("Weak TLS protocol supported: TLSv1.0",
                     engine="tls",
                     tls_detail={"handshake": True,
                                 "cert_parsed": False})
        res = assurance_mod.assess(f)
        self.assertFalse(res["sufficiency"])
        self.assertIn("certificate", res["evidence_gap"])
        f2 = _finding("Weak TLS protocol supported: TLSv1.0",
                      engine="tls",
                      tls_detail={"handshake": True,
                                  "cert_parsed": True})
        self.assertTrue(assurance_mod.assess(f2)["sufficiency"])

    def test_info_findings_keep_info_confirmation(self):
        f = _finding("Third-party cookie: track", engine="cookies",
                     severity="info")
        out = assurance_mod.apply_assurance([f])
        self.assertEqual(out[0]["confirmation"], "info")


# ---------------------------------------------------------------- TLS lab

def _make_cert(tmpdir, name, days, cn="127.0.0.1", san=True):
    key = os.path.join(tmpdir, name + ".key")
    crt = os.path.join(tmpdir, name + ".crt")
    cmd = ["openssl", "req", "-x509", "-newkey", "rsa:2048",
           "-keyout", key, "-out", crt, "-days", str(days),
           "-nodes", "-subj", "/CN=%s" % cn]
    if san:
        cmd += ["-addext", "subjectAltName=IP:127.0.0.1"]
    proc = subprocess.run(cmd, capture_output=True, text=True,
                          timeout=60)
    if proc.returncode != 0 or not os.path.exists(crt):
        raise unittest.SkipTest("openssl cert generation failed: %s"
                                % proc.stderr[:200])
    return key, crt


class _TLSServer:
    def __init__(self, key, crt):
        self.httpd = None
        handler = type("H", (BaseHTTPRequestHandler,), {
            "do_GET": lambda s: (s.send_response(200),
                                 s.send_header("Content-Length", "2"),
                                 s.end_headers(),
                                 s.wfile.write(b"hi")),
            "log_message": lambda *a: None})
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(crt, key)
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket,
                                            server_side=True)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever,
                                       daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()


class TestTLSDeepValidation(unittest.TestCase):
    def _ctx(self, port):
        return {"url": "https://127.0.0.1:%d/" % port,
                "host": "127.0.0.1:%d" % port, "status": 200,
                "headers": {}, "authorized": True}

    def test_self_signed_chain_invalid_with_failed_link(self):
        with tempfile.TemporaryDirectory() as d:
            key, crt = _make_cert(d, "self", 365)
            with _TLSServer(key, crt) as srv:
                res = tls_mod.validate_chain("127.0.0.1", srv.port)
        self.assertFalse(res["chain_valid"])
        self.assertIn("self-signed", (res["error"] or "").lower())
        self.assertTrue(res["failed_link"])

    def test_tls_engine_self_signed_is_separate_finding(self):
        with tempfile.TemporaryDirectory() as d:
            key, crt = _make_cert(d, "self", 365)
            with _TLSServer(key, crt) as srv, \
                    mock.patch.object(tls_mod, "_proxy_suspected",
                                      return_value=False):
                out = tls_mod.run(self._ctx(srv.port))
        names = [f["name"] for f in out["findings"]]
        self.assertIn("TLS certificate is self-signed", names)
        self.assertFalse(out["data"]["chain_valid"])
        self.assertTrue(out["data"]["sans"])
        self.assertTrue(out["data"]["san_match"])
        self.assertIsNotNone(out["data"]["expires_in_days"])
        self.assertGreater(out["data"]["expires_in_days"], 300)
        self.assertEqual(out["data"]["days_left"],
                         out["data"]["expires_in_days"])
        self.assertTrue(out["data"]["protocols_offered"])

    def test_tls_engine_expiring_soon_is_critical_under_7_days(self):
        with tempfile.TemporaryDirectory() as d:
            key, crt = _make_cert(d, "soon", 1)
            with _TLSServer(key, crt) as srv, \
                    mock.patch.object(tls_mod, "_proxy_suspected",
                                      return_value=False):
                out = tls_mod.run(self._ctx(srv.port))
        names = [f["name"] for f in out["findings"]]
        self.assertTrue(any("expires in" in n and "critical" in n
                            for n in names),
                        names)
        self.assertLessEqual(out["data"]["expires_in_days"], 1)

    def test_tls_engine_san_mismatch_is_separate_finding(self):
        with tempfile.TemporaryDirectory() as d:
            key, crt = _make_cert(d, "mis", 365, cn="other.example",
                                  san=False)
            with _TLSServer(key, crt) as srv, \
                    mock.patch.object(tls_mod, "_proxy_suspected",
                                      return_value=False):
                out = tls_mod.run(self._ctx(srv.port))
        names = [f["name"] for f in out["findings"]]
        self.assertIn("TLS certificate hostname mismatch", names)
        self.assertFalse(out["data"]["san_match"])

    def test_expired_cert_days_negative(self):
        cert = {"notAfter": "Jan 01 00:00:00 2020 GMT"}
        self.assertLess(tls_mod.parse_cert_expiry(cert), 0)

    def test_san_match_helper(self):
        cert = {"subject": ((("commonName", "example.com"),),),
                "subjectAltName": (("DNS", "example.com"),
                                   ("DNS", "www.example.com"))}
        matched, _ = tls_mod.check_hostname_match(cert, "example.com")
        self.assertTrue(matched)
        matched2, _ = tls_mod.check_hostname_match(cert, "evil.com")
        self.assertFalse(matched2)

    def test_weak_ciphers_flagged(self):
        for weak in ("RC4-SHA", "RC4-MD5", "DES-CBC3-SHA", "NULL-SHA",
                     "EXP-RC4-MD5", "DES-CBC-SHA"):
            self.assertTrue(tls_mod.is_weak_cipher(weak), weak)
        for strong in ("ECDHE-RSA-AES256-GCM-SHA384",
                       "AES128-GCM-SHA256", "CHACHA20-POLY1305-SHA256"):
            self.assertFalse(tls_mod.is_weak_cipher(strong), strong)

    def test_cipher_enumeration_on_lab_server(self):
        with tempfile.TemporaryDirectory() as d:
            key, crt = _make_cert(d, "ciph", 365)
            with _TLSServer(key, crt) as srv:
                offered, weak = tls_mod.enumerate_ciphers(
                    "127.0.0.1", srv.port)
        self.assertTrue(offered)
        self.assertEqual(weak, [])

    def test_proxy_artefact_labelled_not_a_real_cert_problem(self):
        with tempfile.TemporaryDirectory() as d:
            key, crt = _make_cert(d, "proxy", 365)
            with _TLSServer(key, crt) as srv, \
                    mock.patch.object(tls_mod, "_proxy_suspected",
                                      return_value=True):
                out = tls_mod.run(self._ctx(srv.port))
        names = [f["name"] for f in out["findings"]]
        self.assertNotIn("TLS certificate is self-signed", names)
        self.assertTrue(any("proxy artefact" in n for n in names),
                        names)
        self.assertTrue(out["data"]["proxy_artefact"])


# ---------------------------------------------------------------- ports

class _BannerServer:
    """TCP server that sends a banner on connect (or stays silent)."""

    def __init__(self, banner=b""):
        self.banner = banner
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self.stop = False
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self):
        self.sock.settimeout(0.5)
        while not self.stop:
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                if self.banner:
                    conn.sendall(self.banner)
                conn.close()
            except OSError:
                pass

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.stop = True
        self.sock.close()


class TestPortTwoTier(unittest.TestCase):
    def test_banner_port_is_service_confirmed(self):
        with _BannerServer(b"SSH-2.0-OpenSSH_8.9\r\n") as srv:
            res = ports_mod.check_port("127.0.0.1", srv.port)
        self.assertEqual(res["state"], "service_confirmed")
        self.assertEqual(res["service"], "ssh")

    def test_silent_port_is_tcp_open(self):
        with _BannerServer(b"") as srv:
            res = ports_mod.check_port("127.0.0.1", srv.port)
        self.assertEqual(res["state"], "tcp_open")

    def test_tcp_open_never_a_vulnerability_never_scored(self):
        finding = {"severity": "info", "confirmation": "info",
                   "name": "Port 3306 open but service unidentified "
                           "(tcp_open)"}
        score, _grade, _dist = scoring_mod.score_findings([finding])
        self.assertEqual(score, 100)
        out = ports_mod.run({
            "authorized": True, "ips": ["127.0.0.1"]})
        # run() only reports risky ports; whatever it reports, no
        # tcp_open finding may be a vulnerability.
        for f in out["findings"]:
            if f.get("port_state") == "tcp_open":
                self.assertEqual(f["severity"], "info")
                self.assertEqual(f["confirmation"], "info")

    def test_service_confirmed_risky_port_is_scored(self):
        with _BannerServer(b"SSH-2.0-OpenSSH_8.9\r\n") as srv:
            with mock.patch.object(
                    ports_mod, "scan_ports",
                    return_value=[{"port": 22, "service": "ssh",
                                   "state": "service_confirmed",
                                   "banner": "SSH-2.0-OpenSSH_8.9",
                                   "tls": None},
                                  {"port": 3306, "service": "mysql",
                                   "state": "service_confirmed",
                                   "banner": "mysql_native_password",
                                   "tls": None}]):
                out = ports_mod.run({"authorized": True,
                                     "ips": ["127.0.0.1"]})
        self.assertEqual(out["data"]["service_confirmed_count"], 2)
        self.assertEqual(out["data"]["tcp_open_count"], 0)
        risky = [f for f in out["findings"]
                 if "3306" in f["name"]]
        self.assertEqual(len(risky), 1)
        self.assertEqual(risky[0]["severity"], "high")
        self.assertEqual(risky[0]["confirmation"], "confirmed")
        self.assertEqual(risky[0]["port_state"], "service_confirmed")

    def test_ports_data_has_two_tier_counts(self):
        with mock.patch.object(
                ports_mod, "scan_ports",
                return_value=[{"port": 22, "service": "ssh",
                               "state": "service_confirmed",
                               "banner": "SSH-2.0-x", "tls": None},
                              {"port": 3306, "service": "mysql",
                               "state": "tcp_open", "banner": "",
                               "tls": None}]):
            out = ports_mod.run({"authorized": True,
                                 "ips": ["127.0.0.1"]})
        self.assertEqual(out["data"]["service_confirmed_count"], 1)
        self.assertEqual(out["data"]["tcp_open_count"], 1)
        self.assertEqual(len(out["data"]["service_confirmed_ports"]), 1)
        self.assertEqual(len(out["data"]["tcp_open_ports"]), 1)

    def test_nmap_mapping_both_ways(self):
        xml = ('<nmaprun><host><ports>'
               '<port portid="22"><state state="open"/>'
               '<service name="ssh" product="OpenSSH" version="8.9"/>'
               '</port>'
               '<port portid="3306"><state state="open"/>'
               '<service name="mysql"/></port>'
               '<port portid="8080"><state state="open"/></port>'
               '</ports></host></nmaprun>')
        parsed = nmap_mod.parse_xml(xml)
        by_port = {p["port"]: p for p in parsed}
        self.assertEqual(by_port[22]["state"], "service_confirmed")
        self.assertEqual(by_port[3306]["state"], "service_confirmed")
        self.assertEqual(by_port[8080]["state"], "tcp_open")
        findings = nmap_mod._findings_for(parsed)
        self.assertTrue(any(f["severity"] == "high"
                            for f in findings))
        self.assertFalse(any("8080" in f["name"]
                             and f["severity"] == "high"
                             for f in findings))


# ---------------------------------------------------------------- cookies

class TestCookieContext(unittest.TestCase):
    def test_classify_cookie_contexts(self):
        self.assertEqual(cookies_mod.classify_cookie("sessionid"),
                         "session")
        self.assertEqual(cookies_mod.classify_cookie("PHPSESSID"),
                         "session")
        self.assertEqual(cookies_mod.classify_cookie("JSESSIONID"),
                         "session")
        self.assertEqual(cookies_mod.classify_cookie("connect.sid"),
                         "session")
        self.assertEqual(cookies_mod.classify_cookie("csrftoken"),
                         "csrf")
        self.assertEqual(cookies_mod.classify_cookie("XSRF-TOKEN"),
                         "csrf")
        self.assertEqual(cookies_mod.classify_cookie("_ga"), "tracking")
        self.assertEqual(cookies_mod.classify_cookie("_fbp"), "tracking")
        self.assertEqual(cookies_mod.classify_cookie("theme"),
                         "functional")
        self.assertEqual(cookies_mod.classify_cookie("randomname"),
                         "unknown")

    def test_csrf_cookie_missing_httponly_is_informational_not_finding(self):
        _c, findings = cookies_mod.analyze_cookies(
            ["csrftoken=abc; Path=/; Secure"], "example.com", https=True)
        vulns = [f for f in findings
                 if f["name"] == "Cookie without HttpOnly flag"]
        self.assertEqual(vulns, [])
        info = [f for f in findings
                if f.get("cookie_context") == "csrf"
                and f["severity"] == "info"]
        self.assertTrue(info)
        self.assertIn("MEANT to be read", info[0]["evidence"])

    def test_session_cookie_missing_secure_is_high(self):
        _c, findings = cookies_mod.analyze_cookies(
            ["sessionid=x; Path=/"], "example.com", https=True)
        secure = [f for f in findings
                  if f["name"] == "Cookie without Secure flag"]
        self.assertEqual(len(secure), 1)
        self.assertEqual(secure[0]["severity"], "high")
        self.assertEqual(secure[0]["cookie_context"], "session")
        self.assertIn("stolen", secure[0]["evidence"])

    def test_tracking_cookie_missing_secure_over_http_is_low(self):
        _c, findings = cookies_mod.analyze_cookies(
            ["_ga=x; Path=/"], "example.com", https=False)
        secure = [f for f in findings
                  if f["name"] == "Cookie without Secure flag"]
        self.assertEqual(len(secure), 1)
        self.assertEqual(secure[0]["severity"], "low")
        self.assertEqual(secure[0]["cookie_context"], "tracking")

    def test_tracking_cookie_missing_secure_over_https_not_flagged(self):
        _c, findings = cookies_mod.analyze_cookies(
            ["_ga=x; Path=/; HttpOnly"], "example.com", https=True)
        secure = [f for f in findings
                  if f["name"] == "Cookie without Secure flag"]
        self.assertEqual(secure, [])

    def test_tracking_cookie_missing_httponly_never_flagged(self):
        _c, findings = cookies_mod.analyze_cookies(
            ["_ga=x; Path=/; Secure"], "example.com", https=True)
        self.assertFalse(any(
            f["name"] == "Cookie without HttpOnly flag"
            for f in findings))

    def test_cookie_context_in_data(self):
        out = cookies_mod.run({
            "url": "https://example.com/", "host": "example.com",
            "cookie_headers": ["sessionid=x; Path=/",
                               "csrftoken=y; Path=/"]})
        self.assertEqual(out["data"]["by_context"]["session"], 1)
        self.assertEqual(out["data"]["by_context"]["csrf"], 1)
        self.assertTrue(out["data"]["context_notes"])


# ---------------------------------------------------------------- WAF

class TestWAFConfidence(unittest.TestCase):
    def test_no_signal_reports_low_percent_not_no_waf(self):
        waf = protect_mod.analyze_waf({"server": "nginx/1.25",
                                       "content-type": "text/html"})
        self.assertLessEqual(waf["waf_likelihood"], 15)
        self.assertGreater(waf["waf_likelihood"], 0)
        self.assertIn("no WAF signals observed", waf["verdict"])
        self.assertTrue(waf["checks_performed"])
        self.assertFalse(any(s["observed"] for s in waf["signals"]))

    def test_cloudflare_headers_give_high_likelihood(self):
        waf = protect_mod.analyze_waf({"cf-ray": "abc123",
                                       "cf-cache-status": "HIT",
                                       "server": "cloudflare"})
        self.assertGreaterEqual(waf["waf_likelihood"], 60)
        self.assertIn("likely", waf["verdict"])
        observed = [s for s in waf["signals"] if s["observed"]]
        self.assertTrue(all(s["weight"] > 0 for s in observed))

    def test_waf_cookie_name_is_a_signal(self):
        waf = protect_mod.analyze_waf({}, cookie_names=["cf_clearance"])
        self.assertGreater(waf["waf_likelihood"], 8)
        self.assertTrue(any("cookie" in s["signal"].lower()
                            and s["observed"]
                            for s in waf["signals"]))

    def test_detect_protections_never_says_no_waf(self):
        _p, findings, data = protect_mod.detect_protections(
            {"server": "nginx/1.25"})
        self.assertNotIn("No WAF", " ".join(f["name"] for f in findings))
        self.assertIn("waf_likelihood", data)
        self.assertEqual(data["waf_likelihood"], 8)
        names = [f["name"] for f in findings]
        self.assertTrue(any(n.startswith("WAF likelihood") for n in names))

    def test_benign_probe_block_counts_as_signal(self):
        waf = protect_mod.analyze_waf({"cf-ray": "x"}, probe_blocked=True)
        blocked = [s for s in waf["signals"]
                   if "benign probe" in s["signal"]][0]
        self.assertTrue(blocked["observed"])
        self.assertEqual(blocked["weight"], 25)


# ---------------------------------------------------------------- coverage

class TestCoverageTransparency(unittest.TestCase):
    def _scan(self):
        status = {}
        for name in report_mod.ALL_COVERAGE_ENGINES:
            status[name] = {"status": "completed", "duration_s": 1.0,
                            "retries": 0, "error": ""}
        status["nmap"] = {"status": "not_installed (fallback)",
                          "duration_s": 0.5, "retries": 0, "error": ""}
        status["netexec"] = {"status": "not_applicable",
                             "duration_s": 0.1, "retries": 0, "error": ""}
        status["bloodhound"] = {"status": "timeout", "duration_s": 60,
                                "retries": 0, "error": "timeout after 60s"}
        return {"target": "https://example.com/", "profile": "hive",
                "engines": list(report_mod.ALL_COVERAGE_ENGINES),
                "engine_status": status,
                "results": {"nmap": {"status": "not_installed (fallback)",
                                     "data": {"note": "nmap is not "
                                              "installed; used the "
                                              "built-in TCP connect "
                                              "scan instead."}},
                            "netexec": {"status": "not_applicable",
                                        "data": {"note": "no AD "
                                                 "indicators"}},
                            "bloodhound": {"status": "timeout",
                                           "data": {}}}}

    def test_every_engine_has_status_and_reason(self):
        rows = report_mod.coverage_table(self._scan())
        self.assertEqual(len(rows), 24)
        for row in rows:
            self.assertIn(row["status"],
                          ("ran", "fallback", "skipped", "failed"),
                          row)
            self.assertTrue(row["reason"], row)

    def test_fallback_skipped_failed_rows(self):
        rows = {r["engine"]: r for r in
                report_mod.coverage_table(self._scan())}
        self.assertEqual(rows["nmap"]["status"], "fallback")
        self.assertIn("not installed", rows["nmap"]["reason"])
        self.assertEqual(rows["netexec"]["status"], "skipped")
        self.assertEqual(rows["bloodhound"]["status"], "failed")
        self.assertEqual(rows["crawl"]["status"], "ran")

    def test_four_measures_are_separate_numbers(self):
        scan = self._scan()
        scan.update({"score": 82, "grade": "B", "confidence": 75,
                     "coverage": {"percent": 100},
                     "metrics": {"security_score": 82,
                                 "confidence": 75,
                                 "coverage_percent": 100,
                                 "verification_rate": 60}})
        metrics = scan["metrics"]
        self.assertEqual(
            {metrics["security_score"], metrics["confidence"],
             metrics["coverage_percent"],
             metrics["verification_rate"]},
            {82, 75, 100, 60})
        buf = io.StringIO()
        with redirect_stdout(buf):
            report_mod.print_coverage_table(scan)
        text = buf.getvalue()
        self.assertIn("crawl", text)
        self.assertIn("nmap", text)

    def test_terminal_summary_shows_four_measures_separately(self):
        scan = self._scan()
        scan.update({"score": 82, "grade": "B", "confidence": 75,
                     "coverage": {"percent": 100, "phases_done": 56,
                                  "phases_total": 56},
                     "metrics": {"security_score": 82,
                                 "confidence": 75,
                                 "coverage_percent": 100,
                                 "verification_rate": 60},
                     "validation": {"verified": 5, "observed": 2,
                                    "false_positive": 0},
                     "severity_distribution": {"medium": 2},
                     "findings": [], "false_positives": [],
                     "chains": [], "contradictions": [],
                     "assets": {}, "limits": {}, "recommendations": [],
                     "summary": None, "results": {},
                     "ports_summary": {"service_confirmed": 1,
                                       "tcp_open": 3},
                     "waf_summary": {"waf_likelihood": 8,
                                     "verdict": "low — no WAF signals "
                                                "observed"},
                     "coverage_table": report_mod.coverage_table(scan),
                     "deepdive": {"status": "not_run"}})
        buf = io.StringIO()
        with redirect_stdout(buf):
            report_mod.print_report(scan, lang="en")
        text = buf.getvalue()
        self.assertIn("Four measures (separate", text)
        self.assertIn("score=82%", text)
        self.assertIn("ports: 1 service_confirmed, 3 tcp_open", text)
        self.assertIn("WAF likelihood: 8%", text)
        self.assertIn("Coverage per engine:", text)


# ---------------------------------------------------------------- lab scan

class TestLabScanAssurance(unittest.TestCase):
    def test_deep_lab_scan_has_bundles_coverage_ports_waf(self):
        with LabServer() as base, tempfile.TemporaryDirectory() as d:
            scope = Scope(base_dir=d)
            scope.authorize(base)
            scan = engine_mod.run_scan(
                base, profile="deep", scope=scope,
                settings={"scan_budget_s": 120})
            self.assertIsNotNone(scan["score"])
            # Every finding carries assurance + a bundle id.
            for f in scan["findings"]:
                self.assertIn("evidence_score", f)
                self.assertIn("sufficiency", f)
                self.assertIn("evidence_bundle_id", f)
                if f.get("confirmation") == "confirmed":
                    self.assertTrue(f["sufficiency"]["pass"],
                                    f["name"])
            # Bundles exist, one per finding; HTTP findings have a
            # request/response, DNS/TLS ones say why not.
            self.assertEqual(len(scan["evidence_bundles"]),
                             len(scan["findings"])
                             + len(scan["false_positives"]))
            for b in scan["evidence_bundles"]:
                self.assertTrue(b["verified_at"])
                if b["request_response"] is None:
                    self.assertTrue(b["reason"])
            blob = json.dumps(scan, ensure_ascii=False)
            self.assertNotIn(FAKE_COOKIE_VALUE, blob)
            # Coverage table: 24 rows, four measures separate.
            self.assertEqual(len(scan["coverage_table"]), 24)
            self.assertIsNotNone(scan["metrics"]["security_score"])
            self.assertIsNotNone(scan["metrics"]["confidence"])
            self.assertIsNotNone(scan["metrics"]["coverage_percent"])
            self.assertIsNotNone(
                scan["metrics"]["verification_rate"])
            # Two-tier ports + WAF likelihood present.
            self.assertIn("service_confirmed", scan["ports_summary"])
            self.assertIn("tcp_open", scan["ports_summary"])
            self.assertIn("waf_likelihood", scan["waf_summary"])
            # Storage round-trip keeps bundles.
            db = os.path.join(d, "webdon-scans.db")
            scan_id = storage_mod.save_scan(db, scan)
            loaded = storage_mod.get_scan(db, scan_id)
            self.assertEqual(len(loaded["evidence_bundles"]),
                             len(scan["evidence_bundles"]))
            first = scan["findings"][0]
            bundle = storage_mod.get_evidence_bundle(
                db, scan_id, first["finding_id"])
            self.assertIsNotNone(bundle)
            self.assertEqual(bundle["finding_id"],
                             first["finding_id"])


if __name__ == "__main__":
    unittest.main()
