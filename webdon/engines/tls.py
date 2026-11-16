#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TLS Intelligence engine — SSL/TLS analysis (v5.1 deep validation).

Protocol versions the server actually negotiates, cipher
enumeration with weak-cipher flagging, certificate details
(subject, issuer, SANs, notBefore/notAfter, days left) and full
trust-chain validation against the system CA store (stdlib ssl
with a real context — NOT a hand-rolled check).

v5.1 adds:
- chain validation: ssl.create_default_context() verifies the
  chain; `chain_valid` true/false + which link failed
  (verify message from the real verifier). Self-signed, expired
  and SAN-mismatched certificates are SEPARATE findings, each
  with its own evidence.
- expiry: `expires_in_days` (alias `days_left` kept), warn <30
  days, critical <7 days.
- SAN/hostname match against the target (DNS/IP SANs + CN
  fallback; ssl.match_hostname was removed in Python 3.12).
- protocol enumeration: TLS 1.0/1.1/1.2/1.3 offered or not.
- cipher enumeration: each offered cipher listed; RC4 / 3DES /
  NULL / export ciphers flagged weak (CWE-327).

SANDBOX NOTE: the sandbox egress proxy intercepts TLS, so results
there show proxy artefacts (a proxy certificate, failed chain
validation against the real CA store). When a proxy is suspected
the engine labels the result `proxy_artefact` and does NOT report
the proxy certificate as a real cert problem — re-run on Termux
for a true TLS result. Passive handshake only — no exploitation.
"""
import datetime
import os
import socket
import ssl

NAME = "tls"
TITLE = "SSL/TLS Analysis"

PHASES = ["protocol negotiation", "cipher & handshake", "certificate",
          "chain validation", "cipher enumeration"]

# Ciphers probed one by one (each successful handshake = offered).
# Weak ones are flagged with CWE-327.
CIPHER_PROBES = [
    "ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE-ECDSA-AES128-GCM-SHA256",
    "AES256-GCM-SHA384", "AES128-GCM-SHA256",
    "CHACHA20-POLY1305-SHA256",
    "ECDHE-RSA-AES256-SHA384", "ECDHE-RSA-AES128-SHA256",
    "AES256-SHA256", "AES128-SHA256",
    "DHE-RSA-AES256-SHA256", "DHE-RSA-AES128-SHA256",
    "DES-CBC3-SHA", "RC4-SHA", "RC4-MD5", "NULL-SHA",
    "EXP-RC4-MD5", "DES-CBC-SHA",
]

WEAK_CIPHERS = {
    "DES-CBC3-SHA": "3DES (64-bit block, SWEET32 — CWE-327)",
    "RC4-SHA": "RC4 (broken stream cipher — CWE-327)",
    "RC4-MD5": "RC4 (broken stream cipher — CWE-327)",
    "NULL-SHA": "NULL cipher (no encryption — CWE-327)",
    "EXP-RC4-MD5": "export-grade RC4 (deliberately weak — CWE-327)",
    "DES-CBC-SHA": "single DES (56-bit, broken — CWE-327)",
}


def is_weak_cipher(name):
    """True when a cipher name is in the weak list."""
    return (name or "") in WEAK_CIPHERS


def _proxy_suspected():
    return bool(os.environ.get("http_proxy")
                or os.environ.get("https_proxy")
                or os.environ.get("HTTP_PROXY")
                or os.environ.get("HTTPS_PROXY"))


def _decode_der_cert(der):
    """Decode a DER certificate to a getpeercert()-style dict.

    With verify_mode=CERT_NONE, OpenSSL 3 returns {} from
    getpeercert() even though the certificate bytes are present
    (getpeercert(binary_form=True) works). The DER is decoded
    through OpenSSL itself (ssl._ssl._test_decode_cert on a PEM
    temp file) — no hand-rolled ASN.1 parsing. Returns {} on any
    failure.
    """
    if not der:
        return {}
    import base64
    import tempfile
    pem = ("-----BEGIN CERTIFICATE-----\n"
           + base64.encodebytes(der).decode("ascii")
           + "-----END CERTIFICATE-----\n")
    try:
        with tempfile.NamedTemporaryFile(
                "w", suffix=".pem", delete=False) as f:
            f.write(pem)
            path = f.name
        try:
            return ssl._ssl._test_decode_cert(path) or {}
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass
    except Exception:
        return {}


def _handshake(host, port, minimum, maximum, timeout=8, ciphers=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = minimum
    ctx.maximum_version = maximum
    if ciphers:
        try:
            ctx.set_ciphers(ciphers)
        except ssl.SSLError:
            return None
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        wrapped = ctx.wrap_socket(sock, server_hostname=host)
        cert = wrapped.getpeercert() or {}
        if not cert:
            # CERT_NONE + OpenSSL 3: dict form is empty, DER is not.
            try:
                der = wrapped.getpeercert(binary_form=True)
            except Exception:
                der = None
            cert = _decode_der_cert(der)
        info = {"version": wrapped.version(),
                "cipher": (wrapped.cipher() or [None, None])[0],
                "cert": cert}
        wrapped.close()
        return info
    finally:
        try:
            sock.close()
        except Exception:
            pass


def validate_chain(host, port=443, timeout=8):
    """Full trust-chain validation against the system CA store.

    Uses ssl.create_default_context() — the real verifier, not a
    hand-rolled check. Returns {"chain_valid", "error",
    "failed_link", "cert"} where failed_link is the verifier's
    own message about which link failed.
    """
    ctx = ssl.create_default_context()
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        wrapped = ctx.wrap_socket(sock, server_hostname=host)
        cert = wrapped.getpeercert() or {}
        wrapped.close()
        return {"chain_valid": True, "error": None,
                "failed_link": None, "cert": cert}
    except ssl.SSLCertVerificationError as exc:
        return {"chain_valid": False, "error": str(exc)[:200],
                "failed_link": getattr(exc, "verify_message", None)
                               or str(exc)[:200],
                "cert": {}}
    except Exception as exc:
        return {"chain_valid": False, "error": str(exc)[:200],
                "failed_link": str(exc)[:200], "cert": {}}
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _dns_match(pattern, host):
    """One DNS SAN pattern against a host (*.example.com allowed)."""
    pattern = (pattern or "").lower()
    host = (host or "").lower()
    if pattern == host:
        return True
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return host.endswith("." + suffix) and \
            host.count(".") == suffix.count(".") + 1
    return False


def check_hostname_match(cert, host):
    """SAN/hostname match against the target.

    (ssl.match_hostname was removed in Python 3.12, so the check
    is done here: DNS SANs with single-label wildcard support, IP
    SANs, Common Name fallback.) Returns (matched_bool, detail).
    matched is None when the cert carries no SAN/CN to check.
    """
    if not cert:
        return None, "no certificate to check"
    sans = [v for k, v in cert.get("subjectAltName", [])
            if k in ("DNS", "IP Address")]
    if sans:
        for san in sans:
            if _dns_match(san, host):
                return True, "SAN %s matches %s" % (san, host)
        return False, "SANs %s do not match %s" % (
            ", ".join(sans[:5]), host)
    cn = None
    for rdn in cert.get("subject", []):
        for key, value in rdn:
            if key == "commonName":
                cn = value
    if cn:
        if _dns_match(cn, host):
            return True, "CN %s matches %s" % (cn, host)
        return False, "CN %s does not match %s" % (cn, host)
    return None, "certificate has no SAN or CN to check"


def enumerate_ciphers(host, port=443, timeout=3):
    """Probe each cipher in CIPHER_PROBES; return (offered, weak).

    Only attempted after a base handshake succeeded. Each probe is
    a plain handshake with one cipher forced — no payloads.
    """
    offered = []
    weak = []
    for cipher in CIPHER_PROBES:
        try:
            info = _handshake(host, port, ssl.TLSVersion.TLSv1_2,
                              ssl.TLSVersion.TLSv1_3, timeout=timeout,
                              ciphers=cipher)
        except Exception:
            info = None
        if info and info.get("cipher"):
            offered.append(info["cipher"])
            if is_weak_cipher(info["cipher"]):
                weak.append(info["cipher"])
    return offered, weak


def parse_cert_expiry(cert):
    """Days remaining from a getpeercert() dict (None if unparsable)."""
    try:
        exp = datetime.datetime.strptime(
            cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        return (exp - datetime.datetime.utcnow()).days
    except Exception:
        return None


def run(ctx):
    host = ctx.get("host") or ""
    url = ctx.get("url") or ""
    findings = []
    data = {"host": host, "versions": {}, "cipher": None, "cert": {},
            "days_left": None, "expires_in_days": None, "hsts": None,
            "chain_valid": None, "chain_error": None,
            "failed_link": None, "self_signed": None,
            "san_match": None, "sans": [],
            "protocols_offered": [], "ciphers_offered": [],
            "weak_ciphers": [], "proxy_artefact": False}
    if ctx.get("status") is None:
        return {"engine": NAME, "status": "error",
                "findings": [],
                "data": {"error": "homepage unreachable"}}
    if not url.startswith("https://"):
        data["note"] = "Site is plain HTTP — no TLS to test."
        findings.append({"severity": "high",
                         "name": "No TLS: site served over plain HTTP",
                         "evidence": url,
                         "fix": "Enable HTTPS with a valid certificate.",
                         "tls_detail": {"handshake": False,
                                        "cert_parsed": False}})
        return {"engine": NAME, "status": "completed",
                "findings": findings, "data": data}
    port = 443
    try:
        port = int(host.split(":")[1]) if ":" in host else 443
        host = host.split(":")[0]
    except Exception:
        port = 443
    for label, minimum, maximum in (
            ("TLSv1.0", ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1),
            ("TLSv1.2", ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2),
            ("TLSv1.3", ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3)):
        try:
            info = _handshake(host, port, minimum, maximum)
            data["versions"][label] = True
            if label in ("TLSv1.2", "TLSv1.3") and not data["cipher"]:
                data["cipher"] = info.get("cipher")
        except Exception:
            data["versions"][label] = False
    data["protocols_offered"] = [k for k, v in data["versions"].items()
                                 if v]
    for label in ("TLSv1.0", "TLSv1.1"):
        if data["versions"].get(label):
            findings.append({"severity": "medium",
                             "name": "Weak TLS protocol supported: %s" % label,
                             "evidence": "%s handshake succeeded" % label,
                             "fix": "Disable %s; require TLS 1.2 or newer."
                                    % label,
                             "tls_detail": {"handshake": True,
                                            "cert_parsed": False}})
    if all(v is False for v in data["versions"].values()):
        # TCP connected but NO TLS version handshook — not proof the
        # server lacks modern TLS. Usually a non-TLS service on 443
        # or an intercepting proxy/firewall (common in sandboxes).
        # The honest result is "handshake failed", not a finding
        # that the server has no modern TLS.
        findings.append({"severity": "medium",
                         "name": "TLS handshake failed for all versions",
                         "evidence": "TCP to %s:443 connected, but TLS "
                                     "1.0–1.3 handshakes all failed — "
                                     "possible intercepting proxy/firewall "
                                     "or non-TLS service on port 443"
                                     % host,
                         "fix": "Re-run from a network without an "
                                "intercepting proxy; if the failure "
                                "persists, check the TLS service on "
                                "port 443.",
                         "tls_detail": {"handshake": False,
                                        "cert_parsed": False}})
        data["note"] = ("TLS handshake failed for all versions — results "
                        "unreliable in this network.")
        data["proxy_artefact"] = _proxy_suspected()
    elif data["versions"].get("TLSv1.2") is False \
            and data["versions"].get("TLSv1.3") is False:
        findings.append({"severity": "high",
                         "name": "No modern TLS version supported",
                         "evidence": "TLS 1.2 and 1.3 handshakes both failed",
                         "fix": "Enable TLS 1.2 and TLS 1.3 on the server.",
                         "tls_detail": {"handshake": True,
                                        "cert_parsed": False}})
    cert = {}
    try:
        info = _handshake(host, port, ssl.TLSVersion.TLSv1_2,
                          ssl.TLSVersion.TLSv1_3)
        cert = info.get("cert") or {}
        data["cipher"] = info.get("cipher")
        data["cert"] = {
            "issuer": str(cert.get("issuer", ""))[:160],
            "subject": str(cert.get("subject", ""))[:160],
            "sans": [v for _k, v in cert.get("subjectAltName", [])][:10],
            "not_after": cert.get("notAfter"),
            "not_before": cert.get("notBefore")}
        data["sans"] = data["cert"]["sans"]
        days = parse_cert_expiry(cert)
        data["days_left"] = days
        data["expires_in_days"] = days
        tls_detail = {"handshake": True, "cert_parsed": days is not None}
        if days is not None:
            if days < 0:
                findings.append({"severity": "critical",
                                 "name": "TLS certificate EXPIRED",
                                 "evidence": "expired %s (%d days ago)"
                                             % (cert["notAfter"], -days),
                                 "fix": "Renew the certificate immediately.",
                                 "tls_detail": dict(tls_detail)})
            elif days < 7:
                findings.append({"severity": "critical",
                                 "name": "TLS certificate expires in %d days "
                                         "(critical)" % days,
                                 "evidence": "%d days left (expires %s)"
                                             % (days, cert["notAfter"]),
                                 "fix": "Renew the certificate immediately — "
                                        "under 7 days left.",
                                 "tls_detail": dict(tls_detail)})
            elif days < 30:
                findings.append({"severity": "medium",
                                 "name": "TLS certificate expires soon",
                                 "evidence": "%d days left (expires %s)"
                                             % (days, cert["notAfter"]),
                                 "fix": "Renew the certificate before it "
                                        "expires.",
                                 "tls_detail": dict(tls_detail)})
        # SAN / hostname match against the target host.
        matched, detail = check_hostname_match(cert, host)
        data["san_match"] = matched
        if matched is False:
            findings.append({"severity": "high",
                             "name": "TLS certificate hostname mismatch",
                             "evidence": "SAN/CN does not match %s: %s"
                                         % (host, detail),
                             "fix": "Issue a certificate whose SAN covers "
                                    "%s." % host,
                             "tls_detail": dict(tls_detail)})
        if not data["cert"]["issuer"] and not data["cert"]["subject"]:
            findings.append({"severity": "medium",
                             "name": "TLS certificate chain issue",
                             "evidence": "handshake returned no issuer/"
                                         "subject data",
                             "fix": "Check the certificate chain on the "
                                    "server (full chain file).",
                             "tls_detail": dict(tls_detail)})
    except Exception as exc:
        data["cert_error"] = str(exc)[:120]
    # Full chain validation against the system CA store (real
    # verifier). In a proxy-intercepted network the result is a
    # proxy artefact, labelled as such — never a real cert problem.
    proxy = _proxy_suspected()
    data["proxy_artefact"] = data.get("proxy_artefact") or proxy
    try:
        chain = validate_chain(host, port)
        data["chain_valid"] = chain["chain_valid"]
        data["chain_error"] = chain["error"]
        data["failed_link"] = chain["failed_link"]
        data["self_signed"] = bool(
            chain["error"] and "self-signed" in chain["error"].lower())
        if not chain["chain_valid"]:
            if proxy:
                data["note"] = ("Chain validation inconclusive — "
                                "intercepting proxy suspected in this "
                                "network; re-run on Termux for a true "
                                "result.")
                findings.append({"severity": "info",
                                 "name": "TLS chain validation inconclusive "
                                         "(proxy artefact)",
                                 "evidence": "chain validation failed in a "
                                             "proxy-intercepted network: %s"
                                             % (chain["error"] or "")[:120],
                                 "fix": "Re-run on Termux without an "
                                        "intercepting proxy.",
                                 "tls_detail": {"handshake": True,
                                                "cert_parsed": True,
                                                "proxy_artefact": True}})
            elif data["self_signed"]:
                findings.append({"severity": "high",
                                 "name": "TLS certificate is self-signed",
                                 "evidence": "chain validation failed: %s"
                                             % (chain["error"] or "")[:160],
                                 "fix": "Replace the self-signed certificate "
                                        "with one from a public CA.",
                                 "tls_detail": {"handshake": True,
                                                "cert_parsed": True,
                                                "chain_valid": False}})
            else:
                findings.append({"severity": "high",
                                 "name": "TLS certificate chain invalid",
                                 "evidence": "chain validation failed: %s"
                                             % (chain["failed_link"]
                                                or chain["error"] or "")[:160],
                                 "fix": "Fix the certificate chain on the "
                                        "server (full chain file, valid "
                                        "intermediates).",
                                 "tls_detail": {"handshake": True,
                                                "cert_parsed": True,
                                                "chain_valid": False}})
    except Exception as exc:
        data["chain_error"] = str(exc)[:120]
    # Cipher enumeration (only when a handshake works at all).
    if data["versions"].get("TLSv1.2") or data["versions"].get("TLSv1.3"):
        try:
            offered, weak = enumerate_ciphers(host, port)
            data["ciphers_offered"] = offered
            data["weak_ciphers"] = weak
            for cipher in weak:
                findings.append({"severity": "medium",
                                 "name": "Weak cipher offered: %s" % cipher,
                                 "evidence": "server accepted %s (%s)"
                                             % (cipher,
                                                WEAK_CIPHERS.get(cipher, "")),
                                 "fix": "Disable %s on the server; keep "
                                        "only AEAD ciphers (AES-GCM, "
                                        "CHACHA20-POLY1305)." % cipher,
                                 "tls_detail": {"handshake": True,
                                                "cert_parsed": True}})
        except Exception as exc:
            data["cipher_error"] = str(exc)[:120]
    hsts = (ctx.get("headers") or {}).get("strict-transport-security")
    data["hsts"] = hsts
    return {"engine": NAME, "status": "completed",
            "findings": findings, "data": data}
