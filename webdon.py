#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WEBDON v3.00 HIVE — entry point.

Terminal console (Arabic / French / English) + direct scan mode.
    python3 webdon.py                                  # console
    python3 webdon.py --scan https://example.com
    python3 webdon.py --hive https://example.com       # HIVE: everything
    python3 webdon.py --hive https://example.com --schema api.yaml

A signed scope is required before any scan:
    webdon > scope create https://example.com
    webdon > hive https://example.com
"""
import getpass
import json
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from webdon import __version__  # noqa: E402
from webdon.adapters import bloodhound as bloodhound_mod  # noqa: E402
from webdon.adapters import burp as burp_mod  # noqa: E402
from webdon.adapters import manager as tools_mod  # noqa: E402
from webdon.adapters import neo as neo_mod  # noqa: E402
from webdon.adapters import netexec as netexec_mod  # noqa: E402
from webdon.adapters import openvas as openvas_mod  # noqa: E402
from webdon.adapters import zap as zap_mod  # noqa: E402
from webdon.core import engine as engine_mod  # noqa: E402
from webdon.core import hive as hive_mod  # noqa: E402
from webdon.core import report as report_mod  # noqa: E402
from webdon.core import storage as storage_mod  # noqa: E402
from webdon.core import summary as summary_mod  # noqa: E402
from webdon.core import verify as verify_mod  # noqa: E402
from webdon.core.http import (get, lower_headers, request_retry,  # noqa: E402
                           resolve_ips)
from webdon.core.i18n import t  # noqa: E402
from webdon.core.scope import Scope, normalize_url, valid_url  # noqa: E402
from webdon.engines import BY_NAME, PHASES, PROFILES  # noqa: E402

SETTINGS_FILE = "webdon-settings.json"
DB_FILE = "webdon-scans.db"

WEBDON_BANNER = r"""
 __        __   _____   ____    ____    ___    _   _
 \ \      / /  | ____| | __ )  |  _ \  / _ \  | \ | |
  \ \ /\ / /   |  _|   |  _ \  | | | | | | | | |  \| |
   \ V  V /    | |___  | |_) | | |_| | | |_| | | |\  |
    \_/\_/     |_____| |____/  |____/   \___/  |_| \_|
   WEBDON v%s — Heavy Website Investigation — FOX COMPANY
"""

WELCOME = {
    "ar": [
        "WEBDON v3.00 HIVE — أداة فحص المواقع الثقيلة",
        "نظام التحقيق الدفاعي الشامل — FOX COMPANY",
        "المطور: حافظ مهدي صلاح الدين — الجزائر",
        "",
        "ماذا تفعل الأداة؟",
        "• 24 محركاً + خلية HIVE: ضع الرابط فقط وتعمل كل الأدوات",
        "  التقنيات، الزحف والمسارات، ملفات الإعداد المكشوفة،",
        "  الكوكيز، CORS، المنافذ، متابعة الـ IP وحده، الحمايات،",
        "  والخط الزمني — مع التحقق من كلمات السر المسرّبة (HIBP)",
        "• تعريف صاحب الموقع من السجلات العامة فقط (UNKNOWN إن حُجب)",
        "• بلد الموقع ومزوّد الاستضافة من الـ IP العام",
        "• تقارير JSON/HTML وحفظ كل فحص في قاعدة بيانات",
        "",
        "كيف تعمل؟",
        "1) وقّع الإذن:  scope create https://example.com",
        "2) افحص الكل:    hive https://example.com  (أو auto)",
        "3) تحقق من كلمة سر:  verify",
        "الأوامر: profile (quick/deep/forensic) — history — report — lang — help — exit",
        "",
        "حدود صادقة: عدد المستخدمين الآن، والأجهزة المتصلة، وهوية",
        "الأدمن الخاصة، وتجاوز الحماية — لا يمكن معرفتها سلبياً،",
        "والأداة تُبلغ عنها UNKNOWN ولا تخترع أرقاماً أبداً.",
    ],
    "en": [
        "WEBDON v3.00 HIVE — Heavy Website Investigation Tool",
        "Comprehensive defensive audit system — FOX COMPANY",
        "Developer: Hafed Mehdi Salah Eddine — Algeria",
        "",
        "What does it do?",
        "• 24 engines + HIVE: give only the URL, every tool runs",
        "  headers, technologies, crawl & paths, exposed config files,",
        "  cookies, CORS, ports, IP follow-up alone, protections,",
        "  and timeline — plus leaked-password verification (HIBP)",
        "• Site owner from public records only (UNKNOWN if redacted)",
        "• Site country and hosting provider from the public IP",
        "• JSON/HTML reports and every scan saved in a database",
        "",
        "How to work?",
        "1) Sign authorization:  scope create https://example.com",
        "2) Scan everything:     hive https://example.com  (or auto)",
        "3) Verify a password:   verify",
        "Commands: profile (quick/deep/forensic) — history — report — lang — help — exit",
        "",
        "Honest limits: live user count, connected devices, private",
        "admin identity and protection bypass cannot be known",
        "passively — the tool reports them UNKNOWN and never invents",
        "numbers.",
    ],
    "fr": [
        "WEBDON v3.00 HIVE — Outil lourd d'investigation de sites web",
        "Système complet d'audit défensif — FOX COMPANY",
        "Développeur : Hafed Mehdi Salah Eddine — Algérie",
        "",
        "Que fait l'outil ?",
        "• 24 moteurs + HIVE : donnez seulement l'URL, tout tourne",
        "  technologies, crawl et chemins, fichiers de config exposés,",
        "  cookies, CORS, ports, suivi de l'IP seule, protections,",
        "  chronologie — plus vérification des mots de passe fuités (HIBP)",
        "• Propriétaire du site depuis les registres publics uniquement",
        "  (UNKNOWN si masqué)",
        "• Pays du site et hébergeur depuis l'IP publique",
        "• Rapports JSON/HTML et chaque scan sauvé en base de données",
        "",
        "Comment l'utiliser ?",
        "1) Signez l'autorisation :  scope create https://example.com",
        "2) Tout scanner :         hive https://example.com  (ou auto)",
        "3) Vérifiez un mot de passe :  verify",
        "Commandes : profile (quick/deep/forensic) — history — report — lang — help — exit",
        "",
        "Limites honnêtes : nombre d'utilisateurs en direct, appareils",
        "connectés, identité privée de l'admin et contournement des",
        "protections ne peuvent pas être connus passivement — l'outil",
        "les signale UNKNOWN et n'invente jamais de chiffres.",
    ],
}


def show_welcome(lang, pause=True):
    print("=" * 60)
    for line in WELCOME.get(lang, WELCOME["en"]):
        print(line)
    print("=" * 60)
    if pause:
        try:
            input("%s " % t(lang, "welcome_press"))
        except (EOFError, KeyboardInterrupt):
            pass


def load_settings():
    try:
        with open(SETTINGS_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"language": "ar", "profile": "deep"}


def save_settings(settings):
    try:
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(settings, f, ensure_ascii=False)
    except Exception:
        pass


def choose_language():
    print("1. العربية    2. English    3. Français")
    try:
        choice = input("> ").strip()
    except (EOFError, KeyboardInterrupt):
        return "ar"
    return {"1": "ar", "2": "en", "3": "fr"}.get(choice, "ar")


class Spinner:
    """One-line loader: spinner + current engine + % + elapsed."""

    SPINNER = ["◐", "◓", "◑", "◒"]

    def __init__(self, total, lang):
        self.total = max(1, total)
        self.done = set()
        self.current = ""
        self.lang = lang
        self.started = time.time()
        self.stop = False
        self.thread = None

    def progress(self, name):
        self.done.add(name)
        self.current = name

    def _run(self):
        frame = 0
        while not self.stop:
            spin = self.SPINNER[frame % len(self.SPINNER)]
            pct = min(99, int(100 * len(self.done) / self.total))
            elapsed = int(time.time() - self.started)
            line = "\r%s %s %d%%" % (spin, t(self.lang, "scanning"), pct)
            if self.current:
                line += " — %s" % self.current[:24]
            line += " %ds" % elapsed
            sys.stdout.write(line)
            sys.stdout.flush()
            time.sleep(0.12)
            frame += 1

    def start(self):
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def finish(self, duration):
        self.stop = True
        if self.thread:
            self.thread.join(timeout=1)
        sys.stdout.write("\r%s %s %.1fs — %d/%d %s\n" % (
            "✓", t(self.lang, "done"), duration, len(self.done),
            self.total, t(self.lang, "phases")))
        sys.stdout.flush()


def accept_terms(lang):
    print("=" * 60)
    print("  ⚖  %s" % t(lang, "terms_title"))
    for i in range(1, 5):
        print("   • %s" % t(lang, "terms_%d" % i))
    print("=" * 60)
    try:
        ans = input("%s " % t(lang, "terms_accept")).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    if ans != "y":
        print(t(lang, "terms_declined"))
        return False
    print(t(lang, "terms_accepted"))
    return True


def do_scan(url, profile, lang, scope, settings):
    url = normalize_url(url)
    if not valid_url(url):
        print(t(lang, "invalid_url"))
        return None
    if not scope.is_authorized(url):
        print(t(lang, "scope_required"))
        return None
    if not accept_terms(lang):
        return None
    total = engine_mod.total_phases(profile)
    spin = Spinner(total, lang)
    spin.start()
    scan = None
    try:
        scan = engine_mod.run_scan(url, profile=profile, scope=scope,
                                   settings=settings,
                                   progress=spin.progress)
    except PermissionError as exc:
        print(str(exc))
    finally:
        spin.finish(scan["duration_s"] if scan else 0)
    if scan is None:
        return None
    report_mod.print_report(scan, lang)
    try:
        scan_id = storage_mod.save_scan(DB_FILE, scan)
        scan["scan_id"] = scan_id
    except Exception:
        pass
    record_scan_traffic(scan)
    return scan


BURP_LOG = burp_mod.ProxyLog()


def record_scan_traffic(scan):
    """Log WEBDON's own requests into the Burp-like proxy log
    (method/URL/status/header NAMES only — values never stored)."""
    try:
        BURP_LOG.record("GET", scan.get("target") or "",
                        (scan.get("results") or {}).get("crawl", {})
                        .get("data", {}).get("status"))
        pages = ((scan.get("results") or {}).get("crawl", {})
                 .get("data", {}).get("pages") or [])
        for p in pages[:50]:
            url = p.get("url") if isinstance(p, dict) else str(p)
            if url and url != scan.get("target"):
                BURP_LOG.record("GET", url,
                                p.get("status") if isinstance(p, dict)
                                else None)
    except Exception:
        pass


def do_hive(url, lang, scope, settings, schema_path=None):
    """HIVE: one command runs all six waves. Scope-gated."""
    url = normalize_url(url)
    if not valid_url(url):
        print(t(lang, "invalid_url"))
        return None
    if not scope.is_authorized(url):
        print(t(lang, "scope_required"))
        return None
    if not accept_terms(lang):
        return None
    total = hive_mod.total_phases()
    spin = Spinner(total, lang)
    spin.start()
    scan = None
    try:
        scan = hive_mod.run_hive(url, scope=scope, settings=settings,
                                 progress=spin.progress,
                                 schema_path=schema_path)
    except PermissionError as exc:
        print(str(exc))
    finally:
        spin.finish(scan["duration_s"] if scan else 0)
    if scan is None:
        return None
    print("HIVE waves: %s" % " -> ".join(hive_mod.wave_names()))
    for name, info in (scan.get("hive") or {}).get("adapters", {}).items():
        print("  %-12s %-28s %s" % (name, info.get("status", ""),
                                    info.get("mode", "")[:60]))
    report_mod.print_report(scan, lang)
    try:
        scan_id = storage_mod.save_scan(DB_FILE, scan)
        scan["scan_id"] = scan_id
    except Exception:
        pass
    record_scan_traffic(scan)
    return scan


def tools_cmd(arg, lang):
    """tools list | tools check <name> | tools install <name>"""
    parts = arg.split()
    if not parts or parts[0] == "list":
        print("=" * 60)
        print("WEBDON — tools  (arch: %s)" % tools_mod.arch())
        for row in tools_mod.list_all():
            ver = (" — %s" % row["version"]) if row.get("version") else ""
            print("  %-12s %-22s%s" % (row["name"], row["status"], ver))
            print("      %s" % row.get("note", ""))
        print("=" * 60)
        return
    if parts[0] == "check" and len(parts) == 2:
        row = tools_mod.check(parts[1])
        print("%s: %s%s" % (row["name"], row["status"],
                            (" — %s" % row["version"])
                            if row.get("version") else ""))
        print("  %s" % row.get("note", ""))
        return
    if parts[0] == "install" and len(parts) == 2:
        print("Installing %s — this can take a few minutes "
              "(Go builds)..." % parts[1])
        res = tools_mod.install(parts[1])
        if res.get("installed"):
            print("OK: %s installed — %s" % (parts[1],
                                             res.get("version", "")))
        else:
            print("FAILED: %s" % res.get("error", ""))
            if res.get("manual_command"):
                print("Run manually: %s" % res["manual_command"])
        return
    print("tools list | tools check <name> | tools install <name>")


def openvas_cmd(arg, lang, scope):
    """openvas export <url> | openvas run <url>"""
    parts = arg.split(None, 1)
    if len(parts) != 2 or parts[0] not in ("export", "run"):
        print("openvas export <url> | openvas run <url>")
        print("OpenVAS/GVM is a server — it cannot run inside Termux.")
        print("export writes a ready task for a PC/server; run needs")
        print("GVM_HOST + GVM_USER in the environment and gvm-cli.")
        return
    url = normalize_url(parts[1])
    if not valid_url(url):
        print(t(lang, "invalid_url"))
        return
    if not scope.is_authorized(url):
        print(t(lang, "scope_required"))
        return
    host = url.split("/")[2]
    domain = host.split(":")[0]
    ips = resolve_ips(domain if "." in domain else host)
    ip = ips[0] if ips else ""
    if parts[0] == "export":
        task_path, plan_path = openvas_mod.export_task(url, ip)
        print("Saved: %s" % task_path)
        print("Saved: %s" % plan_path)
        print("Import the task into Greenbone (GVM) on a server/PC.")
        return
    gvm_host = os.environ.get("GVM_HOST")
    gvm_user = os.environ.get("GVM_USER")
    if not gvm_host or not gvm_user:
        print("openvas run needs GVM_HOST + GVM_USER in the environment.")
        print("Example: export GVM_HOST=192.168.1.10 GVM_USER=admin")
        return
    try:
        password = getpass.getpass("GVM password for %s: " % gvm_user)
    except (EOFError, KeyboardInterrupt):
        return
    if not password:
        print("no password given — aborted")
        return
    try:
        res = openvas_mod.run_gvm_task(gvm_host, gvm_user, password, ip)
    finally:
        password = ""
    print("OpenVAS: %s" % res.get("status"))
    for key, val in (res.get("data") or {}).items():
        print("  %s: %s" % (key, val))


def netexec_cmd(arg, lang, scope):
    """netexec run <ip> — explicit opt-in, anonymous/guest only."""
    parts = arg.split()
    if len(parts) != 2 or parts[0] != "run":
        print("netexec run <ip>")
        print("Anonymous/guest enumeration only — no passwords, no")
        print("spraying, no brute force. Runs only when the target")
        print("shows Windows/AD indicators (ports 88/389/445/...).")
        return
    ip = parts[1]
    url = "http://%s/" % ip
    if not scope.is_authorized(url):
        print(t(lang, "scope_required"))
        return
    ctx = {"url": url, "host": ip, "domain": ip, "authorized": True,
           "timeout": 8, "ips": [ip], "pages": [], "scripts": []}
    ctx["ports_data"] = BY_NAME["ports"].run(ctx).get("data") or {}
    res = netexec_mod.run_explicit(ctx)
    print("NetExec: %s" % res.get("status"))
    data = res.get("data") or {}
    for key in ("note", "error"):
        if data.get(key):
            print("  %s" % data[key])
    if (data.get("indicators") or {}).get("evidence"):
        print("  indicators: %s" % data["indicators"]["evidence"])
    for share in data.get("shares") or []:
        print("  share: %s" % share)
    for user in data.get("users") or []:
        print("  user: %s" % user)
    for f in res.get("findings") or []:
        print("  [%s] %s" % (f["severity"].upper(), f["name"]))


def bloodhound_cmd(arg, lang, scope):
    """bloodhound export <url> | bloodhound import <file>"""
    parts = arg.split(None, 1)
    if len(parts) != 2 or parts[0] not in ("export", "import"):
        print("bloodhound export <url> | bloodhound import <file>")
        print("BloodHound CE needs a Neo4j server + a SharpHound")
        print("collection from a domain host — it cannot run here.")
        return
    if parts[0] == "import":
        try:
            res = bloodhound_mod.import_collection(parts[1])
        except (OSError, ValueError) as exc:
            print("bloodhound import error: %s" % exc)
            return
        print("BloodHound import: %s" % res.get("status"))
        summ = (res.get("data") or {}).get("summary") or {}
        print("  total objects: %s" % summ.get("total_objects"))
        for k, v in (summ.get("counts") or {}).items():
            print("  %s: %s" % (k, v))
        return
    url = normalize_url(parts[1])
    if not valid_url(url):
        print(t(lang, "invalid_url"))
        return
    if not scope.is_authorized(url):
        print(t(lang, "scope_required"))
        return
    host = url.split("/")[2]
    domain = host.split(":")[0]
    ips = resolve_ips(domain if "." in domain else host)
    ip = ips[0] if ips else ""
    plan_path, cmd_path = bloodhound_mod.export_plan(url, ip)
    print("Saved: %s" % plan_path)
    print("Saved: %s" % cmd_path)
    print("Collect with SharpHound on the owner's domain host, then:")
    print("  bloodhound import <collected-file.json>")


def zap_cmd(arg, lang, scope):
    """zap export <url> | zap run <url>"""
    parts = arg.split(None, 1)
    if len(parts) != 2 or parts[0] not in ("export", "run"):
        print("zap export <url> | zap run <url>")
        print("Full ZAP runs on a PC; on Termux use zap export.")
        return
    url = normalize_url(parts[1])
    if not valid_url(url):
        print(t(lang, "invalid_url"))
        return
    if not scope.is_authorized(url):
        print(t(lang, "scope_required"))
        return
    if parts[0] == "export":
        ctx_path, plan_path = zap_mod.export_plan(
            url, scope_host=url.split("/")[2])
        print("Saved: %s" % ctx_path)
        print("Saved: %s" % plan_path)
        print("On a PC: import the context into OWASP ZAP and follow "
              "the plan.")
        return
    res = zap_mod.run({"url": url, "authorized": True})
    print("ZAP: %s" % res.get("status"))
    for key, val in (res.get("data") or {}).items():
        if key == "pc_steps":
            for step in val:
                print("  - %s" % step)
        else:
            print("  %s: %s" % (key, val))


def neo_cmd(arg, lang):
    """neo export [id] | neo push [id]"""
    parts = arg.split()
    if not parts or parts[0] not in ("export", "push"):
        print("neo export [id] | neo push [id]")
        print("Push needs NEO_API_KEY + NEO_API_URL in the environment.")
        return
    scan = None
    if len(parts) >= 2:
        try:
            scan = storage_mod.get_scan(DB_FILE, int(parts[1]))
        except ValueError:
            scan = None
    if not scan:
        rows = storage_mod.list_scans(DB_FILE)
        if not rows:
            print("no scans yet — run hive first")
            return
        scan = storage_mod.get_scan(DB_FILE, rows[-1]["id"])
    if parts[0] == "export":
        path = neo_mod.export_findings(scan)
        print("Saved: %s" % path)
        return
    res = neo_mod.push(scan)
    print("Neo push: %s" % res.get("status"))
    for key, val in (res.get("data") or {}).items():
        print("  %s: %s" % (key, val))


def proxy_cmd(arg, lang):
    """proxy — show the Burp-like request log."""
    entries = BURP_LOG.list()
    print("=" * 60)
    print("WEBDON proxy log — %d recorded request(s)" % len(entries))
    if not entries:
        print("Empty: run a scan first; WEBDON logs its own requests.")
    for e in entries[-30:]:
        print("  #%d [%s] %s -> %s" % (e["id"], e["method"], e["url"],
                                       e["status"]))
    print("=" * 60)


def repeater_cmd(arg, lang, scope):
    """repeater <id> [Header: value ...] — resend a logged request."""
    parts = arg.split()
    if not parts:
        print("repeater <id> [Header: value ...]")
        return
    try:
        entry_id = int(parts[0])
    except ValueError:
        print("repeater <id> [Header: value ...]")
        return
    headers = {}
    for piece in parts[1:]:
        if ":" in piece:
            k, v = piece.split(":", 1)
            headers[k.strip()] = v.strip()
    res = burp_mod.repeater(BURP_LOG, entry_id, scope, headers)
    if res.get("error"):
        print("repeater error: %s" % res["error"])
        return
    print("repeater #%d -> HTTP %s (%sms)" % (
        entry_id, res.get("status"), res.get("elapsed_ms")))
    print((res.get("body_preview") or "")[:500])


def sitemap_cmd(arg, lang):
    """sitemap [id] — URL tree of the last (or given) scan."""
    scan = None
    if arg.strip():
        try:
            scan = storage_mod.get_scan(DB_FILE, int(arg.strip()))
        except ValueError:
            scan = None
    if not scan:
        rows = storage_mod.list_scans(DB_FILE)
        if not rows:
            print("no scans yet — run hive first")
            return
        scan = storage_mod.get_scan(DB_FILE, rows[-1]["id"])
    pages = ((scan.get("results") or {}).get("crawl", {})
             .get("data", {}).get("pages") or [])
    tree = burp_mod.sitemap(pages)
    print("=" * 60)
    print("Sitemap — %s (%d pages)" % (scan.get("target"), len(pages)))
    for parent, children in tree.items():
        print("  %s" % parent)
        for child in children[:20]:
            print("    └ %s" % child)
    print("=" * 60)


def scanner_cmd(arg, lang):
    """scanner [id] — built-in misconfiguration scan summary."""
    scan = None
    if arg.strip():
        try:
            scan = storage_mod.get_scan(DB_FILE, int(arg.strip()))
        except ValueError:
            scan = None
    if not scan:
        rows = storage_mod.list_scans(DB_FILE)
        if not rows:
            print("no scans yet — run hive first")
            return
        scan = storage_mod.get_scan(DB_FILE, rows[-1]["id"])
    summ = burp_mod.scanner_summary(scan)
    print("=" * 60)
    print("Scanner — score %s (%s), %d findings"
          % (summ["score"], summ["grade"], summ["total_findings"]))
    for area, count in summ["findings_by_area"].items():
        if count:
            print("  %-10s %d" % (area, count))
    print("=" * 60)


def dashboard(scan, lang):
    while True:
        print("-" * 60)
        print("0. %s    1. %s    2. JSON    3. HTML    4. %s" % (
            t(lang, "back"), t(lang, "findings"), t(lang, "verify")))
        try:
            choice = input("%s " % t(lang, "enter_choice")).strip()
        except (EOFError, KeyboardInterrupt):
            return
        if choice == "0" or choice == "":
            return
        if choice == "1":
            for f in scan.get("findings") or []:
                print("  [%s] %s" % (f["severity"].upper(), f["name"]))
                print("      %s" % f.get("evidence", "")[:180])
                print("      Fix: %s" % f.get("fix", "")[:180])
        elif choice == "2":
            path = report_mod.to_json(scan, "webdon-report.json")
            print("Saved: %s" % path)
        elif choice == "3":
            path = report_mod.to_html(scan, "webdon-report.html")
            print("Saved: %s" % path)
        elif choice == "4":
            do_verify(lang)


def do_verify(lang):
    """HIBP k-anonymity password check. The password is never shown,
    stored or logged — only the first 5 SHA-1 chars leave the process."""
    try:
        secret = getpass.getpass("%s " % t(lang, "verify_prompt"))
    except (EOFError, KeyboardInterrupt):
        return
    if not secret:
        return
    res = verify_mod.check_pwned(secret)
    secret = ""
    if res["status"] == "pwned":
        print("%s — %s" % (t(lang, "verify_pwned"),
                           "breach count: %s" % res["count"]))
        print("Change this password everywhere it is used.")
    elif res["status"] == "not_pwned":
        print(t(lang, "verify_clean"))
    else:
        print("%s (%s)" % (t(lang, "verify_unknown"),
                           res.get("error") or ""))


def show_history(lang):
    rows = storage_mod.list_scans(DB_FILE)
    print("=" * 60)
    print("WEBDON — %s" % t(lang, "history"))
    if not rows:
        print(t(lang, "no_history"))
        return
    for r in rows:
        score = r["score"] if r["score"] is not None else "INCOMPLETE"
        print("#%s  %s  [%s]  score=%s  grade=%s  coverage=%s%%  %s" % (
            r["id"], r["target"], r["profile"], score, r["grade"],
            r["coverage"], r["finished_at"] or ""))


def list_engines():
    print("=" * 60)
    for name, mod in sorted(BY_NAME.items()):
        print("  %-12s — %s  (%d phases)" % (
            name, mod.TITLE, len(PHASES.get(name, [name]))))
    print("  total phases: quick=%d  deep=%d  forensic=%d" % (
        engine_mod.total_phases("quick"),
        engine_mod.total_phases("deep"),
        engine_mod.total_phases("forensic")))
    print("=" * 60)


def run_single_engine(name, url, lang, scope):
    """Run one engine standalone."""
    if name not in BY_NAME:
        print("unknown engine — type engines")
        return
    url = normalize_url(url)
    if not valid_url(url):
        print(t(lang, "invalid_url"))
        return
    if not scope.is_authorized(url):
        print(t(lang, "scope_required"))
        return
    host = url.split("/")[2]
    domain = host.split(":")[0]
    if domain.startswith("www."):
        domain = domain[4:]
    r = request_retry(url, timeout=10, attempts=2)
    ctx = {"url": url, "host": host, "domain": domain,
           "authorized": scope.is_authorized(url), "timeout": 8,
           "profile": "deep",
           "html": r.get("body") or "",
           "headers": lower_headers(r.get("headers") or {}),
           "cookie_headers": [], "status": r.get("status"),
           "ips": resolve_ips(domain if "." in domain else host),
           "pages": [], "scripts": [], "subdomains": [], "tls": {},
           "whois": {}, "ports_data": {}}
    try:
        ctx["cookie_headers"] = list(
            r.get("headers").get_all("Set-Cookie") or [])
    except Exception:
        pass
    if name in ("cookies", "paths", "ipintel", "timeline", "wireshark"):
        crawl_res = BY_NAME["crawl"].run(ctx)
        ctx["pages"] = (crawl_res.get("data") or {}).get("pages") or []
        ctx["scripts"] = (crawl_res.get("data") or {}).get("scripts") or []
        ctx["cookie_headers"] = list(dict.fromkeys(
            ctx["cookie_headers"]
            + ((crawl_res.get("data") or {}).get("cookie_headers") or [])))
    if name == "timeline":
        ctx["tls"] = BY_NAME["tls"].run(ctx).get("data") or {}
        ctx["whois"] = BY_NAME["whois"].run(ctx).get("data") or {}
    if name == "ipintel":
        ctx["ports_data"] = BY_NAME["ports"].run(ctx).get("data") or {}
    if name in ("netexec", "bloodhound"):
        ctx["ports_data"] = BY_NAME["ports"].run(ctx).get("data") or {}
        ctx["open_ports_all"] = sorted(
            {item.get("port")
             for item in (ctx["ports_data"].get("open_ports") or [])})
        from webdon.adapters import netexec as netexec_mod
        ctx["ad_indicators"] = netexec_mod.detect_ad_indicators(ctx)
    out = engine_mod.call_with_timeout(
        lambda: BY_NAME[name].run(ctx), 90)
    if isinstance(out, dict) and out.get("timed_out"):
        print("timeout")
        return
    print("Engine: %s — %s" % (name, (out or {}).get("status")))
    for f in (out or {}).get("findings") or []:
        print("  [%s] %s" % (f["severity"].upper(), f["name"]))
        print("      %s" % f.get("evidence", "")[:180])


def compare_cmd(arg, lang):
    parts = arg.split()
    if len(parts) != 2:
        print("compare <id1> <id2>   (see history for ids)")
        return
    try:
        a = storage_mod.get_scan(DB_FILE, int(parts[0]))
        b = storage_mod.get_scan(DB_FILE, int(parts[1]))
    except ValueError:
        a = b = None
    if not a or not b:
        print("scan not found — type history")
        return
    diff = storage_mod.compare_scans(a, b)
    print("=" * 60)
    print("Compare #%s -> #%s" % (parts[0], parts[1]))
    print("Score: %s -> %s    Coverage: %s%% -> %s%%" % (
        diff["score"][0], diff["score"][1],
        diff["coverage"][0], diff["coverage"][1]))
    for f in diff["added"]:
        print("  + [%s] %s" % (f["severity"].upper(), f["name"]))
    for f in diff["removed"]:
        print("  - [%s] %s" % (f["severity"].upper(), f["name"]))
    for c in diff["changed"]:
        print("  ~ %s: %s -> %s" % (c["name"], c["from"], c["to"]))
    if not diff["added"] and not diff["removed"] and not diff["changed"]:
        print("  (no changes)")
    print("=" * 60)


def resume_cmd(arg, lang, scope):
    parts = arg.split()
    if len(parts) != 1:
        print("resume <id>   (see history for ids)")
        return
    try:
        scan_id = int(parts[0])
    except ValueError:
        print("resume <id>   (see history for ids)")
        return
    print("%s #%d ..." % (t(lang, "help_resume"), scan_id))
    scan, resumed = engine_mod.resume_scan(DB_FILE, scan_id, scope=scope)
    if scan is None:
        print("scan not found — type history")
        return
    if not resumed:
        print("nothing to resume — no timed-out or failed engines")
        return
    print("resumed: %s" % ", ".join(resumed))
    report_mod.print_report(scan, lang)


def summary_cmd(arg, lang):
    """Re-print the executive summary of a stored scan: summary <id>."""
    try:
        scan_id = int(arg.split()[0])
    except (ValueError, IndexError):
        print("summary <id>   (see history for ids)")
        return
    scan = storage_mod.get_scan(DB_FILE, scan_id)
    if not scan:
        print("scan not found — type history")
        return
    summary = scan.get("summary") or summary_mod.build_summary(scan)
    print(summary_mod.format_summary(summary, lang))


def report_cmd(arg, lang):
    """report generate <id> [json|html] — export a stored scan.
    report list — list stored scans."""
    parts = arg.split()
    if not parts or parts[0] == "list":
        show_history(lang)
        return
    if parts[0] == "generate" and len(parts) >= 2:
        try:
            scan_id = int(parts[1])
        except ValueError:
            print("report generate <id> [json|html]")
            return
        scan = storage_mod.get_scan(DB_FILE, scan_id)
        if not scan:
            print("scan not found — type history")
            return
        fmt = parts[2] if len(parts) > 2 else "json"
        path = "webdon-report-%d.%s" % (scan_id, fmt)
        if fmt == "html":
            report_mod.to_html(scan, path)
        else:
            report_mod.to_json(scan, path)
        print("Saved: %s" % path)
        return
    print("report list | report generate <id> [json|html]")


def scope_cmd(arg, lang, scope):
    """scope create <url> | scope list | scope revoke <url>"""
    parts = arg.split()
    if not parts or parts[0] == "list":
        items = scope.list()
        print("=" * 60)
        print("WEBDON — %s" % t(lang, "scope_list"))
        if not items:
            print(t(lang, "scope_empty"))
        for item in items:
            print("  • %s" % item)
        print("=" * 60)
        return
    if parts[0] == "create" and len(parts) == 2:
        url = normalize_url(parts[1])
        if not valid_url(url):
            print(t(lang, "invalid_url"))
            return
        host = scope.authorize(url)
        print("%s: %s" % (t(lang, "scope_created"), host))
        return
    if parts[0] == "revoke" and len(parts) == 2:
        host = scope.revoke(parts[1])
        print("revoked: %s" % host)
        return
    print("scope create <url> | scope list | scope revoke <url>")


def print_help(lang):
    print("=" * 60)
    print("WEBDON — %s" % t(lang, "help_title"))
    print("  scope create <url> — %s" % t(lang, "help_scope"))
    print("  scope list         — %s" % t(lang, "scope_list"))
    print("  hive <url> / auto  — HIVE: every tool, one command (6 waves)")
    print("  tools list | tools check <n> | tools install <n>")
    print("  zap export <url>   — ZAP context + PC plan")
    print("  zap run <url>      — run ZAP only if installed (PC)")
    print("  openvas export <url> | openvas run <url> — GVM server")
    print("  netexec run <ip>   — AD check, anonymous only, opt-in")
    print("  bloodhound export <url> | bloodhound import <file>")
    print("  neo export [id] | neo push [id] — cloud hook (env key only)")
    print("  proxy              — Burp-like request log")
    print("  repeater <id> [H: v] — resend a logged request")
    print("  sitemap [id]       — crawled URL tree")
    print("  scanner [id]       — built-in misconfiguration summary")
    print("  scan <url>         — %s" % t(lang, "help_scan"))
    print("  scan quick|deep|forensic <url> — scan with a profile")
    print("  engine <n> <url>   — %s" % t(lang, "help_engine"))
    print("  engines            — %s" % t(lang, "help_engines"))
    print("  verify             — %s" % t(lang, "help_verify"))
    print("  report list        — %s" % t(lang, "help_history"))
    print("  report generate <id> [json|html] — export a stored scan")
    print("  compare <a> <b>    — %s" % t(lang, "help_compare"))
    print("  resume <id>        — %s" % t(lang, "help_resume"))
    print("  summary <id>       — Executive summary of a stored scan")
    print("  profile <name>     — %s (quick / deep / forensic)" % t(lang, "help_profile"))
    print("  history            — %s" % t(lang, "help_history"))
    print("  lang               — %s" % t(lang, "help_lang"))
    print("  clear              — clear the screen")
    print("  about              — %s" % t(lang, "about"))
    print("  help               — %s" % t(lang, "help_title"))
    print("  exit / 0           — %s" % t(lang, "help_exit"))
    print("=" * 60)


def console():
    settings = load_settings()
    print(WEBDON_BANNER % __version__)
    print(t("ar", "choose_language"))
    lang = choose_language()
    settings["language"] = lang
    save_settings(settings)
    profile = settings.get("profile", "deep")
    scope = Scope()
    print("%s — %s" % (t(lang, "app_subtitle"), t(lang, "org")))
    print(t(lang, "developer"))
    print(t(lang, "welcome"))
    print(t(lang, "how_to"))
    print("profile: %s" % profile)
    show_welcome(lang)
    while True:
        try:
            raw = input("\nwebdon > ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n%s" % t(lang, "goodbye"))
            return
        if not raw:
            continue
        parts = raw.split(None, 1)
        cmd = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else ""
        if cmd in ("exit", "quit", "0"):
            print(t(lang, "goodbye"))
            return
        if cmd == "help":
            print_help(lang)
        elif cmd in ("about", "welcome"):
            show_welcome(lang, pause=False)
        elif cmd == "lang":
            lang = choose_language()
            settings["language"] = lang
            save_settings(settings)
            print("Language: %s" % lang)
        elif cmd == "clear":
            os.system("clear" if os.name != "nt" else "cls")
        elif cmd == "profile":
            if arg in PROFILES:
                profile = arg
                settings["profile"] = profile
                save_settings(settings)
                print("profile: %s (%d phases)" % (
                    profile, engine_mod.total_phases(profile)))
            else:
                print("quick / deep / forensic")
        elif cmd == "history":
            show_history(lang)
        elif cmd == "engines":
            list_engines()
        elif cmd == "engine":
            eparts = arg.split(None, 1)
            if len(eparts) != 2:
                print("engine <name> <url>")
            else:
                run_single_engine(eparts[0], eparts[1], lang, scope)
        elif cmd == "scope":
            scope_cmd(arg, lang, scope)
        elif cmd == "verify":
            do_verify(lang)
        elif cmd == "report":
            report_cmd(arg, lang)
        elif cmd == "compare":
            compare_cmd(arg, lang)
        elif cmd == "resume":
            resume_cmd(arg, lang, scope)
        elif cmd == "summary":
            summary_cmd(arg, lang)
        elif cmd == "scan":
            scan_parts = arg.split(None, 1)
            if scan_parts and scan_parts[0] in PROFILES:
                profile = scan_parts[0]
                target = scan_parts[1] if len(scan_parts) > 1 else ""
            else:
                target = arg
            if not target:
                try:
                    target = input("%s " % t(lang, "enter_url")).strip()
                except (EOFError, KeyboardInterrupt):
                    continue
            scan = do_scan(target, profile, lang, scope, settings)
            if scan:
                dashboard(scan, lang)
        elif cmd in ("hive", "auto"):
            if not arg:
                try:
                    arg = input("%s " % t(lang, "enter_url")).strip()
                except (EOFError, KeyboardInterrupt):
                    continue
            scan = do_hive(arg, lang, scope, settings)
            if scan:
                dashboard(scan, lang)
        elif cmd == "tools":
            tools_cmd(arg, lang)
        elif cmd == "zap":
            zap_cmd(arg, lang, scope)
        elif cmd == "openvas":
            openvas_cmd(arg, lang, scope)
        elif cmd == "netexec":
            netexec_cmd(arg, lang, scope)
        elif cmd == "bloodhound":
            bloodhound_cmd(arg, lang, scope)
        elif cmd == "neo":
            neo_cmd(arg, lang)
        elif cmd == "proxy":
            proxy_cmd(arg, lang)
        elif cmd == "repeater":
            repeater_cmd(arg, lang, scope)
        elif cmd == "sitemap":
            sitemap_cmd(arg, lang)
        elif cmd == "scanner":
            scanner_cmd(arg, lang)
        elif valid_url(normalize_url(raw)):
            scan = do_scan(raw, profile, lang, scope, settings)
            if scan:
                dashboard(scan, lang)
        else:
            print(t(lang, "unknown_command"))


def main(argv):
    if "--version" in argv:
        print("WEBDON v%s" % __version__)
        return 0
    settings = load_settings()
    lang = settings.get("language", "ar")
    profile = settings.get("profile", "deep")
    url = None
    json_out = None
    html_out = None
    scan_flag = False
    hive_flag = False
    schema_path = None
    i = 1
    while i < len(argv):
        a = argv[i]
        if a == "--scan" and i + 1 < len(argv):
            scan_flag = True
            url = argv[i + 1]
            i += 2
        elif a == "--hive" and i + 1 < len(argv):
            hive_flag = True
            url = argv[i + 1]
            i += 2
        elif a == "--schema" and i + 1 < len(argv):
            schema_path = argv[i + 1]
            i += 2
        elif a == "--profile" and i + 1 < len(argv):
            profile = argv[i + 1]
            i += 2
        elif a == "--lang" and i + 1 < len(argv):
            lang = argv[i + 1]
            i += 2
        elif a == "--json" and i + 1 < len(argv):
            json_out = argv[i + 1]
            i += 2
        elif a == "--html" and i + 1 < len(argv):
            html_out = argv[i + 1]
            i += 2
        elif not a.startswith("-"):
            url = a
            i += 1
        else:
            i += 1
    if profile not in PROFILES:
        profile = "deep"
    if not url:
        console()
        return 0
    scope = Scope()
    url = normalize_url(url)
    if not valid_url(url):
        print(t(lang, "invalid_url"))
        return 2
    if not scope.is_authorized(url):
        print(t(lang, "scope_required"))
        return 3
    try:
        if hive_flag:
            scan = hive_mod.run_hive(url, scope=scope, settings=settings,
                                     schema_path=schema_path)
            print("HIVE waves: %s" % " -> ".join(hive_mod.wave_names()))
            for name, info in (scan.get("hive") or {}).get(
                    "adapters", {}).items():
                print("  %-12s %-28s %s" % (name, info.get("status", ""),
                                            info.get("mode", "")[:60]))
        else:
            scan = engine_mod.run_scan(url, profile=profile, scope=scope,
                                       settings=settings)
    except PermissionError as exc:
        print(str(exc))
        return 3
    report_mod.print_report(scan, lang)
    try:
        storage_mod.save_scan(DB_FILE, scan)
    except Exception:
        pass
    if json_out:
        print("Saved: %s" % report_mod.to_json(scan, json_out))
    if html_out:
        print("Saved: %s" % report_mod.to_html(scan, html_out))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
