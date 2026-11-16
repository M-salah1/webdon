#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WEBDON v1.00 — entry point.

Terminal console (Arabic / French / English) + direct scan mode.
    python3 webdon.py                                  # console
    python3 webdon.py --scan https://example.com
    python3 webdon.py --scan https://example.com --profile forensic --json out.json

A signed scope is required before any scan:
    webdon > scope create https://example.com
"""
import getpass
import json
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from webdon import __version__  # noqa: E402
from webdon.core import engine as engine_mod  # noqa: E402
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
        "WEBDON v1.00 — أداة فحص المواقع الثقيلة",
        "نظام التحقيق الدفاعي الشامل — FOX COMPANY",
        "المطور: حافظ مهدي صلاح الدين — الجزائر",
        "",
        "ماذا تفعل الأداة؟",
        "• 13 محرك تحقيق: DNS/IP، WHOIS، SSL/TLS، رؤوس الحماية،",
        "  التقنيات، الزحف والمسارات، ملفات الإعداد المكشوفة،",
        "  الكوكيز، CORS، المنافذ، متابعة الـ IP وحده، الحمايات،",
        "  والخط الزمني — مع التحقق من كلمات السر المسرّبة (HIBP)",
        "• تعريف صاحب الموقع من السجلات العامة فقط (UNKNOWN إن حُجب)",
        "• بلد الموقع ومزوّد الاستضافة من الـ IP العام",
        "• تقارير JSON/HTML وحفظ كل فحص في قاعدة بيانات",
        "",
        "كيف تعمل؟",
        "1) وقّع الإذن:  scope create https://example.com",
        "2) افحص:       scan https://example.com",
        "3) تحقق من كلمة سر:  verify",
        "الأوامر: profile (quick/deep/forensic) — history — report — lang — help — exit",
        "",
        "حدود صادقة: عدد المستخدمين الآن، والأجهزة المتصلة، وهوية",
        "الأدمن الخاصة، وتجاوز الحماية — لا يمكن معرفتها سلبياً،",
        "والأداة تُبلغ عنها UNKNOWN ولا تخترع أرقاماً أبداً.",
    ],
    "en": [
        "WEBDON v1.00 — Heavy Website Investigation Tool",
        "Comprehensive defensive audit system — FOX COMPANY",
        "Developer: Hafed Mehdi Salah Eddine — Algeria",
        "",
        "What does it do?",
        "• 13 investigation engines: DNS/IP, WHOIS, SSL/TLS, security",
        "  headers, technologies, crawl & paths, exposed config files,",
        "  cookies, CORS, ports, IP follow-up alone, protections,",
        "  and timeline — plus leaked-password verification (HIBP)",
        "• Site owner from public records only (UNKNOWN if redacted)",
        "• Site country and hosting provider from the public IP",
        "• JSON/HTML reports and every scan saved in a database",
        "",
        "How to work?",
        "1) Sign authorization:  scope create https://example.com",
        "2) Scan:                scan https://example.com",
        "3) Verify a password:   verify",
        "Commands: profile (quick/deep/forensic) — history — report — lang — help — exit",
        "",
        "Honest limits: live user count, connected devices, private",
        "admin identity and protection bypass cannot be known",
        "passively — the tool reports them UNKNOWN and never invents",
        "numbers.",
    ],
    "fr": [
        "WEBDON v1.00 — Outil lourd d'investigation de sites web",
        "Système complet d'audit défensif — FOX COMPANY",
        "Développeur : Hafed Mehdi Salah Eddine — Algérie",
        "",
        "Que fait l'outil ?",
        "• 13 moteurs : DNS/IP, WHOIS, SSL/TLS, en-têtes de sécurité,",
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
        "2) Scannez :                scan https://example.com",
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
    return scan


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
    if name in ("cookies", "paths", "ipintel", "timeline"):
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
    i = 1
    while i < len(argv):
        a = argv[i]
        if a == "--scan" and i + 1 < len(argv):
            scan_flag = True
            url = argv[i + 1]
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
