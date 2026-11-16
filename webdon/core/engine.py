#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WEBDON orchestrator — runs the engines as one investigation (v1.00).

Waves (independent engines run in parallel inside each wave):
  1. crawl + headers + tls + tech    (needs only the homepage)
  2. dns + whois + cookies + cors + protect + paths
     (needs the crawl: pages, scripts, cookie headers)
  3. ports                         (needs the resolved IP)
  4. ipintel + timeline           (needs the ports result and the
     results of waves 1-2; ipintel is the second phase that
     re-investigates the IP alone)

Every engine runs with its own deadline inside one global budget.
A fast-failing engine is retried once with backoff; a timeout is
never retried — it is recorded as "timeout" and can be resumed
later with resume_scan(), which re-runs only the failed engines.
Partial results are saved and resumable.

The final pipeline: evidence -> validation -> correlation ->
confirmation-weighted scoring. Four separate metrics are reported:
Security Score (confirmed findings only), Confidence (computed
from validation), Coverage (measured from what was actually
done), Verification Rate (share of findings verified).

Scope is mandatory: run_scan() refuses without a signed scope.
"""
import concurrent.futures
import threading
import time

from ..core import assets as assets_mod
from ..core import summary as summary_mod
from ..core import correlation as correlation_mod
from ..core import evidence as evidence_mod
from ..core import scoring as scoring_mod
from ..core import validator as validator_mod
from ..core.http import get, lower_headers, request_retry, resolve_ips
from ..core.scope import normalize_url
from ..engines import BY_NAME, PHASES, PROFILES

ENGINE_DEADLINES = {
    "crawl": 90, "headers": 30, "tls": 40, "tech": 20,
    "dns": 40, "whois": 40, "cookies": 30, "cors": 20,
    "protect": 20, "paths": 90, "ports": 120, "ipintel": 40,
    "timeline": 30,
}

PROFILE_BUDGETS = {"quick": 120, "deep": 300, "forensic": 600}

# What WEBDON honestly cannot know. These are reported as UNKNOWN
# with a one-line explanation — never invented.
LIMITS = {
    "live_users": "UNKNOWN — the number of users on the site right now "
                  "cannot be obtained passively; only the site owner "
                  "can see it in their own analytics/server logs.",
    "devices_on_site": "UNKNOWN — the devices currently on the site "
                       "cannot be listed passively; only the site owner "
                       "can see them in their own server logs.",
    "admin_identity": "UNKNOWN unless published — the admin's private "
                      "identity/contact is never revealed; only the "
                      "public WHOIS organization or public security.txt "
                      "contact is reported, if published.",
    "admin_contact": "UNKNOWN unless published in WHOIS or security.txt "
                     "as a public contact.",
    "live_passwords": "UNKNOWN — real passwords are never harvested or "
                      "displayed. The verify command checks one "
                      "owner-provided password against HIBP "
                      "(k-anonymity) and answers YES/NO only.",
    "bypass_testing": "NOT PERFORMED — WAF/login/protection bypass is "
                      "never tested; protections are detected by "
                      "presence only.",
}


def call_with_timeout(fn, seconds):
    """Run fn in a daemon thread; return {"timed_out": True} on deadline."""
    result = {}

    def _run():
        try:
            result["value"] = fn()
        except Exception as exc:  # noqa: BLE001 - recorded, never raised
            result["error"] = str(exc)

    th = threading.Thread(target=_run, daemon=True)
    th.start()
    th.join(seconds)
    if th.is_alive():
        return {"timed_out": True, "error": "timeout after %ss" % seconds}
    if "error" in result:
        raise Exception(result["error"])
    return result.get("value")


def grade_for(score):
    return scoring_mod.grade_for(score)


def total_phases(profile):
    """Number of phases in a profile (DEEP/FORENSIC aim for 25+)."""
    total = 0
    for name in PROFILES.get(profile, PROFILES["deep"]):
        total += len(PHASES.get(name, [name]))
    return total


def _build_ctx(url, scope):
    """Fetch the homepage once; resolve IPs. Returns (ctx, authorized)."""
    authorized = False
    if scope is not None:
        try:
            authorized = bool(scope.is_authorized(url))
        except Exception:
            authorized = False
    host = url.split("/")[2] if "://" in url else url
    domain = host.split(":")[0]
    if domain.startswith("www."):
        domain = domain[4:]
    ctx = {"url": url, "host": host, "domain": domain,
           "authorized": authorized, "timeout": 8,
           "html": "", "headers": {}, "cookie_headers": [],
           "status": None, "ips": [], "pages": [], "scripts": [],
           "subdomains": [], "tls": {}, "whois": {}}
    r = request_retry(url, timeout=10, attempts=3)
    ctx["status"] = r.get("status")
    ctx["html"] = r.get("body") or ""
    ctx["headers"] = lower_headers(r.get("headers") or {})
    try:
        ctx["cookie_headers"] = list(
            r.get("headers").get_all("Set-Cookie") or [])
    except Exception:
        ctx["cookie_headers"] = []
    ctx["ips"] = resolve_ips(domain if "." in domain else host)
    return ctx, authorized


def _finalize(url, profile, engines, results, status, ctx, t0, authorized):
    """Framework pipeline + four metrics -> the scan dict."""
    raw = []
    for name in engines:
        for f in (results.get(name) or {}).get("findings") or []:
            item = dict(f)
            item["engine"] = name
            raw.append(item)
    evidence = evidence_mod.collect(raw)
    evidence = validator_mod.validate_all(evidence, ctx)
    validation_counts = {"verified": 0, "observed": 0, "false_positive": 0}
    kept = []
    false_positives = []
    for ev in evidence:
        st = (ev.get("validation") or {}).get("status", "observed")
        validation_counts[st] = validation_counts.get(st, 0) + 1
        (kept if st != "false_positive" else false_positives).append(ev)
    findings, chains, contradictions = correlation_mod.correlate(
        kept, results)
    for f in findings:
        if f.get("severity") == "info":
            f["confirmation"] = "info"
        elif (f.get("validation") or {}).get("status") == "verified":
            f["confirmation"] = "confirmed"
        elif f.get("confirmation") != "confirmed":
            f["confirmation"] = "indicator"
    assets = assets_mod.build_assets({"results": results}, ctx)

    phases_done = sum(len(PHASES.get(n, [n])) for n in engines
                      if (status.get(n) or {}).get("status") == "completed")
    phases_total = total_phases(profile)
    coverage = scoring_mod.compute_coverage(
        engines, status, results,
        phases={"done": phases_done, "total": phases_total})
    coverage["phases_done"] = phases_done
    coverage["phases_total"] = phases_total
    reachable = ctx["status"] is not None
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: order.get(f.get("severity"), 5))
    if coverage["percent"] < 50 or not reachable:
        score = None
        grade = "INCOMPLETE"
        dist = {}
        for f in findings:
            dist[f["severity"]] = dist.get(f["severity"], 0) + 1
    else:
        score, grade, dist = scoring_mod.score_findings(findings)
    confidence = scoring_mod.compute_confidence(validation_counts)
    verification_rate = scoring_mod.compute_verification_rate(
        validation_counts)
    duration = round(time.time() - t0, 1)
    completed = [n for n in engines
                 if (status.get(n) or {}).get("status") == "completed"]
    scan = {
        "tool": "WEBDON v1.00", "target": url, "profile": profile,
        "kind": "webdon-scan",
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                    time.gmtime(time.time() - duration)),
        "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "duration_s": duration,
        "score": score, "grade": grade,
        "confidence": confidence if score is not None else 0,
        "coverage": {**coverage,
                     "completed": len(completed), "total": len(engines),
                     "missing": [n for n in engines
                                 if n not in completed]},
        "metrics": {"security_score": score, "confidence": confidence,
                    "coverage_percent": coverage["percent"],
                    "verification_rate": verification_rate},
        "engines": engines, "engine_status": status,
        "results": results, "findings": findings,
        "severity_distribution": dist,
        "evidence": evidence, "validation": validation_counts,
        "false_positives": [
            {"name": ev["name"], "engine": ev["engine"],
             "evidence": ev["evidence"],
             "validation": ev["validation"]} for ev in false_positives],
        "chains": chains, "contradictions": contradictions,
        "assets": assets,
        "limits": dict(LIMITS),
        "recommendations": list(dict.fromkeys(
            f.get("fix", "") for f in findings if f.get("fix")))[:8],
        "scope": {"kind": "authorized" if authorized else "passive",
                  "authorized": authorized},
        "ips": ctx["ips"], "host": ctx["host"], "domain": ctx["domain"],
        "unreachable": not reachable,
    }
    scan["summary"] = summary_mod.build_summary(scan)
    return scan


def _execute(url, profile, scope, settings, progress, existing=None):
    """Run a scan from scratch, or resume one from (results, status).
    On resume, engines that timed out or errored are re-run; completed
    engines are kept."""
    settings = settings or {}
    url = normalize_url(url)
    budget = int(settings.get("scan_budget_s",
                              PROFILE_BUDGETS.get(profile, 240)))
    deadlines = dict(ENGINE_DEADLINES)
    deadlines.update(settings.get("engine_deadlines") or {})
    t0 = time.time()

    def tick(name):
        if progress:
            try:
                progress(name)
            except Exception:
                pass

    def budget_left():
        return budget - (time.time() - t0)

    ctx, authorized = _build_ctx(url, scope)
    ctx["profile"] = profile
    engines = PROFILES.get(profile, PROFILES["deep"])
    if existing:
        results, status = existing
        for n in list(results):
            if (status.get(n) or {}).get("status") in ("timeout", "error"):
                results.pop(n, None)
                status.pop(n, None)
    else:
        results, status = {}, {}

    def _run_engine(name):
        """Run one engine with deadline + one fast-failure retry."""
        tick(name)
        started = time.time()
        attempts = 0
        while True:
            attempts += 1
            try:
                out = call_with_timeout(
                    lambda: BY_NAME[name].run(ctx), deadlines[name])
            except Exception as exc:
                out = {"engine": name, "status": "error",
                       "findings": [], "data": {"error": str(exc)}}
            if isinstance(out, dict) and out.get("timed_out"):
                status[name] = {"status": "timeout",
                                "duration_s": round(time.time() - started, 1),
                                "retries": attempts - 1,
                                "error": out.get("error", "")}
                return {"engine": name, "status": "timeout",
                        "findings": [], "data": {}}
            st = (out or {}).get("status", "completed")
            if st == "error" and attempts <= 1 \
                    and time.time() - started < 10:
                time.sleep(2)
                continue
            status[name] = {"status": st,
                            "duration_s": round(time.time() - started, 1),
                            "retries": attempts - 1,
                            "error": ((out or {}).get("data") or {})
                                     .get("error", "")}
            return out or {"engine": name, "status": st,
                           "findings": [], "data": {}}

    def _run_wave(names):
        """Run a wave in parallel; collect results as they finish."""
        todo = [n for n in names if n in engines and n not in results]
        if not todo or budget_left() <= 5:
            for n in todo:
                tick(n)
                status[n] = {"status": "timeout", "duration_s": 0,
                             "retries": 0, "error": "global budget reached"}
                results[n] = {"engine": n, "status": "timeout",
                              "findings": [], "data": {}}
            return
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=len(todo))
        try:
            futs = {pool.submit(_run_engine, n): n for n in todo}
            done, _ = concurrent.futures.wait(
                futs, timeout=budget_left(),
                return_when=concurrent.futures.ALL_COMPLETED)
            for fut, name in futs.items():
                if fut in done:
                    try:
                        results[name] = fut.result()
                    except Exception as exc:
                        results[name] = {"engine": name, "status": "error",
                                         "findings": [], "data": {}}
                        status[name] = {"status": "error", "duration_s": 0,
                                        "retries": 0, "error": str(exc)}
                else:
                    tick(name)
                    status[name] = {"status": "timeout",
                                    "duration_s": deadlines[name],
                                    "retries": 0,
                                    "error": "global budget reached"}
                    results[name] = {"engine": name, "status": "timeout",
                                     "findings": [], "data": {}}
        finally:
            pool.shutdown(wait=False, cancel_futures=True)

    _run_wave(["crawl", "headers", "tls", "tech"])
    crawl_data = (results.get("crawl") or {}).get("data") or {}
    ctx["pages"] = crawl_data.get("pages") or []
    ctx["scripts"] = crawl_data.get("scripts") or []
    ctx["tls"] = (results.get("tls") or {}).get("data") or {}
    ctx["cookie_headers"] = list(dict.fromkeys(
        ctx.get("cookie_headers") or []
        + (crawl_data.get("cookie_headers") or [])))
    # Raw Set-Cookie lines contain cookie VALUES: drop them from the
    # stored crawl result now that the names/flags are in ctx.
    (results.get("crawl") or {}).get("data", {}).pop("cookie_headers",
                                                    None)
    _run_wave(["dns", "whois", "cookies", "cors", "protect", "paths"])
    ctx["whois"] = (results.get("whois") or {}).get("data") or {}
    _run_wave(["ports"])
    ctx["ports_data"] = (results.get("ports") or {}).get("data") or {}
    _run_wave(["ipintel", "timeline"])
    return _finalize(url, profile, engines, results, status, ctx, t0,
                     authorized)


def run_scan(url, profile="deep", scope=None, settings=None,
             progress=None):
    """Run one full WEBDON scan. Refuses without a signed scope.

    Raises PermissionError when the target has no signed scope.
    Returns the scan dict.
    """
    url = normalize_url(url)
    if scope is None or not scope.is_authorized(url):
        raise PermissionError(
            "No signed scope for %s — run: scope create %s" % (url, url))
    return _execute(url, profile, scope, settings, progress)


def resume_scan(db_path, scan_id, scope=None, settings=None,
                progress=None):
    """Re-run the timed-out / failed engines of a stored scan.
    Returns (scan, resumed_engine_names)."""
    from ..core import storage as storage_mod
    old = storage_mod.get_scan(db_path, scan_id)
    if not old:
        return None, []
    profile = old.get("profile", "deep")
    results = old.get("results") or {}
    status = old.get("engine_status") or {}
    resumed = [n for n in (old.get("engines") or [])
               if (status.get(n) or {}).get("status") in ("timeout", "error")]
    if not resumed:
        return old, []
    scan = _execute(old.get("target"), profile, scope, settings,
                    progress, existing=(results, status))
    scan["resumed_from"] = scan_id
    storage_mod.update_scan(db_path, scan_id, scan)
    return scan, resumed
