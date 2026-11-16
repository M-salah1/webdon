#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SQLite storage: one row per scan (full report as JSON) plus one row
per engine run (engine, status, duration, retries, error).

v4.00 EVIDENCE adds two tables:

- finding_fp: operator-marked false positives (target + finding
  key + reason + timestamp). Marked findings are EXCLUDED from
  the score (never silently deleted — they stay in the report as
  suppressed, with the reason) and auto-suppressed on later scans
  of the same target.
- finding_history: per-finding first_seen / last_seen / status
  for one target (the timeline). Existing rows are backfilled
  from stored scans with first_seen = that scan's date.

The report never contains secret values — engines only ever record
names, flags, statuses and redacted evidence.
"""
import json
import os
import sqlite3
import time

DB_FILE = "webdon-scans.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    profile TEXT,
    started_at TEXT,
    finished_at TEXT,
    duration_s REAL,
    score INTEGER,
    grade TEXT,
    coverage INTEGER,
    report_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS engine_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    engine TEXT NOT NULL,
    status TEXT NOT NULL,
    duration_s REAL,
    retries INTEGER,
    error TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans (id)
);
CREATE TABLE IF NOT EXISTS finding_fp (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    finding_key TEXT NOT NULL,
    finding_name TEXT,
    reason TEXT,
    marked_at TEXT,
    scan_id INTEGER,
    UNIQUE(target, finding_key)
);
CREATE TABLE IF NOT EXISTS finding_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    finding_key TEXT NOT NULL,
    finding_name TEXT,
    first_seen TEXT,
    last_seen TEXT,
    last_scan_id INTEGER,
    status TEXT,
    UNIQUE(target, finding_key)
);
CREATE TABLE IF NOT EXISTS evidence_bundles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    finding_id TEXT NOT NULL,
    finding_name TEXT,
    bundle_json TEXT NOT NULL,
    verified_at TEXT,
    legacy INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (scan_id) REFERENCES scans (id)
);
"""


def init_db(path):
    conn = sqlite3.connect(path)
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()
    return path


def _utcnow():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _key_of(finding):
    """Stable key for a finding (finding_key, else name)."""
    from . import evidence as evidence_mod
    return finding.get("finding_key") or evidence_mod.finding_key(
        finding.get("name", ""))


def _recompute(scan):
    """Recompute score/grade/distribution/recommendations/summary
    from the current (non-suppressed) findings, in place."""
    from . import scoring as scoring_mod
    from . import summary as summary_mod
    findings = scan.get("findings") or []
    coverage = (scan.get("coverage") or {}).get("percent", 0)
    if coverage < 50 or scan.get("unreachable"):
        scan["score"] = None
        scan["grade"] = "INCOMPLETE"
        dist = {}
        for f in findings:
            dist[f["severity"]] = dist.get(f["severity"], 0) + 1
    else:
        score, grade, dist = scoring_mod.score_findings(findings)
        scan["score"] = score
        scan["grade"] = grade
    scan["severity_distribution"] = dist
    scan["recommendations"] = list(dict.fromkeys(
        f.get("fix", "") for f in findings if f.get("fix")))[:8]
    if scan.get("metrics") is not None:
        scan["metrics"]["security_score"] = scan.get("score")
    try:
        scan["summary"] = summary_mod.build_summary(scan)
    except Exception:
        pass
    return scan


def _record_history(conn, scan_id, scan):
    """Upsert first_seen/last_seen for every finding of a scan."""
    target = scan.get("target") or ""
    seen_at = scan.get("finished_at") or scan.get("started_at") \
        or _utcnow()
    current = set()
    # Suppressed (operator-marked FP) findings still count as
    # present: marking one must not fake a "closed" event.
    for f in (scan.get("findings") or []) + \
            (scan.get("false_positives") or []):
        current.add(_key_of(f))
    for f in scan.get("findings") or []:
        key = _key_of(f)
        conn.execute(
            "INSERT INTO finding_history (target, finding_key,"
            " finding_name, first_seen, last_seen, last_scan_id,"
            " status) VALUES (?,?,?,?,?,?,?)"
            " ON CONFLICT(target, finding_key) DO UPDATE SET"
            " finding_name=excluded.finding_name,"
            " last_seen=excluded.last_seen,"
            " last_scan_id=excluded.last_scan_id, status='open'",
            (target, key, f.get("name"), seen_at, seen_at, scan_id,
             "open"))
    # Findings that disappeared since the last scan are closed.
    for (key,) in conn.execute(
            "SELECT finding_key FROM finding_history"
            " WHERE target=? AND status='open'", (target,)).fetchall():
        if key not in current:
            conn.execute(
                "UPDATE finding_history SET status='closed'"
                " WHERE target=? AND finding_key=?", (target, key))


def _apply_fp_marks(conn, scan):
    """Move previously-marked false positives out of the findings
    of a new scan of the same target, then recompute the score."""
    target = scan.get("target") or ""
    rows = conn.execute(
        "SELECT finding_key, reason FROM finding_fp WHERE target=?",
        (target,)).fetchall()
    if not rows:
        return scan
    marks = {k: r for k, r in rows}
    kept, suppressed = [], list(scan.get("false_positives") or [])
    for f in scan.get("findings") or []:
        key = _key_of(f)
        if key in marks:
            item = dict(f)
            item["fp_reason"] = marks[key]
            item["validation"] = dict(item.get("validation") or {})
            item["validation"]["status"] = "false_positive"
            item["validation"]["reason"] = marks[key]
            suppressed.append(item)
        else:
            kept.append(f)
    if len(kept) != len(scan.get("findings") or []):
        scan["findings"] = kept
        scan["false_positives"] = suppressed
        _recompute(scan)
    return scan


def save_scan(db_path, scan, base_dir=None):
    """Store the scan + its engine runs. Returns the scan id."""
    init_db(db_path)
    conn = sqlite3.connect(db_path)
    try:
        scan = _apply_fp_marks(conn, scan)
        payload = json.dumps(scan, ensure_ascii=False)
        cur = conn.execute(
            "INSERT INTO scans (target, profile, started_at, finished_at,"
            " duration_s, score, grade, coverage, report_json)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (scan.get("target"), scan.get("profile"),
             scan.get("started_at"), scan.get("finished_at"),
             scan.get("duration_s"), scan.get("score"), scan.get("grade"),
             (scan.get("coverage") or {}).get("percent"), payload))
        scan_id = cur.lastrowid
        for name, run in (scan.get("engine_status") or {}).items():
            conn.execute(
                "INSERT INTO engine_runs (scan_id, engine, status,"
                " duration_s, retries, error) VALUES (?,?,?,?,?,?)",
                (scan_id, name, run.get("status"),
                 run.get("duration_s"), run.get("retries", 0),
                 (run.get("error") or "")[:500]))
        _record_history(conn, scan_id, scan)
        _save_bundles(conn, scan_id, scan)
        conn.commit()
        return scan_id
    finally:
        conn.close()


def _save_bundles(conn, scan_id, scan):
    """Store the scan's evidence bundles (v5.1), one per finding."""
    from . import assurance as assurance_mod
    bundles = scan.get("evidence_bundles") or []
    if not bundles:
        # Old scan shape / in-memory scan without bundles: build
        # legacy bundles from stored evidence where possible.
        bundles = [assurance_mod.migrate_bundle(f, scan.get("target")
                                                or "")
                   for f in (scan.get("findings") or [])
                   + (scan.get("false_positives") or [])]
    for b in bundles:
        conn.execute(
            "INSERT INTO evidence_bundles (scan_id, finding_id,"
            " finding_name, bundle_json, verified_at, legacy)"
            " VALUES (?,?,?,?,?,?)",
            (scan_id, b.get("finding_id"), b.get("finding_name"),
             json.dumps(b, ensure_ascii=False),
             b.get("verified_at"), 1 if b.get("legacy") else 0))


def get_evidence_bundle(db_path, scan_id, finding_id):
    """One stored evidence bundle (dict) or None."""
    if not os.path.exists(db_path):
        return None
    init_db(db_path)
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            "SELECT bundle_json FROM evidence_bundles"
            " WHERE scan_id=? AND finding_id=?",
            (scan_id, (finding_id or "").upper())).fetchone()
        if not row:
            return None
        try:
            return json.loads(row[0])
        except Exception:
            return None
    finally:
        conn.close()


def list_evidence_bundles(db_path, scan_id):
    """All stored evidence bundles of one scan (list of dicts)."""
    if not os.path.exists(db_path):
        return []
    init_db(db_path)
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(
            "SELECT bundle_json FROM evidence_bundles"
            " WHERE scan_id=? ORDER BY id ASC", (scan_id,)).fetchall()
        out = []
        for (raw,) in rows:
            try:
                out.append(json.loads(raw))
            except Exception:
                pass
        return out
    finally:
        conn.close()


def update_scan(db_path, scan_id, scan):
    """Replace a stored scan (used by resume) with the new report."""
    init_db(db_path)
    payload = json.dumps(scan, ensure_ascii=False)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "UPDATE scans SET target=?, profile=?, started_at=?,"
            " finished_at=?, duration_s=?, score=?, grade=?,"
            " coverage=?, report_json=? WHERE id=?",
            (scan.get("target"), scan.get("profile"),
             scan.get("started_at"), scan.get("finished_at"),
             scan.get("duration_s"), scan.get("score"), scan.get("grade"),
             (scan.get("coverage") or {}).get("percent"), payload, scan_id))
        conn.execute("DELETE FROM engine_runs WHERE scan_id=?",
                     (scan_id,))
        conn.execute("DELETE FROM evidence_bundles WHERE scan_id=?",
                     (scan_id,))
        _save_bundles(conn, scan_id, scan)
        for name, run in (scan.get("engine_status") or {}).items():
            conn.execute(
                "INSERT INTO engine_runs (scan_id, engine, status,"
                " duration_s, retries, error) VALUES (?,?,?,?,?,?)",
                (scan_id, name, run.get("status"),
                 run.get("duration_s"), run.get("retries", 0),
                 (run.get("error") or "")[:500]))
        _record_history(conn, scan_id, scan)
        conn.commit()
    finally:
        conn.close()


def list_scans(db_path, limit=20):
    if not os.path.exists(db_path):
        return []
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(
            "SELECT id, target, profile, finished_at, score, grade,"
            " coverage FROM scans ORDER BY id DESC LIMIT ?",
            (limit,)).fetchall()
        return [{"id": r[0], "target": r[1], "profile": r[2],
                 "finished_at": r[3], "score": r[4], "grade": r[5],
                 "coverage": r[6]} for r in rows]
    finally:
        conn.close()


def list_scans_by_target(db_path, target, limit=50):
    """All scans of one target, chronological (oldest first)."""
    if not os.path.exists(db_path):
        return []
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(
            "SELECT id, target, profile, finished_at, score, grade,"
            " coverage, report_json FROM scans WHERE target=?"
            " ORDER BY id ASC LIMIT ?",
            (target, limit)).fetchall()
        out = []
        for r in rows:
            try:
                scan = json.loads(r[7])
            except Exception:
                scan = {}
            out.append({"id": r[0], "target": r[1], "profile": r[2],
                        "finished_at": r[3], "score": r[4],
                        "grade": r[5], "coverage": r[6],
                        "findings": scan.get("findings") or [],
                        "false_positives":
                            scan.get("false_positives") or []})
        return out
    finally:
        conn.close()


def compare_scans(a, b):
    """Diff two scans by finding key.

    Keeps the old keys (added/removed/changed) and adds the
    v4.00 statuses: new / fixed / persisting / changed /
    fp_suppressed, plus the score delta. A finding is 'fixed'
    when it was in A and is gone in B; 'new' when it appears in
    B only; 'persisting' when it is in both with the same
    severity; 'changed' when severity or confirmation differs.
    """
    def by_key(s):
        out = {}
        for f in s.get("findings") or []:
            out[_key_of(f)] = f
        return out

    def fp_keys(s):
        return {_key_of(f): f for f in s.get("false_positives") or []}

    fa, fb = by_key(a), by_key(b)
    added = [fb[n] for n in fb if n not in fa]
    removed = [fa[n] for n in fa if n not in fb]
    changed = []
    persisting = []
    for n in fa:
        if n not in fb:
            continue
        if fa[n]["severity"] != fb[n]["severity"] or \
                fa[n].get("confirmation") != fb[n].get("confirmation"):
            changed.append({"name": fa[n]["name"], "key": n,
                            "from": fa[n]["severity"],
                            "to": fb[n]["severity"],
                            "confirmation_from":
                                fa[n].get("confirmation"),
                            "confirmation_to":
                                fb[n].get("confirmation")})
        else:
            persisting.append(fb[n])
    fp_a, fp_b = fp_keys(a), fp_keys(b)
    fp_suppressed = []
    for n in fp_a:
        if n not in fb:
            fp_suppressed.append(fp_a[n])
    for n in fp_b:
        if n not in fb and n not in fp_a:
            fp_suppressed.append(fp_b[n])
    score_a, score_b = a.get("score"), b.get("score")
    delta = None
    if score_a is not None and score_b is not None:
        delta = score_b - score_a
    return {"score": (score_a, score_b),
            "score_delta": delta,
            "coverage": ((a.get("coverage") or {}).get("percent"),
                         (b.get("coverage") or {}).get("percent")),
            "added": added, "removed": removed, "changed": changed,
            "new": added, "fixed": removed,
            "persisting": persisting,
            "fp_suppressed": fp_suppressed}


def get_scan(db_path, scan_id):
    if not os.path.exists(db_path):
        return None
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            "SELECT report_json FROM scans WHERE id = ?",
            (scan_id,)).fetchone()
        if not row:
            return None
        scan = json.loads(row[0])
        # Migrate legacy findings (string evidence only) to the
        # structured evidence object.
        from . import evidence as evidence_mod
        target = scan.get("target") or ""
        for f in (scan.get("findings") or []) + \
                (scan.get("false_positives") or []):
            try:
                evidence_mod.migrate_finding(f, target)
            except Exception:
                pass
        # v5.00 DEEP-DIVE migration: old scans have no chain
        # fields — they are L0 findings (depth 0, parent null).
        for f in (scan.get("findings") or []) + \
                (scan.get("false_positives") or []):
            f.setdefault("depth", 0)
            f.setdefault("parent_id", None)
            f.setdefault("follow_ups", [])
            f.setdefault("chain", f.get("finding_id"))
        scan.setdefault("deepdive", {
            "status": "not_run", "max_depth": 0, "deepest": 0,
            "probes_run": 0, "new_findings": 0,
            "new_findings_by_depth": {}, "stop_reason": None})
        # v5.1 EVIDENCE BUNDLES: load stored bundles; old scans get
        # legacy bundles rebuilt from their stored evidence.
        try:
            stored = list_evidence_bundles(db_path, scan_id)
        except Exception:
            stored = []
        if stored:
            scan["evidence_bundles"] = stored
        else:
            from . import assurance as assurance_mod
            scan["evidence_bundles"] = [
                assurance_mod.migrate_bundle(f, target)
                for f in (scan.get("findings") or [])
                + (scan.get("false_positives") or [])]
        for f in (scan.get("findings") or []) + \
                (scan.get("false_positives") or []):
            f.setdefault("evidence_bundle_id",
                         "EB-%s" % (f.get("finding_id") or "?"))
        return scan
    finally:
        conn.close()


def mark_fp(db_path, scan_id, finding_ref, reason):
    """Mark one finding of a stored scan as a false positive.

    finding_ref is a finding_id (F-001) or a finding key. The
    finding is moved to the suppressed list with the reason, the
    score is recomputed, and the mark is stored so later scans of
    the same target auto-suppress it. Returns (ok, info|error).
    """
    scan = get_scan(db_path, scan_id)
    if not scan:
        return False, "scan not found"
    target = scan.get("target") or ""
    ref = (finding_ref or "").strip().lower()
    hit = None
    for f in scan.get("findings") or []:
        if (f.get("finding_id") or "").lower() == ref or \
                _key_of(f) == ref:
            hit = f
            break
    if hit is None:
        return False, "finding not found: %s" % finding_ref
    reason = (reason or "").strip() or "operator-marked false positive"
    init_db(db_path)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "INSERT INTO finding_fp (target, finding_key, finding_name,"
            " reason, marked_at, scan_id) VALUES (?,?,?,?,?,?)"
            " ON CONFLICT(target, finding_key) DO UPDATE SET"
            " reason=excluded.reason, marked_at=excluded.marked_at,"
            " scan_id=excluded.scan_id",
            (target, _key_of(hit), hit.get("name"), reason,
             _utcnow(), scan_id))
        conn.commit()
    finally:
        conn.close()
    scan["findings"] = [f for f in scan.get("findings") or []
                        if f is not hit]
    item = dict(hit)
    item["fp_reason"] = reason
    item["validation"] = dict(item.get("validation") or {})
    item["validation"]["status"] = "false_positive"
    item["validation"]["reason"] = reason
    scan.setdefault("false_positives", []).append(item)
    _recompute(scan)
    update_scan(db_path, scan_id, scan)
    return True, {"finding": hit.get("name"), "reason": reason,
                  "score": scan.get("score"), "grade": scan.get("grade")}


def unmark_fp(db_path, scan_id, finding_ref):
    """Undo a false-positive mark: the finding returns to the
    findings list and the score is recomputed."""
    scan = get_scan(db_path, scan_id)
    if not scan:
        return False, "scan not found"
    target = scan.get("target") or ""
    ref = (finding_ref or "").strip().lower()
    hit = None
    for f in scan.get("false_positives") or []:
        if (f.get("finding_id") or "").lower() == ref or \
                _key_of(f) == ref:
            hit = f
            break
    if hit is None:
        return False, "finding not found among suppressed: %s" \
            % finding_ref
    init_db(db_path)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "DELETE FROM finding_fp WHERE target=? AND finding_key=?",
            (target, _key_of(hit)))
        conn.commit()
    finally:
        conn.close()
    scan["false_positives"] = [
        f for f in scan.get("false_positives") or [] if f is not hit]
    item = dict(hit)
    item.pop("fp_reason", None)
    val = dict(item.get("validation") or {})
    val["status"] = "observed"
    val.pop("reason", None)
    item["validation"] = val
    scan.setdefault("findings", []).append(item)
    scan["findings"].sort(key=lambda f: {"critical": 0, "high": 1,
                                         "medium": 2, "low": 3,
                                         "info": 4}.get(
                                             f.get("severity"), 5))
    _recompute(scan)
    update_scan(db_path, scan_id, scan)
    return True, {"finding": hit.get("name"),
                  "score": scan.get("score"), "grade": scan.get("grade")}


def list_fps(db_path, target=None):
    """Operator-marked false positives (all, or one target)."""
    if not os.path.exists(db_path):
        return []
    init_db(db_path)
    conn = sqlite3.connect(db_path)
    try:
        if target:
            rows = conn.execute(
                "SELECT target, finding_key, finding_name, reason,"
                " marked_at, scan_id FROM finding_fp WHERE target=?"
                " ORDER BY marked_at DESC", (target,)).fetchall()
        else:
            rows = conn.execute(
                "SELECT target, finding_key, finding_name, reason,"
                " marked_at, scan_id FROM finding_fp"
                " ORDER BY marked_at DESC").fetchall()
        return [{"target": r[0], "finding_key": r[1],
                 "finding_name": r[2], "reason": r[3],
                 "marked_at": r[4], "scan_id": r[5]} for r in rows]
    finally:
        conn.close()


def backfill_history(db_path, target):
    """Build finding_history for a target from its stored scans.

    First_seen is the date of the scan where the finding first
    appeared; last_seen is the latest scan where it was present.
    """
    scans = list_scans_by_target(db_path, target)
    if not scans:
        return
    init_db(db_path)
    conn = sqlite3.connect(db_path)
    try:
        for scan in scans:
            seen_at = scan.get("finished_at") or _utcnow()
            for f in scan.get("findings") or []:
                conn.execute(
                    "INSERT INTO finding_history (target, finding_key,"
                    " finding_name, first_seen, last_seen,"
                    " last_scan_id, status) VALUES (?,?,?,?,?,?,?)"
                    " ON CONFLICT(target, finding_key) DO UPDATE SET"
                    " finding_name=excluded.finding_name,"
                    " last_seen=excluded.last_seen,"
                    " last_scan_id=excluded.last_scan_id,"
                    " status='open'",
                    (target, _key_of(f), f.get("name"), seen_at,
                     seen_at, scan["id"], "open"))
        conn.commit()
    finally:
        conn.close()


def get_finding_history(db_path, target):
    if not os.path.exists(db_path):
        return []
    init_db(db_path)
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(
            "SELECT finding_key, finding_name, first_seen, last_seen,"
            " last_scan_id, status FROM finding_history WHERE target=?"
            " ORDER BY first_seen ASC",
            (target,)).fetchall()
        return [{"finding_key": r[0], "finding_name": r[1],
                 "first_seen": r[2], "last_seen": r[3],
                 "last_scan_id": r[4], "status": r[5]} for r in rows]
    finally:
        conn.close()


def timeline(db_path, target):
    """Chronological history for one target: score over time,
    findings opened/closed per scan, first/last seen per finding.
    """
    backfill_history(db_path, target)
    scans = list_scans_by_target(db_path, target)
    events = []
    prev_keys = set()
    scan_rows = []
    for scan in scans:
        # Suppressed findings still count as present (a mark is
        # not a fix — it must not fake a "closed" event).
        keys = {_key_of(f) for f in (scan.get("findings") or [])
                + (scan.get("false_positives") or [])}
        opened = sorted(keys - prev_keys)
        closed = sorted(prev_keys - keys)
        for key in opened:
            name = next((f.get("name") for f in scan["findings"]
                         if _key_of(f) == key), key)
            events.append({"date": scan.get("finished_at"),
                           "type": "opened", "finding_key": key,
                           "finding_name": name,
                           "scan_id": scan["id"]})
        for key in closed:
            events.append({"date": scan.get("finished_at"),
                           "type": "closed", "finding_key": key,
                           "finding_name": key,
                           "scan_id": scan["id"]})
        scan_rows.append({
            "id": scan["id"], "finished_at": scan.get("finished_at"),
            "profile": scan.get("profile"), "score": scan.get("score"),
            "grade": scan.get("grade"),
            "coverage": scan.get("coverage"),
            "findings": len(scan.get("findings") or []),
            "opened": opened, "closed": closed})
        prev_keys = keys
    return {"target": target, "scans": scan_rows,
            "findings": get_finding_history(db_path, target),
            "events": events}
