#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SQLite storage: one row per scan (full report as JSON) plus one row
per engine run (engine, status, duration, retries, error).

The report never contains secret values — engines only ever record
names, flags, statuses and redacted evidence.
"""
import json
import os
import sqlite3

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
"""


def init_db(path):
    conn = sqlite3.connect(path)
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()
    return path


def save_scan(db_path, scan, base_dir=None):
    """Store the scan + its engine runs. Returns the scan id."""
    init_db(db_path)
    payload = json.dumps(scan, ensure_ascii=False)
    conn = sqlite3.connect(db_path)
    try:
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
        conn.commit()
        return scan_id
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
        for name, run in (scan.get("engine_status") or {}).items():
            conn.execute(
                "INSERT INTO engine_runs (scan_id, engine, status,"
                " duration_s, retries, error) VALUES (?,?,?,?,?,?)",
                (scan_id, name, run.get("status"),
                 run.get("duration_s"), run.get("retries", 0),
                 (run.get("error") or "")[:500]))
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


def compare_scans(a, b):
    """Diff two scans by finding name. Returns added/removed/changed."""
    def by_name(s):
        return {f["name"]: f for f in s.get("findings") or []}

    fa, fb = by_name(a), by_name(b)
    added = [fb[n] for n in fb if n not in fa]
    removed = [fa[n] for n in fa if n not in fb]
    changed = [{"name": n, "from": fa[n]["severity"],
                "to": fb[n]["severity"]}
               for n in fa
               if n in fb and fa[n]["severity"] != fb[n]["severity"]]
    return {"score": (a.get("score"), b.get("score")),
            "coverage": ((a.get("coverage") or {}).get("percent"),
                         (b.get("coverage") or {}).get("percent")),
            "added": added, "removed": removed, "changed": changed}


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
        # Legacy rows (flat metrics) are rebuilt by the caller if
        # needed; WEBDON always stores the nested shape.
        return scan
    finally:
        conn.close()
