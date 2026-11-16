#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Schemathesis adapter — API schema checks (v3.00).

Runs ONLY when the owner supplies an OpenAPI schema file and the
scope is signed:
  schemathesis run <schema> --checks not_a_server_error
                 --hypothesis-max-examples 20
Read-only checks (no stateful data-creation runs by default).
Without a schema the adapter reports "skipped_no_schema" —
never a fake result.
"""
import os
import re

from . import NOT_INSTALLED, adapter_result, finding, is_installed, require_scope, run_cmd

NAME = "schemathesis"
TITLE = "Schemathesis — API schema checks"
BINARY = "schemathesis"

FAILED_RE = re.compile(r"(\d+)\s+failed", re.I)
PASSED_RE = re.compile(r"(\d+)\s+passed", re.I)


def build_args(schema_path):
    return [BINARY, "run", schema_path,
            "--checks", "not_a_server_error",
            "--hypothesis-max-examples", "20"]


def parse_summary(text):
    """Extract passed/failed counts from schemathesis output."""
    failed = 0
    passed = 0
    for line in (text or "").splitlines():
        m = FAILED_RE.search(line)
        if m:
            failed = int(m.group(1))
        m = PASSED_RE.search(line)
        if m:
            passed = int(m.group(1))
    return passed, failed


def run(ctx, timeout=300, runner=run_cmd, schema_path=None):
    require_scope(ctx)
    schema = schema_path or ctx.get("schema")
    if not schema or not os.path.isfile(schema):
        return adapter_result(NAME, "skipped_no_schema", [],
                              {"note": "no OpenAPI schema supplied; "
                                       "pass --schema <file> to enable "
                                       "API checks"})
    if not is_installed(BINARY):
        return adapter_result(
            NAME, NOT_INSTALLED, [],
            {"schema": os.path.basename(schema),
             "note": "schemathesis is not installed; API checks skipped",
             "install": "tools install schemathesis"})
    rc, out, err = runner(build_args(schema), timeout=timeout)
    if rc == -1:
        return adapter_result(NAME, "error", [],
                              {"error": err or "schemathesis timed out"})
    passed, failed = parse_summary(out + "\n" + (err or ""))
    findings = []
    if failed:
        findings.append(finding(
            "medium", "Schemathesis: %d failed API checks" % failed,
            "%d checks failed, %d passed (not_a_server_error)"
            % (failed, passed),
            "Fix the endpoints that return 5xx on generated "
            "requests and re-run the schema checks.",
            confirmation="confirmed"))
    return adapter_result(
        NAME, "completed", findings,
        {"schema": os.path.basename(schema), "passed": passed,
         "failed": failed, "rc": rc})
