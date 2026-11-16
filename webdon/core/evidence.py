#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Evidence Collector — every finding becomes one evidence record:
engine, time, what was seen. One ID per record.
"""
import time


def collect(findings):
    """Turn raw findings into evidence records."""
    out = []
    for i, f in enumerate(findings or []):
        item = dict(f)
        item["evidence_id"] = "EV-%04d" % (i + 1)
        item["collected_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                            time.gmtime())
        item.setdefault("validation", {"status": "observed",
                                       "confidence": 50})
        out.append(item)
    return out
