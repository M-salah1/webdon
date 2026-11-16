#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Authorization scope — WEBDON scans only authorized targets.

No scan runs without a signed scope: the operator's own site, or a
site with written permission. Authorizations are remembered in
webdon-scope.json in the working directory.

Console:
    webdon > scope create https://example.com
    webdon > scope list
"""
import json
import os

SCOPE_FILE = "webdon-scope.json"


class Scope:
    def __init__(self, base_dir=None):
        self.base_dir = base_dir or os.getcwd()
        self.path = os.path.join(self.base_dir, SCOPE_FILE)
        self.authorized = set()
        self._load()

    def _load(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
            for u in data.get("authorized", []):
                self.authorized.add(u)
        except Exception:
            pass

    def _save(self):
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump({"authorized": sorted(self.authorized)},
                          f, ensure_ascii=False)
        except Exception:
            pass

    @staticmethod
    def _host(url):
        try:
            return url.split("/")[2].lower()
        except Exception:
            return (url or "").lower()

    def is_authorized(self, url):
        host = self._host(url)
        return host in self.authorized or url in self.authorized

    def authorize(self, url):
        """Sign a scope for a host. Returns the host that was signed."""
        host = self._host(url)
        self.authorized.add(host)
        self._save()
        return host

    def revoke(self, url):
        host = self._host(url)
        self.authorized.discard(host)
        self.authorized.discard(url)
        self._save()
        return host

    def list(self):
        return sorted(self.authorized)


def normalize_url(url):
    url = (url or "").strip()
    if not url:
        return ""
    if "://" not in url:
        url = "https://" + url
    return url.rstrip("/")


def valid_url(url):
    if "://" not in url:
        return False
    try:
        host = url.split("/")[2]
    except Exception:
        return False
    return "." in host or host.startswith("127.") or host == "localhost"
