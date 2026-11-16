#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Precise remediation for every WEBDON finding type (v4.00 EVIDENCE).

A remediation is never generic advice: it carries the exact
header value to set, the exact nginx AND Apache snippets, the
file/setting to change, and a verification step that re-probes
the OBSERVED evidence (the exact URL / header / path from the
finding's evidence object). Templates use {url} (the observed
location), {host} and {path}.

The table is keyed by the same finding keys as
webdon.core.cwe_map, so every mapped finding type is guaranteed
a precise fix (tests assert this). Findings with no mapping get
their own fix wrapped with a re-run verification step; info
findings get no remediation (nothing to fix).
"""
from . import cwe_map as cwe_map_mod


def _rem(summary, header=None, nginx=None, apache=None,
         file_hint=None, verify=None):
    return {"summary": summary, "header": header, "nginx": nginx,
            "apache": apache, "file": file_hint, "verify": verify}


REMEDIATIONS = {
    "missing-csp": _rem(
        "Add a Content-Security-Policy header that only allows "
        "trusted sources (no unsafe-inline / unsafe-eval / *).",
        header="Content-Security-Policy: default-src 'self'; "
               "script-src 'self'; object-src 'none'; "
               "base-uri 'self'; frame-ancestors 'self'",
        nginx="add_header Content-Security-Policy \"default-src "
              "'self'; script-src 'self'; object-src 'none'; "
              "base-uri 'self'; frame-ancestors 'self'\" always;",
        apache="Header always set Content-Security-Policy "
               "\"default-src 'self'; script-src 'self'; "
               "object-src 'none'; base-uri 'self'; "
               "frame-ancestors 'self'\"",
        file_hint="nginx: /etc/nginx/sites-available/<site> (server "
                  "block); Apache: /etc/apache2/sites-available/"
                  "<site>.conf or .htaccess",
        verify="curl -sI {url} | grep -i content-security-policy"),
    "missing-hsts": _rem(
        "Add Strict-Transport-Security with a one-year max-age, "
        "includeSubDomains and preload.",
        header="Strict-Transport-Security: max-age=31536000; "
               "includeSubDomains; preload",
        nginx="add_header Strict-Transport-Security \"max-age="
              "31536000; includeSubDomains; preload\" always;",
        apache="Header always set Strict-Transport-Security "
               "\"max-age=31536000; includeSubDomains; preload\"",
        file_hint="nginx: /etc/nginx/sites-available/<site> (HTTPS "
                  "server block only); Apache: <site>.conf "
                  "(HTTPS vhost only)",
        verify="curl -sI {url} | grep -i strict-transport-security"),
    "short-hsts": _rem(
        "Raise the HSTS max-age to 31536000 and add "
        "includeSubDomains.",
        header="Strict-Transport-Security: max-age=31536000; "
               "includeSubDomains; preload",
        nginx="add_header Strict-Transport-Security \"max-age="
              "31536000; includeSubDomains\" always;",
        apache="Header always set Strict-Transport-Security "
               "\"max-age=31536000; includeSubDomains\"",
        file_hint="nginx: /etc/nginx/sites-available/<site>; "
                  "Apache: <site>.conf",
        verify="curl -sI {url} | grep -i strict-transport-security"),
    "missing-xfo": _rem(
        "Add X-Frame-Options: SAMEORIGIN (or frame-ancestors in "
        "the CSP).",
        header="X-Frame-Options: SAMEORIGIN",
        nginx="add_header X-Frame-Options \"SAMEORIGIN\" always;",
        apache="Header always set X-Frame-Options \"SAMEORIGIN\"",
        file_hint="nginx: /etc/nginx/sites-available/<site>; "
                  "Apache: <site>.conf or .htaccess",
        verify="curl -sI {url} | grep -i x-frame-options"),
    "missing-xcto": _rem(
        "Add X-Content-Type-Options: nosniff.",
        header="X-Content-Type-Options: nosniff",
        nginx="add_header X-Content-Type-Options \"nosniff\" always;",
        apache="Header always set X-Content-Type-Options \"nosniff\"",
        file_hint="nginx: /etc/nginx/sites-available/<site>; "
                  "Apache: <site>.conf or .htaccess",
        verify="curl -sI {url} | grep -i x-content-type-options"),
    "missing-referrer-policy": _rem(
        "Add Referrer-Policy: strict-origin-when-cross-origin.",
        header="Referrer-Policy: strict-origin-when-cross-origin",
        nginx="add_header Referrer-Policy "
              "\"strict-origin-when-cross-origin\" always;",
        apache="Header always set Referrer-Policy "
               "\"strict-origin-when-cross-origin\"",
        file_hint="nginx: /etc/nginx/sites-available/<site>; "
                  "Apache: <site>.conf or .htaccess",
        verify="curl -sI {url} | grep -i referrer-policy"),
    "missing-permissions-policy": _rem(
        "Add a Permissions-Policy header disabling unused features "
        "(camera, microphone, geolocation).",
        header="Permissions-Policy: camera=(), microphone=(), "
               "geolocation=()",
        nginx="add_header Permissions-Policy \"camera=(), "
              "microphone=(), geolocation=()\" always;",
        apache="Header always set Permissions-Policy \"camera=(), "
               "microphone=(), geolocation=()\"",
        file_hint="nginx: /etc/nginx/sites-available/<site>; "
                  "Apache: <site>.conf or .htaccess",
        verify="curl -sI {url} | grep -i permissions-policy"),
    "missing-coop": _rem(
        "Add Cross-Origin-Opener-Policy: same-origin.",
        header="Cross-Origin-Opener-Policy: same-origin",
        nginx="add_header Cross-Origin-Opener-Policy \"same-origin\" "
              "always;",
        apache="Header always set Cross-Origin-Opener-Policy "
               "\"same-origin\"",
        file_hint="nginx: /etc/nginx/sites-available/<site>; "
                  "Apache: <site>.conf or .htaccess",
        verify="curl -sI {url} | grep -i cross-origin-opener-policy"),
    "missing-corp": _rem(
        "Add Cross-Origin-Resource-Policy: same-origin.",
        header="Cross-Origin-Resource-Policy: same-origin",
        nginx="add_header Cross-Origin-Resource-Policy \"same-origin\" "
              "always;",
        apache="Header always set Cross-Origin-Resource-Policy "
               "\"same-origin\"",
        file_hint="nginx: /etc/nginx/sites-available/<site>; "
                  "Apache: <site>.conf or .htaccess",
        verify="curl -sI {url} | grep -i cross-origin-resource-policy"),
    "plain-http": _rem(
        "Redirect ALL traffic to HTTPS (301) and enable HSTS on "
        "the HTTPS vhost.",
        header="Strict-Transport-Security: max-age=31536000; "
               "includeSubDomains; preload",
        nginx="server { listen 80; server_name {host}; return 301 "
              "https://$host$request_uri; }",
        apache="RewriteEngine On\nRewriteCond %{HTTPS} off\n"
               "RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} "
               "[L,R=301]",
        file_hint="nginx: /etc/nginx/sites-available/<site>; "
                  "Apache: <site>.conf or .htaccess (mod_rewrite)",
        verify="curl -sI {url} | grep -i '^HTTP'  # expect 301 to "
               "https, then: curl -sI https://{host}/ | grep -i hsts"),
    "no-tls": _rem(
        "Obtain a TLS certificate (e.g. Let's Encrypt) and serve "
        "the site over HTTPS only.",
        header="Strict-Transport-Security: max-age=31536000; "
               "includeSubDomains",
        nginx="listen 443 ssl; ssl_certificate /etc/letsencrypt/live/"
              "{host}/fullchain.pem; ssl_certificate_key "
              "/etc/letsencrypt/live/{host}/privkey.pem;",
        apache="SSLEngine on\nSSLCertificateFile "
               "/etc/letsencrypt/live/{host}/fullchain.pem\n"
               "SSLCertificateKeyFile /etc/letsencrypt/live/{host}/"
               "privkey.pem",
        file_hint="nginx: /etc/nginx/sites-available/<site>; "
                  "Apache: <site>-ssl.conf; certbot --nginx -d {host}",
        verify="curl -sI https://{host}/ | head -1  # expect HTTP/2 "
               "200"),
    "weak-tls": _rem(
        "Disable TLS 1.0/1.1 (and SSLv3): allow TLS 1.2 and 1.3 "
        "only.",
        header=None,
        nginx="ssl_protocols TLSv1.2 TLSv1.3; ssl_prefer_server_ciphers "
              "on;",
        apache="SSLProtocol -all +TLSv1.2 +TLSv1.3",
        file_hint="nginx: /etc/nginx/nginx.conf (http block) or "
                  "<site>; Apache: mods-enabled/ssl.conf",
        verify="openssl s_client -connect {host}:443 -tls1_1 "
               "</dev/null 2>/dev/null | grep -i 'alert\\|handshake "
               "failure'  # expect failure; -tls1_2 must succeed"),
    "no-modern-tls": _rem(
        "Enable TLS 1.2/1.3 and disable everything older.",
        header=None,
        nginx="ssl_protocols TLSv1.2 TLSv1.3;",
        apache="SSLProtocol -all +TLSv1.2 +TLSv1.3",
        file_hint="nginx: /etc/nginx/nginx.conf; Apache: "
                  "mods-enabled/ssl.conf",
        verify="openssl s_client -connect {host}:443 -tls1_2 "
               "</dev/null 2>/dev/null | grep 'Protocol'"),
    "tls-expired": _rem(
        "Renew the TLS certificate now and automate renewal "
        "(certbot renew / cron).",
        header=None,
        nginx="certbot renew --nginx  # then: nginx -t && systemctl "
              "reload nginx",
        apache="certbot renew --apache  # then: apache2ctl configtest "
               "&& systemctl reload apache2",
        file_hint="crontab: 0 3 * * * certbot renew --quiet "
                  "--post-hook 'systemctl reload nginx'",
        verify="echo | openssl s_client -connect {host}:443 "
               "-servername {host} 2>/dev/null | openssl x509 "
               "-noout -dates"),
    "tls-chain": _rem(
        "Serve the full certificate chain (leaf + intermediates): "
        "point the server at the fullchain file, not cert.pem.",
        header=None,
        nginx="ssl_certificate /etc/letsencrypt/live/{host}/"
              "fullchain.pem;  # NOT cert.pem",
        apache="SSLCertificateFile /etc/letsencrypt/live/{host}/"
               "fullchain.pem",
        file_hint="nginx: <site> ssl_certificate line; Apache: "
                  "<site>-ssl.conf SSLCertificateFile line",
        verify="echo | openssl s_client -connect {host}:443 "
               "-servername {host} 2>/dev/null | grep 'Verify return "
               "code: 0'"),
    "tls-expires-soon": _rem(
        "Renew the certificate before it lapses and automate "
        "renewal.",
        header=None,
        nginx="certbot renew --nginx",
        apache="certbot renew --apache",
        file_hint="crontab: 0 3 * * * certbot renew --quiet",
        verify="echo | openssl s_client -connect {host}:443 "
               "-servername {host} 2>/dev/null | openssl x509 "
               "-noout -dates"),
    "cookie-no-secure": _rem(
        "Set the Secure flag on every cookie (and keep HttpOnly + "
        "SameSite).",
        header="Set-Cookie: <name>=<value>; Secure; HttpOnly; "
               "SameSite=Lax; Path=/",
        nginx="proxy_cookie_flags ~ Secure HttpOnly SameSite=Lax;",
        apache="Header edit Set-Cookie ^(.*)$ $1; Secure; HttpOnly; "
               "SameSite=Lax",
        file_hint="application session config (e.g. PHP "
                  "session.cookie_secure=1; Django SESSION_COOKIE_"
                  "SECURE=True; Express cookie: {secure: true})",
        verify="curl -sI {url} | grep -i '^set-cookie'"),
    "cookie-no-httponly": _rem(
        "Set the HttpOnly flag on every cookie.",
        header="Set-Cookie: <name>=<value>; HttpOnly; Secure; "
               "SameSite=Lax; Path=/",
        nginx="proxy_cookie_flags ~ HttpOnly Secure SameSite=Lax;",
        apache="Header edit Set-Cookie ^(.*)$ $1; HttpOnly; Secure; "
               "SameSite=Lax",
        file_hint="application session config (e.g. PHP "
                  "session.cookie_httponly=1; Django SESSION_COOKIE_"
                  "HTTPONLY=True)",
        verify="curl -sI {url} | grep -i '^set-cookie'"),
    "cookie-no-samesite": _rem(
        "Set SameSite=Lax (or Strict) on every cookie.",
        header="Set-Cookie: <name>=<value>; SameSite=Lax; Secure; "
               "HttpOnly; Path=/",
        nginx="proxy_cookie_flags ~ SameSite=Lax Secure HttpOnly;",
        apache="Header edit Set-Cookie ^(.*)$ $1; SameSite=Lax; "
               "Secure; HttpOnly",
        file_hint="application session config (e.g. PHP "
                  "session.cookie_samesite=Lax; Django SESSION_COOKIE_"
                  "SAMESITE='Lax')",
        verify="curl -sI {url} | grep -i '^set-cookie'"),
    "server-version": _rem(
        "Hide the server version: ServerTokens Prod (Apache) / "
        "server_tokens off (Nginx).",
        header=None,
        nginx="server_tokens off;",
        apache="ServerTokens Prod\nServerSignature Off",
        file_hint="nginx: /etc/nginx/nginx.conf (http block); "
                  "Apache: /etc/apache2/conf-enabled/security.conf",
        verify="curl -sI {url} | grep -i '^server'"),
    "x-powered-by": _rem(
        "Remove the X-Powered-By header.",
        header=None,
        nginx="proxy_hide_header X-Powered-By;  # or: "
              "fastcgi_hide_header X-Powered-By;",
        apache="Header unset X-Powered-By",
        file_hint="application config (e.g. PHP expose_php=Off; "
                  "Express app.disable('x-powered-by'))",
        verify="curl -sI {url} | grep -i 'x-powered-by'  # expect "
               "no output"),
    "dnssec": _rem(
        "Enable DNSSEC signing at the registrar/DNS provider and "
        "publish the DS record.",
        header=None,
        nginx=None,
        apache=None,
        file_hint="DNS provider panel (registrar): enable DNSSEC, "
                  "publish the DS record at the parent zone",
        verify="dig +dnssec {host} | grep -i 'ad flag\\|RRSIG'  # or: "
               "webdon > engine dns {url}"),
    "no-spf": _rem(
        "Publish an SPF TXT record listing the servers allowed to "
        "send mail for the domain.",
        header=None,
        nginx=None,
        apache=None,
        file_hint="DNS zone TXT record: v=spf1 a mx -all  (adjust "
                  "to the real senders, then test with -all)",
        verify="dig +short TXT {host} | grep spf  # or: webdon > "
               "engine dns {url}"),
    "no-dmarc": _rem(
        "Publish a DMARC TXT record (start with p=none, move to "
        "quarantine, then reject).",
        header=None,
        nginx=None,
        apache=None,
        file_hint="DNS zone TXT record _dmarc.{host}: "
                  "v=DMARC1; p=none; rua=mailto:dmarc@{host}",
        verify="dig +short TXT _dmarc.{host} | grep DMARC  # or: "
               "webdon > engine dns {url}"),
    "cors-wildcard": _rem(
        "Stop reflecting '*' as Access-Control-Allow-Origin: echo "
        "only the trusted origin.",
        header="Access-Control-Allow-Origin: https://trusted.example",
        nginx="add_header 'Access-Control-Allow-Origin' "
              "'https://trusted.example' always;",
        apache="Header set Access-Control-Allow-Origin "
               "\"https://trusted.example\"",
        file_hint="application CORS config (allow-list of origins; "
                  "never '*')",
        verify="curl -sI -H 'Origin: https://evil.example' {url} | "
               "grep -i access-control-allow-origin  # must NOT be *"),
    "cors-wildcard-credentials": _rem(
        "URGENT: remove the wildcard + credentials combination — "
        "any site can read authenticated responses. Allow-list one "
        "trusted origin and keep credentials only for it.",
        header="Access-Control-Allow-Origin: https://trusted.example\n"
               "Access-Control-Allow-Credentials: true",
        nginx="add_header 'Access-Control-Allow-Origin' "
              "'https://trusted.example' always;\nadd_header "
              "'Access-Control-Allow-Credentials' 'true' always;",
        apache="Header set Access-Control-Allow-Origin "
               "\"https://trusted.example\"\nHeader set "
               "Access-Control-Allow-Credentials \"true\"",
        file_hint="application CORS config (allow-list; never '*' "
                  "with credentials)",
        verify="curl -sI -H 'Origin: https://evil.example' {url} | "
               "grep -i access-control-allow-origin  # must NOT be *"),
    "cors-credentials-origin": _rem(
        "Audit the origin that receives credentials: keep the "
        "allow-list to origins you fully control.",
        header="Access-Control-Allow-Origin: https://trusted.example",
        nginx="add_header 'Access-Control-Allow-Origin' "
              "'https://trusted.example' always;",
        apache="Header set Access-Control-Allow-Origin "
               "\"https://trusted.example\"",
        file_hint="application CORS config (allow-list)",
        verify="curl -sI -H 'Origin: https://evil.example' {url} | "
               "grep -i access-control-allow-origin"),
    "config-exposed-env": _rem(
        "Move .env outside the web root, block dotfiles on the "
        "server, and ROTATE every secret that was in the file.",
        header=None,
        nginx="location ~ /\\. { deny all; }",
        apache="<FilesMatch \"^\\.\">\n  Require all denied\n"
               "</FilesMatch>",
        file_hint="nginx: <site> server block; Apache: .htaccess or "
                  "<site>.conf; then rotate all secrets in .env",
        verify="curl -sI {url}  # expect 403 or 404 for the .env "
               "path"),
    "config-exposed-wp": _rem(
        "Block direct access to wp-config.php and rotate the "
        "database password and salts.",
        header=None,
        nginx="location = /wp-config.php { deny all; }",
        apache="<Files wp-config.php>\n  Require all denied\n</Files>",
        file_hint="nginx: <site> server block; Apache: .htaccess; "
                  "then rotate DB password + salts in wp-config.php",
        verify="curl -sI {url}  # expect 403 or 404"),
    "config-exposed-generic": _rem(
        "Block direct access to the config file on the web server.",
        header=None,
        nginx="location ~* (config\\.php|\\.env|\\.bak)$ { deny all; }",
        apache="<FilesMatch \"(config\\.php|\\.env|\\.bak)$\">\n  "
               "Require all denied\n</FilesMatch>",
        file_hint="nginx: <site> server block; Apache: .htaccess",
        verify="curl -sI {url}  # expect 403 or 404"),
    "config-exposed-backup": _rem(
        "Move backups outside the web root and delete the public "
        "copy.",
        header=None,
        nginx="location ~* \\.(zip|sql|bak|tar\\.gz)$ { deny all; }",
        apache="<FilesMatch \"\\.(zip|sql|bak|tar\\.gz)$\">\n  Require "
               "all denied\n</FilesMatch>",
        file_hint="backup job: write to /var/backups (outside the "
                  "web root), never to public/",
        verify="curl -sI {url}  # expect 403 or 404"),
    "config-exposed-db": _rem(
        "Move database dumps outside the web root and rotate the "
        "exposed credentials.",
        header=None,
        nginx="location ~* \\.sql$ { deny all; }",
        apache="<FilesMatch \"\\.sql$\">\n  Require all denied\n"
               "</FilesMatch>",
        file_hint="backup job: write dumps to /var/backups; rotate "
                  "any exposed DB password",
        verify="curl -sI {url}  # expect 403 or 404"),
    "config-exposed-phpinfo": _rem(
        "Remove the phpinfo() page from production.",
        header=None,
        nginx="location = /phpinfo.php { deny all; }",
        apache="<Files phpinfo.php>\n  Require all denied\n</Files>",
        file_hint="delete phpinfo.php from the web root",
        verify="curl -sI {url}  # expect 403 or 404"),
    "git-exposed": _rem(
        "Block /.git/ on the web server and audit the history for "
        "committed secrets (rotate any found).",
        header=None,
        nginx="location ~ /\\.git { deny all; }",
        apache="RedirectMatch 404 /\\.git(/.*)?$",
        file_hint="nginx: <site> server block; Apache: .htaccess; "
                  "deploy via export, not by cloning into public/",
        verify="curl -sI {url}  # expect 403 or 404 for /.git/HEAD"),
    "svn-exposed": _rem(
        "Block /.svn/ on the web server.",
        header=None,
        nginx="location ~ /\\.svn { deny all; }",
        apache="RedirectMatch 404 /\\.svn(/.*)?$",
        file_hint="nginx: <site> server block; Apache: .htaccess",
        verify="curl -sI {url}  # expect 403 or 404"),
    "ds-store": _rem(
        "Delete .DS_Store files from the web root and stop "
        "deploying them.",
        header=None,
        nginx="location ~ /\\.DS_Store { deny all; }",
        apache="<Files .DS_Store>\n  Require all denied\n</Files>",
        file_hint="deploy script: exclude .DS_Store; "
                  "find public/ -name .DS_Store -delete",
        verify="curl -sI {url}  # expect 403 or 404"),
    "sensitive-service": _rem(
        "Restrict the sensitive service to trusted IPs / VPN only; "
        "never expose it to the whole internet.",
        header=None,
        nginx="location / { allow 203.0.113.0/24; deny all; }  "
              "# adapt to the service",
        apache="<RequireAll>\n  Require ip 203.0.113.0/24\n"
               "</RequireAll>",
        file_hint="firewall / security group: allow only trusted "
                  "IPs; bind the service to localhost + VPN",
        verify="webdon > engine ports {url}  # the port must no "
               "longer be open to the internet"),
    "no-rate-limit": _rem(
        "Add rate limiting (per-IP, per-endpoint) and return 429 "
        "with Retry-After.",
        header="Retry-After: 60  (with HTTP 429)",
        nginx="limit_req_zone $binary_remote_addr zone=api:10m "
              "rate=10r/s;\nlimit_req zone=api burst=20 nodelay;",
        apache="LoadModule ratelimit_module modules/mod_ratelimit.so\n"
               "SetOutputFilter RATE_LIMIT\nSetEnv rate-limit 100",
        file_hint="nginx: http block + location; Apache: "
                  "mod_ratelimit; application: per-IP throttling",
        verify="for i in 1 2 3 4 5 6 7 8 9 10 11 12; do curl -s -o "
               "/dev/null -w '%{http_code} ' {url}; done  # expect "
               "a 429"),
    "outdated-service": _rem(
        "Upgrade the end-of-life service to a supported release "
        "and re-check its banner.",
        header=None,
        nginx=None,
        apache=None,
        file_hint="package manager / vendor docs for the service "
                  "named in the evidence; upgrade, then re-scan",
        verify="webdon > engine nmap {url}  # banner must show the "
               "new version"),
    "outdated-tls-traffic": _rem(
        "Disable TLS 1.0/1.1 on the server (see weak-tls fix) and "
        "re-check the traffic.",
        header=None,
        nginx="ssl_protocols TLSv1.2 TLSv1.3;",
        apache="SSLProtocol -all +TLSv1.2 +TLSv1.3",
        file_hint="nginx: /etc/nginx/nginx.conf; Apache: "
                  "mods-enabled/ssl.conf",
        verify="openssl s_client -connect {host}:443 -tls1_1 "
               "</dev/null 2>/dev/null | grep -i 'handshake failure'"),
    "plaintext-traffic": _rem(
        "Force HTTPS everywhere (301 redirect + HSTS) so no "
        "cleartext traffic is ever sent.",
        header="Strict-Transport-Security: max-age=31536000; "
               "includeSubDomains",
        nginx="server { listen 80; server_name {host}; return 301 "
              "https://$host$request_uri; }",
        apache="RewriteEngine On\nRewriteCond %{HTTPS} off\n"
               "RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} "
               "[L,R=301]",
        file_hint="nginx: <site>; Apache: <site>.conf",
        verify="curl -sI {url} | grep -i '^HTTP'  # expect 301 to "
               "https"),
    "chain-xss-session": _rem(
        "Fix both halves: add a strict CSP AND set HttpOnly on "
        "every cookie.",
        header="Content-Security-Policy: default-src 'self'; "
               "script-src 'self'; object-src 'none'\n"
               "Set-Cookie: <name>=<value>; HttpOnly; Secure; "
               "SameSite=Lax",
        nginx="add_header Content-Security-Policy \"default-src "
              "'self'; script-src 'self'\" always;\n"
              "proxy_cookie_flags ~ HttpOnly Secure SameSite=Lax;",
        apache="Header always set Content-Security-Policy "
               "\"default-src 'self'; script-src 'self'\"\n"
               "Header edit Set-Cookie ^(.*)$ $1; HttpOnly; Secure; "
               "SameSite=Lax",
        file_hint="nginx: <site>; Apache: <site>.conf; application "
                  "session config",
        verify="curl -sI {url} | grep -iE 'content-security-policy|"
               "^set-cookie'"),
    "chain-session-hijack": _rem(
        "Fix both halves: set Secure + HttpOnly + SameSite on "
        "cookies AND enable HSTS on the HTTPS vhost.",
        header="Strict-Transport-Security: max-age=31536000; "
               "includeSubDomains\nSet-Cookie: <name>=<value>; Secure; "
               "HttpOnly; SameSite=Lax",
        nginx="add_header Strict-Transport-Security \"max-age="
              "31536000; includeSubDomains\" always;\n"
              "proxy_cookie_flags ~ Secure HttpOnly SameSite=Lax;",
        apache="Header always set Strict-Transport-Security "
               "\"max-age=31536000; includeSubDomains\"\n"
               "Header edit Set-Cookie ^(.*)$ $1; Secure; HttpOnly; "
               "SameSite=Lax",
        file_hint="nginx: <site> (HTTPS block); Apache: <site>.conf; "
                  "application session config",
        verify="curl -sI {url} | grep -iE 'strict-transport|"
               "^set-cookie'"),
    "chain-source-secrets": _rem(
        "Block /.git/ and all config/dotfiles, then audit history "
        "and rotate any exposed secret.",
        header=None,
        nginx="location ~ /\\.(git|env) { deny all; }",
        apache="<FilesMatch \"^\\.\">\n  Require all denied\n"
               "</FilesMatch>",
        file_hint="nginx: <site>; Apache: .htaccess; rotate every "
                  "secret found in history",
        verify="curl -sI {url}/.git/HEAD  # expect 403/404; then: "
               "curl -sI {url}/.env  # expect 403/404"),
}


def _fill(template, url, host, path):
    """Fill {url}/{host}/{path} in a template (None stays None)."""
    if template is None:
        return None
    return template.replace("{url}", url or "").replace(
        "{host}", host or "").replace("{path}", path or "")


def build(finding, ctx=None):
    """Build the precise remediation for one finding.

    Returns a dict {summary, header, nginx, apache, file, verify}
    with every template filled from the finding's OBSERVED evidence
    (its location URL), or None for informational findings (nothing
    to fix). The verify step always re-probes the observed location.
    """
    if (finding.get("severity") or "").lower() == "info":
        return None
    ctx = ctx or {}
    ev_obj = finding.get("evidence_obj") or {}
    location = ev_obj.get("location") or finding.get("evidence") or ""
    if location.startswith("/"):
        location = (ctx.get("url") or "").rstrip("/") + location
    url = location if location.startswith("http") else (
        ctx.get("url") or "")
    host = (ctx.get("host") or "")
    if not host and url:
        try:
            host = url.split("/")[2].split(":")[0]
        except Exception:
            host = ""
    path = ""
    if url and ctx.get("url") and url.startswith(ctx["url"].rstrip("/")):
        path = url[len(ctx["url"].rstrip("/")):] or "/"
    mapped = cwe_map_mod.lookup(finding.get("name", ""),
                                finding.get("severity", "medium"))
    template = REMEDIATIONS.get(mapped["key"]) if mapped else None
    if template is None:
        # No mapping table entry (e.g. a Nuclei template finding):
        # keep the finding's own fix and add a re-run verification
        # against the observed location.
        fix = (finding.get("fix") or "").strip()
        if not fix:
            return None
        return {"summary": fix, "header": None, "nginx": None,
                "apache": None,
                "file": "Fix on the target, at the observed location: "
                        "%s" % (location or url or "—"),
                "verify": "webdon > scan %s  # re-run and confirm the "
                          "finding is gone" % (url or ctx.get("url")
                                              or "")}
    out = {}
    for key in ("summary", "header", "nginx", "apache", "file",
                "verify"):
        out[key] = _fill(template.get(key), url, host, path)
    return out
