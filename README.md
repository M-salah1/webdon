# WEBDON v1.00 — Heavy Website Investigation System

**Developer:** Hafed Mehdi Salah Eddine — Algeria
**Organization:** FOX COMPANY
**Platform:** Python 3 (standard library only) — Termux / Linux / Windows
**Interface:** Metasploit-style terminal console in Arabic / English / French

WEBDON is a heavy, modular, defensive website audit tool: **13 engines**,
**3 profiles** (QUICK / DEEP / FORENSIC), **33 phases in FORENSIC**
(31 in DEEP), SQLite history, JSON/HTML reports, and an interactive
console. It takes its time and investigates thoroughly — breadth of
engines and pages crawled, never artificial delays.

> **Authorized only.** Every scan requires a signed authorization scope:
> your own site, or a site with written permission. Without a scope,
> WEBDON refuses to scan.

## The engines

| # | Engine | What it does |
| - | ------ | ------------ |
| 1 | `dns` | A/AAAA/MX/NS/TXT/CNAME/SOA/CAA/DS (DoH), SPF/DMARC/DNSSEC, reverse DNS, ASN, geolocation country + hosting provider |
| 2 | `whois` | RFC 3912 port-43 WHOIS with referral following: registrar, creation/expiry, organization, country. Redacted = UNKNOWN, never guessed |
| 3 | `tls` | SSL/TLS: negotiated versions, cipher, certificate subject/issuer/SANs/expiry/days-left, chain issues |
| 4 | `headers` | Full security-header inventory (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, CORP) + weak values |
| 5 | `tech` | Server, X-Powered-By, generator, CMS, JS libraries — from headers/meta only, never guessed |
| 6 | `crawl` | Same-origin crawl (bounded pages/depth): paths, pages, titles, scripts, stylesheets, forms |
| 7 | `paths` | Well-known files (robots.txt / sitemap.xml / security.txt) + exposed config files checked by **HEAD only** — the body of a config file is never downloaded, read, stored or shown |
| 8 | `cookies` | Full cookie inventory: names + Secure/HttpOnly/SameSite flags, session vs persistent, first/third-party. **Values are never collected, shown or stored** |
| 9 | `cors` | Access-Control-Allow-Origin / credentials analysis only (wildcard + credentials = HIGH). No exploit attempts |
| 10 | `ports` | TCP connect scan of 19 common ports (21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 5432, 6379, 8080, 8443, 27017) with per-port timeout and service states |
| 11 | `ipintel` | **Second phase — the IP alone:** after the site scan, WEBDON re-investigates the resolved IP by itself (reverse DNS, ASN, geolocation, hosting, open ports) |
| 12 | `protect` | WAF/CDN detection (Cloudflare, Akamai, Sucuri, Imperva, CloudFront, Fastly, ModSecurity), rate-limit headers, CSP/HSTS presence — **presence only, no bypass testing** |
| 13 | `timeline` | Dated timeline from public facts only (WHOIS dates, TLS cert dates) |

Plus **Verify mode**: type an owner-provided password hidden
(`getpass`); WEBDON hashes it with SHA-1, sends **only the first 5
hash characters** to the Have I Been Pwned Pwned Passwords range API
(k-anonymity) and answers YES/NO + breach count only. The password
itself is never shown, stored or logged. Offline = UNKNOWN.

## Profiles

- `quick` — 6 engines, 13 phases (crawl, headers, tls, tech, cookies, cors).
- `deep` — 12 engines, 31 phases (everything except the timeline).
- `forensic` — 13 engines, 33 phases (everything).

Engines run in waves in parallel under a global time budget; a
timed-out engine is recorded and can be resumed later (`resume <id>`).
Partial results are saved and resumable.

## Honest scoring

- Score = 100 − confirmation-weighted severity weights
  (confirmed: critical 25, high 15, medium 8, low 3; indicators half).
- Coverage below 50%, or an unreachable target, gives **INCOMPLETE** —
  never a misleading 0%.
- Confidence and Verification Rate are computed from validation,
  never fixed numbers.
- Every finding is validated independently (headers re-fetched,
  cookies re-checked, paths re-HEADed) and duplicates are merged;
  false positives are listed separately, never silently counted.

## What WEBDON cannot know (and never invents)

Every report carries a limits block, reported as UNKNOWN:

- **Live users on the site right now** — only the site owner can see
  this in their own analytics/server logs.
- **Devices currently on the site** — only the site owner can see
  this in their own server logs.
- **Private admin identity/contact** — only the public WHOIS
  organization or a public security.txt contact is reported, if
  published; otherwise UNKNOWN.
- **Real leaked passwords** — never harvested or displayed; Verify
  mode answers YES/NO only.
- **Protection bypass** — never tested; protections are detected by
  presence only.

No SQLi/XSS/CSRF/SSRF/IDOR payloads, no brute force, no login
bypass, no exploitation of any kind. This is a defensive audit tool.

## Install (Termux)

```bash
pkg update && pkg install -y python git
unzip webdon-v1.00.zip
cd webdon
python3 webdon.py
```

No dependencies to install — Python standard library only.

## Run

```bash
python3 webdon.py                                  # console
python3 webdon.py --scan https://example.com --profile deep --json webdon-report.json
python3 webdon.py --scan https://example.com --profile forensic --html webdon-report.html
python3 webdon.py --version
```

Console:

```
webdon > scope create https://example.com   # sign authorization first
webdon > scope list
webdon > scan https://example.com           # uses current profile
webdon > scan deep https://example.com      # scan with a profile
webdon > scan forensic https://example.com
webdon > verify                             # HIBP password check
webdon > engines                            # list the 13 engines
webdon > engine headers https://example.com # run one engine alone
webdon > history                            # previous scans
webdon > summary 1                          # executive summary of scan #1
webdon > report generate 1 html             # export a stored scan
webdon > compare 1 2                        # diff two scans
webdon > resume 1                           # re-run timed-out engines
webdon > profile deep
webdon > lang
webdon > clear
webdon > help
webdon > exit
```

After a scan the dashboard offers: findings, JSON export, HTML
export, Verify.

## Storage

- `webdon-scans.db` — SQLite: one row per scan + one row per engine run.
- `webdon-scope.json` — remembered signed authorizations.
- `webdon-settings.json` — language + profile.
- `webdon-report.json` / `webdon-report.html` — exports.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

24 tests, all passing: scope enforcement, WHOIS parsing (including
redacted → UNKNOWN), headers analysis, the cookie value-free
guarantee, the config-file check never issuing a GET or reading a
body, CORS analysis, port-scan timeout handling, verify-mode
k-anonymity (mocked network), scoring, phase counts (DEEP 31,
FORENSIC 33), and full QUICK + DEEP scans against a local lab
server (weak site: no security headers, cookie without flags,
`/.env` answering HEAD 200 — with a fake secret in its GET body
that never appears in any output).
