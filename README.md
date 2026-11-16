# WEBDON v3.00 NET — Heavy Website Investigation System

**Developer:** Hafed Mehdi Salah Eddine — Algeria
**Organization:** FOX COMPANY
**Platform:** Python 3 (standard library only) — Termux / Linux / Windows
**Interface:** Metasploit-style terminal console in Arabic / English / French

WEBDON is a heavy, modular, defensive website audit tool: **24 engines**,
**4 profiles** (QUICK / DEEP / FORENSIC / HIVE), **56 phases in HIVE**
(33 in FORENSIC, 31 in DEEP), SQLite history, JSON/HTML reports, and an
interactive console. It takes its time and investigates thoroughly —
breadth of engines and pages crawled, never artificial delays.

## HIVE — one command runs everything (خلية النحل)

Give only the URL; WEBDON runs five parallel waves like a beehive:

| Wave | What runs |
| ---- | --------- |
| 1 — recon | crawl, headers, TLS, tech, httpx live probe, Subfinder subdomains |
| 2 — web | DNS, WHOIS, cookies, CORS, protections, paths, Katana crawl, Nuclei templates |
| 3 — vuln | ports, Naabu, Schemathesis (schema only) |
| 4 — IP alone | the resolved IP re-investigated by itself (reverse DNS, ASN, geo, hosting, ports) + timeline |
| 5 — NET | **network & systems tools**: Nmap service scan, Wireshark traffic analysis, OpenVAS outdated-service heuristic + GVM bridge, NetExec AD check, BloodHound CE bridge |
| 6 — report | unified score + JSON/HTML report, with a dedicated "Network & Systems" section |

```bash
webdon > hive https://example.com
webdon > auto https://example.com          # same, short alias
python3 webdon.py --hive https://example.com --json webdon-report.json
python3 webdon.py --hive https://example.com --schema api.yaml   # enables Wave 5 API checks
```

Every wave runs under the same budgets, timeouts and scope gate as
a normal scan; partial results are saved and resumable (`resume <id>`).

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
| 14 | `nmap` | Service & port discovery: `nmap -sV -Pn -T4 --top-ports 100` (no `-O` without root); a service is "identified" only when a banner/version was actually read — never guessed from the port number |
| 15 | `wireshark` | Traffic analysis of WEBDON's **own** traffic to the target only: bounded tshark capture (`-f "host <target-ip>"`, 200 packets) when capture is permitted (root); otherwise an honest fallback to WEBDON's own request log. **Never anyone else's traffic, never packet payloads** |
| 16 | `openvas` | System vulnerability assessment: built-in outdated-service banner heuristic (TLS 1.0/1.1, old OpenSSH/Apache/nginx/IIS/PHP) labelled as a heuristic, **never** as a full OpenVAS scan; the real OpenVAS/GVM server is a bridge (`openvas export` / `openvas run` with `GVM_HOST` + `GVM_USER`) |
| 17 | `netexec` | Windows/AD assessment: runs **only** when AD ports (88/135/139/389/445/636/3268/3269) are open, and **only** with explicit opt-in (`netexec run <ip>`) — anonymous/guest enumeration only. **No password spraying, no brute force, no pass-the-hash, no wordlist.** Without AD indicators: `not_applicable` |
| 18 | `bloodhound` | AD relationship/permission analysis: BloodHound CE needs a Neo4j server + SharpHound collection from a domain host, so it is a bridge (`bloodhound export` writes the collection plan; `bloodhound import <file>` summarizes a supplied collection — counts and names only, **never hashes or credentials**) |

Plus **Verify mode**: type an owner-provided password hidden
(`getpass`); WEBDON hashes it with SHA-1, sends **only the first 5
hash characters** to the Have I Been Pwned Pwned Passwords range API
(k-anonymity) and answers YES/NO + breach count only. The password
itself is never shown, stored or logged. Offline = UNKNOWN.

## Profiles

- `quick` — 6 engines, 13 phases (crawl, headers, tls, tech, cookies, cors).
- `deep` — 12 engines, 31 phases (everything except the timeline).
- `forensic` — 13 engines, 33 phases (everything).
- `hive` — 24 engines, 56 phases, 6 waves (everything + all adapters + the NET wave).

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

NetExec never sprays passwords, never brute-forces, never uses
pass-the-hash, and never runs without AD indicators + explicit
opt-in. Wireshark never captures anyone else's traffic and never
keeps packet payloads. OpenVAS and BloodHound CE are server/PC
bridges — WEBDON never pretends they ran inside Termux.

## Install (Termux)

```bash
pkg update && pkg install -y python git
unzip webdon-v3.00.zip
cd webdon
python3 webdon.py
```

No dependencies to install — Python standard library only.

## Run

```bash
python3 webdon.py                                  # console
python3 webdon.py --hive https://example.com --json webdon-report.json
python3 webdon.py --scan https://example.com --profile deep --json webdon-report.json
python3 webdon.py --scan https://example.com --profile forensic --html webdon-report.html
python3 webdon.py --version
```

Console:

```
webdon > scope create https://example.com   # sign authorization first
webdon > scope list
webdon > hive https://example.com           # HIVE: everything, one command
webdon > auto https://example.com           # same as hive
webdon > tools list                         # status of all 14 tools
webdon > tools install nuclei               # install a tool (Termux ARM64)
webdon > openvas export https://example.com # OpenVAS task for a server/PC
webdon > openvas run https://example.com    # needs GVM_HOST + GVM_USER
webdon > netexec run 10.0.0.5              # AD check, anonymous only
webdon > bloodhound export https://example.com
webdon > bloodhound import collection.json # summary counts only
webdon > zap export https://example.com     # ZAP context + PC plan
webdon > neo export                         # findings JSON for Neo cloud
webdon > proxy                              # Burp-like request log
webdon > repeater 3                         # resend logged request #3
webdon > sitemap                            # crawled URL tree
webdon > scanner                            # built-in scan summary
webdon > scan https://example.com           # uses current profile
webdon > scan deep https://example.com      # scan with a profile
webdon > scan forensic https://example.com
webdon > verify                             # HIBP password check
webdon > engines                            # list the 24 engines
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

## Professional tools — adapters (v2.00 HIVE + v3.00 NET)

WEBDON wraps the real professional tools when they are installed,
and falls back to its built-in stdlib equivalent when they are
not — it never invents results. Every adapter is scope-gated and
detection-only, with timeouts and rate limits.

| Tool | Priority / Termux ARM64 | What WEBDON does |
| ---- | ----------------------- | ---------------- |
| Nuclei | very high | `nuclei -u <url> -severity low,medium,high,critical -exclude-tags dos -rate-limit 50` — template detection only; DoS tags always excluded; JSONL parsed, bodies never kept |
| httpx | very high | live probe: status / title / tech / TLS; feeds the crawl wave |
| Subfinder | high | subdomain enumeration; fallback: crt.sh CT logs + wildcard check |
| Katana | high | crawl with JS discovery; fallback: built-in crawler |
| Naabu | medium | port scan. **On Termux without root it falls back to a TCP connect scan and says so** — SYN needs privileges (`connect-scan fallback, SYN unavailable without root`) |
| Schemathesis | high (via Python) | only with an owner-supplied OpenAPI schema: read-only `not_a_server_error` checks; otherwise `skipped_no_schema` |
| ZAP | high — **best on a PC** | bridge only: `zap export` writes a context + scan plan for a PC; `zap run` only if ZAP is really installed. Full ZAP is a Java app and is not practical on ARM64 Termux — WEBDON never pretends it ran |
| Neo | high — external/cloud | `neo export` writes findings JSON; `neo push` only with `NEO_API_KEY` (+ `NEO_API_URL`) from the environment — the key is never stored in a file |
| Burp-like | built-in | no Burp Suite Professional binary (commercial, cannot be bundled): `proxy` (log of WEBDON's own requests), `repeater` (resend one logged request, GET/HEAD, same authorized host), `sitemap`, `scanner`. No intruder / brute force |
| Nmap | high — `pkg install nmap` | `nmap -sV -Pn -T4 --top-ports 100 -oX -` — service/version discovery; no `-O` (needs root). Fallback when missing: built-in connect scan, said honestly |
| Wireshark (tshark) | high — `pkg install tshark` | bounded capture of **own traffic to the target only** (`-f "host <ip>"`, 200 packets); capture needs root on Termux — otherwise the fallback analyses WEBDON's own request log and says so |
| Greenbone OpenVAS | high — **server/PC bridge** | **cannot run inside Termux.** `openvas export` writes a ready GVM task + plan; `openvas run` creates the task on the operator's GVM server (`GVM_HOST` + `GVM_USER`, password via getpass, never stored). Every hive also runs the built-in outdated-service banner heuristic |
| NetExec | medium — `pip install netexec` | Windows/AD only, **opt-in only** (`netexec run <ip>`), anonymous/guest enumeration only. No spraying, no brute force, no pass-the-hash, no wordlist. No AD indicators → `not_applicable` |
| BloodHound CE | high — **server/PC bridge** | **cannot run on a website or inside Termux.** `bloodhound export` writes the SharpHound collection plan; `bloodhound import <file>` summarizes a supplied collection (counts + names only, never hashes/credentials) |

### Tool manager

```
webdon > tools list              # status table for all 14 tools
webdon > tools check nuclei      # version check now
webdon > tools install nuclei    # install, then verify with --version
```

### Install on Termux (ARM64 / aarch64)

```bash
pkg install -y golang python
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
pip install schemathesis
pkg install nmap tshark
pip install netexec
```
OpenVAS and BloodHound CE have no Termux install — they are
server/PC bridges (`openvas export`, `bloodhound export`).

Or one command per tool from inside WEBDON: `tools install <name>`.
Every install is verified afterwards with the tool's version
command and reported honestly (success / failed + the exact manual
command). A tool is never claimed installed without that check.


## Network & Systems tools — Wave 6 (v3.00 NET)

When you put a URL into `hive <url>`, Wave 6 automatically
applies the network/systems tools to that target — same one
command, no extra input. The unified report has a dedicated
"Network & Systems" section with a per-tool status
(ran / fallback / bridge / not_applicable / skipped) — every
status honest, never invented.

| Tool | What it really does | On Termux vs PC/server |
| ---- | ------------------- | ---------------------- |
| Nmap | Service & port discovery (`-sV --top-ports 100`) | Runs on Termux via `pkg install nmap`; no OS detection without root |
| Wireshark | Traffic analysis of WEBDON's **own** traffic to the target | tshark runs on Termux via `pkg install tshark`, but packet capture needs root — otherwise the own-request-log fallback runs and says so |
| Greenbone OpenVAS | System vulnerability assessment | **Server/PC only** — cannot run inside Termux. WEBDON exports a ready GVM task and runs a banner-based outdated-service heuristic in the meantime |
| NetExec | Windows/AD assessment | Runs on Termux via `pip install netexec`, but only for Windows/AD hosts and only with explicit opt-in (`netexec run <ip>`), anonymous only |
| BloodHound CE | AD relationship/permission analysis | **Server/PC only** — needs a Neo4j server + SharpHound collection from a domain host. WEBDON exports the plan and summarizes a supplied collection |

## Storage

- `webdon-scans.db` — SQLite: one row per scan + one row per engine run.
- `webdon-scope.json` — remembered signed authorizations.
- `webdon-settings.json` — language + profile.
- `webdon-report.json` / `webdon-report.html` — exports.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

93 tests, all passing: everything in v1.00 (scope enforcement,
WHOIS parsing including redacted → UNKNOWN, headers analysis, the
cookie value-free guarantee, the config-file check never issuing a
GET or reading a body, CORS analysis, port-scan timeout handling,
verify-mode k-anonymity with mocked network, scoring, phase counts
DEEP 31 / FORENSIC 33, and full QUICK + DEEP scans against a local
lab server) plus v2.00 HIVE tests — hive phase counts (45) and scope
enforcement, Nuclei argument construction (DoS tags excluded),
Naabu connect-scan fallback, Schemathesis read-only checks and
skipped_no_schema, ZAP honest not-installed, Neo refusing without
an env key, tool-manager detection with mocked version checks,
Burp-like proxy/repeater/sitemap/scanner, adapter-output
sanitizing, and a full HIVE run against the lab server (45 phases,
no secret value anywhere in the output) — plus v3.00 NET tests:
hive now 6 waves / 56 phases / 24 engines, Nmap XML parsing
(identified only with a banner) and no `-O` flag, Wireshark
capture filter limited to the target IP + own-request-log
fallback, OpenVAS bridge status + outdated-service heuristic
labelling, NetExec `not_applicable` without AD indicators and
refusal of spraying/brute-force flags, BloodHound bridge +
import summary counts only (no hashes), the tool manager's five
new tools, the report's Network & Systems section, and a full
HIVE run against the lab server (56 phases).
