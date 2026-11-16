# WEBDON v5.1 PROFESSIONAL ASSURANCE — Heavy Website Investigation System

**Developer:** Hafed Mehdi Salah Eddine — Algeria
**Organization:** FOX COMPANY
**Platform:** Python 3 (standard library only) — Termux / Linux / Windows
**Interface:** Metasploit-style terminal console in Arabic / English / French

WEBDON is a heavy, modular, defensive website audit tool: **24 engines**,
**4 profiles** (QUICK / DEEP / FORENSIC / HIVE), **58 phases in HIVE**
(35 in FORENSIC, 33 in DEEP), SQLite history, JSON/HTML/PDF reports, and an
interactive console. It takes its time and investigates thoroughly —
breadth of engines and pages crawled, never artificial delays.

**v5.1 PROFESSIONAL ASSURANCE** adds independent technical evidence
per finding, an evidence-sufficiency gate, TLS deep validation,
two-tier port classification, cookie-context analysis, WAF
likelihood, and per-engine coverage transparency. See
[v5.1 PROFESSIONAL ASSURANCE](#v51-professional-assurance) below.
v5.00 DEEP-DIVE (recursive investigation: when a scan finds a
result, WEBDON follows it up with deeper probes — max depth 3 by
default, probe + time budgets, full dedup; every finding gains
depth / parent / chain) and v4.00 EVIDENCE (evidence + CVSS/CWE +
remediation + professional reports) are unchanged underneath.

## HIVE — one command runs everything (خلية النحل)

Give only the URL; WEBDON runs five parallel waves like a beehive:

| Wave | What runs |
| ---- | --------- |
| 1 — recon | crawl, headers, TLS, tech, httpx live probe, Subfinder subdomains |
| 2 — web | DNS, WHOIS, cookies, CORS, protections, paths, Katana crawl, Nuclei templates |
| 3 — vuln | ports, Naabu, Schemathesis (schema only) |
| 4 — IP alone | the resolved IP re-investigated by itself (reverse DNS, ASN, geo, hosting, ports) + timeline |
| 5 — NET | **network & systems tools**: Nmap service scan, Wireshark traffic analysis, OpenVAS outdated-service heuristic + GVM bridge, NetExec AD check, BloodHound CE bridge |
| 6 — report | unified score + JSON/HTML/PDF report, with a dedicated "Network & Systems" section, evidence + CVSS/CWE + remediation on every finding |

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
unzip webdon-v5.1.zip
cd webdon
python3 webdon.py
```

No dependencies to install — Python standard library only.

## Run

```bash
python3 webdon.py                                  # console
python3 webdon.py --hive https://example.com --json webdon-report.json
python3 webdon.py --hive https://example.com --depth 2   # deep-dive depth cap (1-5, default 3)
python3 webdon.py --hive https://example.com --pdf webdon-report.pdf
python3 webdon.py --scan https://example.com --profile deep --json webdon-report.json
python3 webdon.py --scan https://example.com --profile forensic --html webdon-report.html
python3 webdon.py --version
```

Console:

```
webdon > scope create https://example.com   # sign authorization first
webdon > scope list
webdon > hive https://example.com           # HIVE: everything, one command
webdon > hive https://example.com --depth 2  # same, deep-dive capped at depth 2
webdon > deep https://example.com           # hive + deep-dive (depth 3)
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
webdon > report html 1                      # interactive HTML report (v4.00)
webdon > report pdf 1                       # professional PDF report (v4.00)
webdon > report json 1                      # full machine-readable report
webdon > report compare 1 2                 # new / fixed / persisting (v4.00)
webdon > report timeline https://example.com # history of one target (v4.00)
webdon > compare 1 2                        # diff two scans
webdon > report chains 1                    # every investigation tree (v5.00)
webdon > evidence show 1 F-001              # one evidence bundle: request + response (v5.1)
webdon > coverage 1                         # per-engine coverage table (v5.1)
webdon > waf https://example.com            # WAF likelihood + signals (v5.1)
webdon > findings chain 1 F-014             # one investigation tree (v5.00)
webdon > findings list 1                    # findings with ids (v4.00)
webdon > findings mark-fp 1 F-003 "Cloudflare header, no version"  # suppress a false positive
webdon > findings unmark 1 F-003            # restore a suppressed finding
webdon > resume 1                           # re-run timed-out engines
webdon > profile deep
webdon > lang
webdon > clear
webdon > help
webdon > exit
```

After a scan the dashboard offers: findings, JSON export, HTML
export, PDF export, Verify.

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

## v4.00 EVIDENCE — evidence, accuracy, professional reporting

نموذج الأدلة والتقارير الاحترافية — كل نتيجة تحمل دليلاً، وCWE وCVSS محسوبين، وإصلاحاً دقيقاً.

### Evidence model — نموذج الدليل

Every finding carries a structured evidence object (`evidence_obj`),
shown in the terminal, HTML and JSON reports:

| Field | Meaning |
| ----- | ------- |
| `observed` | the redacted observed value (never a secret/cookie/session value) |
| `location` | exact URL / path / host:port where it was seen |
| `timestamp` | UTC time of the observation |
| `engine` | the producing engine |
| `method` | how it was probed (e.g. `GET https://… — response headers`, `HEAD /path — existence check, body never read`) |
| `observation` | one-line raw observation summary |

A finding with no evidence object is **rejected by the validator** —
never scored silently. Old scans (string evidence only) are migrated
on load: `evidence_obj` is rebuilt from the old string. The sanitizer
strips credential/session/cookie values from evidence strings too
(`Set-Cookie: sessionid=abc123` → `Set-Cookie: sessionid=[REDACTED]`,
`DB_PASSWORD=…` → `DB_PASSWORD=[REDACTED]`).

### Validation stage — التحقق وتقليل النتائج الكاذبة

After every wave, every suspected finding is **re-probed once**
(the exact URL/header/banner is re-fetched) and either promoted to
confirmed or downgraded/dropped with a reason. Then **cross-engine
corroboration**: a finding backed by 2+ independent engines becomes
confirmed (confidence ≥ 85); a single-signal finding stays suspected
(indicator). Known false-positive rules: sandbox-proxy TLS artefacts,
Cloudflare/default-server headers, 403-is-not-a-finding, wildcard-DNS
artefacts, "200 alone proves nothing".

### False positives — التعامل مع النتائج الكاذبة

```bash
webdon > findings list 1
webdon > findings mark-fp 1 F-003 "Cloudflare header, no version"
webdon > findings unmark 1 F-003
```

A marked false positive is **excluded from the score** (the score is
recomputed — fewer real findings means a higher security score), stored
in SQLite (`finding_fp`: target, finding key, reason, timestamp, scan
id), and shown in reports as **suppressed — never silently deleted**.
Unmarking restores it and recomputes the score again.

### CVSS + CWE — التقييم والتصنيف

- **CVSS v3.1** is **computed from the vector string** (`AV/AC/PR/UI/S/C/I/A`)
  in `webdon/core/cvss.py` — scores are never hardcoded. Verified against
  published scores: CVE-2014-3566 (POODLE) vector computes **3.4**, a
  full critical vector computes **10.0** (scope changed) / **9.8** (scope
  unchanged). Severity bands: None 0.0, Low 0.1–3.9, Medium 4.0–6.9,
  High 7.0–8.9, Critical 9.0–10.0.
- **CWE mapping** (`webdon/core/cwe_map.py`): every finding type maps to a
  CWE id + name + `https://cwe.mitre.org/data/definitions/<id>.html` link
  and a CVSS vector whose metric values are justified by the evidence
  (the reasoning is documented in code comments per rule), e.g. missing
  HSTS → CWE-319, vector `AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` → 4.8 Medium.
- **Honesty note:** if a finding type has no defensible mapping, its CVSS
  is **`null`** and severity comes from the existing scoring — **never an
  invented number**. Nuclei template classification (`cve-id` / `cwe-id` /
  `cvss-metrics`) wins over the table; when a CVE id is identified, the
  public NVD API is consulted (no key, 6 s timeout) for its published
  CVSS/CWE. Offline or no CVE → mapping table only, stated honestly.

### Precise remediation — الإصلاح الدقيق

Every finding type has an exact fix, filled from the **observed evidence**
(which URL, which header, which value): the precise header value
(`Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`),
the exact config snippet for **nginx AND Apache** where applicable, the
file/setting to change, and a **verification step** (the exact `webdon`
command or `curl` to re-run). Generic advice ("enable security headers")
is not accepted — tests assert every finding type has a non-empty,
evidence-referencing remediation.

### Professional reporting — التقارير الاحترافية

| Command | Output |
| ------- | ------ |
| `report html <id>` | Interactive self-contained HTML (no external JS/CSS): inline SVG severity chart, sortable/filterable findings table, expandable evidence + remediation per finding, executive summary, scope + methodology + limitations, CVSS/CWE columns |
| `report pdf <id>` | Professional PDF (pure-Python minimal writer, stdlib only): cover page, executive summary, severity distribution, findings table with CVSS/CWE, remediation appendix, scope/limitations/disclaimer |
| `report json <id>` | Full machine-readable report (findings with evidence/CVSS/CWE/remediation, scores, coverage, timeline refs). The old `--json` flag still writes the raw scan dump |
| `report compare <id1> <id2>` | New / fixed / persisting / changed findings, score delta, per-finding status incl. `fp-suppressed` |
| `report timeline <target>` | Chronological history from SQLite: score over time, findings opened/closed per scan, first-seen/last-seen per finding, change events. Per-finding `first_seen`/`last_seen` are stored in `finding_history` (existing rows migrate with `first_seen` = scan date) |

```bash
python3 webdon.py --hive https://example.com --pdf webdon-report.pdf
webdon > report pdf 1
webdon > report compare 1 2
webdon > report timeline https://example.com
```

## Storage

- `webdon-scans.db` — SQLite: one row per scan + one row per engine run.
- `finding_fp` table — operator false-positive marks (target, finding key, reason, timestamp, scan id).
- `finding_history` table — per-finding first_seen / last_seen / last scan id (drives `report timeline`).
- `webdon-scope.json` — remembered signed authorizations.
- `webdon-settings.json` — language + profile.
- `webdon-report.json` / `webdon-report.html` / `webdon-report.pdf` — exports.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

143 tests, all passing: everything in v1.00 (scope enforcement,
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
HIVE run against the lab server (56 phases) — plus v4.00 EVIDENCE
tests (49): the CVSS v3.1 calculator against independently verified
vectors (POODLE 3.4, 10.0 / 9.8 / 5.3 / 0.0 anchors, malformed
vectors), CWE mapping completeness for every finding type,
evidence-required rejection, the validation stage (promotion /
demotion / corroboration / known-FP rules), persistent FP marking
with score recompute, precise remediation for every finding type,
interactive HTML (sortable table + SVG chart + evidence blocks),
professional PDF (`%PDF` magic + title), the JSON report schema,
scan comparison (new / fixed / persisting), the timeline (ordering +
first/last seen), and the sanitizer stripping secrets from evidence
fields (cookie value + `.env` secret → `[REDACTED]`).

## v5.00 DEEP-DIVE — recursive investigation

التحقيق العميق التكراري — عندما يجد الفحص نتيجة، يتابعها بأدلة أعمق على نفس النتيجة بالضبط، وعندما تجد تلك الأدلة المزيد، يذهب أعمق مرة أخرى. نفس الأمر الواحد (`hive <url>`)، بدون إدخال إضافي.

### Deep-dive model — نموذج التحقيق العميق

After the six HIVE waves, the deep-dive stage walks the findings
level by level: L0 findings → L1 follow-ups → L2 → L3. Every
finding gains four fields:

| Field | Meaning |
| ----- | ------- |
| `depth` | 0 for L0 findings, 1–3 (up to 5) for follow-ups |
| `parent_id` | the finding it followed up (`null` for L0) |
| `follow_ups` | probe ids run because of this finding |
| `chain` | stable path, e.g. `F-014/F-023/F-026` |

Chains survive in SQLite (old scans migrate: depth 0, parent
null) and appear in the terminal report, the JSON report
(`deepdive` + `finding_chains`) and the HTML report (collapsible
trees). New commands: `deep <url>` (hive + deep-dive, depth 3),
`report chains <scan-id>`, `findings chain <scan-id> <finding-id>`.

### Worked chain example — مثال سلسلة

From a real lab-server hive run (depth 3):

```
F-014 [LOW|depth 0] Server version disclosed (F-014)
  via probes: P-ed21966d
  F-023 [INFO|depth 1] Basehttp version detected: 0.6 (F-014/F-023)
    via probes: P-9c55f176
    F-026 [INFO|depth 2] NVD lookup unavailable for basehttp 0.6 (cve_unknown) (F-014/F-023/F-026)
```

The server header disclosed a version → the dive detected the
exact version from headers/meta → it looked the version up on
the public NVD API (6 s timeout; offline → `cve_unknown`, never
an invented CVE). A probe that finds nothing ends its branch.

### Follow-up playbooks — خطط المتابعة

| Finding | Follow-ups |
| ------- | ---------- |
| Missing security header | audit that header on EVERY crawled page + related headers on the same pages |
| Open port | banner grab + service/version id + NVD CVE lookup for the version + neighbouring ports |
| Subdomain found | mini-scan: DNS, TLS cert, headers, liveness |
| Exposed config / sensitive path (HEAD 200) | HEAD-check sibling paths of the same family + robots/sitemap reference check (HEAD only, body never downloaded) |
| Cookie missing a flag | audit ALL cookies on ALL crawled pages for that flag |
| Weak TLS version/cipher | enumerate every TLS version + cipher offered + full cert chain details |
| Tech/CMS detected | version detection + theme/plugin detection (names only) + NVD lookup for the version |
| WHOIS org/registrar found | RDAP record + ASN + hosting neighbours (public data) |
| CORS wildcard | OPTIONS preflight on the site's API paths (detection only, no credentials) |
| Nuclei finding | re-probe the exact URL/template once + related templates of the same family (same CWE) |
| IP found | reverse DNS + ASN + geolocation + hosting; other IPs from DNS get their own follow-ups |

### Bounds — الحدود (the dive can never run forever)

| Bound | Default | Change |
| ----- | ------- | ------ |
| Max depth | 3 levels | `hive <url> --depth N` / `--depth N` (1–5; outside clamps with a warning) |
| Probe budget | 200 follow-up probes per scan | `deepdive_probe_budget` in settings |
| Time budget | 600 s for the deep-dive stage | `deepdive_time_budget_s` in settings |

A deduplication registry guarantees the exact same probe (same
type + target + parameters) is NEVER run twice in one scan. When
a budget stops the dive, the report states exactly which one:
`depth_limit` / `probe_budget` / `time_budget` — never silently
truncated. A neighbour-port finding never spawns further
neighbours, and a bare TCP answer with no banner (firewall /
egress proxy answering SYNs) is not a finding.

### Scoring — النتيجة

Deep-dive findings score exactly like normal findings (confirmed
full, suspected half, FP-marked excluded). The score does NOT
inflate because the dive found more: an audit finding reuses the
canonical engine title, so the same problem has the same
`finding_key` at any depth — the shallowest occurrence is kept,
the deeper one is linked to it, and a confirmed re-probe only
promotes the shallow finding (indicator → confirmed).


## v5.1 PROFESSIONAL ASSURANCE

What changed vs v5.00: every v5.00 feature is intact (hive, deep-dive,
validation, FP marking, compare/timeline/chains, SQLite history).
v5.1 makes seven things real, complete and visible:

### 1. Evidence engine — standalone evidence bundles

Every finding now has a standalone bundle in a new SQLite table
`evidence_bundles` (one per finding): the full HTTP request
(method, URL, headers, body excerpt) AND the full HTTP response
(status, headers, body excerpt, truncated at a safe size), both
redacted by the sanitizer, plus `verified_at` and the engine/method
that produced it. `evidence show <scan-id> <F-001>` prints a bundle;
JSON/HTML reports link each finding to its bundle. Findings with no
HTTP request/response (DNS-only, TLS handshake, TCP probe, HEAD-only
config check) say so explicitly (`request_response: null` + reason)
instead of pretending. Old scans get bundles rebuilt from their
stored evidence where possible, else marked `legacy_evidence`.

### 2. False-positive intelligence — evidence-sufficiency gate

A finding reaches `confirmed` ONLY when its evidence meets the
minimum for its type. Otherwise it stays `suspected` with the missing
evidence named (`evidence_gap`). Every finding carries
`evidence_score` (0–100) + `sufficiency` (pass/fail + gap). The gate
runs AFTER validation and AFTER the deep-dive, and it can only demote
a `confirmed` claim — never promote thin evidence. No finding may be
`confirmed` with sufficiency fail (regression-tested).

| Type | Minimum evidence to reach `confirmed` |
| ---- | -------------------------------------- |
| header | absent on ≥2 distinct URLs, OR on 1 URL + a re-probe |
| cookie | cookie name + flag state observed, + a re-probe |
| tls | completed handshake AND a parsed certificate (or the plain-HTTP response itself for "No TLS") |
| port | a banner or protocol response matched to a service — never a bare TCP answer (`needs banner`) |
| config | HEAD 200 on the exact path, + a re-probe |
| dns / whois | the public record observed, + a re-probe |
| cors / tech / protect / generic | the observation + a re-probe (or a second independent signal) |

### 3. TLS deep validation

Full trust-chain validation against the system CA store (stdlib
`ssl.create_default_context()` — the real verifier, not a hand-rolled
check): `chain_valid` true/false + which link failed. Expiry as
`expires_in_days` (warn <30 days, critical <7). SAN/hostname match
against the target (DNS/IP SANs + CN fallback). Protocol enumeration
(TLS 1.0/1.1/1.2/1.3 offered or not). Cipher enumeration — each
offered cipher listed, RC4 / 3DES / NULL / export flagged weak
(CWE-327). Self-signed, expired and SAN-mismatched are separate
findings with their own evidence. Sandbox note: the sandbox egress
proxy intercepts TLS, so smoke results there show proxy artefacts —
labelled `proxy_artefact`, never reported as real cert problems.

### 4. Port verification — two-tier classification

Every port result is exactly one of:

- `tcp_open` — SYN/connect answered, NO banner/protocol identified.
  Informational only: never a vulnerability, never counted in the
  score. (In the sandbox the egress proxy answers every TCP connect,
  so a smoke scan shows 19 `tcp_open` — that is the proxy, not 19
  services.)
- `service_confirmed` — a banner or protocol response matched to a
  service/version. Only a `service_confirmed` port on a risky service
  is a real finding.

The Nmap adapter maps the same way (`open` + service name →
`service_confirmed`; `open` with no service → `tcp_open`). Reports
show two separate tables/sections and counts; the terminal summary
prints e.g. `ports: 2 service_confirmed, 61 tcp_open (unidentified)`.

### 5. Cookie context analysis

Each cookie is classified before it is judged: `session`
(sessionid/PHPSESSID/JSESSIONID/connect.sid + path /), `csrf`
(csrf/xsrf/_csrf_token), `tracking` (_ga/_gid/_fbp…), `functional`
(theme/lang/cart…), `unknown`.

| Context | Missing Secure | Missing HttpOnly |
| ------- | -------------- | ---------------- |
| session | HIGH | MEDIUM |
| csrf | LOW (on HTTPS) | informational only — a CSRF cookie is MEANT to be read by JavaScript, so missing HttpOnly is EXPECTED, never a finding |
| tracking | LOW, only when set over plain HTTP | never flagged (analytics JS needs to read it) |
| functional | LOW (on HTTPS) | never flagged |
| unknown | MEDIUM | MEDIUM |

Each cookie finding states its context and WHY the flag matters (or
doesn't) for that context; remediation is per context. Note: the
"value shape" check for session cookies is deliberately not done —
cookie values are never collected, so a value's shape can never be
inspected; name + path classify a session cookie here.

### 6. WAF confidence

The binary verdict is gone. `waf_likelihood` is a probability
0–100% with the contributing signals listed:

| Signal | Weight |
| ------ | ------ |
| Known WAF header (cf-ray, x-sucuri-id, x-iinfo, x-mod-security…) | +25 to +40 |
| WAF-identifying Server header (cloudflare, Sucuri, Akamai…) | +25 |
| WAF cookie name (__cfduid, cf_clearance, AWSALB, Akamai BM…) | +20 |
| Block response to a benign probe (GET/OPTIONS, no payloads) | +25 |
| Status-code pattern (403/406/419 with WAF headers) | +10 |

No signal observed → `waf_likelihood: low (8%) — no WAF signals
observed`, with the checks performed named. That is never reported
as "no WAF" — absence of signals is not proof of absence.
`waf <url>` prints the likelihood + each signal with its weight.
Detection-only: benign probes only, no bypass attempts.

### 7. Coverage transparency

Every report (terminal, JSON, HTML) has a per-engine coverage table
for all 24 engines/adapters: `ran` (with phases completed),
`fallback` (what replaced it and why), `skipped` (why: tool not
installed, not applicable, not in profile), `failed` (error,
redacted). The four measures are always four separate numbers —
score, confidence, coverage, verification_rate — never merged into
one. `coverage <scan-id>` prints the table for a scan.

## v5.1 — التطمين المهني (ملخص عربي)

- **الأدلة:** حزمة أدلة مستقلة لكل نتيجة (الطلب + الرد الكامل،
  منقّحة) في جدول `evidence_bundles`، وأمر `evidence show`.
- **بوابة الكفاية:** لا تصل النتيجة إلى `confirmed` إلا بدليل كافٍ
  لنوعها (جدول أعلاه)؛ وإلا تبقى `suspected` مع تسمية الدليل الناقص.
- **TLS عميق:** تحقق من السلسلة بمخزن CA الحقيقي، الأيام المتبقية
  للشهادة، مطابقة SAN، إصدارات TLS، وتعداد الشفرات مع تمييز الضعيفة.
- **المنافذ:** `tcp_open` (معلومة فقط، ليست ثغرة) مقابل
  `service_confirmed` (خدمة مؤكدة بالبانر).
- **الكوكيز:** التصنيف حسب السياق قبل الحكم؛ كوكي CSRF بدون
  HttpOnly أمر متوقَّع وليس ثغرة.
- **WAF:** احتمالية 0–100٪ مع الإشارات وأوزانها؛ لا "لا يوجد WAF"
  كيقين أبداً.
- **التغطية:** جدول حالة كل محرك من الـ 24 في كل تقرير، والمقاييس
  الأربعة أرقام منفصلة دائماً.
