```
   ███████╗██╗   ██╗██████╗ ███████╗ ██████╗ ███╗   ██╗ █████╗ ██████╗
   ██╔════╝██║   ██║██╔══██╗██╔════╝██╔═══██╗████╗  ██║██╔══██╗██╔══██╗
   ███████╗██║   ██║██████╔╝███████╗██║   ██║██╔██╗ ██║███████║██████╔╝
   ╚════██║██║   ██║██╔══██╗╚════██║██║   ██║██║╚██╗██║██╔══██║██╔══██╗
   ███████║╚██████╔╝██████╔╝███████║╚██████╔╝██║ ╚████║██║  ██║██║  ██║
   ╚══════╝ ╚═════╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝
```

# subsonar

**asynchronous subdomain & web-interface sonar** — a production-grade, ultra-fast
subdomain enumerator and web-interface scanner with anonymous DNS resolution and a
Monokai Pro Dark interface.

![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?style=flat&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat)
![OSINT](https://img.shields.io/badge/OSINT-100%25%20free%2C%20no%20paid%20APIs-2ea44f?style=flat)

subsonar discovers, resolves and verifies the live web interfaces on a target
domain. It harvests hostnames from free OSINT sources and brute-force wordlists,
resolves them through a privacy-only DNS pool (no Google, no Cloudflare, no ISP
resolver), sweeps a curated port matrix and verifies every open port over real
HTTP — then fingerprints what it finds, checks for exposed files, and scores each
result 0–100 with the reasoning attached. The whole pipeline is `asyncio` from
top to bottom, every report is a set of clickable URLs, and no scanned address
ever leaves your machine.

## Highlights

* 100 % `asyncio` — non-blocking DNS, TCP and HTTP across the whole pipeline
* **Anonymous resolver pool** — 18 privacy-focused resolvers, strictly **no** Google
  (`8.8.8.8`) and **no** Cloudflare (`1.1.1.1`); the pool is enforced at import time
* **Custom DNS wire resolver** — raw UDP queries via `asyncio` datagram endpoints so
  the OS resolver (and therefore your ISP's DNS) is never consulted
* **Port matrices** — a curated **Top-50 core** matrix by default, an **extended
  ~170-port** matrix covering web/admin/dev/DB/monitoring services
  (`--port-matrix extended`), and full spec syntax for anything else
  (`--ports 8000-8100,11434,6443`; even `--ports 1-65535` if you insist)
* **11 brute-force wordlists** in a registry (`--wordlist NAME`): SecLists Top-1M
  slices (5 k / 20 k / 110 k), bitquark, dnsrecon namelist, DeepMagic prefixes,
  fierce, shubs, jhaddix — plus subsonar's own **AI Super** list (23 052 curated +
  generated labels, built in, no download). `python main.py wordlists`
* **Async TCP probing** — `asyncio.open_connection` with a strict 1.8 s timeout,
  TLS fingerprinting (cert CN/SAN, TLS version, cipher)
* **3 built-in OSINT sources** — CRT.sh, HackerTarget, Anubis (plus 7 plugins below
  and active brute-force). No paid APIs, ever
* **SecLists streamed from raw GitHub** and cached locally on first use
* **8 scan profiles** — from a zero-packet passive sweep to stealth mode
* **Wildcard DNS detection** with dynamic false-positive filtering
* **Office 365-style tenants are skipped entirely** — a host whose CNAME chain
  lands on the Exchange Online / SharePoint / identity families
  (`*.mail.protection.outlook.com`, `*.sharepoint.com`, `*.microsoftonline.com`,
  Okta, Auth0, …) is left unscanned: no port sweep, no HTTP probe, no finding.
  Those are shared tenants — scanning them tells you nothing about the target.
  **CDN / PaaS / hosting vhosts are still scanned** (CloudFront, S3, Heroku,
  Netlify, Akamai, …): that vhost is usually the target's own service, and the
  report records where it lives.
  Scanning somebody else's shared infrastructure tells you nothing about the
  target.  The host is still listed with its provider and the reason
  (`provider_hosts` in JSON, `## Third-party hosted (not scanned)` in Markdown,
  a `provider` column in CSV/HTML); `--scan-provider-hosts` scans them anyway
* **Strict output filter** — a subdomain is only reported when it answers a real
  HTTP/HTTPS probe on at least one port of the matrix, and one vhost serving on
  many ports is collapsed into a single finding with `also_on_ports` aliases
* **Live scanning log** — every wildcard check, OSINT fetch, DNS request, TCP probe,
  HTTP verification, filter decision and network error streams to the UI in real time
  through an accumulating, scrollable buffer: nothing is ever cleared mid-scan, the
  newest line stays on top, and the panel refreshes through a Streamlit fragment
  (pause · newest-first · clear · download the whole log)
* **Clickable URLs** — `http(s)://domain:port` rendered as actionable hyperlinks
  (OSC-8 in modern terminals, `LinkColumn` in the web dashboard, real anchors in HTML)
* **10 free OSINT sources** through a plugin registry — CRT.sh, HackerTarget, Anubis,
  CertSpotter, RapidDNS, urlscan.io, AlienVault OTX, ThreatMiner, Common Crawl,
  subdomain.center. No paid APIs, no signups, no keys
* **Active discovery** — TLS certificate SAN harvesting, CNAME-chase provider
  inference and recursive hostname permutations, turning a handful of known names
  into thousands of candidates for free
* **Fingerprinting** — Shodan-compatible favicon hash (pure-Python MurmurHash3),
  131-signature technology detection, and data-file probes
* **Explainable confidence scoring** — every finding ranked 0–100 with the reasons
  and penalties that produced the score
* **Results are never cleared** — a follow-up scan (passive → brute, or any profile
  change) merges the newest report for the same domain into the new run instead of
  starting empty; merged rows are marked `from_previous_scan` / `prev` in every UI
  and the JSON/CSV (`--no-carry-over` starts fresh)
* **Rate limiters on both planes** — token buckets bound *queries per second* and
  *connects per second*, globally and per resolver/host, on top of the concurrency
  limits: every profile paces by default (Medium 250 q/s + 600 connects/s, Stealth
  25 q/s + 60 connects/s) and `--dns-rate` / `--port-rate` override it, so a scan
  can be as gentle as it needs to be without touching concurrency
* **Offline geo + ASN per resolved IP** — country flag, country name and AS
  organisation next to every address, from a free one-off BGP dump (ip2asn.com,
  RIR files as fallback) parsed into a local SQLite index. Hover the flag in the
  web UI for the country and AS organisation. **The scanned IP never leaves the
  machine** (`--no-geo`, `python main.py geoip --stats|--lookup IP|--build`)
* **Free DNS intelligence per target** — MX/mail platform, recursive SPF include
  chain, DKIM selectors, DMARC policy, CAA issuers, NS/SOA hosting, DNSSEC state
  and third-party verification tokens (Google, Microsoft, Atlassian, …). All of it
  is ordinary DNS, no API and no key (`--no-dns-intel`)
* **Reverse DNS (PTR) enrichment** for resolved addresses (`--no-reverse-dns`)
* **Web mining + second wave** — robots.txt, sitemap.xml (and sitemap-index
  children), `/.well-known/security.txt`, CSP/`Link`/`Location` headers and page
  bodies are mined for further in-scope hostnames, which are then resolved and
  swept in a second wave (`--no-mining`)
* **10 free OSINT sources** through a plugin registry — CRT.sh, HackerTarget,
  Anubis, CertSpotter, RapidDNS, urlscan.io, AlienVault OTX, ThreatMiner, Common
  Crawl, subdomain.center. No paid APIs, no signups, no keys
* **Resumable scans, diff mode and TOML config** — interrupted sweeps continue where
  they stopped, and each rescan reports what is new, changed or gone

---

## Performance

Measured on this machine, not estimated:

| Stage | Before | After |
|---|---|---|
| 50-port sweep of a filtered host | 1.83 s | **0.47 s** |
| Repeat scan DNS phase (warm cache) | 2.60 s | **0.03 s** (87×) |
| DNS query transport | socket per query (p50 215 µs) | **1 socket per resolver**, ID-multiplexed |
| HTTP body read | 96 KiB fixed | **stops at `</head>`**, 64 KiB cap |

How:

* **Port-major scheduling.** Work is queued as `(host, port)` pairs and drained by a
  shared worker pool, so one filtered host can no longer idle a worker slot. Ports
  are issued as a single `host × port` matrix rather than port-by-port.
* **Adaptive timeouts.** The first pass uses 0.45 s; only ports that timed out *on a
  host that answered something* are retried at 1.8 s. A host that never responds is
  never retried — verified by a self-test check.
* **Streaming pipeline.** Port scanning and HTTP verification overlap: each batch's
  confirmed open ports go straight to the prober instead of waiting for a phase barrier.
* **DNS UDP multiplexing.** One long-lived socket per resolver, responses matched by
  transaction ID (`DNSConnection` / `DNSConnectionPool`). Transaction IDs are pooled,
  so an answer can never be mis-attributed.
* **Persistent DNS cache.** SQLite/WAL keyed on `(name, qtype)` with absolute expiry;
  NXDOMAIN answers get a short TTL. Brute-force repeats are near-100 % redundant, so
  rescans collapse to milliseconds.

```powershell
python main.py scan example.com --no-adaptive-timeout   # flat timeout, for comparison
python main.py scan example.com --no-multiplex-dns      # socket per query
python main.py scan example.com --no-disk-cache         # no cross-run cache
python tools/profile_hotpaths.py --live                 # bounded profiling harness
python tools/probe_timing.py                            # port-phase measurement
python tools/dns_cache_bench.py                         # cold vs warm DNS cache
```

Every profiling tool is **hard timeout-bounded** and reports `TIMEOUT` rather than
hanging, because an earlier version of this work hung the shell.

---

## Discovery

Beyond the ten passive sources, subsonar actively expands the candidate pool:

* **TLS SAN harvesting** — reads the certificate at the apex and on `www`, extracts
  in-scope `dNSName` SANs, and queues them. One handshake, often several hostnames.
* **CNAME chasing** — follows chains and infers the provider from 50+ known suffixes
  (CloudFront, Heroku, Netlify, Vercel, GitHub Pages, Azure, Akamai, Salesforce, …),
  reporting the naming conventions in use.
* **Recursive permutations** — mutates known names the way real teams do:
  `admin` → `admin-dev`, `dev-admin`, `admin2`, `admin.staging`, `eu-admin`.
  `--permutation-depth 2` feeds the first round back in.
* **Web mining (second wave)** — anything the target publishes on purpose
  (`robots.txt`, `sitemap.xml`, `security.txt`, CSP/`Link` headers, page bodies) is
  mined for further in-scope hostnames, which are then resolved and swept in a
  bounded second wave.
* **Apex DNS intelligence** — MX/SPF/DKIM/DMARC/CAA/NS/SOA/DNSSEC and verification
  tokens, i.e. what the organisation says about itself (see below).

```
06:12:04.118 ▸ phase  Phase 2b — active discovery (TLS SAN harvesting, CNAME chase, recursive permutations)
06:12:04.900 ☁ osint  Certificate on ://example.com:443 lists 3 in-scope SAN hostname(s)
06:12:05.240 ☁ osint  CNAME providers observed — AWS CloudFront×2, GitHub Pages×1
06:12:05.881 ☁ osint  Active discovery queued 1,284 new candidate host(s) (SAN 3, permutations 281, CNAME hops 2)
```

```powershell
python main.py scan example.com --no-discovery        # passive only
python main.py scan example.com --no-san --no-cnames  # permutations only
python main.py scan example.com --permutation-depth 2 --max-candidates 20000
```

---

## Fingerprinting and confidence

Each confirmed interface gets a favicon hash, technology matches and data-file
status codes; every finding is then scored 0–100 with the reasoning attached:

```
06:14:22.310 ↯ http  Fingerprint portal.example.com:8443 — favicon -391155043 ·
                     nginx, Django, Grafana · files: /robots.txt=200, /.well-known/security.txt=200
06:14:22.998 ∑ stat  Confidence scoring — 3 high, 5 medium, 2 low
```

| Signal | Effect |
|---|---|
| real 2xx/3xx, title, plausible length, TLS, `Server` header | positive |
| favicon hash, technologies, security headers, data files | positive |
| fingerprint distinct from siblings, resolvers agreeing | positive |
| 4xx/5xx, `kind=redirect`, empty title | negative |
| content length / fingerprint shared with other findings | negative |
| `also_on_ports` aliases present | negative |

Sensitive paths (`/.env`, `/.git/config`, `/.svn/entries`) are probed with the body
**structurally never read** — `read_limit=0`. subsonar reports that they exist, never
what is in them. Reports carry `confidence`, `confidence_label`, `technologies`,
`favicon_hash` and `data_files` columns.

---

## Workflow

```powershell
python main.py init                       # write a commented subsonar.toml
python main.py scan                       # uses ./subsonar.toml automatically
python main.py scan example.com --resume  # continue an interrupted sweep
python main.py scan example.com --domains a.com,b.com   # sequential batch
python main.py diff example.com           # new / changed / gone since the baseline
python main.py diff example.com --set-baseline
python main.py resume --all               # list saved scan state
```

* **Resumable state** is checkpointed per target under `.subsonar_cache/state-<domain>.json`
  after every phase; `--resume` skips already-resolved candidates.
* **Diff mode** compares the newest report with the stored baseline and writes a
  Markdown diff. This is the feature that makes continuous recon usable.
* **Office 365 / SaaS hosts are never scanned.** Discovery already follows CNAME
  chains; a chain that terminates in a known provider suffix (Exchange Online,
  SharePoint, S3, CloudFront, Heroku, Netlify, Akamai, Zendesk, …) marks the host
  as third-party hosted, and such a host is skipped before any packet is sent —
  no port sweep and no HTTP probe against somebody else's shared infrastructure.
  The host and its provider are written into the report (`provider_hosts` in
  JSON, a `## Third-party hosted (not scanned)` table in Markdown, a `provider`
  column in CSV/HTML) and counted as `3RD-PARTY SKIP` in the live statistics.
  `--scan-provider-hosts` (or `skip_provider_hosts = false`) scans them anyway.
  The suffix table lives in `subsonar/core/providers.py`, and its
  most-specific-first ordering is validated at import time.
* **Multi-domain runs are sequential on purpose** — running targets in parallel
  multiplies the packet rate against unrelated infrastructure.
* **TOML config** with CLI flags overriding file values; unknown keys are ignored.

---

## Wordlists

`--wordlist NAME` picks from a registry (`python main.py wordlists`); the scan
profile still decides *how much* of the list is used, so any list works with any
profile (e.g. `--wordlist jhaddix -p 2` = the first 1 000 labels of a 26 MB list).

| Name | Labels | Where it comes from |
|---|---|---|
| `seclists-top1m` *(default)* | 110 000 | SecLists `subdomains-top1million-110000.txt` |
| `seclists-5k` / `seclists-20k` | 5 000 / 20 000 | SecLists Top-1M slices (fastest sweeps) |
| `bitquark` | 100 000 | bitquark's popularity-ranked DNS list — a different token mix |
| `namelist` | ~190 000 | the dnsrecon namelist, mirrored in SecLists |
| `deepmagic` / `deepmagic-50k` | 500 / 50 000 | deepmagic.com network-prefix study (ISP/carrier vocabulary) |
| `fierce` | ~2 000 | the original fierce hostlist |
| `shubs` | ~600 000 | Shubham Shah's merged real-world recon output |
| `jhaddix` | ~2 000 000 | jhaddix's `all.txt` merge (deepest) |
| `ai-super` | 23 052 | **subsonar's own list** — built in, no download |

Aliases work too: `--wordlist ai`, `--wordlist 5k`, `--wordlist dnsrecon`,
`--wordlist jhaddix-all`. Remote lists are streamed from raw GitHub (with
jsDelivr/githack mirrors as fallbacks) and cached under `.subsonar_cache/` for 30
days; `ai-super` needs no network at all, which is what makes `--offline` useful
from a cold start.

### AI Super (`ai-super`)

The public lists are frequency dumps: excellent coverage of everything that has
ever existed, but a short scan burns its budget on dead vocabulary. `ai-super` is
ordered instead — the first few thousand labels are the ones that resolve in
practice, followed by systematic expansion:

* **curated (506)** hand-picked names: `autodiscover`, `adfs`, `owa`, `cpanel`,
  `argocd`, `vault`, `sso-login`, `k8s`, `grafana`, `ollama`, `dev-api`, …
* **theme vocabulary (913)** across ~20 themes: role, env, web, mail, identity,
  infra, dev/CI, data, streaming, monitoring, containers, cloud, security,
  business, AI/ML, tooling, network, devices
* **systematic expansion (~21 600)**: `role × environment` and the reverse
  (`api-dev`, `dev-api`), `role × number/version` (`api2`, `api-v2`),
  `role × region` (`api-eu`, `us-east-api`) and `product × role`
  (`checkout-dev`, `grafana-host`)

It is deterministic (the file is byte-identical to what the generator produces —
asserted by the test suite) and regenerated with:

```powershell
.\.venv\Scripts\python.exe tools\build_ai_wordlist.py           # write the list
.\.venv\Scripts\python.exe tools\build_ai_wordlist.py --stats   # numbers only
.\.venv\Scripts\python.exe tools\build_ai_wordlist.py --check   # CI guard
```

Licence: CC0-1.0 (generic naming vocabulary, no data copied from a licensed
corpus). The SecLists lists are MIT — see the repository for attribution.

---

## Ports: is 50 enough?

Short answer: 50 is the right *default*, ~170 is the right *"catch more"* mode,
and ranges cover the rest. Ports cost time linearly — a `/24` with the core 50 is
12 800 connects, the extended 170 is 43 520, and all 65 535 is 16.7 million —
while the extra hit rate beyond a couple of hundred hand-picked ports collapses
almost immediately (all of them are either ephemeral/random or service ports that
do not speak HTTP).

So there are three levels:

| Level | What you get | How |
|---|---|---|
| core (default) | 50 curated web/admin/dev ports, profile-aware | `--port-matrix core` |
| extended | 171 ports: the core plus dev/CI, container, DB, monitoring, remote-admin and alternative-web ports (Kibana 5601, Vault 8200, Ollama 11434, k8s 6443, Docker 2375/2376, WinRM 5985/5986, Plex 32400, Zabbix 10050, Netdata 19999, …) | `--port-matrix extended` |
| custom | any spec: names, lists, ranges, mixes | `--ports extended,9000-9010,11434` / `--ports 1-1024` / `--ports 1-65535` |

The extended matrix is still curated (every entry has a label and a reason), and
it keeps the core 50 first so the most likely ports are probed first. TLS-only
additions (2376, 5001, 5061, 5986, 6443, 8243, 8531, 8883) join
`TLS_FIRST_PORTS`, so they are probed with `https` before `http` and do not
pollute the log with bogus plain-HTTP protocol errors.

If you want the empirical detail rather than my summary, the sources to diff
against are `nmap-services` (nmap's own frequency ranking),
`Discovery/Infrastructure/nmap-ports-top1000.txt` in SecLists, and Shodan/Censys
top-port statistics — when a port from one of those starts showing up as a web
interface in your own scans, add it to `EXTENDED_PORT_MATRIX` in
`subsonar/core/config.py` (the consistency of every matrix is asserted at import
time by `ports.validate_matrix()`).

---

## Free OSINT enrichment (no API, no key, nothing leaves the machine)

Everything here runs by default on every non-passive profile and can be switched
off individually.

### Offline country + ASN next to every resolved IP

`23.227.38.74 🇩🇰 DK · AS13335 CLOUDFLARENET`

The data comes from one free download of `ip2asn.com` (a daily BGP dump: range →
ASN → AS organisation → country), with the five RIR *delegation* files as a
country-only fallback. It is parsed **once** into a compact SQLite index under
`.subsonar_cache/geoip/` (~720 000 ranges, ~4 s to build) and every lookup after
that is a local indexed query.

Why not a geo API: sending the scanned addresses to `ipinfo`/`ipapi`/Google — in
bulk, from one IP — would undo the entire anonymous-resolver design. The only
network request flags ever make is for the tiny country flag PNG in the web UI
(`flagcdn.com/20x15/dk.png`), which reveals a country code and nothing else.

```powershell
python main.py geoip --build               # download + build (one-off, ~10 MB)
python main.py geoip --stats                # entries, families, age, sources
python main.py geoip --lookup 23.227.38.74  # 🇺🇸 US · AS13335 CLOUDFLARENET
python main.py scan example.com --no-geo    # skip it entirely
$env:SUBSONAR_GEOIP_OFFLINE = "1"           # never download (CI, air-gapped)
```

Flags show up in the live log, the Rich table (console), the TUI table (Geo
column), the dashboard (flag + country + ASN + reverse DNS, hover a flag for the
full tooltip), and in the reports (Markdown `Geo` column, HTML flag images with
`title=` tooltips, CSV `country_code/country/asn/as_org/ptr` columns, JSON
`country_code`/`country`/`asn`/`as_org`/`ptr` keys).

### Apex DNS intelligence

All ordinary DNS, all free: the MX platform (Microsoft 365, Google Workspace,
Proofpoint, Mimecast, DanDomain, …), the SPF record with its **recursively
expanded `include:` chain** and `ip4/ip6` mechanisms, DKIM selectors, the DMARC
policy (`p=`, `sp=`, `pct=`, `rua=`), CAA issuers, NS/SOA hosting and the SOA
administrative mailbox, DNSSEC signing, and the third-party verification tokens a
company leaks in TXT records (Google Search Console, Microsoft 365, Atlassian,
Meta, Shopify, Adobe, Slack, Zoom, DocuSign, Stripe, Twilio, Miro, OneTrust, …).

It also grades what is **missing** — no SPF, a soft `~all`, `p=none` DMARC, no
CAA, unsigned zone — which is the part that is actually useful in a report:

```
DNS intel · mail: Microsoft 365 (Exchange Online)
DNS intel · mx: example-com.mail.protection.outlook.com
DNS intel · dns: Cloudflare DNS
DNS intel · spf includes: spf.protection.outlook.com, _spf.google.com
DNS intel · dmarc: p=quarantine rua=mailto:dmarc@example.com
DNS intel · dkim selectors: selector1, selector2
DNS intel · caa: issue=digicert.com
DNS intel · dnssec: signed
Mail/DNS posture — SPF does not end in -all (qualifier ~all) — spoofing is only soft-failed
```

### Reverse DNS (PTR) and web mining

Both are free by-products of what a scan already does:

* **PTR** for every resolved address (`portal.example.com` → `lb1.hoster.example`),
  deduplicated and capped (`max_ptr_lookups`, default 128) so shared hosting with
  one PTR for 40 hosts costs one query.
* **Mining** of `robots.txt` (including `Sitemap:` directives), `sitemap.xml`
  (following up to three `sitemapindex` children), `/.well-known/security.txt`,
  `Content-Security-Policy`/`Link`/`Location`/`X-Backend-Server` headers and page
  bodies for further **in-scope** hostnames. Anything new is listed under
  `mined_hosts`, and `mining_wave2` (on by default) resolves and sweeps them in a
  bounded second wave (Phase 5) — the scanner therefore finds hosts that only
  exist inside the target's own published files.

```powershell
python main.py scan example.com --no-dns-intel --no-reverse-dns --no-mining
```

### Results are never cleared


Running profile 1 (passive) and then profile 3 (brute) on the same domain used to
produce an empty findings table: the second run started from a fresh result set.
Now the newest report of that domain is read back, converted to findings, marked
`from_previous_scan` and merged — so a follow-up scan **adds to** what you already
found:

```
Merged 7 finding(s) from the previous scan of example.com (2026-10-01 09:41)
— results are never cleared, only added to
```

Merged rows keep working everywhere: they are tagged `prev` in the dashboard /
Markdown, `previous scan` in the sorted grid, `carried_over=yes` in CSV and
`from_previous_scan: true` in JSON, and a row that *is* found again in the new run
replaces the carried-over copy of itself — including when the address **rotated**
between runs (Cloudflare-style round-robin DNS answers with a different edge IP per
query, which would otherwise show the same URL twice):

```
Dropped carried-over ://www.example.com:443 — re-confirmed this run at 104.20.23.12
(the address rotated from 172.66.147.249)
```

`--no-carry-over` restores the old behaviour.

### DNS rate limiting

`dns_concurrency` bounds how many queries are *in flight*; it does not bound how
many queries per second leave the machine, which is what a resolver operator
actually notices. Every profile therefore paces its queries by default, and
`--dns-rate` adjusts it:

```powershell
python main.py scan example.com                     # profile default: 250 q/s, 50/node
python main.py scan example.com --dns-rate 40       # 40 q/s, whole pool
python main.py scan example.com --dns-rate 40 --dns-rate-per-server 8
python main.py scan example.com --dns-rate 20 --dns-rate-burst 60
python main.py scan example.com --dns-rate 0        # remove the cap entirely
```

Tokens refill continuously, so a burst up to `--dns-rate-burst` is still allowed
while the long-run average equals the rate; cache hits cost no token (no packet);
retries are paced too. The live log reports what the limiter cost:

```
Phase 3/4 — anonymous DNS resolution of 4,312 host(s) via 18 privacy resolvers · DNS rate limit: 250 q/s global (burst 250), 50 q/s per key
DNS resolution complete — 1,204 host(s) answered (3,108 failures) · rate limiter waited 41.7s over 2,915 query attempt(s)
```

### DNS failover budget (resolution speed)

Failover is what makes the anonymous pool reliable — but the attempt budget alone
allowed `attempts × dns_timeout` (6 × 2.5 s = **15 s**) for a *single* dead name,
and a brute list is mostly dead names. That, not the rate limit, used to be the
ceiling on the DNS phase.

* **First attempt** gets the full `--dns-timeout`.
* **Failover attempts** get 30 % of it (0.75 s by default) — a healthy privacy
  resolver answers in tens of milliseconds, so a node silent for that long is not
  going to answer, and the time is better spent on the *next* node.
* **`--dns-deadline SECONDS`** (default 6) caps the wall-clock time one hostname
  may spend across all its attempts; `0` restores "as many attempts as it takes".
  A name that hits the budget is still reported, with `deadline_hit` set, and the
  phase summary counts them:

```
DNS resolution complete — 15 host(s) answered (2,485 failures) · rate limiter waited 1.4s over 2,915 query attempt(s) · 1 name(s) abandoned at the 6s per-name budget
```

Measured on the same 2 500-candidate run (profile 2, 250 q/s cap):

| | DNS phase | Names resolved |
|---|---|---|
| before (6 × 2.5 s per dead name) | **57.5 s** | 13 |
| after (failover retries at 0.75 s + 6 s budget) | **9.7 s** | **15** |

The phase got ~6× faster *and* found two more hosts: those two had timed out on
the first resolver and then been poisoned by the stale error (see below), so the
engine had been discarding them.

### Two quiet correctness fixes in the same path

* **A failover answer is no longer "poisoned" by an earlier failure.** `DNSResult.ok`
  is `bool(addresses) and error is None`, and the failing attempt used to leave its
  error string on the result. A host that timed out on resolver A and answered on
  resolver B therefore came back as *resolved but `ok=False`* → dropped as
  unresolved and never cached. Working answers now clear the stale error.
* **`rtt_ms` measures the resolver, not our own queue.** The timer used to start
  *before* the rate limiter handed out a token, so a 20 ms answer that waited for
  one showed up as `NXDOMAIN from [94.140.15.15] (13313 ms)`. The exchange is timed
  on its own and a long wait is reported for what it is:
  `NXDOMAIN from [94.140.15.15] (18 ms, queued 13.1s (rate limit))`.

### TCP connect rate limiting (the port sweep)

The same token bucket guards the port phase, because a firewall or IPS measures
**connects per second from one source**, not the worker count. Each profile
brings a default (400–800 connects/s, 40–80 per host; stealth 60/s with 10/s per
host) and `--port-rate`, `--port-rate-per-host` and `--port-rate-burst` override
it:

```powershell
python main.py scan example.com --port-rate 200 --port-rate-per-host 20
python main.py scan example.com -p 8 --port-rate 30   # be very gentle
```

The limiter is applied *before* a worker slot is taken, so a waiting probe never
holds a concurrency permit. The phase banner and final summary report both caps
and what they cost:

```
Phase 4/4 — port-major sweep (50 ports × 12 host(s) in 1 batch(es), fast timeout 0.45s → 1.80s) + streaming HTTP verification · connect limit: 600 connects/s global (burst 600), 60 connects/s per key
Port sweep stats — 600 probes in 1.1s (545/s): 30 open, 12 refused, 558 timed out, 0 adaptive retry(ies), connect limiter waited 0.4s over 40 probe(s)
```

Need it faster for an authorised, load-tested target? `--port-rate 0 --dns-rate 0`
removes both caps and leaves only concurrency limits.

---

## Feature summary (8 profiles, 4 matrices, 11 wordlists, 10 OSINT sources)

| Capability | Flag |
|---|---|
| Active discovery | `--no-discovery`, `--no-san`, `--no-permutations`, `--no-cnames`, `--permutation-depth` |
| Wordlists | `--wordlist NAME` (11 lists) · `python main.py wordlists` |
| Port matrix | `--port-matrix core\|extended\|web\|audit` · `--ports 8000-8100,11434` |
| Third-party host policy | `--scan-provider-hosts` (default: Exchange/identity/SharePoint tenants are skipped entirely; CDN/PaaS hosts are scanned) |
| Results carry-over | (default on) `--no-carry-over` to start from an empty result set |
| **DNS rate limit** | `--dns-rate QPS` · `--dns-rate-per-server QPS` · `--dns-rate-burst N` (every profile paces: 250 q/s for Medium, 25 q/s for Stealth) |
| **TCP connect limit** | `--port-rate CPS` · `--port-rate-per-host CPS` · `--port-rate-burst N` (600 connects/s for Medium, 60/s for Stealth) |
| **Offline geo / ASN** | (default on) `--no-geo` · `--no-geo-download` · `python main.py geoip --build\|--stats\|--lookup IP` |
| **DNS intelligence** | (default on) `--no-dns-intel` (MX/SPF/DKIM/DMARC/CAA/NS/SOA/DNSSEC) |
| **Reverse DNS (PTR)** | (default on) `--no-reverse-dns` |
| **Web mining + wave 2** | (default on) `--no-mining` |
| IPv6 / AAAA scanning | `--ipv6` |
| Multi-resolver confirmation | `--confirm-resolvers 2` |
| Performance tuning | `--host-batch`, `--tcp-fast-timeout`, `--port-concurrency`, `--max-candidates` |
| Caching / transport | `--no-disk-cache`, `--no-multiplex-dns`, `--no-adaptive-timeout` |
| Workflow | `--resume`, `--no-state`, `--config`, `--domains` |

---

## Quick start

### One-command install & launch (Windows)

`install.ps1` does everything — finds Python, creates the `.venv`, installs the
dependencies, then starts the dashboard and opens the browser:

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

Then open **http://localhost:8501** (the script opens it for you). Options:

| Flag | What it does |
|---|---|
| `-Port 8502` | run the dashboard on a different port |
| `-NoBrowser` | don't auto-open the browser (starts headless) |
| `-Reinstall` | recreate `.venv` from scratch (fresh install) |

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1 -Port 8502 -NoBrowser
powershell -ExecutionPolicy Bypass -File .\install.ps1 -Reinstall
```

The script is idempotent: run it again and it reuses the existing `.venv` and
just launches the dashboard.

### Manual Windows (PowerShell)

Prerequisites: **Python 3.11 or newer** (`python --version`). On Windows the
Python launcher `py` also works — use `py -3.12` instead of `python` below if
that is how your machine is set up.

```powershell
# 1. clone, then create the virtual environment in the repo root
git clone <your-repo-url> subsonar
cd subsonar
python -m venv .venv

# 2. activate it and install the dependencies
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

> If PowerShell blocks `Activate.ps1` with a "running scripts is disabled"
> error, either allow it for this session (`Set-ExecutionPolicy -Scope Process
> RemoteSigned`) or skip activation and run everything through
> `.\.venv\Scripts\python.exe` directly, as in the examples below.

Verify the engine end-to-end (loopback only, no internet traffic):

```powershell
.\.venv\Scripts\python.exe main.py selftest     # expect 26/26 checks passed
```

Launch the interface you want:

```powershell
# interactive Textual TUI (full-screen, Monokai Pro Dark)
.\.venv\Scripts\python.exe main.py

# headless scan → prints the live log, writes ./output/* reports
.\.venv\Scripts\python.exe main.py scan example.com -p 3

# Streamlit web dashboard → then open http://localhost:8501 in Chrome
.\.venv\Scripts\python.exe main.py web
```

`main.py web` launches the dashboard and prints the URL; open
**http://localhost:8501** in your browser. Add `--headless` to skip the
auto-open attempt, or `--port 8501` to change the port.

A convenience wrapper that picks the venv automatically is included, so any of
these can be shortened to:

```powershell
.\subsonar.cmd selftest
.\subsonar.cmd scan example.com -p 3
.\subsonar.cmd web
.\subsonar.cmd
```

On macOS/Linux the same commands apply with `python3 -m venv .venv` and
`source .venv/bin/activate` (the `subsonar.cmd` wrapper is Windows-only).

### CLI reference

```
python main.py scan <domain> [options]

  -p, --profile {1..8|key}   scan profile (default 3 = Medium Brute)
  --dns-timeout SECONDS      DNS timeout (default 2.5)
  --tcp-timeout SECONDS      TCP connect timeout (default 1.8)
  --http-timeout SECONDS     HTTP timeout (default 4.0)
  --dns-concurrency N        default 400
  --port-concurrency N       default 300
  --http-concurrency N       default 60
  --dns-rate QPS             DNS rate limit across the pool (0 = unlimited)
  --dns-rate-per-server QPS  per-resolver DNS rate limit
  --dns-rate-burst N         burst allowance for --dns-rate
  --dns-deadline SECONDS     per-name failover budget (default 6, 0 = unlimited)
  --port-rate CPS            TCP connect rate limit for the port sweep
  --port-rate-per-host CPS   per-host connects/second cap
  --port-rate-burst N        burst allowance for --port-rate
  --ports 80,443,8443        override the port matrix
  --port-matrix NAME         core | extended | web | audit
  --wordlist NAME            brute-force list from the registry
  --permute-wordlist         mutate labels with env/region/number affixes
  --wordlist-permutation-limit N  cap the extra labels the mutation pass adds
  --no-carry-over            do not merge the previous report of this domain
  --no-geo                   skip offline country/ASN enrichment
  --no-geo-download          use an existing geo index only, never download
  --no-reverse-dns           skip PTR lookups for resolved addresses
  --no-dns-intel             skip MX/SPF/DKIM/DMARC/CAA/DNSSEC intelligence
  --no-mining                skip robots/sitemap/security.txt/header mining
  --no-template-checks       skip the status-only exposure checks
  --offline                  never fetch wordlists/OSINT (cache only)
  --debug-log                include debug/trace events in the live log
  --jsonl                    stream every finding to a live .jsonl file
  --formats json,csv,md,html,txt,jsonl
  --no-reports               skip report writing
  --output DIR               report directory (default ./output)

python main.py geoip [--build|--refresh|--stats|--lookup IP] [--cache-dir DIR] [--json]
```

Exit codes: `0` findings written · `2` scan completed with no web interface ·
`1` error · `130` interrupted.

---

## The 8 scan profiles

A profile is **three independent settings**, not one:

| Setting | What it controls | Overridable with |
|---|---|---|
| **Wordlist slice** | *how many* candidate labels are taken from the wordlist (the list itself is a separate choice) | — (the profile sizes the slice) |
| **Port matrix** | *which* ports are swept (`core` 50 / `web` 10 / `audit` 30; profile 1 skips the sweep) | `--port-matrix`, `--ports` |
| **Rate limits** | *how fast* DNS queries and TCP connects are allowed to leave (below) | `--dns-rate`, `--port-rate`, `--rate-*` |

| # | Profile | Wordlist slice | Ports | Default pacing (DNS / connects) | Behaviour |
|---|---------|----------|-------|-------|-----------|
| 1 | **Passive Only** | — | 80, 443 (verify only) | 60 q/s (20/node) · no sweep | OSINT + DNS intel only. **0 brute-force packets** |
| 2 | **Light Brute** | first 1 000 | Top-50 core | 150 q/s (30/node) · 400/s (40/host) | Fast, low-noise first pass |
| 3 | **Medium Brute** | first 5 000 | Top-50 core | 250 q/s (50/node) · 600/s (60/host) | Balanced production default |
| 4 | **Deep Brute** | first 20 000 | Top-50 core | 300 q/s (60/node) · 800/s (80/host) | Exhaustive sweep |
| 5 | **Full Postal** | first 5 000 | Top-50 core | 250 q/s (50/node) · 500/s (50/host) | Passive OSINT **+** Medium brute |
| 6 | **HTTP Quick Check** | first 500 | web core (10) | 300 q/s (60/node) · 800/s (80/host) | Sub-minute triage |
| 7 | **Infrastructure Audit** | first 2 000 | 30 admin ports | 250 q/s (50/node) · 500/s (50/host) | 8443, 9443, 10000, 2083, 2087, … |
| 8 | **Stealth Mode** | first 5 000 | Top-50 core | 25 q/s (8/node) · 60/s (10/host) | Low-and-slow, 0.35–1.25 s randomised gaps |

### So: `-p 2 --wordlist seclists-top1m` does exactly what?

* **Wordlist** — `seclists-top1m` is a 110 000-line list; the profile takes the
  **first 1 000 labels** of it (`profile.wordlist_size`). The list only changes
  *which* 1 000 names those are: `--wordlist ai-super -p 2` = the first 1 000 of
  subsonar's own list, `--wordlist jhaddix -p 2` = the first 1 000 of a 2 M list.
  Want more coverage? Raise the profile (`-p 4` = 20 000) — the matrix and the
  wordlist are independent knobs.
* **Ports** — profile 2 brings the **Top-50 core** matrix, so
  `--port-matrix extended` (172 ports) *replaces* it (that is the `port matrix`
  dropdown in the web UI; it says `explicit` instead of `profile default`).
* **Rate** — DNS is paced at 150 q/s with 30 q/s per resolver and the sweep at
  400 connects/s with 40/s per host. Those are the defaults; `--dns-rate 60`
  makes it quieter, `--dns-rate 0` removes the cap entirely.
* Everything else in the profile still applies: OSINT sources, wildcard
  pre-flight, permutations, adaptive timeouts.

The live log prints the effective plan at the start of every run, and the
dashboard's *Scan plan* tab shows the same lines:

```
profile           : 2. Light Brute
wordlist          : 1,000 of seclists-top1m
port matrix       : extended (172 ports, explicit)
rate limits       : dns 150/s (30/node) · ports 400/s (40/host)
```

```powershell
python main.py profiles                      # the table above, from the CLI
python main.py scan example.com -p 2 --wordlist ai-super
python main.py scan example.com -p 3 --port-matrix extended --dns-rate 80
python main.py scan example.com -p 8 --port-rate 30 --port-rate-per-host 5
```

---

## Anonymous DNS

`subsonar/core/dns.py` implements a complete DNS client on top of
`asyncio` datagram endpoints (A, AAAA, CNAME, NS, MX, TXT, PTR, **SOA, DS,
DNSKEY and CAA**, with compression pointer handling and a TTL-aware LRU cache).
Every query rotates to the next resolver in the anonymous pool:

```
9.9.9.10        149.112.112.10   Quad9 un-censored
194.242.2.2     194.242.2.4      Mullvad DNS
185.228.168.168 185.228.169.168  CleanBrowsing (privacy filter)
76.76.2.0       76.76.19.19      ControlD (no-log)
94.140.14.14    94.140.15.15     AdGuard DNS (no-log)
194.150.168.168 5.175.46.10      OpenNIC (NZ / CA)
84.200.69.80    84.200.70.40     DNS.WATCH
91.239.100.100  89.233.43.71     UncensoredDNS (CCC)
159.89.120.20   185.95.218.42    Blindside Networks / Applied Privacy
```

`FORBIDDEN_DNS_SERVERS` contains `8.8.8.8`, `8.8.4.4`, `1.1.1.1`, `1.0.0.1` and the
*filtered* Quad9 `9.9.9.9`. Constructing a resolver with one of them raises
immediately, and `_assert_privacy()` fails the import if the pool is ever edited.

The custom resolver is also injected into `aiohttp` (`AnonymousAiohttpResolver`),
so **web probes resolve names anonymously too** — the OS resolver is never used.

### Resolver pre-flight health check

Public resolver pools drift: nodes get retired, migrate to DoT/DoH only, or block
plain UDP/53 from a given network. Before any target traffic is emitted, subsonar
probes **every** configured node with a recursive query and drops the silent ones
from the rotation:

```
06:00:31.402 ▸ phase  Resolver pre-flight — probing 18 anonymous DNS nodes (no Google, no Cloudflare)
06:00:31.884 ⌁ dns    DNS Request (A) sent to [9.9.9.10] for ://example.com
06:00:32.490 ✔ dns    Resolver health check — 9/18 anonymous nodes answering UDP/53
06:00:32.491 ⌁ dns    Unreachable nodes skipped this session: 194.242.2.2 (rcode=5), 76.76.19.19 (DNSTimeout) …
06:00:32.492 ⌁ dns    Active rotation: 5.175.46.10, 76.76.2.0, 84.200.69.80, 9.9.9.10, 94.140.14.14 …
```

The full pool stays documented and configured; dead nodes are only skipped for the
session, and a background loop re-probes the pool every 10 minutes during long
scans. A node that starts answering again is automatically re-admitted.

*Why "SYN-equivalent"?* A true TCP SYN requires raw sockets (administrator/root)
and silently breaks behind NAT; subsonar therefore issues a full non-blocking
`connect()` with a 1.8 s timeout. The live log labels each probe honestly and the
scan aborts the socket the moment the handshake resolves.

---

### Live scanning log

Every interface shows the same granular stream — the TUI's *live scanning log*
panel, the Streamlit *Live scanning log* tab, and the headless console. The
dashboard panel is an **accumulating, scrollable buffer**: nothing is ever cleared
while a scan runs, and you can read back through the whole run.

```
05:46:31.418 ▸ phase     Phase 1/4 — passive OSINT collection (0 packets to target)
05:46:31.419 ☁ osint     Querying CRT.sh API asynchronously...            example.com
05:46:31.902 ⌁ dns       DNS Request (A) sent to [185.228.168.168] for ://example.com
05:46:32.144 ⇄ port      TCP SYN-equivalent connect() sent to ://admin.example.com on Port: 8443 [HTTPS-Alt] → 203.0.113.9
05:46:32.402 ⇄ port      Port OPEN ://admin.example.com:8443 [HTTPS-Alt] — handshake in 258 ms
05:46:32.681 ↯ http      Sending GET request to https://admin.example.com:8443... Status: 200 · Title: 'Admin Portal'
05:46:32.690 ✔ probe     WEB INTERFACE — https://admin.example.com:8443 · 200 · Admin Portal
05:46:33.115 ⊘ filter    Filtered out ://legacy.example.com - Port 80/443 closed (No Web Interface)
05:46:33.480 ⁂ wildcard  Wildcard DNS detected for example.com — 2 rotating address(es): 203.0.113.5, 203.0.113.6
05:46:34.002 ⇄ port      Timeout on ://dev.example.com:8080 — dropping socket
```

#### Why the panel used to flash and clear

The panel rendered `BUS.drain()`, which **removes** the events it returns, and the
page re-ran the whole app every half second while scanning. Each rerun therefore
showed only the handful of lines emitted since the previous one — so the log
appeared to reset itself continuously and nothing could be scrolled back into.

The fix has three parts:

1. **A growing buffer.** Events are mirrored into a 6 000-line session buffer
   keyed on the monotonic event sequence number, so no line is ever lost or
   duplicated — and the *Download log* button hands you the whole thing as a
   `.txt`, including lines that scrolled past the rendered window.
2. **Newest first.** The newest line sits at the top, so the panel never jumps
   under the cursor; history is a scroll *down* and stays exactly where you left it.
3. **A fragment instead of a page-wide rerun.** The KPI strip, progress bar and
   log live inside `@st.fragment(run_every=1s)`, so only that panel refreshes —
   the findings table, filters and tabs are not rebuilt, which removes the
   flashing entirely (and the app-wide `time.sleep(0.5); st.rerun()` loop is gone).

Controls above the panel: **⏸ Pause live view** (freezes the view so you can read
and scroll while the scan continues buffering in the background), **Newest first**
(switch to oldest-first for a tail -f feel), **↺ Clear** and **⇩ Download log**.
The caption tells you exactly what you are looking at:

```
3 812 line(s) buffered · showing 1 500 · newest first — scroll down for history
· 2 312 older line(s) hidden · 4 dropped (bus evicted)
```

The *Quiet log* sidebar switch hides debug/filter chatter **retroactively** — the
events stay buffered (and downloadable), so toggling it rewrites the whole view
instead of only affecting future lines.

Statistics (candidates, DNS queries/resolutions/failures, ports probed/open, HTTP
probes, web findings, filtered, wildcard-filtered, errors, timeouts, rate) and a
live progress bar refresh continuously in the TUI and dashboard.

---

## Architecture

```
subsonar/
├── main.py                     CLI (scan / tui / web / profiles / wordlists / selftest)
├── subsonar.cmd                Windows launcher using .venv
├── install.ps1                 one-command Windows install + launch (web dashboard)
├── requirements.txt
├── .streamlit/config.toml      Monokai Pro Streamlit theme
├── subsonar/
│   ├── __init__.py             version + branding
│   ├── runner.py               thread-hosted engine bridge (ScanRunner)
│   ├── reporters.py            JSON / CSV / Markdown / HTML / TXT writers
│   ├── core/
│   │   ├── config.py           anonymous resolver pool, Top-50 matrix, ScanConfig
│   │   ├── theme.py            Monokai Pro palette, ASCII logo, ANSI helpers
│   │   ├── events.py           thread-safe EventBus, ScanEvent, Stats
│   │   ├── dns.py              wire resolver, UDP multiplexing, wildcard detection
│   │   ├── ratelimit.py        token-bucket query pacing (global + per resolver)
│   │   ├── dnsintel.py         MX/SPF/DKIM/DMARC/CAA/NS/SOA/DNSSEC intelligence
│   │   ├── dnscache.py         durable SQLite DNS answer cache
│   │   ├── geoip.py            offline country + ASN index (ip2asn/RIR, SQLite)
│   │   ├── mining.py           host extraction from robots/sitemap/headers
│   │   ├── miner.py            bounded fetcher for those well-known files
│   │   ├── ports.py            port matrix helpers + validation
│   │   ├── scanner.py          port-major TCP/TLS scanner, adaptive timeouts
│   │   ├── services.py         banner + port service detection (SSH, Redis, …)
│   │   ├── web_probe.py        aiohttp verifier, HEAD/status probes, body capping
│   │   ├── osint.py            CRT.sh / HackerTarget / Anubis collectors
│   │   ├── sources/            plugin registry + 7 extra free sources
│   │   ├── discovery.py        SAN harvesting, CNAME chasing, permutations
│   │   ├── fingerprint.py      murmur3/favicon hash, tech detection, data files
│   │   ├── templates.py        status-only exposure checks (/.env, /.git/config, …)
│   │   ├── signatures.py       131-entry signature table
│   │   ├── confidence.py       explainable 0-100 finding scoring
│   │   ├── wordlist.py         SecLists streaming + caching
│   │   ├── profiles.py         the 8 scan profiles
│   │   ├── workflow.py         TOML config, resumable state, diffs, multi-domain
│   │   ├── engine.py           orchestration + strict output filtering
│   │   └── selftest.py         loopback end-to-end verification
│   ├── ui/
│   │   ├── __init__.py         re-exports the render helpers
│   │   ├── render.py           palette-aware Rich rendering helpers
│   │   ├── console.py          headless Rich live-log renderer
│   │   ├── tui.py              Textual Monokai Pro TUI
│   │   └── dashboard.py        Streamlit web dashboard
├── tools/                      installer + timeout-bounded profiling harnesses
└── tests/
    ├── test_subsonar.py        engine, DNS, ports, profiles, filters, reports
    ├── test_performance.py     scheduling, multiplexing, cache, discovery, workflow
    ├── test_sources.py         plugin registry + 7 sources (mock-backed)
    ├── test_carryover.py       passive→brute merge, Finding round-trip, dedupe
    ├── test_geoip.py           BGP/RIR parsers, SQLite index, flags, `geoip` CLI
    ├── test_ratelimit.py       token bucket, per-resolver cap, resolver pacing
    ├── test_dnsintel.py        SOA/DS/DNSKEY/CAA decoding, SPF walk, posture
    ├── test_mining.py          robots/sitemap/security.txt/header mining + wave 2
    ├── test_fingerprint.py     murmur3, signatures, tech detection, data files
    ├── test_confidence.py      scoring spread, ranking, explainability
    ├── test_tui.py             headless TUI mount/stream/actions
    ├── test_tui_findings.py    findings table + click-to-open URL
    ├── test_features.py        service detection, template checks, JSONL export
    └── test_dashboard.py       Streamlit AppTest render + rich findings table
```

### Pipeline

```
   apex DNS intelligence (MX · SPF includes · DKIM · DMARC · CAA · NS/SOA · DNSSEC)
   offline geo index (BGP/RIR → local SQLite; no address ever leaves the machine)
   built-in OSINT (crt.sh ∥ HackerTarget ∥ Anubis)
 + plugin OSINT  (CertSpotter ∥ RapidDNS ∥ urlscan ∥ OTX ∥ ThreatMiner ∥ CommonCrawl ∥ subdomain.center)
 + active discovery (TLS SAN harvest · CNAME chase · permutations)
 + wordlist (SecLists streaming, cached)
                │
                ▼
        candidate pool  ──►  wildcard DNS pre-flight (drop false positives)
                │
                ▼
   anonymous async DNS  (UDP-multiplexed, health-checked pool, disk cache,
                         token-bucket rate limit)
                │            └─ optional: AAAA augmentation, N-resolver confirmation
                ▼
   port-major sweep (Top-50 matrix, adaptive fast→slow timeouts)
                │
                ▼  streaming — open ports go straight to the prober
   HTTP/HTTPS verification (aiohttp, anonymous DNS, </head>-bounded reads)
                │
                ▼
   strict filter (interface / restricted / redirect / drop)
                │
                ▼
   fingerprint (favicon hash · 131 signatures · data files)
                │
                ▼
   web mining (robots/sitemap/security.txt/headers) ──► second wave (re-resolve + sweep)
                │
                ▼
   enrichment (country flag · ASN · PTR) → confidence scoring →
   merge previous report → findings → live log + reports + diffs + baselines
```

---

## Output

Reports land in `./output/` (override with `--output`):

* `subsonar_<domain>_<timestamp>.json` — full machine-readable result
* `.csv` — findings table for spreadsheets
* `.md` — Markdown report with clickable links
* `.html` — standalone Monokai Pro Dark report (self-contained)
* `.txt` — fixed-width terminal report

Every report contains only verified web interfaces:

| Subdomain | Resolved IP | Port | Status | Kind | Title | URL |
|---|---|---|---|---|---|---|
| `portal.example.com` | `203.0.113.9` | 8443 | 200 | interface | Admin Portal | https://portal.example.com:8443 |
| `intranet.example.com` | `203.0.113.20` | 443 | 403 | restricted | Login required | https://intranet.example.com |

### What counts as a web interface

A TCP accept is **not** enough. subsonar only reports a port when the HTTP
response is a genuine application answer:

| Response | Verdict | Why |
|---|---|---|
| `200`/`30x` with a body or `<title>` **on the scanned port** | ✅ `interface` | real application |
| `401`/`403`/`407`/`429`/`451` | ✅ `restricted` | real app, credentials needed |
| `301` → a **different port** (e.g. `:2082` → `https://host/`) | ⚠️ `redirect` | the port only bounces elsewhere |
| `400 The plain HTTP request was sent to HTTPS port` | ❌ dropped | protocol error — a plain HTTP probe hit a TLS-only port |
| `400`/`405`/`408`/`414`/`426`/`431`/`501`/`505` | ❌ dropped | HTTP-layer rejection, no application behind it |
| `404`/`410` with no title and a tiny body | ❌ dropped | the port speaks HTTP but serves nothing here |
| `5xx` with no payload | ❌ dropped | gateway/proxy error, not an interface |
| empty body, no `<title>` | ❌ dropped | nothing to verify |

Three mechanisms produced the "20xx ports with no web interface" false positives,
and all three are now fixed:

1. **TLS-only ports were probed with plain HTTP.** `2083`/`2087`/`2096` (cPanel
   SSL) and `8443` only speak TLS, so a plain `GET` returns Apache's
   `400 The plain HTTP request was sent to HTTPS port`. Those ports are now in
   `TLS_FIRST_PORTS` and probed with `https` first, and that 400 body is on the
   rejection list either way.
2. **Content from the redirect target was credited to the bouncing port.** A
   Cloudflare-fronted cPanel port answers `301 → https://host/`; the probe used
   to follow that redirect and then read the *body, title and 200 status* off the
   final response — so `:2082` was reported as hosting the site that is really
   served on `:443`. Body, title, `Server` header and status are now read from
   the hop that belongs to the scanned port, and a redirect that changes the port
   is classified `redirect` instead of `interface`.
3. **One vhost answering on many ports was reported many times.** A single
   interface reachable on `2082`, `2086`, `2095` and `8080` is one web interface.
   Findings are grouped by `(host, ip, response fingerprint, scheme, status)` and
   only the most canonical port survives; the others become `also_on_ports`
   aliases and a `Filtered out … identical response fingerprint` log line.
   Genuinely different interfaces (a distinct fingerprint, or an HTTP/HTTPS pair)
   are never collapsed.

```
06:26:00.345 ✔ probe     WEB INTERFACE — http://support.example.com:2082 · 200 · Support : Example Inc
06:26:00.345 ✔ probe     WEB INTERFACE — http://support.example.com:2086 · 200 · Support : Example Inc
06:26:00.345 ✔ probe     WEB INTERFACE — http://support.example.com:2095 · 200 · Support : Example Inc
06:26:00.468 ✔ probe     Collapsed 2 duplicate port finding(s) — 1 distinct web interface(s) remain
```

| Subdomain | IP | Port | Status | Kind | also_on_ports | URL |
|---|---|---|---|---|---|---|
| `support.example.com` | `162.159.140.147` | 2082 | 200 | interface | 2086, 2095 | http://support.example.com:2082 |

### Redirect-only ports

A bounce is **not** an interface, so it is dropped whenever the host has a real
interface elsewhere. It is not thrown away either: if nothing else answers for
that host — the common case when `443` is firewalled — the bounce is promoted as a
`kind=redirect` finding so a live web service is never hidden. Its **link points
at the destination**, not at the port that cannot be opened, because browsers
force HTTPS on a cleartext alt-port and fail with `ERR_SSL_PROTOCOL_ERROR`:

```
06:50:02.615 ✔ probe  support.example.com:2082 Only a redirect answered for
          support.example.com — reporting https://support.example.com/ as a redirect
          entry (kind=redirect)
```

| Subdomain | IP | Port | Status | Kind | URL (clickable) |
|---|---|---|---|---|---|
| `support.example.com` | `172.66.0.145` | 2082 | 301 | redirect | https://support.example.com/support/home |

---

## Interface

### Textual TUI (`python main.py`)

```
┌ subsonar ────────────────────────────── profile · target · elapsed ┐
│ ASCII logo · live progress bar                                      │
├ live statistics ───────┬ live scanning log ────────────────────────┤
│ CANDIDATES  5,013      │ 05:46:31.419 ☁ osint  Querying CRT.sh ... │
│ DNS RESOLVED  1,204    │ 05:46:31.902 ⌁ dns    DNS Request (A) ... │
│ PORTS OPEN      382    │ 05:46:32.402 ⇄ port   Port OPEN ...       │
│ WEB FOUND        17    │ 05:46:32.690 ✔ probe  WEB INTERFACE ...   │
├ findings ──────────────┴───────────────────────────────────────────┤
│ # │ Subdomain        │ IP         │ Port │ Code │ Title │ URL      │
└ F1 help · F2 open · F3 export · F4 filter · F5 stop · F9 new ──────┘
```

Keys: `F1` help · `F2` open the selected URL in the host browser · `F3` export all
formats · `F4` toggle debug/filter events · `F5` cooperative stop · `F9` new scan ·
`Ctrl+Q` quit. Clicking a **URL** cell opens the link immediately.

### Streamlit dashboard (`python main.py web`)

Built for a real desktop rather than a 730-pixel column:

* **Full-width layout** — Streamlit's default `max-width` is overridden, so a 4K
  screen is actually used; `@media` rules scale the KPI figures, the live log and
  the findings table up at 2400 px and again at 3200 px.
* **One KPI strip** — 14 counters (candidates, resolved, DNS queries/failures/cache
  hits, open ports, HTTP probes, web found, filtered, third-party skips, carried
  over, OSINT/brute host counts, in-flight tasks) in a CSS grid that reflows to
  however many fit.
* **Findings view with flags** — a dense HTML table that spans the screen: `#`,
  subdomain, resolved IP, **country flag (hover for country + AS org + PTR)**,
  AS organisation, PTR, port, code, confidence, kind, provider, title, URL. Sort by
  confidence/subdomain/IP/port/status/country, free-text filter over every column,
  an "only merged" switch for the rows carried over from a previous scan, and a
  `sortable grid` toggle for the native Streamlit dataframe.
* **Findings that are live, not just final** — the table reads the engine's
  in-progress result, so rows appear as hosts are confirmed instead of only after
  the scan ends; it lives in its own 2 s fragment, which also means typing in the
  filter box re-runs only the table. When the scan finishes the app repaints once
  (banner + final collapsed rows + written reports) rather than looping.
* **Live log that behaves** — 68 vh tall, dark custom scrollbar, hover highlight,
  newest line on top, refreshed by a `@st.fragment(run_every=1s)` so the rest of the
  page never rebuilds (no flashing), with **⏸ Pause live view**, **Newest first**,
  **↺ Clear** and **⇩ Download log** above it. Quiet-log filtering rewrites the whole
  view retroactively; the caption reports exactly how many lines are buffered,
  rendered, hidden and (rarely) evicted.
* **Scope controls in the sidebar** — wordlist registry, port matrix, "merge
  previous results", "offline geo", the DNS rate limit and the TCP connect rate
  limit, on top of the target/profile/offline/quiet switches. The *Scan plan* tab
  prints the *effective* configuration (wordlist slice, matrix name, pacing) — the
  same lines the run itself logs at start-up.

```powershell
# default port 8501
python main.py web --port 8501 --headless

# a dashboard is already running in this workspace on port 8501:
#   http://127.0.0.1:8501
```

The page is themed purely through the Monokai Pro hex codes injected from
`subsonar.core.theme.Palette`, so the palette can never drift out of sync with the
TUI; `.streamlit/config.toml` mirrors the same values for Streamlit's own chrome.

---

## Robustness

* **Wildcard DNS** — randomised non-existent labels are resolved before any
  brute-force traffic is generated; matching IPs (and wildcard HTTP fingerprints)
  are filtered dynamically and logged as warnings. The explicitly requested apex
  and OSINT-confirmed hosts are exempt, so a fully wildcard domain still reports
  its real interface instead of nothing.
* **False-positive suppression** — protocol errors (plain HTTP probed against a
  TLS-only port), bare 4xx/5xx pages, redirect-only ports and duplicate ports
  serving one interface are all dropped with an explicit live-log entry
  explaining the decision. Bounces are retained as `kind=redirect` entries whose
  link points at the working destination.
* **Rate limiting** — every subsystem is gated by its own `asyncio.Semaphore`
  (DNS 400, ports 300, HTTP 60 by default; 60/40/12 in stealth mode). Stealth mode
  additionally inserts randomised inter-request delays.
* **Error handling** — DNS timeouts fall over to the next anonymous resolver,
  expired/self-signed/wrong-host certificates are accepted for fingerprinting but
  never crash the probe, `ConnectionResetError`/`BrokenPipeError`/`IncompleteReadError`
  are caught per probe, and the UI survives every failure via a defensive top-level
  guard. Ctrl+C and `F5` perform a cooperative shutdown that drains in-flight tasks.
* **Warm-start cache** — the SecLists wordlist is cached under `.subsonar_cache/`
  for 30 days; if the network is unavailable the cached copy is used, and a
  150-entry embedded seed list guarantees the scanner still runs from a cold start.

---

## Testing

```powershell
.\.venv\Scripts\python.exe -m pytest tests -q     # 545 tests
.\.venv\Scripts\python.exe main.py selftest       # 26/26 engine checks
python tools/selftest_bounded.py                  # same, hard 90 s timeout
```

`selftest` spins up a mock authoritative DNS server and a mock web server on
loopback, then runs the real engine through the entire pipeline — DNS wire
encode/decode, anonymous resolution, wildcard detection and false-positive
filtering, the async port matrix, HTTP verification and title extraction, the
strict web-interface filter, 500-writer event-bus concurrency, the full engine run
and all five report writers — without sending a single packet to a third party.

The pytest suite additionally verifies the Textual TUI headlessly (mounting,
live-log streaming, help/filter actions, findings table population and the
click-to-open-URL behaviour) using Textual's `run_test` pilot.

---

## Tooling & sandbox notes

`pip` cannot complete inside a restricted workspace sandbox (its temporary-directory
cleanup is denied and `pip install` stalls before touching site-packages). Two
zero-dependency helpers are therefore bundled:

| Tool | Purpose |
|---|---|
| `tools/wheel_installer.py` | Resolves wheels from the PyPI JSON API and extracts them straight into `site-packages` (dependency resolution, PEP 425 tag matching, PEP 508 markers, sha256 verification, console-script shims) |
| `tools/build_ai_wordlist.py` | Generates (or `--check`s) the built-in AI Super subdomain list from `subsonar/core/wordlistgen.py` |
| `tools/pip_shim.py` | Runs the bundled `ensurepip` pip wheel directly, for environments where `import pip` fails |
| `tools/profile_hotpaths.py` | Timeout-bounded profiling of every hot path |
| `tools/probe_timing.py` | Port-phase measurement against a realistic filtered address |
| `tools/dns_cache_bench.py` | Cold vs warm persistent DNS cache |
| `tools/selftest_bounded.py` | Self-test under a hard timeout, with per-check progress |
| `tools/resolver_matrix.py` | Benchmarks every anonymous resolver node |
| `tools/probe_one.py` | Raw wire interrogation of one `host:port` on both schemes |
| `tools/show_report.py` | Pretty-prints the newest JSON report |

```powershell
.\.venv\Scripts\python.exe tools\wheel_installer.py --check aiohttp textual streamlit
.\.venv\Scripts\python.exe tools\wheel_installer.py --list aiohttp
.\.venv\Scripts\python.exe tools\resolver_matrix.py
```

If you have a working `pip`, plain `pip install -r requirements.txt` is equivalent.

---

## Legal

subsonar is built for **authorised** security testing, asset discovery on domains
you own, and CTF/lab work. Port scanning and brute-forcing third-party
infrastructure without written permission is illegal in most jurisdictions. You
are responsible for how you use it.
