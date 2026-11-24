# Advanced reconnaissance expansion: coverage map

This maps each item in the expansion specification (modules 1–34) to what ReconForge implements.
**Implemented** means the code exists and is exercised in the lab or by unit tests. **Registry** means
the tool is described in the tool registry (`reconforge tools`) with its install method, purpose,
profile and maintenance status. If the binary is installed it runs through a generic or dedicated
adapter; otherwise the registry records it as a reference. **Not executed by design** marks tools that
conflict with the safety constraints.

## Tool management and selection (spec 17)

- **Registry.** `reconforge/data/tools.yaml` holds 60+ tools. Each entry has a name, purpose, category,
  phase, install method, version check (with a binary signature check), input and output format, API
  environment variables, execution profile (`passive` / `active` / `opt-in` / `reference`), and
  maintenance status. Extend it through `tool_registry:` in config without changing code. The lab adds
  `lab-subenum` this way.
- **Selection engine** (`core/registry.py`). For each category it checks whether the tool is installed,
  whether it is the right binary, whether credentials are present, whether the profile allows it,
  whether the scan is offline, and whether the tool is discontinued. Decisions and reasons are stored
  per scan (`summary.coverage.tool_selection`). They appear on the dashboard's Coverage & tools page and
  in `reconforge tools`.
- **Execution.** Complementary tools in a category all run. Their output is merged by the correlation
  engine (dedup plus noisy-OR confidence), and per-source unique contributions are reported. Execution
  time and errors are recorded per source. Missing coverage is listed explicitly. Rediscovery passes
  re-run only the modules needed for newly found hosts.

## Per-module status

| Spec | Area | Implemented | Registry / not executed |
|---|---|---|---|
| 1 | Subdomain enumeration | CT (crt.sh); passive providers: OTX, HackerTarget, URLScan, SecurityTrails, VirusTotal, Shodan DNS, Chaos, WhoisXML; search (Brave); Common Crawl; GitHub code search; historical (Wayback); controlled wordlist brute force; permutations; bounded recursion; ASN data; wildcard detection; resolution validation; CNAME analysis; clustering (name pattern, IP, environment); **source comparison with unique contribution** | amass, assetfinder, findomain, chaos, github-subdomains run through the generic adapter if installed; puredns/shuffledns as brute-force engines; sublist3r (unmaintained) and crobat (discontinued) are reference only. Censys, Netlas and RapidDNS are not built in; add them as providers or registry tools |
| 2 | DNS | Record enumeration, nameserver identification with provider and IPs, DNSSEC (DNSKEY/DS), CAA, SPF (lookup counting, multiple records), DMARC policy, DKIM selector presence, MTA-STS, TLS-RPT, BIMI, wildcard, dangling-CNAME **candidates** (manual verification wording), CNAME chains, historical DNS via asset states, opt-in AXFR check | dig, delv, dnsrecon, dnsenum, fierce, dnsviz, dnsvalidator, massdns: reference (dnspython equivalents) |
| 3 | IP / ASN / network | Team Cymru ASN, static maps, PTR, RDAP network ownership, Shodan InternetDB exposure, GreyNoise, IPinfo, hosting/cloud/CDN classification, historical IP via states, graph visualisation; shared IP/CDN never implies ownership | BGPView, HE BGP, FOFA, ZoomEye, Censys, Netlas are not built in |
| 4 | Ports / services | Configured-port TCP connect with banner reading, nmap (`-sT -sV --version-light`, no NSE scripts), naabu, service fingerprinting, admin-service exposure classification, alternate web ports fed to HTTP probing, conservative rate limiting | rustscan (reference); masscan, zmap, unicornscan not executed by design; UDP not implemented |
| 5 | Web fingerprinting | 70 built-in rules with confidence and evidence per technology, WhatWeb adapter, PD httpx tech output, JS library banners, CDN/WAF/cloud/API-documentation categories | webanalyze (reference); retire, gitleaks and trufflehog registered (adapters not yet wired); WPScan, CMSeeK and JoomScan not integrated |
| 6 | URL / endpoint discovery | Crawler, katana, Wayback, gau/waybackurls/waymore (generic adapter), Common Crawl, Brave Search, sitemap, robots, JS extraction, OpenAPI routes, **parameter inventory**, normalization and dedup, the 12 functional **URL categories** (labelled as function, not weakness) | gospider, hakrawler, paramspider, xnlinkfinder: reference. Burp and ZAP are manual tools |
| 7 | JavaScript intelligence | Endpoint, API, GraphQL and WebSocket extraction, source maps, third parties, library versions, secret patterns (redacted, never used or validated) | LinkFinder, SecretFinder, JSLuice: reference; TruffleHog and Gitleaks registered (must run with `--no-verification`) |
| 8 | Public repositories | GitHub code search (references only; secrets redacted) | GitDorker, searchcode, PublicWWW not integrated |
| 9 | Cloud | S3, Azure Blob, GCS, Firebase, App Engine, Heroku, API Gateway and other references from DNS, HTML, JS and headers (ownership unverified); cloud hosting classification | cloud_enum and s3scanner are opt-in; ScoutSuite, Prowler and Cloudlist are authenticated-account tools (reference) |
| 10 | API | OpenAPI/Swagger parsing (operations, parameters, request-body fields, security schemes), GraphQL detection by GET, WebSocket, OIDC and SAML metadata, API versions, API host inventory. Documented operations are never called | Kiterunner and Arjun not executed (brute force) |
| 11 | TLS | Certificate chain trust, SANs (with discovery), expiry, issuer, key, signature, negotiated version, ALPN/HTTP2, hostname mismatch, CT, certificate history | testssl.sh and sslyze: reference; sslscan registered. Full cipher-suite enumeration not implemented |
| 12 | Historical / OSINT | Wayback, Common Crawl, URLScan, OTX, GitHub, historical states and certificates | waymore and gau via the adapter; VirusTotal (subdomains); Intelligence X not integrated |
| 13 | Misconfiguration | Headers, CSP and HSTS details, cookies, CORS, directory listing, default pages, debug markers, version banners, DNS and email posture, TLS, CVE/EOL correlation, reviewed Nuclei. Each item is labelled as an **observation**, a **version correlation (unconfirmed)**, or a **detection** | Observatory, ZAP, Checkov, Semgrep not integrated |
| 14 | Attack surface map | NetworkX graph covering every listed asset type, shared infrastructure, interactive Cytoscape view, GraphML/DOT/JSON/PNG/SVG export | Maltego, Neo4j and Gephi can import the GraphML export |
| 15 | Processing and correlation | All listed items; coverage measurement in `coverage.py` | — |
| 16 | Reporting | Every listed report as a section in all formats (see `reports.sections`), with timestamps, sources, evidence, confidence and limitations | — |
| 18 | HTTP intelligence | Per-app profile: redirect chain, HTTP version, HTTP/2 (ALPN), HTTP/3 (Alt-Svc), compression, cache-control, HSTS/CSP/CORS details, cookies, TLS, CDN/proxy, server fingerprint, **HTTP vs HTTPS** comparison per host | curl, wget, gowitness: reference |
| 19 | Virtual hosts | Default-vhost baseline (a random name under the in-scope root, never arbitrary Host fuzzing), apps grouped by IP and shared certificate, redirect destinations | — |
| 20 | Crawling and app mapping | Bounded GET crawl, forms recorded and never submitted, JS collection, entry points, login and registration pages, documentation, site map, screenshots, version comparison through change detection | — |
| 21 | Nuclei | Allow-list only, intrusive tags excluded, template ID, name, severity, URL, matched evidence, timestamp, confidence and false-positive note | — |
| 22 | Content metadata | robots, sitemap, security.txt, HTML/OG/canonical metadata, public document inventory via **HEAD only** (no downloads, no PII retention), source maps, directory indexes | ExifTool and PDF metadata extraction intentionally not done (they would require downloading documents) |
| 23 | Mail infrastructure | MX, provider identification, SPF, DMARC, DKIM, MTA-STS, TLS-RPT, DNSSEC, third-party mail services. No emails are sent | — |
| 24 | Identity | Login, registration and password-reset inventory, IdP detection (Okta, Entra ID, Auth0, Cognito, Keycloak, …), OIDC and SAML metadata, session-cookie observations. No auth attempts | — |
| 25 | Third parties | Categorised dependency inventory (analytics, payments, support, error tracking, monitoring, marketing, email delivery, identity, CDN, cloud hosting, external APIs, …) from DNS, HTML, JS, headers and redirects. Third parties are never scanned | — |
| 26 | Dependencies | JS library and version identification, curated CVE/EOL correlation, outdated framework EOL | OSV, Grype, Trivy, Syft, Dependency-Check: reference (OSV lookup not yet implemented) |
| 27 | Cloud and storage | Same as 9 | BBOT reference |
| 28 | API and modern apps | Same as 10, plus WebSocket inventory and API-host relationships | — |
| 29 | Internet exposure | Shodan InternetDB (no key), GreyNoise, IPinfo, plus an "indexed ports not covered" coverage observation | Shodan full API, Censys, FOFA, ZoomEye, Netlas, uncover not integrated |
| 30 | Visual recon | Headless Chrome pinned to scoped IPs, perceptual-hash grouping, near-blank detection, default/login/staging identification, visual change across scans | gowitness and eyewitness: reference |
| 31 | Search-engine OSINT | Brave Search API (key), Common Crawl, Internet Archive, GitHub | Google and Bing are not queried (no scraping) |
| 32 | Change detection | All listed categories, plus visual change | — |
| 33 | Coverage and quality | Every listed metric, phase status (completed / partial / failed / skipped / not run), unavailable and failed sources, and an explicit statement that never claims more than what ran | — |
| 34 | Database | SQLite/PostgreSQL models, NetworkX graph, exports in JSON, CSV, Markdown and HTML (and PDF) | Elasticsearch/OpenSearch indexing not implemented |

## Verification status

All modules above marked implemented ran end to end in the lab (`./lab/run_demo.sh`) and are asserted
in `tests/test_lab_integration.py::test_expansion_intelligence`. External provider APIs were exercised
against lab emulators or mocked HTTP transports, not the live services. Their response formats follow
the providers' public documentation and may need adjusting if a provider changes its API.
