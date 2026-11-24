# Modules

Run `reconforge modules` to see the live list, which external tools are installed, and the profiles.

| Module | Phase | Traffic | Engines | Produces |
|---|---|---|---|---|
| domain_intel | passive | DNS resolvers | dnspython | domain DNS, SPF/MX/TXT integrations, email-auth observations |
| crtsh | passive | crt.sh | HTTP JSON | subdomains (CT) |
| subfinder | passive | public sources | subfinder | subdomains |
| github_intel | passive | GitHub API (token) | HTTP JSON | repository references, hostnames (secrets redacted) |
| historical_urls | passive | Wayback CDX | HTTP JSON, gau | historical endpoints, hostnames |
| dns_resolve | resolve | DNS resolvers | dnspython, dnsx | resolution, IPs, CNAME chains, wildcard and dangling-CNAME detection |
| asn_intel | network | DNS (Team Cymru) | static map, Team Cymru | ASN, provider, CDN, PTR |
| port_scan | network | **active**: configured TCP ports, allowed IPs | connect+banner, nmap, naabu | services, sensitive-service exposure |
| http_probe | http | **active**: one GET / per origin | httpx (python), PD httpx | web apps, headers, status, CDN/WAF, default-vhost filtering |
| tech_detect | fingerprint | active (reuses cached responses) | 70 built-in rules, WhatWeb | technologies with versions and categories |
| tls_inspect | fingerprint | **active**: TLS handshakes | ssl+cryptography, tlsx | certificates, SAN-based discovery, TLS issues |
| crawler | content | **active**: GET, same origin, bounded, robots.txt | built-in, katana | endpoints, forms (never submitted), JS files, third parties |
| js_analysis | content | **active**: GET of in-scope JS | built-in | API calls with methods, WebSockets, third parties, secret-like patterns (redacted), source maps |
| api_discovery | content | **active**: GET of ~15 well-known paths | built-in | OpenAPI/Swagger operations (documented, never called), GraphQL (GET only), OIDC metadata |
| security_config | assessment | none (analyses cached responses) | built-in | headers, cookies, CORS, banners, listings, debug markers |
| cloud_intel | assessment | none | built-in | S3/Azure/GCS/Firebase/... references (ownership unverified) |
| nuclei | assessment | **active**: full template library | nuclei | detections; aggressive/state-changing tags excluded |
| cve_intel | assessment | none | local YAML DB | version-match CVE and EOL observations (labelled unconfirmed) |
| vhost_discovery | fingerprint | **active**: GET / per web IP with in-scope candidate `Host` headers | built-in | hidden virtual hosts (staging/internal apps reachable only by Host header) |
| content_discovery | content | **active**: GET per wordlist entry, soft-404 calibrated, rate limited | built-in, ffuf, feroxbuster, gobuster, dirsearch, dirb | dirb-style directories/files, listings, sensitive paths (backups, VCS, debug, admin) |
| cms_intel | assessment | **active**: GET of CMS version files, plugin readme.txt, REST users, xmlrpc.php | built-in | WordPress/Drupal/Joomla version, plugins/themes with versions, user listing, XML-RPC, debug.log |
| url_patterns | assessment | none | built-in | gf-style xss/sqli/ssrf/redirect/lfi/rce/idor/debug candidate lists, parameter inventory, tokens in URLs (redacted) |
| lookalike_domains | passive | DNS resolvers only | built-in | dnstwist-style typosquats (omission, homoglyph, bitsquat, TLD swap, affixes) that are registered, with A/MX |
| broken_links | assessment | DNS resolvers only | built-in | external domains the target links to that no longer exist (broken-link hijacking candidates) |
| asn_prefixes | network | RIPEstat API | HTTP JSON | prefixes announced by organisation-owned ASNs (shared cloud/CDN ASNs skipped; never auto-scanned) |
| dork_builder | passive | none | built-in | Google/GitHub/Shodan/Censys/crt.sh/Wayback/urlscan pivot links for manual OSINT |
| favicon_hash | fingerprint | **active**: GET /favicon.ico per app | built-in MurmurHash3 | Shodan-compatible favicon hash + MD5, product match, clusters of hosts sharing an icon |
| waf_detect | fingerprint | none (analyses cached responses) | built-in | WAF / CDN / load balancer / API gateway per app (Cloudflare, Akamai, Imperva, AWS, F5, Azure, …) |
| well_known | content | **active**: GET of ~13 well-known files | built-in | Android/iOS app links, change-password, host-meta, nodeinfo, JWKS, web manifest, ads.txt, humans.txt |
| source_maps | content | **active**: GET of each JS file's map | built-in | publicly served source maps and the original source paths they reveal |
| exposed_files | content | **active**: GET/HEAD of ~33 curated paths, soft-404 aware | built-in | VCS metadata, env/config files, status/debug pages, backups. Secret values are redacted and never stored |
| contact_intel | assessment | none | built-in | e-mail addresses (in-scope role accounts flagged) and social profiles published on collected pages |
| cors_check | assessment | **active**: 3 GETs per app with a foreign / look-alike / null `Origin` | built-in | reflected-origin CORS, with or without credentials (no cookies are sent) |
| panel_detect | assessment | none | built-in | exposed admin, DevOps, monitoring, database, VPN and mail interfaces (no login attempts) |
| takeover_check | assessment | none | built-in | CNAME + "unclaimed resource" fingerprint matches (candidates only; nothing is ever claimed) |
| screenshots | capture | **active**: headless Chrome, IP-pinned, all other hosts blocked | Chrome/Chromium | screenshot evidence |

Engines are chosen per module in config, for example `dns_resolve: {engine: dnsx}` or
`port_scan: {engine: nmap}`. An external tool is used only if it is enabled, found on PATH, and its
version banner matches the expected project. For example, the Python `httpx` client CLI is not mistaken
for ProjectDiscovery httpx.

## Safety properties

- Active modules refuse to run without `authorization.confirmed: true`.
- `HttpFetcher` connects only to IPs that DNS produced and `scope.ip_allowed()` accepts. It sets
  Host/SNI to the hostname, rejects out-of-scope hosts, and raises if asked for any method other than
  GET or HEAD.
- Private, loopback and link-local addresses are refused unless explicitly listed in `scope.ip_allow`.
- A global rate limiter (`network.rate_limit_per_second`) applies to all active modules.
- Third-party hosts are never probed. They are only recorded as references.
- Secret-like values are redacted to a 4-character prefix plus a hash before storage.
- Nuclei runs its whole installed template library by default (auto-updated before each run), against
  in-scope web apps, resolved hostnames and non-HTTP services. Aggressive and state-changing tags
  (intrusive, DoS, fuzzing, brute-force, SQLi/XSS/RCE/SSRF/LFI) are excluded by default; set
  `nuclei.exclude_tags: []` to run everything, or `nuclei.reviewed_templates: [...]` for an allow-list.
  Because templates may POST, Nuclei is the one module that can send non-GET/HEAD requests, and only
  with confirmed authorization.

## Writing a module (plugin)

```python
from reconforge.core.module import Module, SkipModule, register
from reconforge.core.observation import Obs, Rel

@register
class MyTool(Module):
    name = "my_tool"
    description = "What it does"
    phase = "content"          # passive|resolve|network|http|fingerprint|content|assessment|capture
    active = True              # True if it sends traffic to target hosts (requires authorization)
    requires_internet = False  # True if it queries public third-party services
    tools = ["mytool"]         # optional external binaries (add a tools.mytool config entry)
    produces = ["endpoint"]

    def run(self, ctx):
        apps = ctx.live("web_app")             # assets observed in this scan
        if not apps:
            raise SkipModule("nothing to do")
        for app in apps:
            if ctx.incremental and not ctx.needs_refresh(app, self.name):
                ctx.mark_skipped_input(app.attributes["host"]); continue
            proc = ctx.run_tool("mytool", ["--json", app.key])        # logged + recorded
            ev = ctx.evidence("tool_output", f"mytool {app.key}", proc.stdout)
            ctx.emit(Obs("endpoint", app.key + "/x", {"kind": "api", "+discovered_via": [self.name]},
                         evidence_id=ev,
                         relations=[Rel("has_endpoint", "web_app", app.key, confirmed=True, reverse=True)]))
```

There are three ways to register a module:
- add the file to `reconforge/modules/`;
- list it in the config under `plugins: ["path/to/file.py", "pkg.module:Class"]`;
- publish a package with an entry point in the `reconforge.modules` group.

Then add the module to a profile, or use `--add my_tool`. See `examples/plugins/security_txt.py` for a
complete example.

Conventions:
- In `attrs`, a key prefixed with `+` is union-merged as a list; any other key overwrites.
- Use `common.finding(...)` for security observations so they get a severity, a recommendation, host
  attribution and a `has_observation` relation to their subject.
- Emit relations with `confirmed=False` when they are inferred.
