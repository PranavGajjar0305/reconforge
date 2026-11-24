# Dashboard

```bash
reconforge                       # = reconforge dashboard: API + UI + scheduler, opens the browser
reconforge --port 9000 --no-browser
reconforge -c config/lab.yaml    # use a config file (targets, providers, notifications, ...)
```

The dashboard binds to 127.0.0.1. Set `RECONFORGE_API_TOKEN` to require a bearer token (the UI asks
for it).

## Scans and targets

A **scan** is a named set of targets that run together. Create one on the **Scanner** page with
**New scan**: paste any mix of targets, one per line or comma-separated, and tick **I am authorized to test
these targets** (without it only the passive profile can run) —
- domains (`example.com`; each covers its subdomains, and a listed host under another listed domain is
  folded into it),
- IP addresses (`203.0.113.7`, `[2001:db8::1]`),
- CIDR ranges up to 4,096 addresses (`198.51.100.0/28`),
- URLs or `host:port` (reduced to the host).

The form classifies every entry as you type and flags invalid ones. **Create and start scan** saves it
and runs it immediately. Every module runs against all targets in a single execution: IP targets are
treated as hosts in their own right (port scan, HTTP/HTTPS probing, TLS, fingerprinting, nuclei, ASN and
IP intelligence) and appear in the inventory as "IP target" rows; domain-only sources (certificate logs,
subfinder, DNS security, brute force, …) are skipped with a clear reason when a scan has no domains.
Listed IPs are always contactable; addresses that domains resolve to still follow the public-only /
`ip_allow` rule. In config files the same is expressed as `root_domains:` plus `ip_targets:`.

Scans come from the config file (read-only in the UI) or the Scanner page (stored in the database,
`targets.config.source = dashboard`). Each one has:
- its targets (root domains and IP targets);
- include/exclude patterns (default `domain` and `*.domain`);
- allowed IP ranges for active checks (empty means public IPs only);
- optional port list;
- a default profile;
The authorization checkbox is enforced by the API as well as the UI: a scan that is not marked as
authorized can only run the passive profile. Config-file scans use `authorization.confirmed: true`.
Removing a scan keeps its execution history.

## Running scans

**▶ Run** calls `POST /api/scans`. The server validates the request synchronously (target, modules,
authorization), assigns a scan id, and runs the full pipeline in a background thread: modules,
rediscovery, correlation, change detection, prioritisation, reports, and notifications if enabled.
Only one run per target is allowed at a time.

### Live console

`/live/<scan_id>` shows:
- a terminal view streamed over Server-Sent Events (`GET /api/scans/{id}/stream`);
- the module pipeline, with each module's status and observation count;
- live asset counters and elapsed time.

Filters: *commands* (exec lines, HTTP GET/HEAD, DNS, TCP, TLS, provider lookups), *modules*,
*errors*, or free text. **Stop** cancels between modules (and terminates a long-running tool such as
Nuclei). The scan is then marked `cancelled` and is never used as a comparison baseline.

The module strip is interactive: an **All modules** chip shows the merged console with the current
module highlighted, and each module chip filters the console to just that module's log
(`GET /api/scans/{id}/log?module=<name>`, served from the full log so it survives the stream window).
**Download log** saves the complete execution log (`?download=1`). Opening `/live` with no id jumps to
the running scan, or the most recent one.

Every concrete action is logged by the module that performs it. The same lines are kept in
`data/logs/<scan>.log`, shown under Execution history (with **Show** / **Download execution log**), and
any in-progress result page shows what has been collected so far rather than a blank screen.

## Findings: triage board

`/triage` ranks every observation by a review-priority score: severity, detection confidence, the
exposure tier of its host (from Review priorities), whether it is new in the latest execution, and the
category. Severity counters double as filters; "Most exposed hosts" filters by host; rows can be grouped
by host, category or issue. Each observation has a decision workflow — **New, Investigating, Confirmed,
False positive, Accepted risk, Fixed** — with an analyst note, set one at a time or in bulk
(`POST /api/assets/{id}/triage`). False positive also sets the asset's false-positive flag, so it drops
out of reports and exports; closed states sink to the bottom of the list.

## Screenshots

`/screenshots` is a gallery of every screenshot taken (`GET /api/targets/{name}/screenshots`): filter by
URL, title, server or technology and by status class, collapse look-alike default pages (perceptual
hash), adjust thumbnail size, open any one full size (arrow keys page through them) and download one or
all of them as a zip.

## Output files

After every execution ReconForge writes plain files into `data/output/<scan>/<date>_<execution id>/`
(`GET /api/scans/{id}/files`, `…/files/{path}`, `…/files-zip`):

| Folder | Contents |
|---|---|
| `00_INDEX.txt` | every file with its line count and a description |
| `all/` | `subdomains.txt`, `subdomains_resolved.txt`, `ips.txt`, `open_ports.txt`, `live_urls.txt`, `web_apps.tsv`, `urls.txt`, `api_endpoints.txt`, `content_discovery.txt`, `parameters.txt`, `js_files.txt`, `technologies.txt`, `certificates.tsv`, `third_parties.txt`, `emails.txt`, `lookalike_domains.txt`, `dorks.txt`, `asn_prefixes.txt` |
| `findings/` | `findings.tsv` and one file per severity |
| `urls/gf/` | gf-style candidate lists: `xss.txt`, `sqli.txt`, `ssrf.txt`, `redirect.txt`, `lfi.txt`, `rce.txt`, `idor.txt`, … |
| `modules/<module>/` | what that module or tool found in this execution, e.g. `modules/subfinder/subfinder_subdomains.txt`, `modules/passive_sources/otx/otx_subdomains.txt` |
| `raw/<module>/` | raw stdout of every external tool (nuclei JSONL, nmap XML, ffuf JSON, …) |
| `screenshots/` | `<host>_<port>.png` for every screenshot |
| `logs/execution.log` | the full log |

The **Output files** page browses this tree, previews any file (first 500 lines or the image), and
downloads one file or the whole folder. **Regenerate** rebuilds it from the database at any time.

## OSINT & brand

`/osint` collects the passive intelligence that needs a human: Google / GitHub / Shodan / Censys / crt.sh
/ Wayback / urlscan / VirusTotal pivot links per domain (dork_builder), registered look-alike domains
with their A and MX records, published e-mail addresses and social profiles, the gf-style URL candidate
counts and most common parameters, and the prefixes announced by the organisation's own ASNs.

## API keys & integrations

`/settings` lists every key ReconForge or a registered tool can use (Shodan, SecurityTrails, VirusTotal,
Chaos/PDCP, GitHub, Cert Spotter, FullHunt, BinaryEdge, LeakIX, WhoisXML, OTX, urlscan, HackerTarget,
Brave Search, GreyNoise, IPinfo, plus any `api_env` declared in the registry). Keys are stored in
`data/settings.json` (mode 600, git-ignored), exported to the scan process so built-in providers and
external tools pick them up (subfinder also receives them through a temporary provider config), and
never returned to the browser — the page only shows whether a key is set and where it comes from.
Custom names must end in `_API_KEY`, `_KEY`, `_TOKEN` or `_SECRET`; variables that change how programs
load (`PATH`, `LD_*`, `DYLD_*`, `PYTHON*`, proxies, …) are refused.

**Notifications** (same page): turn alerts on, pick the minimum significance, and configure Slack,
Discord (webhook URL, `https://` only), Telegram (bot token + chat ID) and e-mail (SMTP host, port,
STARTTLS, username, from, recipients, password). Webhook URLs, tokens and passwords are stored next to
the API keys and are write-only. **Send test** posts a message that contains no scan data. Dashboard
values override the `notifications:` section of the config file for every later scan, including
scheduled and CLI scans.

**Burp Suite scope**: the Security page's **Burp scope** button downloads the target's scope (root
domains, include/exclude patterns, IPs and small CIDR ranges) as a Burp project-options file; load it
in Burp under Settings → Project → Scope.

Paths in API responses, logs and file previews are shortened: anything inside the project folder is shown
relative to it (`./data/...`) and anything else in your home directory starts with `~`, so screenshots and
exports do not reveal your account or folder names.

## Navigation

**Ctrl/⌘ + K** (or the search box in the header) jumps to any page and searches hosts, URLs, IPs and
findings of the current scan.

## Security of the dashboard

- Binds to 127.0.0.1. Without `RECONFORGE_API_TOKEN` only requests whose `Host` header is a loopback name
  (or one listed in `api.allowed_hosts` / `RECONFORGE_ALLOWED_HOSTS`) are accepted, which blocks DNS
  rebinding. With a token set, every request needs it (`Authorization: Bearer`, constant-time compared).
- State-changing requests from another origin (including `Origin: null`) are refused (CSRF).
- Every response carries a strict Content-Security-Policy (`script-src 'self'`), `X-Frame-Options: DENY`,
  `nosniff` and `Referrer-Policy: no-referrer`; API responses are `Cache-Control: no-store`.
- Files are served only from the execution's own output folder (path traversal is refused); errors are
  returned as JSON without stack traces.

## Tool output

`/output/<scan_id>` lists every module of an execution (status, results, evidence, log volume). Selecting
one shows its command, duration, results by asset type and four views: **Console** (that module's log
lines), **Results** (each asset it recorded, with the data it added and the evidence link), **Evidence**
and **Raw tool output** (stdout of external tools such as nuclei or subfinder). Each module downloads as
TXT, JSON or CSV (`GET /api/scans/{id}/modules/{module}/export?format=`), and **All modules (.zip)**
bundles every module plus the full execution log (`GET /api/scans/{id}/modules-export`). The same
downloads are on the Live console (for the selected module) and in Execution history.

## Exports

Every result page has an **Export** menu that downloads the page's complete data — not just the rows
on screen — as CSV, JSON or Markdown: `GET /api/targets/{name}/export/{surface}?format=csv|json|md`.
`GET /api/export-surfaces` lists the surfaces (subdomains, ports, web-apps, endpoints, technologies,
dns, certificates, third-parties, findings, cves, priorities, changes, scans, tools, graph, inventory,
coverage, …; `full` is the whole report dataset as JSON). The graph also exports as Graphviz and GraphML.

## Tools & commands

`GET /api/actions?target=` lists every built-in module and every registered tool, with the command or
action it performs against the selected target, its install status, and whether it can run.
**▶ Execute** (`POST /api/actions/run`) runs that single item as a standalone scan:
- stored assets are used as input, so `tls_inspect` alone re-checks known HTTPS apps;
- registry tools run through their module (for example `nmap` through `port_scan` with
  `engine: nmap`);
- generic tools run with `only_tools` set to that tool.

Single-item runs are labelled `single-action`, never send notifications, and are ignored by "latest
scan" views. Only registered commands run. The dashboard never accepts arbitrary shell commands.

**Install** appears beside Execute for any tool that is registered but not yet installed. It runs
`install.sh --only <tool>` (`POST /api/tools/{name}/install`), streaming progress into the row, then
re-detects the binary and records its path — so a missing engine can be added without leaving the
dashboard. Only names from `install.sh`'s own table are accepted; the browser can never trigger an
arbitrary install. Tools that are deliberately not executed (mass scanners, brute-forcers, exploit
checks) stay labelled with the reason instead of an Execute button.

### Findings report

The **Security observations** page exports a focused, shareable report of all findings and
version/CVE correlations — **HTML report** (opens in a tab, print-to-PDF ready) and **PDF report**
(`GET /api/targets/{name}/findings-report?format=html|pdf`). Each item keeps its severity, subject,
confidence and evidence id, with the standard "observations, not confirmed vulnerabilities" caveat.

## AI analysis

Providers (stored in `<data_dir>/settings.json`, mode 600; API keys are never returned to the browser):

| Provider | Notes |
|---|---|
| Offline analyst | Rule-based; nothing leaves the machine |
| Anthropic Claude | Official SDK, `claude-opus-5-5` by default, adaptive thinking and an effort setting, structured JSON output, server-side refusal fallback. Key from settings, `ANTHROPIC_API_KEY`, or an `ant auth login` profile |
| OpenAI | Chat Completions (`https://api.openai.com/v1`), JSON mode. Enter the model name you have access to. Key from settings or `OPENAI_API_KEY` |
| OpenAI-compatible | Any server with `/chat/completions`: Ollama (`http://localhost:11434/v1`), LM Studio, vLLM, OpenRouter, Groq, Azure-style gateways. Key optional |

External providers need an explicit consent tick, because the evidence pack for the target is sent to
that provider. The model must return:
- the standard sections;
- **`top_priorities`**: a ranked list with `priority` (critical/high/medium/low, meaning urgency of
  manual review, not a confirmed severity) and a `rationale`.

The evidence guard rejects statements, or rationales, that cite unknown evidence or mention hosts, IPs,
ports or CVEs that were not collected. Rejections are listed for audit.

**Any AI chat.** *Copy full prompt*, or download the prompt (`.txt`) or bundle (`.json`), paste it into
ChatGPT, Claude.ai or a local UI, then paste the JSON answer back into **Import answer**. Imported
answers pass through the same guard.

The lab provides a stub OpenAI-compatible endpoint at `http://127.0.0.1:8099/llm/v1` (any model name).
It returns an answer built from the evidence plus one fabricated statement, so you can see the guard
reject it.
