# Architecture

## Package layout

```
reconforge/
  config.py            YAML config deep-merged over defaults; profiles
  scope.py             scope + authorization enforcement (hosts, IP allow-lists)
  util.py              normalization (hosts, URLs, origins), hashing, ids
  core/
    module.py          Module base class, phases, @register, plugin loading (builtin, entry points, files)
    context.py         ScanContext handed to modules: emit(), evidence(), live()/assets(), tools, rate limiter
    observation.py     Obs / Rel dataclasses emitted by modules
    net.py             DNS resolver factory; HttpFetcher (GET/HEAD only, IP-pinned, scope-checked)
    tools.py           external tool discovery (with version-banner check) and execution
    pipeline.py        run_scan(): planning, execution, rediscovery, diff, scoring, AI, reports, notify
  modules/             19 built-in modules (one file per concern)
  correlation/engine.py  identity normalization, upsert/merge, provenance, confidence, relations
  diff/changes.py      per-scan asset state snapshots, coverage-aware change detection
  prioritize/engine.py explainable attention scoring
  ai/analyst.py        evidence pack, providers (Claude, heuristic), EvidenceGuard
  reports/             data assembly, Jinja templates (MD/HTML), CSV, PDF (ReportLab)
  graph/build.py       NetworkX graph, shared-infrastructure detection, Cytoscape/GraphML/DOT/SVG
  notify/dispatcher.py email/Telegram/Discord/Slack with fingerprint dedup
  scheduler/service.py cron engine, schedules, daemon, tick
  storage/maintenance.py backup, export/import, retention, history, scan comparison
  api/app.py           FastAPI; serves the built React dashboard from api/static
frontend/              React + Vite + Tailwind + Cytoscape + Recharts source
lab/                   controlled lab server and demo script
```

## Scan lifecycle (`core/pipeline.py`)

1. **Plan.** Resolve the profile, apply `--modules/--add/--skip`, and sort by phase (`passive → resolve →
   network → http → fingerprint → content → assessment → capture`). If any planned module is active, the
   target must have `authorization.confirmed: true`, or the scan is refused before it starts.
2. **Execute.** Each module runs inside a `ModuleRun` record (status, tool, command, counts, skip reason,
   error). A module failure is logged with a traceback and the scan continues. `SkipModule` records why a
   module did not run (tool missing, offline, no input).
3. **Rediscovery.** Hostnames found late (TLS SANs, JavaScript, crawling, code search) are resolved and
   probed in up to two extra passes restricted to the new hosts (`ctx.host_filter`).
4. **Snapshot and diff.** Each asset touched in the scan gets an `AssetState` row (a hash of its
   type-specific state fields). These are compared with the previous completed scan to produce `Change`
   rows (see below).
5. **Prioritize.** Writes `AssetScore` rows.
6. **Post-processing.** Optional AI analysis, report generation and notifications. Each runs in its own
   session and its failures are logged without losing the scan.

## Correlation model

- **Identity:** `(target, type, normalized key)`. The key is normalized per type: hostnames are
  lower-cased with wildcards and trailing dots removed; URLs are canonicalized (default ports dropped,
  query values removed, parameters sorted); web apps are keyed by origin; services by `ip:port/proto`;
  certificates by SHA-256 fingerprint. The same thing reported by different tools collapses into one
  asset with a stable `ast_…` id.
- **No over-merging.** Shared infrastructure never merges assets. Two hosts on the same IP stay two
  assets connected to one IP node. The graph marks shared nodes (IP, certificate, ASN, provider) and says
  this does not imply common ownership. A certificate's out-of-scope SANs are counted but never turned
  into assets. Third-party domains get `scope=third_party`, and their relation means "referenced by".
- **Provenance.** Every `Observation` row stores the module, source tool, timestamp, attribute payload,
  evidence id and confidence. `Evidence` rows hold DNS answers, HTTP exchanges, certificates (PEM), tool
  output, banners, JavaScript and screenshots, each with a SHA-256 hash. Content is stored inline up to
  16 KB and as a file on disk above that.
- **Confidence.** Each source has a configurable reliability. An asset's confidence is
  `1 − Π(1 − rᵢ)` over its distinct sources, so independent corroboration raises it. Inferred relations
  are discounted.
- **Direct vs referenced.** An asset emitted by a module counts as *observed*. An asset that only appears
  as the target of a relation counts as *referenced*. Only direct observation decides removal coverage.
- **False positives.** `false_positive` flags persist across re-observation. Flagged assets are excluded
  from reports, prioritisation and notifications. They stay visible in the dashboard with a toggle.

## Change detection (coverage-aware)

State fields per type (see `diff/changes.py:STATE_FIELDS`) include DNS records and resolution for
subdomains, technologies with versions, security headers, TLS fingerprint and status for web apps,
product and version for services, and expiry for certificates.

An asset missing from the current scan is only marked **removed** when all three of these hold:

1. a module that directly observed it before completed successfully in this scan;
2. no module skipped its host in incremental mode (host-less assets are carried whenever anything was
   skipped);
3. a parent it derives from (`has_observation`, `references`, `has_endpoint`, `loads`, `exposes`, …)
   was re-examined in this scan or was itself removed (removal cascades).

Otherwise the previous state is **carried forward** (`AssetState.carried = true`). As a result, a failed
module, a profile with fewer modules, or an incremental skip never produces false "removed" or
"resolved" results. The lab integration test checks this: an incremental scan straight after a full
scan yields zero changes.

## Prioritisation

The scorer covers web apps, non-web services, and resolving hosts with no web service. Factors include
internet reachability, CDN/WAF mediation (negative), API surface, public API documentation,
login/admin-like titles, non-production hostname labels (only labels left of the root domain), public
advisory and EOL matches, configuration observations by severity, co-located sensitive services, and
being new or changed in this scan. The total is multiplied by `0.6 + 0.4 × confidence`. Every factor
carries a written reason. Tiers run from P1 (≥ 60) to P4. The disclaimer that exposure is not severity
appears in every view.

## AI analysis and the evidence guard

`build_evidence_pack()` serializes only collected records, each with an id. The model must return JSON
(schema-enforced structured output). Each statement carries `kind` (`fact` or `hypothesis`) and `refs`.
`EvidenceGuard` rejects a statement when:
- it has no refs, or a ref is unknown;
- it names a hostname, IP address, port or CVE that does not appear in the pack;
- its kind is invalid.

Rejected statements are stored separately for audit and never shown as results. If the provider fails
(no credentials, network error, refusal or truncation), the deterministic heuristic analyst runs instead,
and the error is recorded.

The Claude provider uses `client.beta.messages.create` with model `claude-opus-5-5`, effort `high`,
`output_config.format` (JSON schema), and server-side refusal fallbacks
(`betas=["server-side-fallback-2026-07-01"], fallbacks="default"`). It reads credentials the standard
way (`ANTHROPIC_API_KEY`, or an `ant auth login` profile).

## Extensibility

New tools are added as modules without changing the core. See [MODULES.md](MODULES.md). Report sections,
profiles, notification channels (`notify/dispatcher.py: CHANNELS`) and CVE data are also driven by
configuration or data.
