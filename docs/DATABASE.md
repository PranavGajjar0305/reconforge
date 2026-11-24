# Database

The default is SQLite, using WAL mode with foreign keys on. The same SQLAlchemy models target PostgreSQL:
set `database.url: postgresql+psycopg://…` or `RECONFORGE_DATABASE_URL`, and install
`reconforge[postgres]`. Only SQLite has been exercised by the test suite. The full DDL is in
[schema.sql](schema.sql), generated from `reconforge/db/models.py`.

| Table | Purpose | Key columns |
|---|---|---|
| `targets` | configured targets (snapshot of target config) | name, config |
| `scans` | one row per execution | profile, status (running/completed/partial/failed), trigger (manual/schedule/api), incremental, started/finished, modules_planned/completed/failed/skipped, tools_executed, results_count, report_dir, log_path, prev_scan_id, summary |
| `module_runs` | per-module execution record | module (`name` or `name#2` for rediscovery), tool, status, observations, skipped_inputs, command, error, skip_reason |
| `assets` | one row per unique asset | type, key (normalized), display, scope, attributes (merged latest), sources (provenance + reliability), confidence, status (active/removed), first/last_seen, first/last_scan_id, false_positive, fp_reason |
| `observations` | every individual observation | scan, asset, module, source, observed_at, data, evidence_id, confidence |
| `relations` | edges between assets | src, dst, type, confirmed, confidence, sources, evidence_ids, first/last_seen |
| `evidence` | raw evidence | kind, summary, content (≤16 KB inline) or path, sha256 |
| `asset_states` | per-scan snapshot of each asset's state fields | scan, asset, state_hash, state, modules (direct observers), carried |
| `changes` | detected changes | category, significance, summary, previous, current, first_observed, evidence_id, fingerprint, notified |
| `asset_scores` | prioritisation per scan | score, tier, factors[{factor, points, reason}] |
| `schedules` | scan schedules | frequency, cron, profile, incremental, enabled, next/last_run_at, last_status |
| `notification_log` | delivery audit | channel, status (sent/failed/suppressed), fingerprints, change_ids, preview, error |
| `ai_analyses` | AI results | provider, model, status (completed/fallback), result, rejected, error |
| `reports` | generated report files | format, path |

## Asset types

`domain, subdomain, ip, asn, provider, certificate, service, web_app, technology, endpoint, js_file,
cloud_resource, third_party, repository, finding`

## Relation types

`has_subdomain, resolves_to, cname_to, announced_by, operated_by, exposes, serves, hosted_on,
redirects_to, presents, covers, uses, has_endpoint, loads, references, references_endpoint, documents,
links_to, historical_url, integrates_with, authorizes_sender, mail_handled_by, mentions,
has_observation`

## Historical queries

- `reconforge history <asset_id>` (or `GET /api/assets/{id}`) returns per-scan states, every
  observation, and changes for one asset.
- `reconforge diff <scanA> <scanB>` (or `GET /api/compare?a=&b=`) compares any two scans by asset state.
- `reconforge db export --target t` writes a portable JSON export. `db import` loads it, for example
  into a fresh SQLite or PostgreSQL database.
- `reconforge db backup` takes an online SQLite backup, or a JSON export for other engines.
- `reconforge db retention --days 90 [--dry-run]` deletes observations, evidence, states and changes of
  old scans while always keeping the newest `keep_min_scans` per target. Assets keep their
  first/last-seen history.
