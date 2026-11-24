# Operations

## Continuous reconnaissance

Schedules can be declared in config (`schedules:`) or managed with the CLI, API or dashboard.

```bash
reconforge schedule add --name corp-daily --target example-corp --frequency daily --at 02:30
reconforge schedule add --name corp-weekly --target example-corp --frequency weekly --day mon --at 03:00 --profile standard --full
reconforge schedule add --name corp-cron --target example-corp --frequency cron --cron "15 */6 * * *"
reconforge schedule add --name once --target example-corp --frequency once
reconforge schedule list
```

All times are UTC. There are three ways to run schedules:
- `reconforge serve --with-scheduler` runs them in the dashboard process;
- `reconforge scheduler run [--interval 30]` runs a standalone daemon, with a lock file that prevents
  two daemons from running at once;
- `reconforge scheduler tick` runs whatever is due once, for system cron, launchd or systemd timers:

  ```text
  */5 * * * * cd /opt/ReconForge && .venv/bin/reconforge scheduler tick >> data/logs/scheduler.log 2>&1
  ```

The `continuous` profile is incremental: passive sources always run, while hosts probed within
`incremental.max_age_hours` are skipped and their state is carried forward. Use `--full` or
`incremental: false` for periodic full re-baselines, for example a weekly full scan alongside an
incremental daily one.

## Notifications

Enable channels under `notifications:`, keeping secrets in environment variables:

| Channel | Config | Secret env |
|---|---|---|
| Email | `smtp_host`, `smtp_port`, `starttls`, `username`, `from`, `to` | `RECONFORGE_SMTP_PASSWORD` |
| Telegram | `chat_id`, `api_base` | `RECONFORGE_TELEGRAM_TOKEN` |
| Discord | — | `RECONFORGE_DISCORD_WEBHOOK` (or `webhook_url`) |
| Slack | — | `RECONFORGE_SLACK_WEBHOOK` (or `webhook_url`) |

Each scan sends one summary per enabled channel. A summary lists:
- the target and each change's type;
- the first-observed time, previous value and current value;
- an evidence link and a report link built from `report_base_url`.

Changes whose fingerprint (category, asset and new value) was already sent within `dedup_hours` are
suppressed. Use `min_significance` and `categories` to filter further. To resend or test manually, run
`reconforge notify <scan_id> [--channels slack]`. Every attempt is logged in `notification_log` and shown
in the dashboard.

## Reports

Reports are generated automatically after each scan (`reports.auto_generate`) into
`data/reports/<target>/<scan>/`:
- `report.md`, `report.html`, `report.json`, `report.pdf`;
- CSVs for hosts, web apps, services, endpoints, findings, changes and priorities;
- `graph.graphml`, `graph.dot` and `graph.json`.

To toggle sections, set them under `reports.sections`, or pass
`reconforge report <scan> --disable cve,evidence --formats pdf` for a single run.

## Data management

```bash
reconforge db backup                          # online SQLite backup to data/backups/
reconforge db export --target example-corp    # portable JSON
reconforge db import --path export.json
reconforge db retention --days 180 --dry-run  # then without --dry-run
```

## Deployment notes

- Keep the API on 127.0.0.1, or put it behind an authenticating reverse proxy, and set
  `RECONFORGE_API_TOKEN`.
- Run scans from a host whose egress IP the asset owner has approved.
- Logs: one per scan in `data/logs/<scan>.log`, also viewable in the dashboard's execution history.
- For PostgreSQL: `pip install 'reconforge[postgres]'` and
  `RECONFORGE_DATABASE_URL=postgresql+psycopg://user:pass@db/reconforge`. Tables are created on first
  start. This path has not been exercised by the test suite.
