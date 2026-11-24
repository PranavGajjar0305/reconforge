# REST API

Start the server with `reconforge serve [--host] [--port] [--with-scheduler]`. It binds to 127.0.0.1:8765
by default. Interactive OpenAPI docs are at `/api/docs`. If `RECONFORGE_API_TOKEN` (or the variable named
in `api.token_env`) is set, every `/api` request needs `Authorization: Bearer <token>`. For file
downloads, `?token=` is also accepted.

| Method & path | Description |
|---|---|
| `GET /api/meta` | targets, profiles, modules, auth mode, running scans |
| `GET /api/targets/{t}/overview` | executive overview of the latest scan, trend, priorities, recent changes, coverage gaps |
| `GET /api/targets/{t}/inventory` | one correlated row per host (DNS, IPs, HTTP, ports, tech, hosting, CDN/WAF, TLS, last seen) |
| `GET /api/targets/{t}/assets?type=&q=&scope=&status=&include_fp=` | asset list with priority |
| `GET /api/targets/{t}/report-data[?scan_id=]` | full structured report data |
| `GET /api/assets/{id}` | asset details, related assets (confirmed/inferred, evidence), history, observations |
| `POST /api/assets/{id}/false-positive` | `{false_positive, reason}` |
| `GET /api/evidence/{id}[?raw=1]` | evidence metadata and content, or the raw file (screenshots, large output) |
| `GET /api/scans?target=` | execution history with module runs |
| `GET /api/scans/{id}/log` | scan execution log |
| `GET /api/scans/{id}/reports`, `GET /api/reports/{rid}` | generated reports |
| `POST /api/scans` | `{target, profile?, incremental?}` starts a background scan of a **configured** target |
| `POST /api/scans/{id}/reports` | regenerate reports |
| `GET /api/scans/{id}/ai`, `POST /api/scans/{id}/analyze[?provider=heuristic]` | AI analysis |
| `GET /api/targets/{t}/changes?category=` | change history across scans |
| `GET /api/compare?a=&b=` | compare two scans |
| `GET /api/targets/{t}/graph?types=&format=cytoscape\|graphml\|dot` | relationship graph |
| `GET/POST /api/schedules`, `DELETE /api/schedules/{name}` | schedules |
| `GET /api/notifications` | notification delivery log |

The API never proxies or replays requests to discovered endpoints.
