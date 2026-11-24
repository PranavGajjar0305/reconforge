# Controlled lab

`lab/lab_server.py` simulates a fictional organization, Acme, under the reserved `.test` TLD. Every
service listens on 127.0.0.1, and all data is synthetic.

| Service | Port | Notes |
|---|---|---|
| DNS (UDP) | 5354 | authoritative for `acme.test`, plus PTR; NXDOMAIN otherwise |
| HTTP vhosts | 8080 | `www` (redirects to HTTPS), `dev` (Apache 2.4.49 / PHP 7.4.3 banners, debug page, weak cookie), `old` (phase 1), `beta` (phase 2) |
| HTTPS vhosts | 8443 | `www` (WordPress meta, jQuery 3.4.1, app.js with API calls, a WebSocket, an S3 reference and the AWS documentation example key), `api` (OpenAPI, Swagger UI, GraphQL, permissive CORS), `internal-admin` (login page, certificate expiring in 10 days, discoverable only through the `api` certificate's SAN) |
| SSH banner | 2222 | OpenSSH 8.2p1 |
| Search service | 9200 | phase 2 only (new open port) |
| Feeds and sinks | 8099 | crt.sh-, Wayback-CDX- and GitHub-search-compatible endpoints; Slack, Discord and Telegram webhook sinks |
| SMTP sink | 2525 | captures notification e-mails into `lab/runtime/mail/` |

Lab extras:
- `assets.acme.test` is a CNAME to a non-resolving S3 name, which demonstrates the dangling-CNAME check.
- `jenkins.acme.test` only appears in the emulated code-search result.

Expansion features in the lab:
- `vpn.acme.test` is only discoverable by wordlist brute force.
- `staging-api.acme.test` is only discoverable by permuting `api`, and serves a default nginx page.
- A DKIM key is published at `google._domainkey`.
- `shop.acme.test` comes only from the emulated OTX feed.
- `cdn-origin.acme.test` comes only from the registry stand-in tool `lab/bin/lab-subenum`, which is
  added purely through config.
- The emulated InternetDB, RDAP and Common Crawl return data.
- `www` serves security.txt, sitemap.xml, Open Graph and canonical metadata, plus a PDF (inventoried
  via HEAD).
- `internal-admin` links to an Okta SSO URL and a password-reset page.
- The OpenAPI document declares security schemes and parameters.

## Phase 2 changes

- `beta.acme.test` added (Next.js)
- `old.acme.test` removed
- `api` gains `/v2/orders` and `/v2/payments` and a reissued certificate
- `www` moves from nginx 1.18.0 to 1.24.0, adds a CSP header, and loads Stripe plus a new `checkout.js`
- port 9200 opens
- an `api` TXT record is added

## Running the demo

```bash
./lab/run_demo.sh
```

Expected results, each asserted by `tests/test_lab_integration.py`:

1. **Baseline scan.** 17 modules complete. `subfinder` and `nuclei` are skipped (offline, and no
   reviewed templates). Assets include 9 hostnames, 1 IP (shared by every host, so hosts are *not*
   merged), 3 certificates, around 8 web apps, around 25 endpoints, 2 cloud references and around 36
   observations. `internal-admin.acme.test` is found through a TLS SAN and probed in the rediscovery pass.
2. **Phase-2 scan.** Around 31 changes, including:
   - `new_subdomain` beta, `new_open_port` 9200, `new_web_application`;
   - `new_api_endpoint` ×2, `tech_version_changed` nginx, `security_headers_changed` (CSP added);
   - `certificate_changed` and `new_certificate`, `new_third_party_integration` js.stripe.com;
   - `subdomain_unresolved` and `removed_web_application` for `old`, with the observations tied to the
     old app resolved.
3. **Notifications.** One summary each by email, Telegram, Discord and Slack lands in the local sinks.
4. **Incremental scan.** 0 changes and no false removals. Notifications are suppressed.
5. **Analysis, reports and exports.** Heuristic AI analysis with 0 statements rejected by the guard, all
   report formats, GraphML/DOT graph exports, and a database backup.

The lab records any non-GET/HEAD request in `lab/runtime/unexpected_methods.log`. The integration test
asserts that it stays empty.

After the demo, start the dashboard and open http://127.0.0.1:8765:

```bash
reconforge -c config/lab.yaml serve
```

## Demo data set for screenshots (`lab/make_demo.sh`)

`lab_server.py --domain example.com` serves the same organization under another name: every
`acme.test` / `Acme` in DNS answers, certificates, pages and emulator responses becomes `example.com` /
`Example`, and incoming names are mapped back. The lab's own DNS server (127.0.0.1:5354) answers for
`example.com`, and `config/demo.yaml` points ReconForge at it with `network.offline: true`, so no request
reaches the real domain.

`./lab/make_demo.sh` resets `data/demo/` (git-ignored), runs a comprehensive scan against phase 1 and
another against phase 2, then runs the offline analyst. Open it with
`.venv/bin/python -m reconforge.cli -c config/demo.yaml serve --port 8790`. The README screenshots in
`docs/screenshots/` were taken from this data set.
