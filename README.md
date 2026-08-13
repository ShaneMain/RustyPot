# RustyPot

Self-hosted exploit-path honeypot with sticky deception. Traps credential stuffers, captures post-exploitation payloads, and feeds everything into a Grafana dashboard.

## What it does

When bots probe your site for WordPress / config files / PHP shells, RustyPot:

1. **Serves realistic fake responses** — WP login forms, XML-RPC faults, admin dashboards, `.env` 404s
2. **Captures every submitted credential** — usernames, passwords, XML-RPC tokens
3. **Tarpits credential submissions** — 30-second delay per POST to slow bot sweeps
4. **Grants fake login success** after a per-IP threshold (10-100 attempts) or on a canary credential (`admin/admin`) — then captures **everything the bot does post-login**: webshell uploads, plugin file edits, backdoor user creation, spam content injection
5. **Logs everything** to Postgres with source IP, user-agent, full POST body, parsed credentials, response status, and tarpit delay

## Currently trapped paths

| Path | Behavior |
|---|---|
| `/wp-login.php` | GET: fake WP login form. POST: parse `log`/`pwd`, 30s tarpit, return "Incorrect password". After threshold/canary: 302 + WP auth cookies |
| `/xmlrpc.php` | POST: parse XML-RPC creds from `<string>` tags, 30s tarpit, return fault |
| `/wp-admin/*` | GET: fake admin dashboard. POST: capture body (webshell source, file edits) |
| `/wp-json/*` | GET: 200 + empty JSON. POST: capture body, return 201 |
| `/.env`, `/.git/*` | 404 + log |
| `/phpinfo.php`, `/index.php` | 404 + log |

More CMS targets (Drupal, Joomla, Ghost) planned.

## Quick start

### Prerequisites
- Postgres database (for the `honeypot_event` table)
- Docker or a Rust toolchain

### Docker

```bash
docker build -t rustypot .

docker run -p 8080:8080 \
  -e DATABASE_URL=postgres://user:pass@host/db \
  -e STICKY_SALT=$(openssl rand -hex 32) \
  rustypot
```

### Cloud Run

```bash
docker build -t gcr.io/YOUR_PROJECT/rustypot .
docker push gcr.io/YOUR_PROJECT/rustypot

gcloud run deploy rustypot \
  --image gcr.io/YOUR_PROJECT/rustypot \
  --region us-east1 \
  --port 8080 \
  --set-env-vars "STICKY_SALT=$(openssl rand -hex 32)" \
  --set-secrets "DATABASE_URL=your-db-url-secret:latest" \
  --allow-unauthenticated \
  --max-instances 3 --memory 256Mi --cpu 1 --timeout 60
```

### Traffic routing (Cloudflare Worker)

Deploy `cloudflare-worker.js` via Wrangler to split traffic at the edge — exploit paths go to RustyPot, everything else to your app. Set `HONEYPOT_BACKEND` and `APP_BACKEND` as Worker secrets.

## Configuration

| Env var | Required | Default | Description |
|---|---|---|---|
| `DATABASE_URL` | Yes | — | Postgres connection string |
| `PORT` | No | `8080` | HTTP listen port |
| `STICKY_SALT` | No | `rustypot-default` | Salt for per-IP threshold derivation. **Set this to a random value** so attackers can't compute thresholds from the public source. |
| `RUST_LOG` | No | `info` | Tracing filter |

## Database schema

Run the included migration to create the `honeypot_event` table:

```sql
-- See migrations/ for the full schema
```

Key columns: `source_ip`, `via_cloudflare`, `user_agent`, `method`, `path`, `post_body` (truncated 4 KiB), `submitted_user`, `submitted_pass`, `response_status`, `response_delay_ms`, `request_headers` (JSONB).

## Grafana dashboard

Query `honeypot_event` via the Postgres datasource for:
- Hits/day timeseries
- Top attacker IPs, paths, usernames, passwords, user-agents
- Fake-success triggers (`response_status = 302`)
- Post-exploitation path sequences
- Captured payloads (webshell source code, spam content)

## Features

- **Sticky trap**: after N attempts (10-100, deterministic per IP), returns fake login success. Bots proceed to post-exploitation — uploading webshells, creating backdoor users, injecting spam. All captured.
- **Canary credential**: `admin/admin` grants immediate fake success. Catches low-volume scanners that try 3-5 common passwords then move on.
- **Rate limiting**: 10 req/min/IP prevents self-DoS via tarpit concurrency.
- **Body limiting**: 4 KiB for credential routes, 256 KiB for admin capture routes (webshells are bigger).
- **Credential truncation**: submitted usernames/passwords truncated to 1 KiB for storage safety.

## License

GPL-3.0
