# RustyPot

[![CI](https://github.com/ShaneMain/rustypot/actions/workflows/ci.yml/badge.svg)](https://github.com/ShaneMain/rustypot/actions)
[![License: GPL-3.0](https://img.shields.io/github/license/ShaneMain/rustypot)](LICENSE)

Standalone honeypot that traps WordPress / config-file / PHP-shell probes, captures submitted credentials, tarpits each attempt 30 seconds, and fingerprints attackers by the specific password they use at their threshold position.

## Fingerprinting

Each probing IP has a deterministic threshold (10-100 POST attempts, derived from `hash(ip + STICKY_SALT)`). Different IPs get different thresholds. When the counter reaches the threshold, the submitted credential is checked against `granted_credentials`:

- **New password** → grant fake login success (302 + WP auth cookies), record the credential, reset the counter.
- **Already-known password** → don't grant. The counter stays pinned at threshold, so every subsequent attempt also fires the check. The attacker churns through their remaining dictionary (each attempt still gets the 30s tarpit) until they submit a password that isn't in the table yet.

The result: each IP contributes unique passwords to `granted_credentials`. When one of those passwords appears later from a different IP, you can correlate the attackers — even if they've rotated infrastructure.

```
IP 1.2.3.4   threshold=23  →  granted on attempt 23: admin/qwerty123
IP 5.6.7.8   threshold=67  →  granted on attempt 67: admin/passw0rd!
IP 9.10.11.12 threshold=12 →  granted on attempt 12: admin/letmein
```

## Trapped paths

| Path | Method | Behavior |
|---|---|---|
| `/wp-login.php` | GET | Fake WP login form |
| `/wp-login.php` | POST | Parse creds, tarpit 30s, return error — or 302 on threshold grant |
| `/xmlrpc.php` | POST | Parse XML-RPC creds, tarpit 30s, return fault |
| `/wp-admin/*` | any | GET: fake dashboard. POST: capture body (webshell source, file edits) |
| `/wp-json/*` | any | GET: 200 `[]`. POST: capture body, return 201 |
| `/.env` `/.git/*` | GET | 404 + log |
| `/phpinfo.php` `/index.php` | GET | 404 + log |

## Deploy

```bash
docker run -p 8080:8080 \
  -e DATABASE_URL=postgres://user:pass@host/db \
  -e STICKY_SALT=$(openssl rand -hex 32) \
  ghcr.io/shanemain/rustypot:latest
```

For Cloud Run and Cloudflare Worker routing, see the commands below.

<details>
<summary>Cloud Run</summary>

```bash
gcloud run deploy rustypot \
  --image us-east1-docker.pkg.dev/PROJECT/REPO/rustypot:latest \
  --region us-east1 --port 8080 \
  --set-env-vars "STICKY_SALT=$(openssl rand -hex 32)" \
  --set-secrets "DATABASE_URL=your-db-secret:latest" \
  --allow-unauthenticated \
  --max-instances 3 --memory 256Mi --timeout 60
```
</details>

<details>
<summary>Cloudflare Worker (edge routing)</summary>

Deploy `cloudflare-worker.js` via Wrangler. Exploit-path prefixes route to RustyPot; everything else passes through to your app. The attacker sees the same hostname.

Set `HONEYPOT_BACKEND` and `APP_BACKEND` as Worker secrets.
</details>

## Configuration

| Env var | Required | Default | Description |
|---|---|---|---|
| `DATABASE_URL` | yes | — | Postgres connection string (TLS required) |
| `STICKY_SALT` | recommended | `rustypot-default` | Salt for per-IP threshold derivation. Set to a random value per deployment. |
| `PORT` | no | `8080` | Listen port |
| `RUST_LOG` | no | `info` | Tracing filter |

## Database schema

See `migrations/001_honeypot.sql`. Two tables:

- `honeypot_event` — one row per request (source_ip, ua, method, path, post_body, submitted creds, response status, tarpit delay)
- `granted_credentials` — fingerprint registry (username, password, first-granted IP, grant count)

## Architecture

```
         Cloudflare Worker
         /              \
   exploit paths    everything else
        |                |
   RustyPot          Your App
        |
   Postgres
```

## Roadmap

- [ ] Drupal, Joomla, Ghost trap routes
- [ ] IP enrichment (ASN, cloud provider, geo)
- [ ] Localization capture (Accept-Language, CF-IPCountry)

## Origin

Extracted from [FillerKiller](https://fillerkiller.app), a TV filler-episode voting app. In its first 67 days the honeypot captured 2,461 exploit-path probes from 8 attacker IPs.

## License

GPL-3.0
