# RustyPot

[![CI](https://github.com/ShaneMain/RustyPot/actions/workflows/ci.yml/badge.svg)](https://github.com/ShaneMain/RustyPot/actions)
[![License: GPL-3.0](https://img.shields.io/github/license/ShaneMain/RustyPot)](LICENSE)

Honeypot for exploit-path probes. Serves fake WordPress / Drupal / Joomla / Django login pages, tarpits credential submissions with escalating delays, fingerprints attackers by the password they use at their threshold position, plants per-IP honeytokens in fake `.env` files, traps scanners in an infinite git-object chain, and cookie-bombs clients to cut their throughput.

## Fingerprinting

Each probing IP has a deterministic threshold (10-100, derived from `hash(ip + STICKY_SALT)`). The counter increments per credential POST and pins at threshold until the attacker submits a password not already in `granted_credentials`. On a new password: grant fake login success (302 + cookies), record it, reset the counter. On a known password: withhold the grant, keep the counter pinned, let the attacker churn through their dictionary.

Each IP contributes unique passwords. When one appears later from a different IP, you can correlate the attackers — even if they've rotated infrastructure.

## `.env` honeytoken

`GET /.env` returns a realistic `.env` file containing a per-IP planted DB password (`fk` + 12 chars, deterministic from IP hash). The password is inserted into `granted_credentials`. If an attacker reads the `.env` and later submits that password at any login form, the submission is captured and matchable to the original probe — correlating the attacker across vectors.

## Attacker engagement

Beyond passive capture, RustyPot actively wastes attacker resources:

- **Tarpit escalation** — after each fake-success grant, the tarpit delay for failed attempts increases: 30s → 60s → 120s → 240s (capped below Cloud Run's timeout). The attacker's throughput drops progressively.
- **Canary links** — every link in the fake admin dashboard carries a per-IP tracking token (`?fk=...`). When a bot clicks any link, the token is logged, mapping their post-exploitation path sequence.
- **Git loop** — `/.git/config` returns a realistic git config. `/.git/objects/` returns HTML directory listings. Each object page links to 3 more subdirectories, each with 10 objects — an infinite chain for HTML-following scanners. Pack files return 8KB with valid `PACK` headers.
- **Cookie bombing** — the first fake-success response sets 20 cookies of 400 bytes each (~9KB). The attacker's HTTP client echoes all cookies on every subsequent request, cutting effective throughput.

## Trapped paths

| Path | Method | Behavior |
|---|---|---|
| **Credential capture + threshold** | | |
| `/wp-login.php` | any | GET: fake WP login form. POST: parse creds, tarpit, threshold/fingerprint |
| `/xmlrpc.php` | POST | Parse XML-RPC creds, tarpit, return fault |
| `/user/login` | any | Drupal login form + cred capture |
| `/administrator/index.php` | any | Joomla admin login + cred capture |
| `/admin/login/` | any | Django admin login + cred capture |
| **Honeytoken** | | |
| `/.env` `/.env.local` `/.env.production` | any | Fake `.env` with per-IP planted credential |
| **Active traps** | | |
| `/.git/*` | any | Infinite git-object chain (config → HEAD → refs → objects → loop) |
| `/wp-admin/*` | any | Fake dashboard with canary links. POST: capture body |
| `/admin/*` `/administrator/*` | any | Drupal/Django/Joomla post-login capture |
| `/wp-json/*` | any | GET: 200 `[]`. POST: capture body, return 201 |
| **Passive 404 + log** | | |
| `/.svn/*` `/.hg/*` | any | VCS exposure |
| `/.aws/*` `/.ssh/*` | any | Cloud key / SSH key probes |
| `/actuator/*` `/_ignition/*` | any | Spring Boot / Laravel debug endpoints |
| `/solr/*` `/server-status` `/server-info` | any | Service exposure |
| `/composer.json` `/package.json` | GET | Dependency file probes |
| `/phpinfo.php` `/shell.php` `/c99.php` `/r57.php` `/webshell.php` `/index.php` `/adminer.php` | any | PHP shell probes |
| `/phpmyadmin/*` `/phpMyAdmin/*` `/pma/*` `/dbadmin/*` `/mysql/*` `/sqlmanager/*` | any | DB admin variants |

All routes are rate-limited (10 req/min/IP). Credential POSTs are body-limited to 4 KiB; admin capture routes allow 256 KiB for webshell uploads.

## Deploy

```bash
docker run -p 8080:8080 \
  -e DATABASE_URL=postgres://user:pass@host/db \
  -e STICKY_SALT=$(openssl rand -hex 32) \
  ghcr.io/shanemain/rustypot:latest
```

<details>
<summary>Cloud Run</summary>

```bash
gcloud run deploy rustypot \
  --image us-east1-docker.pkg.dev/PROJECT/REPO/rustypot:latest \
  --region us-east1 --port 8080 \
  --set-env-vars "STICKY_SALT=$(openssl rand -hex 32)" \
  --set-secrets "DATABASE_URL=your-db-secret:latest" \
  --allow-unauthenticated \
  --max-instances 3 --memory 256Mi --timeout 300
```
</details>

<details>
<summary>Cloudflare Worker (edge routing)</summary>

Deploy `cloudflare-worker.js` via Wrangler. Exploit-path prefixes route to RustyPot; everything else passes through to your app. Set `HONEYPOT_BACKEND` and `APP_BACKEND` as Worker secrets.
</details>

## Configuration

| Env var | Required | Default | Description |
|---|---|---|---|
| `DATABASE_URL` | yes | — | Postgres connection string (TLS required) |
| `STICKY_SALT` | recommended | `rustypot-default` | Salt for threshold + honeytoken derivation. Set per deployment. |
| `PORT` | no | `8080` | Listen port |
| `RUST_LOG` | no | `info` | Tracing filter |

## Database

See `migrations/`. Two tables:

- `honeypot_event` — one row per request (source_ip, ua, method, path, query, post_body, submitted creds, response status, tarpit delay)
- `granted_credentials` — fingerprint registry (username, password, first-granted IP, grant count)

Optional: `ip_enrichment` table for cloud-provider / country / ASN lookups (enrichment script in the repo).

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

## License

GPL-3.0
