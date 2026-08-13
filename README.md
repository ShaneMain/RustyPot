# RustyPot

[![CI](https://github.com/ShaneMain/RustyPot/actions/workflows/ci.yml/badge.svg)](https://github.com/ShaneMain/RustyPot/actions)
[![License: GPL-3.0](https://img.shields.io/github/license/ShaneMain/RustyPot)](LICENSE)

Honeypot for exploit-path probes. Serves fake WordPress / Drupal / Joomla / Django login pages and config files, tarpits credential submissions 30 seconds each, fingerprints attackers by the specific password they use at their threshold position, and plants per-IP honeytokens in fake `.env` responses for cross-vector correlation.

## Fingerprinting

Each probing IP has a deterministic threshold (10-100, derived from `hash(ip + STICKY_SALT)`). Different IPs get different thresholds. The counter increments per credential POST and pins at threshold until the attacker submits a password not already in `granted_credentials`. On a new password: grant fake login success (302 + cookies), record it, reset the counter. On a known password: withhold the grant, keep the counter pinned, let the attacker churn through their dictionary (each attempt still costs 30s of tarpit).

Each IP thus contributes unique passwords. When one appears later from a different IP, you can correlate the attackers.

## `.env` honeytoken

`GET /.env` returns a realistic `.env` file containing a per-IP planted DB password (`fk` + 12 chars, deterministic from IP hash). The password is inserted into `granted_credentials`. If an attacker reads the `.env` and later submits that password at any login form, the submission is captured in `honeypot_event` and matchable to the original `.env` probe — correlating the attacker across vectors and infrastructure.

## Trapped paths

| Path | Method | Behavior |
|---|---|---|
| **Credential capture** | | |
| `/wp-login.php` | any | GET: fake WP login form. POST: parse creds, tarpit, threshold/fingerprint logic |
| `/xmlrpc.php` | POST | Parse XML-RPC creds, tarpit, return fault |
| `/user/login` | any | GET: fake Drupal login form. POST: parse `name`/`pass`, same threshold logic |
| `/administrator/index.php` | any | GET: fake Joomla admin login. POST: parse `username`/`passwd` |
| `/admin/login/` | any | GET: fake Django admin login. POST: parse `username`/`password` |
| **Honeytoken** | | |
| `/.env` `/.env.local` `/.env.production` | any | Return fake `.env` with per-IP planted credential |
| **Post-exploitation capture** | | |
| `/wp-admin/*` | any | Fake dashboard. POST: capture body (webshell source, file edits, spam) |
| `/admin/*` | any | Drupal/Django post-login capture |
| `/administrator/*` | any | Joomla post-login capture |
| `/wp-json/*` | any | GET: 200 `[]`. POST: capture body, return 201 |
| **Passive 404 + log** | | |
| `/.git/*` `/.svn/*` `/.hg/*` | any | VCS exposure probes |
| `/.aws/*` `/.ssh/*` | any | Cloud key / SSH key probes |
| `/actuator/*` `/_ignition/*` | any | Spring Boot / Laravel debug endpoints |
| `/solr/*` `/server-status` `/server-info` | any | Service exposure |
| `/composer.json` `/package.json` | GET | Dependency file probes |
| `/phpinfo.php` `/shell.php` `/c99.php` `/r57.php` `/webshell.php` `/index.php` `/adminer.php` | any | PHP shell probes |
| `/phpmyadmin/*` `/phpMyAdmin/*` `/pma/*` `/dbadmin/*` `/mysql/*` `/sqlmanager/*` | any | DB admin variants |

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
  --max-instances 3 --memory 256Mi --timeout 60
```
</details>

<details>
<summary>Cloudflare Worker (edge routing)</summary>

Deploy `cloudflare-worker.js` via Wrangler. Exploit-path prefixes route to RustyPot; everything else passes through to your app. The attacker sees the same hostname. Set `HONEYPOT_BACKEND` and `APP_BACKEND` as Worker secrets.
</details>

## Configuration

| Env var | Required | Default | Description |
|---|---|---|---|
| `DATABASE_URL` | yes | — | Postgres connection string (TLS required) |
| `STICKY_SALT` | recommended | `rustypot-default` | Salt for per-IP threshold + honeytoken derivation. Set to a random value per deployment. |
| `PORT` | no | `8080` | Listen port |
| `RUST_LOG` | no | `info` | Tracing filter |

## Database

See `migrations/`. Two tables:

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

- [ ] Ghost trap routes (`/ghost/api/admin/session`)
- [ ] Magento trap routes (`/admin`, array-style form fields)
- [ ] IP enrichment (ASN, cloud provider, geo)
- [ ] Localization capture (`Accept-Language`, `CF-IPCountry`)

## License

GPL-3.0
