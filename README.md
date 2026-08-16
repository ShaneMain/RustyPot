# RustyPot

[![CI](https://github.com/ShaneMain/RustyPot/actions/workflows/ci.yml/badge.svg)](https://github.com/ShaneMain/RustyPot/actions)
[![License: GPL-3.0](https://img.shields.io/github/license/ShaneMain/RustyPot)](LICENSE)

Honeypot for exploit-path probes. Serves fake WordPress / Drupal / Joomla / Django login pages, tarpits credential submissions with escalating delays, fingerprints attackers by the password they use at their threshold position, plants per-IP honeytokens in fake `.env` files, traps scanners in an infinite git-object chain, and cookie-bombs clients to cut their throughput.

## Fingerprinting

Each probing IP has a deterministic threshold (10-100, derived from `hash(ip + STICKY_SALT)`). The counter increments per credential POST and pins at threshold until the attacker submits a password not already in `granted_credentials`. On a new password: grant fake login success (302 + cookies), record it, reset the counter. On a known password: withhold the grant, keep the counter pinned, let the attacker churn through their dictionary.

Each IP contributes unique passwords. When one appears later from a different IP, you can correlate the attackers — even if they've rotated infrastructure.

## Installer claim

Bots race to complete WordPress's setup wizard on fresh installs — whoever finishes `install.php` first owns the site (they set the admin password, then upload a "plugin"). RustyPot mirrors the full wizard so installer-claim kits run their whole playbook against us:

1. `GET /wp-admin/setup-config.php` → DB-details form (real field names: `dbname`, `uname`, `pwd`, `dbhost`, `prefix`)
2. `POST setup-config.php?step=2` → DB creds logged, tarpit, "All right, sparky!" page linking the installer
3. `GET /wp-admin/install.php` → the five-minute-install form (exact core field names: `user_name`, `admin_password`, ...)
4. `POST install.php?step=2` → the kit's **chosen admin credentials** recorded with `origin='install'` in `granted_credentials`, tarpit, "Success!" page + WP session cookies (cookie bomb on the IP's first grant)
5. The kit verifies by logging in at `/wp-login.php` — an `origin='install'` pair is granted **immediately** (no stuffer threshold), because a verification that fails would make the kit flag the site as fake

`granted_credentials.origin` is write-once (`'login' | 'env' | 'install'`): the first trap to record a pair keeps its origin. Login/env-origin pairs keep the stuffer treatment (withheld grants, dictionary churn); install-origin pairs verify instantly. Bonus correlation: a stuffer IP that submits a *different* IP's claimed pair links the two actors.

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
| `/wp-login.php` | any | GET: fake WP login form. POST: parse creds, tarpit, threshold/fingerprint (`origin='install'` pairs grant immediately) |
| `/wp-admin/install.php` | any | GET: five-minute-install form. POST `?step=2`: capture chosen admin creds (`origin='install'`), tarpit, Success page + session cookies |
| `/wp-admin/setup-config.php` | any | GET: DB-details form. POST `?step=2`: capture DB creds, tarpit, "All right, sparky!" → install.php |
| `/xmlrpc.php` | POST | Parse XML-RPC creds, tarpit, return fault |
| `/user/login` | any | Drupal login form + cred capture |
| `/administrator/index.php` | any | Joomla admin login + cred capture |
| `/admin/login/` | any | Django admin login + cred capture |
| **Honeytoken** | | |
| `/.env*` (any variant: `.env.dev`, `.envrc`, `.env_copy`, ...) and `/{subdir}/.env*` | any | Fake `.env` with per-IP planted credential — matches any path segment containing `.env` |
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
| `/phpinfo.php` `/shell.php` `/c99.php` `/r57.php` `/webshell.php` `/index.php` | any | PHP shell probes |
| `/phpmyadmin/*` `/phpMyAdmin/*` `/pma/*` `/dbadmin/*` `/mysql/*` `/sqlmanager/*` `/adminer.php` | any | DB admin variants |

All routes are rate-limited (10 req/min/IP). Credential POSTs are body-limited to 4 KiB; admin capture routes allow 256 KiB for webshell uploads.

## Deploy

RustyPot's traps are configurable. By default all are enabled, which suits sites that don't use any of the spoofed paths (Rust/Node/Go APIs, SPAs, static sites). If your site actually runs WordPress (or Drupal, Joomla, Django, Spring Boot), disable the matching trap families so the Worker routes only your dead paths to the honeypot.

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
| `ENABLED_TRAPS` | no | `all` | Comma-separated trap families to enable. See below. |
| `TARPIT_ESCALATION` | no | `30,60,120,240` | Comma-separated tarpit ladder (seconds). Nth value applies after Nth grant; last value repeats. Cap 3600s/entry — keep below your platform's request timeout. |
| `THRESHOLD_MIN` / `THRESHOLD_MAX` | no | `10` / `100` | Per-IP grant threshold range. Swapped automatically if min > max. |
| `RATE_LIMIT_PER_MINUTE` | no | `10` | Per-IP rate limit across all honeypot routes. |
| `HONEYTOKEN_PREFIX` | no | `fk` | 1-8 alphanumeric chars prefixing planted credentials. |
| `COOKIE_BOMB_COUNT` | no | `20` | Cookies set on first grant. `0` disables the bomb. |
| `COOKIE_BOMB_SIZE` | no | `400` | Bytes per bomb cookie. |
| `PORT` | no | `8080` | Listen port |
| `RUST_LOG` | no | `info` | Tracing filter |

Invalid values log a warning at startup and fall back to defaults.

### Trap families

| Family | Claimed paths | Disable if your site... |
|---|---|---|
| `wordpress` | `/wp-login.php` `/xmlrpc.php` `/wp-json/*` `/wp-content/*` `/wp-includes/*` `/wp-admin/*` | runs WordPress |
| `drupal` | `/user/login` | runs Drupal |
| `joomla` | `/administrator/*` | runs Joomla |
| `django` | `/admin/login/` `/admin/*` | runs Django/Flask |
| `git` | `/.git/*` (infinite loop) | serves a git repo |
| `env-honeytoken` | `/.env*` | serves a real `.env` |
| `cloud-keys` | `/.aws/*` `/.ssh/*` | |
| `vcs` | `/.svn/*` `/.hg/*` | |
| `framework-debug` | `/actuator/*` `/_ignition/*` | runs Spring Boot / Laravel |
| `php-shells` | `/phpinfo.php` `/index.php` `/shell.php` `/c99.php` `/r57.php` `/webshell.php` | runs PHP |
| `db-admin` | `/phpmyadmin/*` `/pma/*` `/dbadmin/*` `/mysql/*` `/sqlmanager/*` `/adminer.php` | serves phpMyAdmin |
| `service-exposure` | `/solr/*` `/server-status` `/server-info` `/composer.json` `/composer.lock` `/package.json` | serves those files |

Disabled families return 404 from RustyPot. If you use the edge router (`cloudflare-worker.js`), also remove the matching prefixes from its `HONEYPOT_PATHS` regex — otherwise the Worker keeps routing those paths to RustyPot and your real site gets 404s instead of traffic. Unknown family names are logged and skipped at startup; `all` (default) and `none` are keywords, and `wp`/`env` are aliases.

Examples:

```bash
# All traps (default — for sites on non-spoofed stacks like Rust/Node/Go/SPAs)
ENABLED_TRAPS=all

# Protecting a real WordPress site: keep only dead-path traps
ENABLED_TRAPS=git,env-honeytoken,cloud-keys,vcs,php-shells,db-admin

# Only credential capture
ENABLED_TRAPS=wordpress,drupal,joomla,django
```

## Database

See `migrations/`. Two tables:

- `honeypot_event` — one row per request (source_ip, ua, method, path, query, post_body, submitted creds, response status, tarpit delay)
- `granted_credentials` — fingerprint registry (username, password, first-granted IP, grant count, origin: `'login' | 'env' | 'install'`)

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
