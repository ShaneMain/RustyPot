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

The planted pair is recorded in `honeypot_event.planted_user` / `planted_pass` — **never** in `submitted_user` / `submitted_pass`. Those two columns mean "the attacker sent us this", exclusively. (They did not always: the trap originally wrote plants into the `submitted_*` columns, which made the honeypot's own output indistinguishable from attacker input and inflated every credential metric roughly fourfold. Migration `004` separates the historical rows.)

## Attacker engagement

Beyond passive capture, RustyPot actively wastes attacker resources:

- **Tarpit escalation** — after each fake-success grant, the tarpit delay for failed attempts increases: 30s → 60s → 120s → 240s (capped below Cloud Run's timeout). The attacker's throughput drops progressively.
- **Slow-response budget** — every delaying trap reserves a slot before it
  holds a request open (`SLOW_RESPONSE_BUDGET`, default 64). Cloud Run gives
  this service `containerConcurrency` 80 across `maxScale` 3 — 240 request
  slots — and a held response occupies one for its full duration. Without a cap,
  enough parallel tarpits would fill the pool and the honeypot would stop being
  able to record new probes: tarpitting itself out of existence. When the budget
  is spent the trap answers immediately instead, and logs a delay of 0, so
  `response_delay_ms` always reflects time actually spent rather than time
  intended. A fast response is unremarkable to an attacker; a request the
  platform kills at its 300 s timeout is a 504 that identifies the trap.
- **Recon tarpit** — the `.env` and `.git` families get their own, much shorter ladder (`RECON_TARPIT_ESCALATION`, default `0,2,5,10,20` s), stepped by how many recon paths the IP has swept (`RECON_TARPIT_STEP`, default 10). Secrets harvesting is the most common objective observed, and it used to be the one family that cost the attacker nothing. The ladder is deliberately short: sweepers hit hundreds of paths, and a 30–240 s hold per path would pin every instance and starve the credential traps. A one-off probe sits on rung 0; a 300-path enumerator climbs.
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
| `/wp-admin/admin-ajax.php` | any | Plugin exploit surface: parses the account a privilege-escalation creates (recorded `origin='ajax'`, grants instantly at login), answers injection attempts with a fabricated `wp_users` dump |
| `/wp-content/plugins/*/*.php` | any | Plugin entry points — the exploit the fingerprint bait advertises now lands somewhere instead of 404ing |
| `/wp-admin/*` | any | Fake dashboard with canary links. POST: capture body |
| `/admin/*` `/administrator/*` | any | Drupal/Django/Joomla post-login capture |
| `/wp-json/batch/v1` | any | Real batch semantics — one row per bundled sub-request, so a 50-attempt amplification batch reads as 50 attempts |
| `/wp-json/*` | any | GET: 200 `[]`. POST: capture body, return 201 |
| `/.aws/credentials` `/.git-credentials` `/.gitconfig` `/.gitlab-ci.yml` `/.github/workflows/*` `/.npmrc` `/.docker/config.json` | any | Secret-file honeytokens with a per-IP planted credential (`origin='secret'`) |
| `/phpinfo.php` | any | Full fake `phpinfo()` (~27 KB) with planted credentials in the environment block |
| `/actuator` `/actuator/env` `/actuator/health` `/actuator/mappings` `/actuator/configprops` | any | Spring Boot Actuator with planted datasource credentials |
| `/actuator/heapdump` | any | Valid HPROF header, then a slow trickle — the one endpoint attackers expect to be huge and slow. Holds a budget slot for the stream, released on hang-up; served whole and fast when the budget is spent |
| `/phpmyadmin/*` `/pma/*` `/dbadmin/*` `/adminer.php` (15 spellings) | any | phpMyAdmin login form + credential capture |
| `/wp-includes/js/*` `/wp-includes/css/*` `/wp-admin/css/*` | any | Core JS/CSS. A real WordPress always serves these; 404ing them identified the install as fake |
| **Passive 404 + log** | | |
| `/.svn/*` `/.hg/*` | any | VCS exposure |
| `/.ssh/*` | any | SSH key probes |
| `/_ignition/*` | any | Laravel debug endpoint |
| `/solr/*` `/server-status` `/server-info` | any | Service exposure |
| `/composer.json` `/package.json` | GET | Dependency file probes |
| `/shell.php` `/c99.php` `/r57.php` `/webshell.php` | any | PHP shell probes |
| `/index.php` | any | PHP probe; also serves an injected XML-RPC canary post back to the IP that injected it |
| `/mysql/*` `/sqlmanager/*` | any | DB admin variants |
| **Fingerprint bait** | | |
| `/wp-includes/version.php` | any | Raw core `version.php` naming an outdated `$wp_version` |
| `/readme.html` | any | Core readme naming the same version |
| `/wp-content/plugins/{slug}/readme.txt` | any | Plugin readme with an outdated `Stable tag:` — a real name and a known-vulnerable version for ~35 catalogued slugs, a conservative default for the rest |
| `/wp-content/themes/{slug}/style.css` | any | Theme header with an outdated `Version:` |
| **Catch-all** | | |
| anything else the edge routes here | any | Logged, then 404 — including method mismatches (`GET /xmlrpc.php`) |

## Secret-file honeytokens

Beyond `.env`, every file an attacker reads specifically to extract a
credential is a honeytoken vector on the same model: `.aws/credentials`,
`.aws/config`, `.git-credentials`, `.gitconfig`, `.gitlab-ci.yml`,
`.github/workflows/*.yml`, `.npmrc`, `.docker/config.json`. Each carries a
deterministic per-IP secret recorded with `origin='secret'`.

`.aws/credentials` is the highest-intel member. Set `AWS_CANARY_ACCESS_KEY_ID`
and `AWS_CANARY_SECRET_ACCESS_KEY` to a **real** AWS canary token (a
permissionless IAM user with a CloudTrail alarm) and you learn the attacker's
IP at the moment they *use* the key — the only signal here that survives their
infrastructure rotation. A genuine canary is necessarily one fixed credential,
so per-IP attribution comes from the `honeypot_event` row that recorded serving
it, matched on time. Unset, the file carries a per-IP fake with the right shape.

`/phpinfo.php` and `/actuator/env` plant the same way: both are pages whose
whole purpose is dumping the process environment, so credentials in them look
like a misconfiguration rather than bait.

## Impersonated crawlers

User-agents branded as ChatGPT-User, PerplexityBot, Amazonbot, GPTBot and
friends show up requesting `.env`, `.aws/credentials` and login forms. No
legitimate crawler does that; the branding is chosen because sites commonly
allowlist those crawlers. Requests matching a crawler user-agent **on a path no
crawler would request** get a distinct honeytoken prefix (`fk` → `fkx`), so a
credential surfacing later carries "this actor impersonates AI crawlers" as a
tooling fingerprint without needing a join.

## Wire-level disguise

Every HTML trap response is dressed as PHP-served WordPress by middleware —
`X-Powered-By`, WordPress's fixed 1984 `Expires`, the no-cache pair, the
`wordpress_test_cookie` on `wp-login.php`, and the `Link: rel="https://api.w.org/"`
REST advertisement. `cloudflare-worker.js` strips `x-cloud-trace-context`
on the way back, which the container cannot do itself and which otherwise
reaches the client on every response. (`server` needs no rewrite: Cloudflare
already replaces the origin's value with `server: cloudflare`.) Applied
centrally so a new trap cannot forget it.

`PUBLIC_HOSTNAME` supplies the host for the REST `Link` header. It is never
derived from the request's `Host`: behind the edge that is the origin's own
address, so echoing it would publish the backend URL and identify the stack.
Unset, the header is simply omitted.

## Content-injection canary

`metaWeblog.newPost` probes inject a unique token as the post title and body,
then search the web for it — if it appears, the site accepts unauthenticated
publishing and joins a spam farm. RustyPot reports success with a post id and
serves the token back at `/index.php?p=<id>`, which earns the follow-up visit.

**The injected content is served only to the IP that injected it, only with
`X-Robots-Tag: noindex`, and always HTML-escaped.** Attacker-supplied content
reachable by anyone else, or indexable, would turn this service into a spam
relay for whatever they inject next. The store is bounded at 512 posts.

## Reading the data

Query **`honeypot_event_live`**, not `honeypot_event`. The raw table also holds:

- **Synthetic rows** (`synthetic = TRUE`) — written by the out-of-band backfill
  importers, not captured by this service. They carry no POST body, no real
  headers, and in the `drop-recovery` case an *inferred* source IP. Aggregating
  them with live captures fabricates attacker behaviour that was never observed.
- **Cloudflare-origin rows** — requests whose client is Cloudflare itself
  (`cf-connecting-ip` is a Cloudflare address), not an attacker proxied through
  it. `is_cloudflare_origin(source_ip)` tests this against the `cloudflare_ranges`
  table; refresh that table from https://www.cloudflare.com/ips/ when the
  published prefixes change.

The view excludes both. `honeypot_event` remains the place to answer questions
*about* capture coverage — which is what the provenance panel does.

Every request that reaches the service is recorded, including ones it answers
with 404 or 503 — the paths RustyPot does *not* yet trap are the feed for
deciding which trap to build next, so they must not be dropped silently.

The fingerprint bait exists because scanners read before they attack: the
observed pattern is a bot confirming WordPress, reading the core version, then
enumerating plugin `readme.txt` files, and leaving without an exploit attempt
when those come back 404. A scanner compares `Stable tag:` against the affected
range of whatever bug it knows, so `KNOWN_PLUGINS` in `templates.rs` names a
version inside the publicly-known-vulnerable range for the plugins currently
being exploited in the wild, biased low — being wrong about a patch boundary
costs a missed escalation, never cover. Refresh that list as trends move; the
dashboard's "Untrapped probes" and "Fingerprint bait" panels show which slugs
are actually being asked for.

All routes are rate-limited (240 req/min/IP) as an abuse valve only: over-quota
requests are still recorded, and are answered with WordPress's "Error
establishing a database connection" page rather than a `429`, which no real
WordPress emits. Credential POSTs are body-limited to 4 KiB; admin capture
routes allow 256 KiB for webshell uploads.

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

Deploy `cloudflare-worker.js` via Wrangler on a fresh setup. Exploit-path prefixes route to RustyPot; everything else passes through to your app. Set `HONEYPOT_BACKEND` and `APP_BACKEND` as Worker secrets.

**Updating an already-deployed Worker: use `./deploy-worker.sh`, not `wrangler deploy`.** This Worker routes *all* traffic for the zone, the real app included. Wrangler reconciles the whole Worker against `wrangler.toml`, so anything that file omits — the route binding, `HONEYPOT_BACKEND`, `APP_BACKEND` — it may rewrite or drop, and losing either backend binding returns 500 for every request to the site, not just the honeypot. The script uses the script-upload API with `keep_bindings`, which replaces the code and leaves routes and secrets untouched.

```
CF_API_TOKEN=…                     ./deploy-worker.sh   # lists script names
CF_API_TOKEN=… WORKER_NAME=fk-edge ./deploy-worker.sh   # deploys
```

The token needs **Account > Workers Scripts > Edit** and nothing else.
</details>

## Configuration

| Env var | Required | Default | Description |
|---|---|---|---|
| `DATABASE_URL` | yes | — | Postgres connection string (TLS required) |
| `STICKY_SALT` | recommended | `rustypot-default` | Salt for threshold + honeytoken derivation. Set per deployment. |
| `ENABLED_TRAPS` | no | `all` | Comma-separated trap families to enable. See below. |
| `TARPIT_ESCALATION` | no | `30,60,120,240` | Comma-separated tarpit ladder (seconds). Nth value applies after Nth grant; last value repeats. Cap 3600s/entry — keep below your platform's request timeout. |
| `THRESHOLD_MIN` / `THRESHOLD_MAX` | no | `10` / `100` | Per-IP grant threshold range. Swapped automatically if min > max. |
| `RATE_LIMIT_PER_MINUTE` | no | `240` | Per-IP abuse valve across all honeypot routes. Over-quota requests are still logged and answered with the WP database-error page. |
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
