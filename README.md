<p align="center">
  <h1 align="center">🪤 RustyPot</h1>
  <p align="center">Self-hosted exploit-path honeypot with per-attacker fingerprinting</p>
</p>

<p align="center">
  <a href="https://github.com/ShaneMain/rustypot/actions"><img src="https://github.com/ShaneMain/rustypot/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/rust-1.75%2B-orange.svg" alt="Rust">
  <img src="https://img.shields.io/badge/axum-0.8-blue.svg" alt="Axum">
  <img src="https://img.shields.io/github/license/ShaneMain/rustypot?color=blue" alt="License">
  <img src="https://img.shields.io/github/last-commit/ShaneMain/rustypot" alt="Last commit">
  <img src="https://img.shields.io/github/stars/ShaneMain/rustypot?style=social" alt="Stars">
</p>

---

## What it does

When bots probe your site for WordPress, config files, and PHP shells, RustyPot:

1. **Serves realistic fake responses** — WP login forms, XML-RPC faults, admin dashboards
2. **Tarpits every attempt** — 30-second delay per POST, wasting the attacker's VPS compute
3. **Captures every credential** — usernames, passwords, XML-RPC tokens, full POST bodies
4. **Grants fake login success** on a per-IP threshold — then records what the bot does next
5. **Fingerprints each attacker** via the specific password they use at their threshold position

## How the fingerprinting works

This is RustyPot's signature feature. Each probing IP has a **deterministic threshold** (10-100 attempts, derived from a hash of the IP + a deployment-specific salt). Different IPs get different thresholds.

```
IP 1.2.3.4  →  threshold = 23  →  granted on their 23rd password: "admin/qwerty123"
IP 5.6.7.8  →  threshold = 67  →  granted on their 67th password: "admin/passw0rd!"
IP 9.10.11.12 → threshold = 12 → granted on their 12th password: "admin/letmein"
```

The password at the threshold position becomes that attacker's **fingerprint tag**. It's recorded in the `granted_credentials` table. When that same password appears again from **any** IP, you can correlate the attackers — even if they switch infrastructure.

**The threshold is one-shot**: after granting, the counter resets to zero. The attacker churns through another full N attempts (each costing 30s of tarpit) before the next grant. This maximizes:

- **Password capture** — every failed attempt logs the submitted credential
- **VPS time wasted** — 30s per attempt × N attempts = minutes of wasted compute per cycle
- **Fingerprint diversity** — each cycle can contribute a different unique password

**Known passwords are rejected**: if the threshold fires but the submitted password is already in `granted_credentials`, the grant is silently withheld. The attacker burns the cycle for nothing and keeps churning. This ensures each entry in the fingerprint table is unique.

## Currently trapped paths

| Path | Method | Behavior |
|---|---|---|
| `/wp-login.php` | GET | Fake WP login form |
| `/wp-login.php` | POST | Parse `log`/`pwd`, tarpit 30s, return "Incorrect password" — or fake 302 on threshold |
| `/xmlrpc.php` | POST | Parse XML-RPC creds, tarpit 30s, return fault |
| `/wp-admin/*` | GET | Fake admin dashboard |
| `/wp-admin/*` | POST | **Capture body** — webshell source code, file edits, spam content |
| `/wp-json/*` | GET | 200 + empty JSON array |
| `/wp-json/*` | POST | **Capture body** — user creation, post injection |
| `/.env`, `/.git/*` | GET | 404 + log |
| `/phpinfo.php`, `/index.php` | GET | 404 + log |

## Quick start

### Docker

```bash
docker run -p 8080:8080 \
  -e DATABASE_URL=postgres://user:pass@host/db \
  -e STICKY_SALT=$(openssl rand -hex 32) \
  ghcr.io/shanemain/rustypot:latest
```

### Cloud Run

```bash
gcloud run deploy rustypot \
  --image us-east1-docker.pkg.dev/PROJECT/REPO/rustypot:latest \
  --region us-east1 --port 8080 \
  --set-env-vars "STICKY_SALT=$(openssl rand -hex 32)" \
  --set-secrets "DATABASE_URL=your-db-secret:latest" \
  --allow-unauthenticated \
  --max-instances 3 --memory 256Mi --timeout 60
```

### Cloudflare Worker (traffic routing)

Deploy `cloudflare-worker.js` to split traffic at the edge — exploit paths go to RustyPot, everything else to your app. The attacker sees the same hostname; the split is invisible.

## Configuration

| Env var | Required | Default | Description |
|---|---|---|---|
| `DATABASE_URL` | Yes | — | Postgres connection string (TLS required) |
| `PORT` | No | `8080` | HTTP listen port |
| `STICKY_SALT` | **Set this** | `rustypot-default` | Salt for per-IP threshold derivation. Each deployment should have a unique random value so attackers can't compute thresholds from the public source. |
| `RUST_LOG` | No | `info` | Tracing filter |

## Database

```sql
CREATE TABLE honeypot_event (
    id              BIGSERIAL    PRIMARY KEY,
    ts              TIMESTAMPTZ  NOT NULL DEFAULT now(),
    source_ip       TEXT         NOT NULL,
    via_cloudflare  BOOLEAN      NOT NULL,
    user_agent      TEXT,
    method          TEXT         NOT NULL,
    path            TEXT         NOT NULL,
    post_body       TEXT,              -- truncated to 4 KiB
    submitted_user  TEXT,
    submitted_pass  TEXT,
    response_status INTEGER      NOT NULL,
    response_delay_ms INTEGER    NOT NULL DEFAULT 0
);

CREATE TABLE granted_credentials (
    username        TEXT        NOT NULL,
    password        TEXT        NOT NULL,
    first_granted_ts TIMESTAMPTZ NOT NULL DEFAULT now(),
    first_granted_ip TEXT,
    grant_count     INTEGER     NOT NULL DEFAULT 1,
    PRIMARY KEY (username, password)
);
```

## Grafana dashboard

Query `honeypot_event` + `granted_credentials` via Postgres for:

- **Hits/day** — attack volume over time
- **Top attacker IPs** — who's probing the most
- **Top passwords** — the dictionary the bots are cycling
- **Fingerprint tags** — which password was granted to which IP, and where it's been seen since
- **Captured payloads** — webshell source code, spam content, file edits from post-exploitation
- **Fake-success triggers** (`response_status = 302`) — when attackers "got in"

## Architecture

```
                    ┌──────────────────┐
                    │   Cloudflare     │
                    │   (edge Worker)  │
                    └──┬───────────┬───┘
           exploit paths│           │everything else
                       ▼           ▼
              ┌────────────┐  ┌──────────┐
              │  RustyPot  │  │ Your App │
              │  (honeypot)│  │          │
              └─────┬──────┘  └──────────┘
                    │
                    ▼
              ┌────────────┐
              │  Postgres  │
              │ (captures) │
              └────────────┘
```

## Features

- 🪤 **Sticky trap** — fake login success after 10-100 per-IP attempts (deterministic, one-shot)
- 🔑 **Per-attacker fingerprinting** — each IP's threshold-crossing password becomes a unique tag
- 🐌 **30-second tarpit** — every failed credential attempt wastes the attacker's compute
- 📦 **Post-exploitation capture** — `/wp-admin/*` POST bodies logged (webshells, file edits, spam)
- 🛡️ **Rate-limited** — 10 req/min/IP prevents self-DoS via tarpit concurrency
- 📊 **Grafana-ready** — all data in queryable Postgres tables
- ☁️ **Cloud Run native** — reads `PORT`, health check on `/health`, autoscaling-friendly
- 🔒 **GPL-3.0** — copyleft, same as the project it was born from

## Roadmap

- [ ] Drupal trap routes (`/user/login`, `/admin/config`)
- [ ] Joomla trap routes (`/administrator/index.php`)
- [ ] Ghost trap routes (`/ghost/api/admin/session`)
- [ ] IP enrichment (ASN, cloud provider, geo) via background script
- [ ] Localization capture (`Accept-Language`, `CF-IPCountry`, WP submit button text)
- [ ] Mastodon/Fediverse exploitation detection

## Origin

RustyPot was born defending [FillerKiller](https://fillerkiller.app), a TV filler-episode voting app. In its first 67 days live, it captured 2,461 exploit-path probes from 8 unique attacker IPs, including a sustained WordPress credential-stuffing campaign from a DigitalOcean VPS. The honeypot was extracted into this standalone container so others can deploy the same defense.

## License

[GPL-3.0](LICENSE) — because security tools should be free and open.
