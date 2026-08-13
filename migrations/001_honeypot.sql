-- Honeypot — captures exploit-path probes and parsed credentials from
-- WordPress / xmlrpc / config-file scanners. Written by api/src/honeypot.rs.
--
-- Design: one row per attacker request that hit a honeypot route. The
-- `path` column is the verbatim path (not normalized) because per-path
-- aggregation is the point here. POST bodies are truncated to 4 KiB to bound
-- row size; we never need more than the leading credential fields.
--
-- `submitted_user` / `submitted_pass` are parsed out of the POST body for the
-- common cases (form-urlencoded WP login, xmlrpc.php system.multicall). When
-- the body doesn't parse, they're NULL and the raw body remains in
-- `post_body` for forensics.
--
-- `via_cloudflare` is TRUE when the request arrived with a CF-Connecting-IP
-- header. The `source_ip` is always the immediate peer (CF edge IP when
-- proxied, attacker IP when direct). To attribute a CF-proxied attacker,
-- dig into `request_headers->>'cf-connecting-ip'`.

CREATE TABLE honeypot_event (
    id                BIGSERIAL    PRIMARY KEY,
    ts                TIMESTAMPTZ  NOT NULL DEFAULT now(),
    source_ip         TEXT         NOT NULL,
    via_cloudflare    BOOLEAN      NOT NULL,
    user_agent        TEXT,
    method            TEXT         NOT NULL,
    path              TEXT         NOT NULL,
    query             TEXT,
    post_body         TEXT,
    submitted_user    TEXT,
    submitted_pass    TEXT,
    request_headers   JSONB        NOT NULL DEFAULT '{}'::jsonb,
    response_status   INTEGER      NOT NULL,
    response_delay_ms INTEGER      NOT NULL DEFAULT 0
);

-- Time-series scan (dashboard hits/day, recent-events table).
CREATE INDEX honeypot_event_ts_idx        ON honeypot_event (ts DESC);
-- Top-attacker-IP aggregation.
CREATE INDEX honeypot_event_source_ip_idx ON honeypot_event (source_ip);
-- Per-path frequency.
CREATE INDEX honeypot_event_path_idx      ON honeypot_event (path);
-- Credential-submission drilldown (only set on /wp-login.php and /xmlrpc.php POSTs).
CREATE INDEX honeypot_event_has_creds_idx ON honeypot_event (ts DESC) WHERE submitted_user IS NOT NULL;
