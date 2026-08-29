-- Event provenance + plant/submission separation.
--
-- Three problems this fixes, all of which made the dashboard unreadable:
--
-- 1. `synthetic` — rows imported by out-of-band backfill scripts (they tagged
--    themselves with a `source` key in request_headers: 'gap-recovery',
--    'drop-recovery') were indistinguishable from live captures. They carry no
--    POST body, no real headers, and in the 'drop-recovery' case an *inferred*
--    source_ip. Aggregating them with real captures inflates every panel and
--    fabricates attacker behaviour that was never observed.
--
-- 2. `planted_user` / `planted_pass` — the `.env` honeytoken wrote the
--    credential IT PLANTED into `submitted_user`/`submitted_pass`, the columns
--    that are supposed to mean "the attacker sent us this". Any
--    "credentials captured" panel counted our own plants; the real number was
--    roughly a quarter of what was displayed. Plants now have their own
--    columns, and `submitted_*` means attacker-supplied, exclusively.
--
-- 3. `cloudflare_ranges` + `honeypot_event_live` — traffic originating from
--    Cloudflare's own infrastructure (cf-connecting-ip is itself a Cloudflare
--    address) is not an attacker. It was the single largest "attacker" path in
--    the dashboard. The view filters it, and Grafana should query the view.

ALTER TABLE honeypot_event
    ADD COLUMN IF NOT EXISTS synthetic    BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS planted_user TEXT,
    ADD COLUMN IF NOT EXISTS planted_pass TEXT;

-- Backfill 1: tag every row an importer wrote.
UPDATE honeypot_event
   SET synthetic = TRUE
 WHERE request_headers ? 'source'
   AND NOT synthetic;

-- Backfill 2: move honeytoken plants out of the submitted_* columns. A plant is
-- an env-trap row whose password carries the honeytoken prefix; the attacker
-- never typed it, we generated and served it.
UPDATE honeypot_event
   SET planted_user   = submitted_user,
       planted_pass   = submitted_pass,
       submitted_user = NULL,
       submitted_pass = NULL
 WHERE submitted_pass IS NOT NULL
   AND submitted_pass ~ '^fk[A-Za-z0-9]'
   AND path ~ '\.env'
   AND planted_pass IS NULL;

-- Published Cloudflare edge prefixes (https://www.cloudflare.com/ips/).
-- Seeded rather than hardcoded in a WHERE clause so the list can be refreshed
-- without a code change when Cloudflare adds a range.
CREATE TABLE IF NOT EXISTS cloudflare_ranges (prefix INET PRIMARY KEY);

INSERT INTO cloudflare_ranges (prefix) VALUES
    ('173.245.48.0/20'), ('103.21.244.0/22'), ('103.22.200.0/22'),
    ('103.31.4.0/22'),   ('141.101.64.0/18'), ('108.162.192.0/18'),
    ('190.93.240.0/20'), ('188.114.96.0/20'), ('197.234.240.0/22'),
    ('198.41.128.0/17'), ('162.158.0.0/15'),  ('104.16.0.0/13'),
    ('104.24.0.0/14'),   ('172.64.0.0/13'),   ('131.0.72.0/22'),
    ('2400:cb00::/32'),  ('2606:4700::/32'),  ('2803:f800::/32'),
    ('2405:b500::/32'),  ('2405:8100::/32'),  ('2a06:98c0::/29'),
    ('2c0f:f248::/32')
ON CONFLICT (prefix) DO NOTHING;

-- source_ip is TEXT on purpose (we log whatever the proxy sent, including
-- malformed values). Cast defensively so one bad row can't error a dashboard.
CREATE OR REPLACE FUNCTION try_inet(txt TEXT) RETURNS INET AS $$
BEGIN
    RETURN txt::INET;
EXCEPTION WHEN others THEN
    RETURN NULL;
END;
$$ LANGUAGE plpgsql IMMUTABLE RETURNS NULL ON NULL INPUT;

-- TRUE when the client is Cloudflare itself rather than an attacker proxied
-- through it. Note this tests source_ip, which extract_source_ip() sets from
-- cf-connecting-ip — so a real attacker behind Cloudflare is NOT matched here.
CREATE OR REPLACE FUNCTION is_cloudflare_origin(txt TEXT) RETURNS BOOLEAN AS $$
    SELECT EXISTS (
        SELECT 1 FROM cloudflare_ranges r WHERE try_inet(txt) <<= r.prefix
    );
$$ LANGUAGE sql STABLE;

-- The view Grafana should point at: genuine, externally-originated captures.
CREATE OR REPLACE VIEW honeypot_event_live AS
    SELECT * FROM honeypot_event
     WHERE NOT synthetic
       AND NOT is_cloudflare_origin(source_ip);

CREATE INDEX IF NOT EXISTS honeypot_event_synthetic_idx
    ON honeypot_event (ts DESC) WHERE NOT synthetic;

-- Replaces honeypot_event_has_creds_idx's intent: attacker-submitted only.
CREATE INDEX IF NOT EXISTS honeypot_event_submitted_idx
    ON honeypot_event (ts DESC) WHERE submitted_user IS NOT NULL AND NOT synthetic;
