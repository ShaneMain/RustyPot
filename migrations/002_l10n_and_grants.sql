-- Localization indicators + fingerprint registry.
--
-- accept_language: the bot's HTTP client locale header (e.g. zh-CN,zh;q=0.9).
-- cf_ipcountry:    Cloudflare-injected country code (present only when traffic
--                  arrives through the CF edge; direct probes are NULL).
-- form_submit_text: the login-button form field value, which localizes with the
--                  bot's WP language pack (e.g. 登录 = "Log In" in Chinese) —
--                  fingerprints the tool's configured locale, distinct from
--                  the HTTP client locale.

ALTER TABLE honeypot_event
    ADD COLUMN IF NOT EXISTS accept_language TEXT,
    ADD COLUMN IF NOT EXISTS cf_ipcountry     TEXT,
    ADD COLUMN IF NOT EXISTS form_submit_text TEXT;

CREATE TABLE IF NOT EXISTS granted_credentials (
    username         TEXT        NOT NULL,
    password         TEXT        NOT NULL,
    first_granted_ts TIMESTAMPTZ NOT NULL DEFAULT now(),
    first_granted_ip TEXT,
    grant_count      INTEGER     NOT NULL DEFAULT 1,
    PRIMARY KEY (username, password)
);
