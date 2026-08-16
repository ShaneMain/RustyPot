-- Origin column for granted_credentials: which trap first recorded the pair.
--
-- 'login'   — captured at a CMS login form via the threshold/grant flow
--             (default; also covers rows recorded before this migration).
-- 'env'     — planted .env honeytoken, recorded when the file was served.
-- 'install' — chosen by the attacker at the fake wp-admin/install.php claim.
--
-- Install-origin pairs grant immediately at ANY login form: the claim
-- playbook's verification step (log in with the just-chosen password) must
-- succeed, or the kit flags the site as fake. Login/env origins keep the
-- stuffer treatment (withhold, pin the counter, churn for new passwords).

ALTER TABLE granted_credentials
    ADD COLUMN IF NOT EXISTS origin TEXT NOT NULL DEFAULT 'login';
