//! DB sink for honeypot events. Isolated from the handler module so each file
//! owns one concept: handlers turn requests into responses, this turns the
//! request metadata into a `honeypot_event` row.
//!
//! `sqlx::query()` (runtime, not the `query!` macro) because `honeypot_event`
//! is brand new and has no cached `.sqlx/query-*.json` metadata. Generating
//! that needs a live DB with the migration applied — impossible under the
//! SQLX_OFFLINE=true gate. The schema is fully specified by 0016_honeypot.sql.

use std::net::IpAddr;
use std::time::Duration;

use axum::http::{HeaderMap, Method};
use axum::response::{Html, IntoResponse, Response};

use crate::handlers::MAX_POST_BODY_BYTES;
use crate::headers::{capture_headers, extract_source_ip, header_str};
use crate::parsers::{extract_form_field, truncate_to_boundary};
use crate::sticky;
use crate::Error;
use crate::HoneypotState;

const MAX_CRED_LEN: usize = 1024;

/// `granted_credentials.origin` values. Constants, not an enum, because the
/// column is runtime-SQL TEXT; a typo here would silently degrade install
/// pairs to the withheld (stuffer) treatment and break kit verification.
pub(crate) const ORIGIN_LOGIN: &str = "login";
pub(crate) const ORIGIN_ENV: &str = "env";
pub(crate) const ORIGIN_INSTALL: &str = "install";

/// Grant decision for a credential POST: install-origin pairs (site claimed
/// via the fake installer) grant immediately — the kit's verification login
/// must succeed or it flags the site as fake; other known pairs are withheld
/// (churn for new passwords); a genuinely new pair grants only at the
/// stuffer threshold.
fn decide_grant(has_creds: bool, origin: Option<&str>, threshold_hit: bool) -> bool {
    if !has_creds {
        return false;
    }
    match origin {
        Some(o) if o == ORIGIN_INSTALL => true,
        Some(_) => false,
        None => threshold_hit,
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn log_event(
    state: &HoneypotState,
    headers: &HeaderMap,
    method: &Method,
    path: &str,
    query: Option<&str>,
    post_body: Option<&str>,
    submitted_user: Option<&str>,
    submitted_pass: Option<&str>,
    response_status: u16,
    response_delay_ms: u32,
) -> Result<(), Error> {
    let source_ip = extract_source_ip(headers);
    let via_cloudflare = headers.contains_key("cf-connecting-ip");
    let user_agent = header_str(headers, "user-agent").map(str::to_owned);
    let request_headers = capture_headers(headers);
    let accept_language = header_str(headers, "accept-language")
        .map(|s| truncate_to_boundary(s, MAX_CRED_LEN).to_owned());
    let cf_ipcountry = header_str(headers, "cf-ipcountry").map(str::to_owned);
    let submit_text = post_body
        .and_then(|b| extract_form_field(b, "wp-submit"))
        .map(|s| truncate_to_boundary(&s, 128).to_owned());
    let truncated_body = post_body.map(|b| truncate_to_boundary(b, MAX_POST_BODY_BYTES).to_owned());
    let user = submitted_user.map(|s| truncate_to_boundary(s, MAX_CRED_LEN).to_owned());
    let pass = submitted_pass.map(|s| truncate_to_boundary(s, MAX_CRED_LEN).to_owned());

    sqlx::query(
        r#"
        INSERT INTO honeypot_event
            (source_ip, via_cloudflare, user_agent, method, path, query,
             post_body, submitted_user, submitted_pass, request_headers,
             response_status, response_delay_ms,
             accept_language, cf_ipcountry, form_submit_text)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
        "#,
    )
    .bind(source_ip)
    .bind(via_cloudflare)
    .bind(user_agent)
    .bind(method.as_str())
    .bind(path)
    .bind(query)
    .bind(truncated_body)
    .bind(user)
    .bind(pass)
    .bind(request_headers)
    .bind(i32::from(response_status))
    .bind(i32::try_from(response_delay_ms).unwrap_or(0))
    .bind(accept_language)
    .bind(cf_ipcountry)
    .bind(submit_text)
    .execute(&state.pool)
    .await?;
    Ok(())
}

/// Origin of a row in `granted_credentials`. `Some(origin)` means the pair
/// was seen before (origin = which trap recorded it first); `None` means the
/// pair is new. Subsumes the old `is_granted_credential` boolean.
pub(crate) async fn credential_origin(
    pool: &sqlx::PgPool,
    user: &str,
    pass: &str,
) -> Result<Option<String>, Error> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT origin FROM granted_credentials WHERE username = $1 AND password = $2",
    )
    .bind(truncate_to_boundary(user, MAX_CRED_LEN))
    .bind(truncate_to_boundary(pass, MAX_CRED_LEN))
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| r.0))
}

/// Insert (or bump) a granted credential. `origin` is write-once in effect:
/// the `ON CONFLICT` branch only increments `grant_count`, so the first trap
/// to record a pair keeps its origin — that origin is the correlation anchor.
/// Creds are truncated to `MAX_CRED_LEN` (same cap as `log_event`) so a
/// multi-KB field can't bloat the table or trip Postgres's index-tuple limit.
pub(crate) async fn record_granted_credential(
    pool: &sqlx::PgPool,
    user: &str,
    pass: &str,
    source_ip: &str,
    origin: &str,
) -> Result<(), Error> {
    sqlx::query(
        r#"
        INSERT INTO granted_credentials (username, password, first_granted_ip, origin)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (username, password) DO UPDATE
        SET grant_count = granted_credentials.grant_count + 1
        "#,
    )
    .bind(truncate_to_boundary(user, MAX_CRED_LEN))
    .bind(truncate_to_boundary(pass, MAX_CRED_LEN))
    .bind(source_ip)
    .bind(origin)
    .execute(pool)
    .await?;
    Ok(())
}

pub(crate) async fn trap_and_record(
    state: &HoneypotState,
    headers: &HeaderMap,
    path: &str,
    body_str: &str,
    user: Option<String>,
    pass: Option<String>,
    failure_html: &'static str,
) -> Result<Response, Error> {
    let ip_str = extract_source_ip(headers);
    let ip: IpAddr = ip_str.parse().unwrap_or(IpAddr::from([0, 0, 0, 0]));
    let s = &state.settings;
    let threshold_hit = sticky::check_and_increment(
        &state.honeypot_tracker,
        &ip,
        s.threshold_min,
        s.threshold_max,
    );
    let origin = match (&user, &pass) {
        (Some(u), Some(p)) => credential_origin(&state.pool, u, p).await?,
        _ => None,
    };
    let granted = decide_grant(
        matches!((&user, &pass), (Some(u), Some(p)) if !u.is_empty() && !p.is_empty()),
        origin.as_deref(),
        threshold_hit,
    );
    // Only a genuinely new pair grants via the threshold; resetting on any
    // other path would skip the next threshold cycle.
    if granted && origin.is_none() {
        sticky::reset_counter(&state.honeypot_tracker, &ip);
    }
    let tarpit_secs = s.tarpit_delay(sticky::grant_count(&state.grant_tracker, &ip));
    let delay_ms = if granted {
        0
    } else {
        u32::try_from(tarpit_secs * 1000).unwrap_or(0)
    };
    log_event(
        state,
        headers,
        &Method::POST,
        path,
        None,
        Some(body_str),
        user.as_deref(),
        pass.as_deref(),
        if granted { 302 } else { 200 },
        delay_ms,
    )
    .await?;
    if granted {
        if let (Some(ref u), Some(ref p)) = (&user, &pass) {
            // ORIGIN_LOGIN is inert here for install-origin pairs: the ON
            // CONFLICT branch never touches origin (write-once), so this only
            // labels genuinely new pairs.
            let _ = record_granted_credential(&state.pool, u, p, &ip_str, ORIGIN_LOGIN).await;
        }
        let grants_before = sticky::grant_count(&state.grant_tracker, &ip);
        sticky::increment_grants(&state.grant_tracker, &ip);
        return Ok(sticky::fake_success_response(grants_before, s));
    }
    tokio::time::sleep(Duration::from_secs(tarpit_secs)).await;
    Ok(Html(failure_html).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decide_grant_matrix() {
        for (has_creds, origin, threshold, expected) in [
            (true, Some(ORIGIN_INSTALL), false, true),
            (true, Some(ORIGIN_INSTALL), true, true),
            (true, Some(ORIGIN_LOGIN), true, false),
            (true, Some(ORIGIN_ENV), true, false),
            (true, None, true, true),
            (true, None, false, false),
            (false, Some(ORIGIN_INSTALL), true, false),
            (false, None, true, false),
        ] {
            assert_eq!(
                decide_grant(has_creds, origin, threshold),
                expected,
                "has_creds={has_creds}, origin={origin:?}, threshold={threshold}"
            );
        }
    }
}
