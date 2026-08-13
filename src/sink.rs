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

use crate::handlers::{MAX_POST_BODY_BYTES, TARPIT_DELAY_SECS};
use crate::headers::{capture_headers, extract_source_ip, header_str};
use crate::parsers::truncate_to_boundary;
use crate::sticky;
use crate::Error;
use crate::HoneypotState;

const MAX_CRED_LEN: usize = 1024;

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
    let truncated_body = post_body.map(|b| truncate_to_boundary(b, MAX_POST_BODY_BYTES).to_owned());
    let user = submitted_user.map(|s| truncate_to_boundary(s, MAX_CRED_LEN).to_owned());
    let pass = submitted_pass.map(|s| truncate_to_boundary(s, MAX_CRED_LEN).to_owned());

    sqlx::query(
        r#"
        INSERT INTO honeypot_event
            (source_ip, via_cloudflare, user_agent, method, path, query,
             post_body, submitted_user, submitted_pass, request_headers,
             response_status, response_delay_ms)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
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
    .execute(&state.pool)
    .await?;
    Ok(())
}

pub(crate) async fn is_granted_credential(
    pool: &sqlx::PgPool,
    user: &str,
    pass: &str,
) -> Result<bool, Error> {
    let row: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM granted_credentials WHERE username = $1 AND password = $2",
    )
    .bind(user)
    .bind(pass)
    .fetch_one(pool)
    .await?;
    Ok(row.0 > 0)
}

pub(crate) async fn record_granted_credential(
    pool: &sqlx::PgPool,
    user: &str,
    pass: &str,
    source_ip: &str,
) -> Result<(), Error> {
    sqlx::query(
        r#"
        INSERT INTO granted_credentials (username, password, first_granted_ip)
        VALUES ($1, $2, $3)
        ON CONFLICT (username, password) DO UPDATE
        SET grant_count = granted_credentials.grant_count + 1
        "#,
    )
    .bind(user)
    .bind(pass)
    .bind(source_ip)
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
    let threshold_hit = sticky::check_and_increment(&state.honeypot_tracker, &ip);
    let granted = if threshold_hit {
        match (&user, &pass) {
            (Some(u), Some(p)) => {
                if is_granted_credential(&state.pool, u, p).await? {
                    false
                } else {
                    sticky::reset_counter(&state.honeypot_tracker, &ip);
                    true
                }
            }
            _ => false,
        }
    } else {
        false
    };
    let delay_ms = if granted {
        0
    } else {
        u32::try_from(TARPIT_DELAY_SECS * 1000).unwrap_or(0)
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
            let _ = record_granted_credential(&state.pool, u, p, &ip_str).await;
        }
        return Ok(sticky::fake_success_response());
    }
    tokio::time::sleep(Duration::from_secs(TARPIT_DELAY_SECS)).await;
    Ok(Html(failure_html).into_response())
}
