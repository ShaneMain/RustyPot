//! WordPress / xmlrpc / .env / .git / .php exploit-path honeypot. Captures
//! scanner probes and parsed credentials into `honeypot_event` and tarpits
//! credential submissions to slow credential-stuffing sweeps.
//!
//! Routes are wired in `main.rs`. POST-only handlers (`xmlrpc`) fall through
//! to axum's fallback on GET — that 404 is intentional: a scanner GET-ing
//! `/xmlrpc.php` doesn't deserve a real response, and not seeing one biases
//! attackers toward POST where we capture creds.

use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Json;
use serde_json::json;

use crate::parsers;
use crate::sink;
use crate::templates;
use crate::Error;
use crate::HoneypotState;

use parsers::{body_to_string, parse_form_creds, parse_xmlrpc_creds};
use sink::log_event;
use templates::{
    WP_ADMIN_DASHBOARD_HTML, WP_INSTALL_HTML, WP_LOGIN_FORM_ERROR_HTML, WP_LOGIN_FORM_HTML,
    XMLRPC_FAULT_BODY,
};

/// Per-credential-submission delay. Bounded attacker sweep rate even when the
/// upstream CDN rate-limiter is bypassed; intentionally past most bot HTTP
/// timeouts so the connection is dropped client-side before we finish.
pub const TARPIT_DELAY_SECS: u64 = 30;

/// Bound on the `post_body` column — matches the migration's 4 KiB design
/// (enough to capture the leading credential fields of any scanner payload).
pub const MAX_POST_BODY_BYTES: usize = 4 * 1024;

/// Body limit for post-exploitation capture routes (`/wp-admin/{*rest}`).
/// Larger than `MAX_POST_BODY_BYTES` because webshell uploads and file edits
/// routinely exceed 4 KiB. The `post_body` column is still truncated to
/// `MAX_POST_BODY_BYTES` for storage — this limit just prevents axum from
/// rejecting the request with 413 before the handler runs.
pub const MAX_EXPLOIT_BODY_BYTES: usize = 256 * 1024;

pub async fn wp_login(
    State(state): State<HoneypotState>,
    headers: HeaderMap,
    method: Method,
    body: Bytes,
) -> Result<Response, Error> {
    match method {
        Method::GET => {
            log_event(
                &state,
                &headers,
                &Method::GET,
                "/wp-login.php",
                None,
                None,
                None,
                None,
                200,
                0,
            )
            .await?;
            Ok(Html(WP_LOGIN_FORM_HTML).into_response())
        }
        Method::POST => {
            let body_str = body_to_string(&body);
            let (user, pass) = parse_form_creds(&body_str);
            sink::trap_and_record(
                &state,
                &headers,
                "/wp-login.php",
                &body_str,
                user,
                pass,
                WP_LOGIN_FORM_ERROR_HTML,
            )
            .await
        }
        _ => Ok(StatusCode::METHOD_NOT_ALLOWED.into_response()),
    }
}

pub async fn xmlrpc(
    State(state): State<HoneypotState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Error> {
    let body_str = body_to_string(&body);
    let (user, pass) = parse_xmlrpc_creds(&body_str);
    let delay_ms = u32::try_from(TARPIT_DELAY_SECS * 1000).unwrap_or(0);
    log_event(
        &state,
        &headers,
        &Method::POST,
        "/xmlrpc.php",
        None,
        Some(body_str.as_str()),
        user.as_deref(),
        pass.as_deref(),
        200,
        delay_ms,
    )
    .await?;
    tokio::time::sleep(Duration::from_secs(TARPIT_DELAY_SECS)).await;
    Ok((
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "text/xml; charset=utf-8")],
        XMLRPC_FAULT_BODY,
    )
        .into_response())
}

pub async fn wp_admin_index(
    State(state): State<HoneypotState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Result<Response, Error> {
    log_event(
        &state,
        &headers,
        &Method::GET,
        uri.path(),
        uri.query(),
        None,
        None,
        None,
        200,
        0,
    )
    .await?;
    Ok(Html(WP_ADMIN_DASHBOARD_HTML).into_response())
}

pub async fn wp_admin_install(
    State(state): State<HoneypotState>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    log_event(
        &state,
        &headers,
        &Method::GET,
        "/wp-admin/install.php",
        None,
        None,
        None,
        None,
        200,
        0,
    )
    .await?;
    Ok(Html(WP_INSTALL_HTML).into_response())
}

pub async fn wp_json_catch(
    State(state): State<HoneypotState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    method: Method,
    body: Bytes,
) -> Result<Response, Error> {
    let path = uri.path();
    let body_str = body_to_string(&body);
    let body_ref = if body_str.is_empty() {
        None
    } else {
        Some(body_str.as_str())
    };
    let (status, response) = if method == Method::POST {
        log_event(
            &state,
            &headers,
            &method,
            path,
            uri.query(),
            body_ref,
            None,
            None,
            201,
            0,
        )
        .await?;
        (
            StatusCode::CREATED,
            Json(json!({ "id": 1, "status": "draft" })).into_response(),
        )
    } else {
        log_event(
            &state,
            &headers,
            &method,
            path,
            uri.query(),
            None,
            None,
            None,
            200,
            0,
        )
        .await?;
        (StatusCode::OK, Json(json!([])).into_response())
    };
    let _ = status;
    Ok(response)
}

/// Generic post-exploitation capture handler for `/wp-admin/*` routes that
/// aren't matched by a more specific handler. Logs the request (including POST
/// body — this is where we capture webshell source code, spam content, etc.)
/// and returns a fake WP admin page so the bot keeps exploring.
pub async fn post_exploit_capture(
    State(state): State<HoneypotState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    method: Method,
    body: Bytes,
) -> Result<Response, Error> {
    let body_str = body_to_string(&body);
    let body_ref = if body_str.is_empty() {
        None
    } else {
        Some(body_str.as_str())
    };
    log_event(
        &state,
        &headers,
        &method,
        uri.path(),
        uri.query(),
        body_ref,
        None,
        None,
        200,
        0,
    )
    .await?;
    Ok(Html(WP_ADMIN_DASHBOARD_HTML).into_response())
}

pub async fn config_probe(
    State(state): State<HoneypotState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    method: Method,
) -> Result<Response, Error> {
    log_event(
        &state,
        &headers,
        &method,
        uri.path(),
        uri.query(),
        None,
        None,
        None,
        404,
        0,
    )
    .await?;
    Ok(StatusCode::NOT_FOUND.into_response())
}

pub async fn php_probe(
    State(state): State<HoneypotState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    method: Method,
) -> Result<Response, Error> {
    log_event(
        &state,
        &headers,
        &method,
        uri.path(),
        uri.query(),
        None,
        None,
        None,
        404,
        0,
    )
    .await?;
    Ok(StatusCode::NOT_FOUND.into_response())
}

const ENV_FILE_TEMPLATE: &str = "APP_NAME=Production\n\
APP_ENV=production\n\
APP_KEY=base64:Y3zZrN9mBvP4tF8sK2hQ7wJxLnVc6dG1bH5aMsE0pUy=\n\
APP_DEBUG=false\n\
\n\
DB_CONNECTION=pgsql\n\
DB_HOST=127.0.0.1\n\
DB_PORT=5432\n\
DB_DATABASE=application\n\
DB_USERNAME=app_user\n\
DB_PASSWORD=__PLANTED__\n\
\n\
REDIS_HOST=127.0.0.1\n\
REDIS_PASSWORD=null\n\
REDIS_PORT=6379\n\
\n\
MAIL_MAILER=smtp\n\
MAIL_HOST=smtp.mailtrap.io\n\
MAIL_PORT=2525\n\
MAIL_ENCRYPTION=tls\n\
\n\
AWS_ACCESS_KEY_ID=AKIA2BS4DJKP9MN7QRXT\n\
AWS_SECRET_ACCESS_KEY=xT7nQ9vK4pR2bW6mZ8sF3cL1jY5hD0gUeNoVwAt\n";

pub async fn env_honeytrap(
    State(state): State<HoneypotState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    method: Method,
) -> Result<Response, Error> {
    use std::net::IpAddr;
    let ip_str = crate::headers::extract_source_ip(&headers);
    let ip: IpAddr = ip_str.parse().unwrap_or(IpAddr::from([0, 0, 0, 0]));
    let credential = crate::sticky::planted_credential(&ip);
    let env_content = ENV_FILE_TEMPLATE.replace("__PLANTED__", &credential);

    let _ = sink::record_granted_credential(&state.pool, "app_user", &credential, &ip_str).await;

    sink::log_event(
        &state,
        &headers,
        &method,
        uri.path(),
        uri.query(),
        None,
        Some("app_user"),
        Some(&credential),
        200,
        0,
    )
    .await?;

    Ok((
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; charset=utf-8",
        )],
        env_content,
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tarpit_constant_is_thirty_seconds() {
        assert_eq!(TARPIT_DELAY_SECS, 30);
    }
}
