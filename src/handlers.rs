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
    plugin_readme_txt, wp_install_success_html, WP_LOGIN_FORM_ERROR_HTML, WP_LOGIN_FORM_HTML,
    WP_SETUP_CONFIG_DONE_HTML, WP_SETUP_CONFIG_HTML, WP_VERSION_PHP, WP_WELCOME_HTML,
    XMLRPC_FAULT_BODY,
};

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
    // Base ladder entry — xmlrpc has no grant/threshold tracking, so no escalation.
    let tarpit_secs = state.settings.tarpit_delay(0);
    let body_str = body_to_string(&body);
    let (user, pass) = parse_xmlrpc_creds(&body_str);
    let delay_ms = u32::try_from(tarpit_secs * 1000).unwrap_or(0);
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
    tokio::time::sleep(Duration::from_secs(tarpit_secs)).await;
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
    use std::net::IpAddr;
    let ip: IpAddr = crate::headers::extract_source_ip(&headers)
        .parse()
        .unwrap_or(IpAddr::from([0, 0, 0, 0]));
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
    Ok(Html(crate::canary::admin_dashboard(&ip)).into_response())
}

/// A parsed installer claim is only recordable when BOTH fields came back
/// non-empty — a half-parsed form would poison `granted_credentials` with
/// unusable rows.
fn recordable_claim(user: &Option<String>, pass: &Option<String>) -> bool {
    matches!((user, pass), (Some(u), Some(p)) if !u.is_empty() && !p.is_empty())
}

/// `wp-admin/install.php` — the installer-claim trap. GET serves the
/// five-minute-install form; `?step=2` POST is a kit claiming the site with
/// its chosen admin credentials. The chosen pair is recorded with
/// `origin='install'` (so `wp-login.php` verification grants it immediately,
/// bypassing the stuffer threshold) and answered with the Success page plus
/// WP session cookies + the first-grant cookie bomb.
pub async fn wp_admin_install(
    State(state): State<HoneypotState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    method: Method,
    body: Bytes,
) -> Result<Response, Error> {
    use std::net::IpAddr;
    let ip: IpAddr = crate::headers::extract_source_ip(&headers)
        .parse()
        .unwrap_or(IpAddr::from([0, 0, 0, 0]));
    match method {
        Method::GET => {
            log_event(
                &state,
                &headers,
                &Method::GET,
                "/wp-admin/install.php",
                uri.query(),
                None,
                None,
                None,
                200,
                0,
            )
            .await?;
            Ok(Html(WP_WELCOME_HTML).into_response())
        }
        Method::POST => {
            let body_str = body_to_string(&body);
            let (user, pass) = parsers::parse_install_form(&body_str);
            // Base-ladder entry — the installer is a one-shot claim, not a
            // repeated-guess surface, so no escalation by grant count here.
            let tarpit_secs = state.settings.tarpit_delay(0);
            let delay_ms = u32::try_from(tarpit_secs * 1000).unwrap_or(0);
            log_event(
                &state,
                &headers,
                &Method::POST,
                "/wp-admin/install.php",
                uri.query(),
                Some(body_str.as_str()),
                user.as_deref(),
                pass.as_deref(),
                200,
                delay_ms,
            )
            .await?;
            if recordable_claim(&user, &pass) {
                let _ = sink::record_granted_credential(
                    &state.pool,
                    user.as_deref().unwrap_or_default(),
                    pass.as_deref().unwrap_or_default(),
                    &crate::headers::extract_source_ip(&headers),
                    sink::ORIGIN_INSTALL,
                )
                .await;
                tokio::time::sleep(Duration::from_secs(tarpit_secs)).await;
                // A recordable claim is the "you're in" moment: session
                // cookies + the one-shot bomb only for it — a garbage POST
                // must not burn the IP's first-grant bomb.
                let grants_before = crate::sticky::grant_count(&state.grant_tracker, &ip);
                crate::sticky::increment_grants(&state.grant_tracker, &ip);
                let mut resp = Html(wp_install_success_html(user.as_deref().unwrap_or_default()))
                    .into_response();
                crate::sticky::attach_wp_session(&mut resp, grants_before, &state.settings);
                Ok(resp)
            } else {
                tokio::time::sleep(Duration::from_secs(tarpit_secs)).await;
                Ok(Html(wp_install_success_html("")).into_response())
            }
        }
        _ => Ok(StatusCode::METHOD_NOT_ALLOWED.into_response()),
    }
}

/// `wp-admin/setup-config.php` — the DB-details wizard step that precedes the
/// installer. Kits walking the full playbook submit throwaway DB credentials
/// here; they're logged structured (kit defaults are an identifier), then the
/// "All right, sparky!" interstitial funnels them into `install.php`.
pub async fn wp_setup_config(
    State(state): State<HoneypotState>,
    OriginalUri(uri): OriginalUri,
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
                "/wp-admin/setup-config.php",
                uri.query(),
                None,
                None,
                None,
                200,
                0,
            )
            .await?;
            Ok(Html(WP_SETUP_CONFIG_HTML).into_response())
        }
        Method::POST => {
            let body_str = body_to_string(&body);
            let (user, pass) = parsers::parse_setup_config_form(&body_str);
            let tarpit_secs = state.settings.tarpit_delay(0);
            let delay_ms = u32::try_from(tarpit_secs * 1000).unwrap_or(0);
            log_event(
                &state,
                &headers,
                &Method::POST,
                "/wp-admin/setup-config.php",
                uri.query(),
                Some(body_str.as_str()),
                user.as_deref(),
                pass.as_deref(),
                200,
                delay_ms,
            )
            .await?;
            tokio::time::sleep(Duration::from_secs(tarpit_secs)).await;
            Ok(Html(WP_SETUP_CONFIG_DONE_HTML).into_response())
        }
        _ => Ok(StatusCode::METHOD_NOT_ALLOWED.into_response()),
    }
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
    use std::net::IpAddr;
    let ip: IpAddr = crate::headers::extract_source_ip(&headers)
        .parse()
        .unwrap_or(IpAddr::from([0, 0, 0, 0]));
    Ok(Html(crate::canary::admin_dashboard(&ip)).into_response())
}

pub async fn config_probe(
    State(state): State<HoneypotState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    method: Method,
) -> Result<Response, Error> {
    // Nested env variants (/wp-content/.env, /solr/.env, ...) are honeytoken
    // material — this route only wins them via family-prefix priority, so
    // delegate before the 404 swallows the capture.
    if is_env_variant(uri.path()) {
        return env_honeytrap(State(state), OriginalUri(uri), headers, method).await;
    }
    // Version/plugin fingerprinting gets a plausible answer rather than a 404.
    // A scanner that reads an outdated `Stable tag:` or `$wp_version` escalates
    // to an exploit attempt, and the exploit is the capture we actually want —
    // a 404 ends the conversation with nothing recorded but the probe itself.
    if let Some(bait) = fingerprint_bait(uri.path()) {
        log_event(
            &state,
            &headers,
            &method,
            uri.path(),
            uri.query(),
            None,
            None,
            None,
            200,
            0,
        )
        .await?;
        return Ok((
            [(
                axum::http::header::CONTENT_TYPE,
                "text/plain; charset=utf-8",
            )],
            bait,
        )
            .into_response());
    }
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

/// Body for the two fingerprinting probes worth answering: WordPress core's
/// `version.php` (served raw by hosts with a broken PHP handler) and any
/// plugin `readme.txt`. `None` means "no bait for this path" — 404 as before.
pub(crate) fn fingerprint_bait(path: &str) -> Option<String> {
    let lower = path.to_ascii_lowercase();
    if lower == "/wp-includes/version.php" {
        return Some(WP_VERSION_PHP.to_owned());
    }
    let rest = lower.strip_prefix("/wp-content/plugins/")?;
    let (slug, file) = rest.split_once('/')?;
    if file != "readme.txt" || slug.is_empty() {
        return None;
    }
    if !slug
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return None;
    }
    Some(plugin_readme_txt(slug))
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

struct EnvVariant {
    app_env: &'static str,
    app_debug: &'static str,
    db_name: &'static str,
    db_user: &'static str,
    app_key: &'static str,
    placeholder: bool,
}

const ENV_PROD: EnvVariant = EnvVariant {
    app_env: "production",
    app_debug: "false",
    db_name: "application",
    db_user: "app_user",
    app_key: "base64:Y3zZrN9mBvP4tF8sK2hQ7wJxLnVc6dG1bH5aMsE0pUy=",
    placeholder: false,
};

const ENV_STAGE: EnvVariant = EnvVariant {
    app_env: "staging",
    app_debug: "true",
    db_name: "application_staging",
    db_user: "staging_user",
    app_key: "base64:Qm7wR2tK8pXzN4vB6mC1sJ5hL0dF3aG7eY9uIoPqRfS=",
    placeholder: false,
};

const ENV_LOCAL: EnvVariant = EnvVariant {
    app_env: "local",
    app_debug: "true",
    db_name: "application_dev",
    db_user: "dev_user",
    app_key: "base64:Zx4cV1bN7mL2kJ9hG5fD3sA8pQ6wE0rT1yU3iO5pA7u=",
    placeholder: false,
};

// Real example/sample files carry placeholder values, never live creds.
const ENV_EXAMPLE: EnvVariant = EnvVariant {
    app_env: "local",
    app_debug: "true",
    db_name: "application",
    db_user: "app_user",
    app_key: "base64:",
    placeholder: true,
};

fn env_variant(path: &str) -> &'static EnvVariant {
    let p = path.to_ascii_lowercase();
    if p.contains("example") || p.contains("sample") || p.contains("template") || p.contains("dist")
    {
        &ENV_EXAMPLE
    } else if p.contains("stag") {
        &ENV_STAGE
    } else if p.contains("local") || p.contains("dev") || p.ends_with("config.env") {
        &ENV_LOCAL
    } else {
        &ENV_PROD
    }
}

fn build_env_file(v: &EnvVariant, credential: &str) -> String {
    if v.placeholder {
        return format!(
            "APP_NAME={name}\n\
             APP_ENV={env}\n\
             APP_KEY=\n\
             APP_DEBUG={debug}\n\
             \n\
             DB_CONNECTION=pgsql\n\
             DB_HOST=127.0.0.1\n\
             DB_PORT=5432\n\
             DB_DATABASE={db}\n\
             DB_USERNAME={user}\n\
             DB_PASSWORD=\n\
             \n\
             REDIS_HOST=127.0.0.1\n\
             REDIS_PASSWORD=null\n\
             REDIS_PORT=6379\n\
             \n\
             MAIL_MAILER=smtp\n\
             MAIL_HOST=\n\
             MAIL_PORT=2525\n\
             MAIL_ENCRYPTION=tls\n",
            name = "Application",
            env = v.app_env,
            debug = v.app_debug,
            db = v.db_name,
            user = v.db_user,
        );
    }
    format!(
        "APP_NAME={name}\n\
         APP_ENV={env}\n\
         APP_KEY={key}\n\
         APP_DEBUG={debug}\n\
         \n\
         DB_CONNECTION=pgsql\n\
         DB_HOST=127.0.0.1\n\
         DB_PORT=5432\n\
         DB_DATABASE={db}\n\
         DB_USERNAME={user}\n\
         DB_PASSWORD={cred}\n\
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
         AWS_SECRET_ACCESS_KEY=xT7nQ9vK4pR2bW6mZ8sF3cL1jY5hD0gUeNoVwAt\n",
        name = if v.app_env == "production" {
            "Production"
        } else {
            "Application"
        },
        env = v.app_env,
        key = v.app_key,
        debug = v.app_debug,
        db = v.db_name,
        user = v.db_user,
        cred = credential,
    )
}

pub async fn env_honeytrap(
    State(state): State<HoneypotState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    method: Method,
) -> Result<Response, Error> {
    use std::net::IpAddr;
    let ip_str = crate::headers::extract_source_ip(&headers);
    let ip: IpAddr = ip_str.parse().unwrap_or(IpAddr::from([0, 0, 0, 0]));
    let path = uri.path();
    let variant = env_variant(path);

    if variant.placeholder {
        sink::log_event(
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
        return Ok((
            StatusCode::OK,
            [(
                axum::http::header::CONTENT_TYPE,
                "text/plain; charset=utf-8",
            )],
            build_env_file(variant, ""),
        )
            .into_response());
    }

    let credential =
        crate::sticky::planted_credential(&ip, path, &state.settings.honeytoken_prefix);
    let env_content = build_env_file(variant, &credential);

    let _ = sink::record_granted_credential(
        &state.pool,
        variant.db_user,
        &credential,
        &ip_str,
        sink::ORIGIN_ENV,
    )
    .await;

    sink::log_event(
        &state,
        &headers,
        &method,
        path,
        uri.query(),
        None,
        Some(variant.db_user),
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

fn is_env_variant(path: &str) -> bool {
    path.split('/')
        .any(|seg| seg.to_ascii_lowercase().contains(".env"))
}

pub async fn env_catch(
    State(state): State<HoneypotState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    method: Method,
) -> Result<Response, Error> {
    if !is_env_variant(uri.path()) {
        return unrouted_probe(State(state), OriginalUri(uri), headers, method).await;
    }
    env_honeytrap(State(state), OriginalUri(uri), headers, method).await
}

/// Terminal 404 for anything the edge routed here that no trap family claimed
/// (`/wp-config.php`, `/phpinfo`, a bare `/administrator/`, a method no route
/// accepts). It records first: these probes are the feed for deciding which
/// trap to build next, and dropping them made the honeypot blind to exactly
/// the paths it does not yet cover.
pub async fn unrouted_probe(
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
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recordable_claim_requires_both_fields_non_empty() {
        let u = |s: &str| Some(s.to_owned());
        assert!(recordable_claim(&u("admin"), &u("s3cret")));
        assert!(!recordable_claim(&u("admin"), &Some(String::new())));
        assert!(!recordable_claim(&Some(String::new()), &u("s3cret")));
        assert!(!recordable_claim(&None, &u("s3cret")));
        assert!(!recordable_claim(&u("admin"), &None));
        assert!(!recordable_claim(&None, &None));
    }

    #[test]
    fn fingerprint_bait_answers_version_and_plugin_readmes() {
        let v = fingerprint_bait("/wp-includes/version.php").expect("version bait");
        assert!(v.contains("$wp_version = '5.8.1'"));
        // case-insensitive: scanners probe /WP-includes/Version.php too
        assert!(fingerprint_bait("/WP-Includes/VERSION.PHP").is_some());

        let r = fingerprint_bait("/wp-content/plugins/wp-fastest-cache/readme.txt")
            .expect("readme bait");
        assert!(r.contains("=== Wp Fastest Cache ==="));
        assert!(r.contains("Stable tag: 1.2.3"));
    }

    #[test]
    fn fingerprint_bait_declines_everything_else() {
        // not a readme, and not a plugin path at all
        assert!(fingerprint_bait("/wp-content/plugins/foo/foo.php").is_none());
        assert!(fingerprint_bait("/wp-includes/css/buttons.css").is_none());
        assert!(fingerprint_bait("/wp-content/uploads/readme.txt").is_none());
        // traversal / injection in the slug must not reach the template
        assert!(fingerprint_bait("/wp-content/plugins/../../readme.txt").is_none());
        assert!(fingerprint_bait("/wp-content/plugins/<script>/readme.txt").is_none());
        // bare prefix, no slug
        assert!(fingerprint_bait("/wp-content/plugins/readme.txt").is_none());
    }

    #[test]
    fn env_variant_detection() {
        assert!(is_env_variant("/.env.dev"));
        assert!(is_env_variant("/.envrc"));
        assert!(is_env_variant("/.env.dev.local"));
        assert!(is_env_variant("/.env_copy"));
        assert!(is_env_variant("/.env.example"));
        assert!(is_env_variant("/core/.env"));
        assert!(is_env_variant("/web/.env"));
        assert!(is_env_variant("/backend/.env"));
        assert!(is_env_variant("/config.env"));
        assert!(is_env_variant("/.env"));
        assert!(is_env_variant("src/.env"));
        assert!(!is_env_variant("/wp-login.php"));
        assert!(!is_env_variant("/.git/config"));
        assert!(!is_env_variant("/administrator/index.php"));
        assert!(!is_env_variant("/"));
        assert!(!is_env_variant("/environment"));
        assert!(is_env_variant("/core/.ENV"));
        assert!(is_env_variant("/foo/.env/bar"));
    }

    #[test]
    fn env_variant_classifier_mapping() {
        assert_eq!(env_variant("/.env").app_env, "production");
        assert_eq!(env_variant("/.env.production").app_env, "production");
        assert!(!env_variant("/.env").placeholder);
        assert_eq!(env_variant("/.env.staging").app_env, "staging");
        assert_eq!(env_variant("/stage/.env").app_env, "staging");
        assert_eq!(env_variant("/.env.local").app_env, "local");
        assert_eq!(env_variant("/.env.dev").app_env, "local");
        assert_eq!(env_variant("/config.env").app_env, "local");
        assert!(env_variant("/.env.EXAMPLE").placeholder);
        assert!(env_variant("/.env.sample").placeholder);
        assert!(env_variant("/.env.template").placeholder);
        assert!(env_variant("/.env.dist").placeholder);
    }

    #[test]
    fn build_env_file_shapes() {
        let prod = build_env_file(&ENV_PROD, "fkAAA111222333");
        assert!(prod.contains("APP_DEBUG=false"));
        assert!(prod.contains("DB_PASSWORD=fkAAA111222333"));
        assert!(prod.contains("APP_NAME=Production"));

        let local = build_env_file(&ENV_LOCAL, "fkBBB333444555");
        assert!(local.contains("APP_DEBUG=true"));
        assert!(local.contains("DB_DATABASE=application_dev"));
        assert!(local.contains("DB_USERNAME=dev_user"));

        let example = build_env_file(&ENV_EXAMPLE, "");
        assert!(example.contains("DB_PASSWORD=\n"));
        assert!(example.contains("APP_KEY=\n"));
        assert!(!example.contains("AWS_ACCESS_KEY_ID"));
    }
}
