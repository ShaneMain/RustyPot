//! `wp-admin/admin-ajax.php` — plugin exploit endpoint.
//!
//! This is where WordPress plugins expose unauthenticated actions, and it is
//! the single richest capture surface this service has. Two real payloads were
//! already sitting unparsed in the catch-all before this module existed:
//!
//! - `action=pods_admin&method=save_user&user_login=…&user_pass=…&role=administrator`
//!   — a Pods privilege-escalation creating a backdoor admin. The credentials
//!   the kit CHOOSES are exactly the capture the installer-claim trap was built
//!   for and never got, because the kits use this path instead.
//! - `action=gamipress_get_logs&orderby=,(SELECT EXTRACTVALUE(1,CONCAT(0x7e,
//!   (SELECT GROUP_CONCAT(CONCAT(user_login,0x3a,user_pass)…) FROM wp_users…`
//!   — error-based SQL injection dumping the user table.
//!
//! Both get answered convincingly. A created account is recorded with
//! `origin='ajax'` so the kit's follow-up login succeeds (see `decide_grant`),
//! and an injection gets a fabricated `wp_users` dump back.

use axum::body::Bytes;
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use std::net::IpAddr;

use crate::parsers::{body_to_string, extract_form_field};
use crate::sink;
use crate::{Error, HoneypotState};

/// Markers of an injection attempt in a parameter value. Matched
/// case-insensitively against the whole body.
const SQLI_MARKERS: &[&str] = &[
    "extractvalue",
    "updatexml",
    "union select",
    "information_schema",
    "group_concat",
    "benchmark(",
    "sleep(",
    "@@version",
    "0x7e",
];

pub fn looks_like_sqli(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    SQLI_MARKERS.iter().any(|m| lower.contains(m))
}

/// Field names plugins use for the account an escalation exploit creates.
/// Ordered by how commonly they appear in the observed payloads.
const USER_FIELDS: &[&str] = &["user_login", "username", "user_name", "log", "new_user"];
const PASS_FIELDS: &[&str] = &["user_pass", "password", "user_password", "pwd", "pass"];

/// Fields naming the role an escalation exploit assigns. Their presence is
/// what separates "a kit created an admin" from "someone posted a form".
const ROLE_FIELDS: &[&str] = &["role", "user_role", "wp_capabilities", "new_role"];

/// True when the payload is really trying to create a privileged account.
///
/// Without this gate, ANY post carrying user/pass fields registered the pair as
/// `origin='ajax'`, which grants instantly at the login form. That is a
/// two-request fingerprinting oracle: post an arbitrary pair here, then present
/// it at `wp-login.php`. Real WordPress answers an unknown admin-ajax action
/// with `0` and creates nothing, so that login would fail — an instant success
/// identifies the honeypot outright. It also let an attacker mark common
/// dictionary pairs as instantly-granted, short-circuiting the churn that makes
/// stuffers work through their whole list.
///
/// Credentials are still captured either way; only the instant-grant
/// registration is gated.
pub fn is_privilege_escalation(body: &str) -> bool {
    ROLE_FIELDS.iter().any(|f| {
        extract_form_field(body, f).is_some_and(|v| {
            let v = v.to_ascii_lowercase();
            v.contains("admin") || v.contains("editor") || v.contains("level_10")
        })
    })
}

pub fn parse_created_account(body: &str) -> (Option<String>, Option<String>) {
    let user = USER_FIELDS.iter().find_map(|f| extract_form_field(body, f));
    let pass = PASS_FIELDS.iter().find_map(|f| extract_form_field(body, f));
    (user, pass)
}

/// A WordPress phpass hash: `$P$B` + 8 salt chars + 22 hash chars.
///
/// These are deliberately NOT derived from any password — nothing will ever
/// crack them, which is the point: a kit that dumps them spends real GPU time
/// on hashes with no preimage. The correlation value is in the USERNAMES,
/// which are per-IP honeytokens: one of them presented at a login form later
/// identifies the actor that pulled this dump.
fn phpass_hash(ip: &IpAddr, seed: &str) -> String {
    const ITOA: &[u8] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    format!("$P$B{}", crate::sticky::derived_chars(ip, seed, ITOA, 30))
}

/// Usernames are per-IP so a later login attempt naming one of them proves the
/// attacker read this dump.
fn fabricated_users(ip: &IpAddr) -> Vec<(String, String)> {
    let tag = crate::sticky::planted_credential(ip, "/admin-ajax#users", "");
    let short: String = tag.chars().take(4).collect();
    ["admin", "editor", "webmaster", "support", "backup"]
        .iter()
        .enumerate()
        .map(|(i, role)| {
            (
                format!("wp_{role}_{short}"),
                phpass_hash(ip, &format!("/admin-ajax#u{i}")),
            )
        })
        .collect()
}

/// The MySQL error an EXTRACTVALUE injection produces, wrapped in the
/// `WordPress database error` envelope a real install prints when
/// `WP_DEBUG_DISPLAY` is on. The leading `~` is the 0x7e the payload injects.
fn sqli_error_page(ip: &IpAddr, action: &str) -> String {
    let dump = fabricated_users(ip)
        .into_iter()
        .map(|(u, h)| format!("{u}:{h}"))
        .collect::<Vec<_>>()
        .join("|");
    let truncated: String = dump.chars().take(31).collect();
    format!(
        "<br />\n<b>WordPress database error:</b> [XPATH syntax error: '~{truncated}']<br />\n\
         <code>SELECT * FROM wp_posts WHERE post_type = '{action}' ORDER BY ,(SELECT EXTRACTVALUE(1,CONCAT(0x7e,(SELECT GROUP_CONCAT(CONCAT(user_login,0x3a,user_pass)) FROM wp_users LIMIT 5))))</code><br />\n\
         <!-- {dump} -->\n0"
    )
}

pub async fn admin_ajax(
    State(state): State<HoneypotState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    method: Method,
    body: Bytes,
) -> Result<Response, Error> {
    let path = uri.path();
    let ip_str = crate::headers::extract_source_ip(&headers);
    let ip: IpAddr = ip_str.parse().unwrap_or(IpAddr::from([0, 0, 0, 0]));
    let body_str = body_to_string(&body);
    // The action can arrive in the query string as well as the body.
    let action = extract_form_field(&body_str, "action")
        .or_else(|| uri.query().and_then(|q| extract_form_field(q, "action")))
        .unwrap_or_default();

    if method == Method::GET || method == Method::HEAD {
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
        // Unknown/unauthenticated actions get a bare "0" from real WordPress.
        return Ok((StatusCode::OK, "0").into_response());
    }

    if looks_like_sqli(&body_str) {
        sink::log_event(
            &state,
            &headers,
            &method,
            path,
            uri.query(),
            Some(&body_str),
            None,
            None,
            200,
            0,
        )
        .await?;
        return Ok((
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "text/html; charset=UTF-8")],
            sqli_error_page(&ip, &action),
        )
            .into_response());
    }

    let (user, pass) = parse_created_account(&body_str);
    if let (Some(u), Some(p)) = (&user, &pass) {
        if !u.is_empty() && !p.is_empty() && is_privilege_escalation(&body_str) {
            let _ = sink::record_granted_credential(&state.pool, u, p, &ip_str, sink::ORIGIN_AJAX)
                .await;
        }
    }
    sink::log_event(
        &state,
        &headers,
        &method,
        path,
        uri.query(),
        Some(&body_str),
        user.as_deref(),
        pass.as_deref(),
        200,
        0,
    )
    .await?;

    // Plugins answer a successful admin-ajax action with a JSON envelope.
    // Reporting success is what makes the kit proceed to its verification
    // login, which the ajax origin then grants.
    let payload = if user.is_some() {
        r#"{"success":true,"data":{"message":"User created","id":7}}"#
    } else {
        r#"{"success":true,"data":null}"#
    };
    Ok((
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "application/json; charset=UTF-8",
        )],
        payload,
    )
        .into_response())
}

/// True for a request at a plugin's own PHP entry point, e.g.
/// `/wp-content/plugins/some-plugin/includes/upload.php`.
pub fn is_plugin_endpoint(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.starts_with("/wp-content/plugins/") && lower.ends_with(".php")
}

/// Plugin entry points.
///
/// The fingerprint bait advertises outdated, publicly-vulnerable plugin
/// versions, and scanners do read it — but they then probed the plugin's actual
/// endpoint, got a 404, concluded the plugin was not really installed, and
/// left. Two IPs read 12 and 6 plugin readmes respectively and departed inside
/// four minutes without a single exploit attempt. Answering these paths is what
/// converts a readme read into a captured payload.
pub async fn plugin_endpoint(
    State(state): State<HoneypotState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    method: Method,
    body: Bytes,
) -> Result<Response, Error> {
    let path = uri.path();
    if !is_plugin_endpoint(path) {
        // readme.txt and asset requests keep the fingerprint-bait behaviour.
        return crate::handlers::config_probe(State(state), OriginalUri(uri), headers, method)
            .await;
    }
    let ip_str = crate::headers::extract_source_ip(&headers);
    let ip: IpAddr = ip_str.parse().unwrap_or(IpAddr::from([0, 0, 0, 0]));
    let body_str = body_to_string(&body);

    if !body_str.is_empty() && looks_like_sqli(&body_str) {
        sink::log_event(
            &state,
            &headers,
            &method,
            path,
            uri.query(),
            Some(&body_str),
            None,
            None,
            200,
            0,
        )
        .await?;
        let action = path.rsplit('/').next().unwrap_or("plugin");
        return Ok((
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "text/html; charset=UTF-8")],
            sqli_error_page(&ip, action),
        )
            .into_response());
    }

    let (user, pass) = parse_created_account(&body_str);
    if let (Some(u), Some(p)) = (&user, &pass) {
        if !u.is_empty() && !p.is_empty() && is_privilege_escalation(&body_str) {
            let _ = sink::record_granted_credential(&state.pool, u, p, &ip_str, sink::ORIGIN_AJAX)
                .await;
        }
    }

    sink::log_event(
        &state,
        &headers,
        &method,
        path,
        uri.query(),
        (!body_str.is_empty()).then_some(body_str.as_str()),
        user.as_deref(),
        pass.as_deref(),
        200,
        0,
    )
    .await?;

    // A file-upload exploit expects the uploaded path echoed back; a generic
    // handler expects a success envelope. Both are answered with a JSON body
    // naming a plausible uploads path, which is also the next thing the kit
    // fetches — and that fetch is another capture.
    let payload = json_success(path);
    Ok((
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "application/json; charset=UTF-8",
        )],
        payload,
    )
        .into_response())
}

fn json_success(path: &str) -> String {
    let name = path.rsplit('/').next().unwrap_or("file");
    format!(
        r#"{{"success":true,"status":"ok","file":"/wp-content/uploads/2026/08/{name}","url":"https://fillerkiller.app/wp-content/uploads/2026/08/{name}","error":null}}"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_plugin_php_entry_points() {
        assert!(is_plugin_endpoint(
            "/wp-content/plugins/wp-fastest-cache/includes/upload.php"
        ));
        assert!(is_plugin_endpoint("/wp-content/plugins/foo/ajax.php"));
        // readme/asset requests stay with the fingerprint bait.
        assert!(!is_plugin_endpoint(
            "/wp-content/plugins/wp-fastest-cache/readme.txt"
        ));
        assert!(!is_plugin_endpoint("/wp-content/themes/x/style.css"));
        assert!(!is_plugin_endpoint("/wp-content/uploads/2026/08/a.php"));
    }

    #[test]
    fn upload_success_names_a_plausible_uploads_path() {
        let j = json_success("/wp-content/plugins/foo/upload.php");
        let v: serde_json::Value = serde_json::from_str(&j).expect("valid JSON");
        assert_eq!(v["success"], true);
        assert!(v["file"]
            .as_str()
            .unwrap()
            .starts_with("/wp-content/uploads/"));
    }

    #[test]
    fn detects_the_observed_gamipress_injection() {
        let body = "action=gamipress_get_logs&orderby=%2C%28SELECT+EXTRACTVALUE%281%2CCONCAT%280x7e%2C%28SELECT+GROUP_CONCAT%28CONCAT%28user_login%2C0x3a%2Cuser_pass%29";
        assert!(looks_like_sqli(body));
    }

    #[test]
    fn ordinary_payloads_are_not_flagged_as_injection() {
        assert!(!looks_like_sqli(
            "action=pods_admin&method=save_user&user_login=wp_x&user_pass=abc"
        ));
        assert!(!looks_like_sqli("action=heartbeat&_nonce=abc123"));
    }

    #[test]
    fn parses_the_observed_pods_escalation() {
        let body = "action=pods_admin&method=save_user&meta-box-loader=1&user_login=wp_bsxu9x&user_pass=hztnn1w0%21Aa1&user_email=wp_bsxu9x%40u4jpv1.com&role=administrator";
        let (u, p) = parse_created_account(body);
        assert_eq!(u.as_deref(), Some("wp_bsxu9x"));
        assert_eq!(p.as_deref(), Some("hztnn1w0!Aa1"), "percent-decoded");
    }

    #[test]
    fn only_role_bearing_payloads_earn_an_instant_grant() {
        // The observed Pods escalation assigns administrator, so it counts.
        assert!(is_privilege_escalation(
            "action=pods_admin&method=save_user&user_login=x&user_pass=y&role=administrator"
        ));
        assert!(is_privilege_escalation("action=x&new_role=editor"));

        // A bare credential post must NOT register an instant-grant pair —
        // that was a two-request oracle for identifying the honeypot, and a way
        // to short-circuit the stuffer churn on common passwords.
        assert!(!is_privilege_escalation(
            "user_login=admin&user_pass=123456"
        ));
        assert!(!is_privilege_escalation("action=heartbeat"));
        assert!(!is_privilege_escalation("action=x&role=subscriber"));
    }

    #[test]
    fn parses_alternate_field_names() {
        let (u, p) = parse_created_account("action=x&username=bob&password=hunter2");
        assert_eq!(u.as_deref(), Some("bob"));
        assert_eq!(p.as_deref(), Some("hunter2"));
    }

    #[test]
    fn phpass_hash_has_wordpress_shape() {
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let h = phpass_hash(&ip, "seed");
        assert!(h.starts_with("$P$B"));
        assert_eq!(h.len(), 34, "$P$B + 30 chars is the phpass layout");
        assert_eq!(h, phpass_hash(&ip, "seed"), "deterministic");
        // A visible period in the hash body would mark the dump as fabricated
        // to anyone who looked before spending GPU time on it.
        assert_ne!(&h[4..14], &h[14..24], "no repeating block");
    }

    #[test]
    fn fabricated_users_are_per_ip() {
        let a: IpAddr = "203.0.113.9".parse().unwrap();
        let b: IpAddr = "203.0.113.10".parse().unwrap();
        let ua = fabricated_users(&a);
        assert_eq!(ua.len(), 5);
        assert_ne!(ua, fabricated_users(&b), "usernames identify the reader");
        assert_eq!(ua, fabricated_users(&a), "stable for correlation");
    }

    #[test]
    fn sqli_page_looks_like_a_wordpress_db_error() {
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let page = sqli_error_page(&ip, "gamipress_get_logs");
        assert!(page.contains("WordPress database error"));
        assert!(page.contains("XPATH syntax error"));
        // Real EXTRACTVALUE errors truncate at 32 chars — a full dump in the
        // error string is the tell that it was fabricated.
        let start = page.find("error: '~").unwrap() + "error: '~".len();
        let end = page[start..].find('\'').unwrap();
        assert!(end <= 31, "error text must respect MySQL's 32-char limit");
        assert!(page.contains("$P$B"), "hashes reachable in the comment");
    }
}
