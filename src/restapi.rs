//! WordPress REST batch endpoint.
//!
//! `/wp-json/batch/v1` bundles many sub-requests into one HTTP request. That is
//! useful to attackers for exactly one reason: it multiplies how many login or
//! password-reset attempts fit inside a single request, defeating per-request
//! rate limiting.
//!
//! Every observed probe here carried the body `{"requests": []}` — a capability
//! check. The kit asks whether the endpoint exists and answers coherently
//! before it commits its real batch. Answering that probe with a correctly
//! shaped batch response is what earns the follow-up, and the follow-up is
//! where dozens of credentials arrive at once instead of one.

use axum::body::Bytes;
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::{json, Value};

use crate::parsers::{body_to_string, extract_form_field};
use crate::sink;
use crate::{Error, HoneypotState};

/// Cap on sub-requests captured from one batch.
///
/// The endpoint's whole purpose for an attacker is amplification, and the
/// handler did one DB insert per credential pair with no ceiling. A single
/// 141 KB request produced 2000 event rows, 8 MB of stored body text and held
/// a pool connection for 38 seconds — against a five-connection pool, a
/// handful of those starves every other trap. The cap keeps the capture that
/// matters (the head of the dictionary and the usernames) while bounding write
/// amplification. WordPress itself refuses batches larger than 25, so this is
/// also the more faithful answer.
const MAX_BATCH_CAPTURES: usize = 25;

const USER_KEYS: &[&str] = &[
    "username",
    "user_login",
    "log",
    "user",
    "email",
    "user_email",
];
const PASS_KEYS: &[&str] = &["password", "user_pass", "pwd", "pass"];

/// Pull credentials out of one sub-request body, which may be a JSON object or
/// a form-encoded string depending on the client.
fn creds_from_body(body: &Value) -> (Option<String>, Option<String>) {
    match body {
        Value::Object(map) => {
            let find = |keys: &[&str]| {
                keys.iter().find_map(|k| {
                    map.get(*k)
                        .and_then(Value::as_str)
                        .map(std::borrow::ToOwned::to_owned)
                })
            };
            (find(USER_KEYS), find(PASS_KEYS))
        }
        Value::String(s) => (
            USER_KEYS.iter().find_map(|k| extract_form_field(s, k)),
            PASS_KEYS.iter().find_map(|k| extract_form_field(s, k)),
        ),
        _ => (None, None),
    }
}

/// Every (user, pass) pair carried by a batch envelope, in order.
pub fn extract_batch_credentials(raw: &str) -> Vec<(Option<String>, Option<String>)> {
    let Ok(v) = serde_json::from_str::<Value>(raw) else {
        return Vec::new();
    };
    let Some(requests) = v.get("requests").and_then(Value::as_array) else {
        return Vec::new();
    };
    requests
        .iter()
        .map(|r| r.get("body").map_or((None, None), creds_from_body))
        .collect()
}

/// The batch envelope WordPress returns. `failed` is null when validation
/// passed; each sub-response carries its own status.
fn batch_response(count: usize) -> String {
    let responses: Vec<Value> = (0..count)
        .map(|_| {
            json!({
                "body": {"code": "invalid_username",
                         "message": "Unknown username. Check again or try your email address.",
                         "data": {"status": 401}},
                "status": 401,
                "headers": {}
            })
        })
        .collect();
    json!({"failed": null, "responses": responses}).to_string()
}

pub async fn batch(
    State(state): State<HoneypotState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    method: Method,
    body: Bytes,
) -> Result<Response, Error> {
    let path = uri.path();
    let ip_str = crate::headers::extract_source_ip(&headers);

    if method != Method::POST {
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
        // The endpoint advertises itself on GET, which is how kits confirm it.
        return Ok((
            StatusCode::OK,
            [(
                axum::http::header::CONTENT_TYPE,
                "application/json; charset=UTF-8",
            )],
            json!({"namespace": "batch/v1", "routes": {"/batch/v1": {"methods": ["POST"]}}})
                .to_string(),
        )
            .into_response());
    }

    let raw = body_to_string(&body);
    let pairs = extract_batch_credentials(&raw);
    let carrying: Vec<_> = pairs
        .iter()
        .filter(|(u, p)| u.is_some() || p.is_some())
        .collect();

    // One row per sub-request, so a batch reads as the many attempts it is
    // rather than one opaque POST — but bounded, and with the envelope stored
    // once. Repeating the truncated body on every row turned a single request
    // into megabytes of duplicated text.
    let mut logged = 0usize;
    for (user, pass) in carrying.iter().take(MAX_BATCH_CAPTURES) {
        if let (Some(u), Some(p)) = (user, pass) {
            let _ = sink::record_granted_credential(&state.pool, u, p, &ip_str, sink::ORIGIN_LOGIN)
                .await;
        }
        sink::log_event(
            &state,
            &headers,
            &method,
            path,
            uri.query(),
            // First row carries the envelope; the rest carry the parsed pair,
            // which is what the dashboards actually read.
            (logged == 0).then_some(raw.as_str()),
            user.as_deref(),
            pass.as_deref(),
            200,
            0,
        )
        .await?;
        logged += 1;
    }
    if logged == 0 {
        // The empty capability probe still deserves a row.
        sink::log_event(
            &state,
            &headers,
            &method,
            path,
            uri.query(),
            Some(&raw),
            None,
            None,
            200,
            0,
        )
        .await?;
    } else if carrying.len() > MAX_BATCH_CAPTURES {
        tracing::info!(
            source_ip = %ip_str,
            captured = MAX_BATCH_CAPTURES,
            submitted = carrying.len(),
            "batch amplification capped"
        );
    }

    Ok((
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "application/json; charset=UTF-8",
        )],
        batch_response(pairs.len().min(MAX_BATCH_CAPTURES)),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_probe_yields_a_valid_empty_envelope() {
        // This is the exact body every observed probe sent.
        assert!(extract_batch_credentials(r#"{"requests": []}"#).is_empty());
        let v: Value = serde_json::from_str(&batch_response(0)).unwrap();
        assert!(v["failed"].is_null());
        assert_eq!(v["responses"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn extracts_credentials_from_a_json_batch() {
        let raw = r#"{"validation":"require-all-validate","requests":[
            {"method":"POST","path":"/wp/v2/users","body":{"username":"admin","password":"hunter2"}},
            {"method":"POST","path":"/wp/v2/users","body":{"username":"admin","password":"letmein"}}
        ]}"#;
        let pairs = extract_batch_credentials(raw);
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0].0.as_deref(), Some("admin"));
        assert_eq!(pairs[0].1.as_deref(), Some("hunter2"));
        assert_eq!(pairs[1].1.as_deref(), Some("letmein"));
    }

    #[test]
    fn extracts_credentials_from_form_encoded_sub_bodies() {
        let raw = r#"{"requests":[{"method":"POST","body":"log=root&pwd=toor"}]}"#;
        let pairs = extract_batch_credentials(raw);
        assert_eq!(pairs[0].0.as_deref(), Some("root"));
        assert_eq!(pairs[0].1.as_deref(), Some("toor"));
    }

    #[test]
    fn malformed_bodies_do_not_panic() {
        assert!(extract_batch_credentials("not json").is_empty());
        assert!(extract_batch_credentials("{}").is_empty());
        assert!(extract_batch_credentials(r#"{"requests":"nope"}"#).is_empty());
        assert!(
            extract_batch_credentials(r#"{"requests":[{"body":42}]}"#)[0]
                .0
                .is_none()
        );
    }

    #[test]
    fn oversized_batches_are_capped() {
        let subs: Vec<String> = (0..2000)
            .map(|i| {
                format!(r#"{{"method":"POST","body":{{"username":"u{i}","password":"p{i}"}}}}"#)
            })
            .collect();
        let raw = format!(r#"{{"requests":[{}]}}"#, subs.join(","));
        let pairs = extract_batch_credentials(&raw);
        assert_eq!(pairs.len(), 2000, "parsing still sees the whole batch");
        assert_eq!(
            pairs.iter().take(MAX_BATCH_CAPTURES).count(),
            25,
            "write amplification must stay bounded"
        );
        let v: Value =
            serde_json::from_str(&batch_response(pairs.len().min(MAX_BATCH_CAPTURES))).unwrap();
        assert_eq!(v["responses"].as_array().unwrap().len(), 25);
    }

    #[test]
    fn response_length_matches_the_batch() {
        let v: Value = serde_json::from_str(&batch_response(3)).unwrap();
        assert_eq!(v["responses"].as_array().unwrap().len(), 3);
        assert_eq!(v["responses"][0]["status"], 401);
    }
}
