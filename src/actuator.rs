//! Spring Boot Actuator traps.
//!
//! `/actuator/env` and friends were answering 404 despite steady demand.
//! Actuator is a secrets-disclosure target: `env` prints the whole property
//! source including datasource passwords, so it is a natural honeytoken vector,
//! and `heapdump` is the rare endpoint an attacker *expects* to be enormous and
//! slow — which makes it the most credible tarpit in the whole surface. A bot
//! that starts a heapdump download will wait, because a fast one would be the
//! suspicious outcome.

use axum::body::Body;
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use std::net::IpAddr;
use std::time::Duration;
use tokio::sync::OwnedSemaphorePermit;

use crate::sink;
use crate::sticky::planted_credential;
use crate::{Error, HoneypotState};

/// Actuator masks values it considers sensitive with `******`. Leaving a few
/// masked is what makes the unmasked ones look like a real misconfiguration
/// rather than bait.
fn env_json(secret: &str, db_pass: &str) -> String {
    format!(
        r#"{{
  "activeProfiles": ["prod"],
  "propertySources": [
    {{
      "name": "systemEnvironment",
      "properties": {{
        "SPRING_DATASOURCE_URL": {{"value": "jdbc:postgresql://10.0.4.17:5432/fillerkiller"}},
        "SPRING_DATASOURCE_USERNAME": {{"value": "app_user"}},
        "SPRING_DATASOURCE_PASSWORD": {{"value": "{db_pass}"}},
        "SPRING_REDIS_PASSWORD": {{"value": "{secret}"}},
        "JWT_SIGNING_KEY": {{"value": "{secret}"}},
        "AWS_SECRET_ACCESS_KEY": {{"value": "{secret}"}},
        "MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE": {{"value": "*"}},
        "PATH": {{"value": "/usr/local/bin:/usr/bin:/bin"}}
      }}
    }},
    {{
      "name": "applicationConfig: [classpath:/application-prod.yml]",
      "properties": {{
        "server.port": {{"value": 8080}},
        "spring.jpa.hibernate.ddl-auto": {{"value": "validate"}},
        "management.endpoint.heapdump.enabled": {{"value": true}},
        "app.admin.token": {{"value": "******"}}
      }}
    }}
  ]
}}"#
    )
}

const HEALTH_JSON: &str = r#"{"status":"UP","components":{"db":{"status":"UP","details":{"database":"PostgreSQL","validationQuery":"isValid()"}},"diskSpace":{"status":"UP","details":{"total":103068663808,"free":41203781632,"threshold":10485760}},"ping":{"status":"UP"}}}"#;

const MAPPINGS_JSON: &str = r#"{"contexts":{"application":{"mappings":{"dispatcherServlets":{"dispatcherServlet":[{"handler":"ApiController#login(LoginRequest)","predicate":"{POST /api/v1/auth/login}"},{"handler":"ApiController#users()","predicate":"{GET /api/v1/users}"},{"handler":"AdminController#exec(String)","predicate":"{POST /api/v1/admin/exec}"}]}}}}}"#;

const CONFIGPROPS_JSON: &str = r#"{"contexts":{"application":{"beans":{"spring.datasource-org.springframework.boot.autoconfigure.jdbc.DataSourceProperties":{"prefix":"spring.datasource","properties":{"url":"jdbc:postgresql://10.0.4.17:5432/fillerkiller","username":"app_user","driverClassName":"org.postgresql.Driver"}}}}}}"#;

/// A Java heap dump begins with the HPROF magic string and a header. Kits
/// check the magic before committing to a long download.
fn hprof_header() -> Vec<u8> {
    let mut v = Vec::from(&b"JAVA PROFILE 1.0.2\0"[..]);
    v.extend_from_slice(&4u32.to_be_bytes()); // identifier size
    v.extend_from_slice(&0u64.to_be_bytes()); // timestamp
    v
}

const HEAPDUMP_CHUNKS: usize = 60;

/// Stream `total_bytes` over `seconds`, so the transfer looks like a real
/// multi-megabyte heapdump crawling over a slow link. Each chunk is sent then
/// awaited; the receiver disconnecting ends the task.
///
/// `permit` is the slow-response slot this stream occupies. It is moved into
/// the streaming task and dropped when the stream ends — including when the
/// attacker hangs up — so an abandoned download returns its slot immediately
/// instead of holding it for the full duration.
///
/// The filler is allocated once as `Bytes`; cloning it is a refcount bump, not
/// a copy. Cloning a `Vec` per chunk instead would put
/// `chunk_size * chunks * concurrent_streams` through the allocator and, at the
/// upper end of `HEAPDUMP_BYTES`, threaten a 256 MiB container.
fn heapdump_body(total_bytes: usize, seconds: u64, permit: OwnedSemaphorePermit) -> Body {
    let header = hprof_header();
    let chunk_size = total_bytes.saturating_sub(header.len()) / HEAPDUMP_CHUNKS.max(1);
    let gap = Duration::from_millis(seconds.saturating_mul(1000) / HEAPDUMP_CHUNKS as u64);

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<axum::body::Bytes, std::io::Error>>(1);
    tokio::spawn(async move {
        // Held for the life of the stream; dropped on return, hang-up included.
        let _permit = permit;
        if tx.send(Ok(header.into())).await.is_err() {
            return;
        }
        // Heap contents are mostly repeated object headers and string data, so
        // a low-entropy filler reads like the real thing.
        let filler = axum::body::Bytes::from(vec![b'\0'; chunk_size]);
        for _ in 0..HEAPDUMP_CHUNKS {
            tokio::time::sleep(gap).await;
            if tx.send(Ok(filler.clone())).await.is_err() {
                return;
            }
        }
    });
    Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(rx))
}

/// Cap on the unbudgeted heapdump body.
///
/// This path runs precisely when the slow-response budget is spent — that is,
/// when concurrency is highest — so it must be the *cheaper* of the two, not
/// the more expensive one. Buffering the full `HEAPDUMP_BYTES` here would
/// allocate up to 16 MiB per in-flight request with no ceiling on how many,
/// against a 256 MiB container: the fallback would OOM the service under the
/// exact load it exists to survive. A truncated dump is unremarkable — real
/// ones are interrupted all the time — and the HPROF magic still reads.
const HEAPDUMP_IMMEDIATE_CAP: usize = 64 * 1024;

/// The dump served whole, for when the slow-response budget is spent. A fast
/// heapdump is unremarkable; a request the platform kills at its timeout is a
/// 504 that identifies the trap.
/// Bytes the unbudgeted path buffers. Split out so the cap is directly
/// testable without reaching into an opaque `Body`.
fn immediate_len(total_bytes: usize) -> usize {
    total_bytes
        .min(HEAPDUMP_IMMEDIATE_CAP)
        .max(hprof_header().len())
}

fn heapdump_immediate(total_bytes: usize) -> Body {
    let mut v = hprof_header();
    v.resize(immediate_len(total_bytes), 0);
    Body::from(v)
}

pub async fn actuator(
    State(state): State<HoneypotState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    method: Method,
) -> Result<Response, Error> {
    let path = uri.path();
    let ip_str = crate::headers::extract_source_ip(&headers);
    let ip: IpAddr = ip_str.parse().unwrap_or(IpAddr::from([0, 0, 0, 0]));
    let prefix =
        crate::sticky::honeytoken_prefix(&state.settings.honeytoken_prefix, &headers, path);

    let tail = path.trim_start_matches("/actuator").trim_matches('/');
    let json_ct = "application/vnd.spring-boot.actuator.v3+json";

    if tail == "heapdump" {
        let permit = crate::tarpit::try_reserve(&state.slow_budget);
        let held_secs = crate::tarpit::effective_delay(state.settings.heapdump_seconds, &permit);
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
            u32::try_from(held_secs * 1000).unwrap_or(0),
        )
        .await?;
        let body = match permit {
            Some(p) => heapdump_body(state.settings.heapdump_bytes, held_secs, p),
            None => heapdump_immediate(state.settings.heapdump_bytes),
        };
        return Ok((
            StatusCode::OK,
            [
                (axum::http::header::CONTENT_TYPE, "application/octet-stream"),
                (
                    axum::http::header::CONTENT_DISPOSITION,
                    "attachment; filename=\"heapdump\"",
                ),
            ],
            body,
        )
            .into_response());
    }

    let (body, planted) = match tail {
        "env" => {
            let secret = planted_credential(&ip, "/actuator/env#secret", &prefix);
            let db_pass = planted_credential(&ip, "/actuator/env#db", &prefix);
            (env_json(&secret, &db_pass), Some(db_pass))
        }
        "health" => (HEALTH_JSON.to_owned(), None),
        "mappings" => (MAPPINGS_JSON.to_owned(), None),
        "configprops" => (CONFIGPROPS_JSON.to_owned(), None),
        // The index lists what is exposed, which is how kits discover heapdump.
        "" => (
            r#"{"_links":{"self":{"href":"/actuator","templated":false},"env":{"href":"/actuator/env","templated":false},"health":{"href":"/actuator/health","templated":false},"heapdump":{"href":"/actuator/heapdump","templated":false},"mappings":{"href":"/actuator/mappings","templated":false},"configprops":{"href":"/actuator/configprops","templated":false}}}"#.to_owned(),
            None,
        ),
        _ => {
            return crate::handlers::config_probe(State(state), OriginalUri(uri), headers, method)
                .await
        }
    };

    if let Some(ref db_pass) = planted {
        let _ = sink::record_granted_credential(
            &state.pool,
            "app_user",
            db_pass,
            &ip_str,
            sink::ORIGIN_SECRET,
        )
        .await;
    }

    sink::log_planted_event(
        &state,
        &headers,
        &method,
        path,
        uri.query(),
        planted.as_ref().map(|_| "app_user"),
        planted.as_deref(),
        200,
        0,
    )
    .await?;

    Ok((
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, json_ct)],
        body,
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_json_plants_credentials_and_keeps_one_masked() {
        let j = env_json("fkSECRET", "fkDBPASS");
        assert!(j.contains("fkDBPASS"));
        assert!(j.contains("fkSECRET"));
        assert!(j.contains("******"), "a masked value sells the rest");
        assert!(j.contains("SPRING_DATASOURCE_PASSWORD"));
    }

    #[test]
    fn immediate_body_is_capped_and_keeps_the_hprof_magic() {
        // Never buffers more than the cap, whatever HEAPDUMP_BYTES says.
        for requested in [0, 1024, 16 * 1024 * 1024] {
            let len = immediate_len(requested);
            assert!(
                len <= HEAPDUMP_IMMEDIATE_CAP,
                "requested {requested} buffered {len}"
            );
            assert!(len >= hprof_header().len(), "magic must survive");
        }
        assert_eq!(immediate_len(1024), 1024, "small dumps pass through");
    }

    #[test]
    fn unbudgeted_path_is_cheaper_than_the_streamed_one() {
        // The whole point: the fallback runs at peak concurrency, so it must
        // not be the memory-hungrier branch.
        let streamed_chunk = (16 * 1024 * 1024) / HEAPDUMP_CHUNKS;
        assert!(
            HEAPDUMP_IMMEDIATE_CAP <= streamed_chunk * 2,
            "fallback must stay comparable to one streamed chunk"
        );
    }

    #[test]
    fn heapdump_starts_with_hprof_magic() {
        let h = hprof_header();
        assert!(h.starts_with(b"JAVA PROFILE 1.0.2\0"));
        assert_eq!(h.len(), 19 + 4 + 8);
    }

    #[test]
    fn actuator_json_payloads_parse() {
        for j in [HEALTH_JSON, MAPPINGS_JSON, CONFIGPROPS_JSON] {
            serde_json::from_str::<serde_json::Value>(j).expect("valid JSON");
        }
        serde_json::from_str::<serde_json::Value>(&env_json("a", "b")).expect("env is valid JSON");
    }

    #[test]
    fn concurrent_heapdumps_cannot_exhaust_container_memory() {
        // Worst case resident filler = chunk_size * every slow-response slot.
        // The container limit is 256 MiB; stay well clear of it.
        let s = crate::config::Settings::default();
        let max_bytes = 16 * 1024 * 1024; // the HEAPDUMP_BYTES ceiling
        let chunk = max_bytes / HEAPDUMP_CHUNKS;
        let worst_case = chunk * s.slow_response_budget;
        assert!(
            worst_case < 32 * 1024 * 1024,
            "worst-case heapdump memory {worst_case} B is too close to the 256 MiB limit"
        );
    }

    #[test]
    fn heapdump_duration_stays_under_cloud_run_timeout() {
        let s = crate::config::Settings::default();
        assert!(
            s.heapdump_seconds < 300,
            "a response past the platform timeout returns 504 and reveals the trap"
        );
    }
}
