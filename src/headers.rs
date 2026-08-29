//! Header-derived signal extraction for the honeypot. `extract_source_ip`
//! mirrors the trust chain in `rate_limit::client_ip` (CF-Connecting-IP →
//! first XFF hop → True-Client-IP), but returns the raw string instead of
//! parsing to `IpAddr` — the honeypot logs whatever the proxy sent, including
//! malformed values, for forensic completeness.

use axum::http::HeaderMap;
use serde_json::Value;

pub(crate) fn extract_source_ip(headers: &HeaderMap) -> String {
    if let Some(v) = header_str(headers, "cf-connecting-ip") {
        return v.to_owned();
    }
    if let Some(v) = header_str(headers, "x-forwarded-for") {
        if let Some(first) = v.split(',').next() {
            let trimmed = first.trim();
            if !trimmed.is_empty() {
                return trimmed.to_owned();
            }
        }
    }
    if let Some(v) = header_str(headers, "true-client-ip") {
        return v.to_owned();
    }
    "0.0.0.0".to_owned()
}

/// User-agent substrings claimed by major AI crawlers.
const CRAWLER_MARKERS: &[&str] = &[
    "chatgpt-user",
    "oai-searchbot",
    "gptbot",
    "perplexitybot",
    "amazonbot",
    "amzn-searchbot",
    "cohere-ai",
    "claudebot",
    "google-extended",
    "bingbot",
];

/// Paths no legitimate crawler ever requests: secret files, credential forms
/// and exploit endpoints. A crawler-branded user-agent on one of these is
/// forged — the branding is chosen because many sites allowlist those crawlers.
fn is_never_crawled(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    p.contains(".env")
        || p.contains("/.aws/")
        || p.contains("/.ssh/")
        || p.contains("/.git")
        || p.contains("credentials")
        || p.contains("admin-ajax")
        || p.contains("xmlrpc")
        || p.contains("wp-login")
        || p.contains("/actuator/")
}

/// True when the client brands itself as an AI crawler while requesting
/// something no crawler would. Used to give the actor its own honeytoken
/// prefix, so a credential surfacing later carries "this actor impersonates
/// AI crawlers" as a tooling fingerprint without needing a join.
pub(crate) fn is_impersonating_crawler(headers: &HeaderMap, path: &str) -> bool {
    if !is_never_crawled(path) {
        return false;
    }
    header_str(headers, "user-agent").is_some_and(|ua| {
        let lower = ua.to_ascii_lowercase();
        CRAWLER_MARKERS.iter().any(|m| lower.contains(m))
    })
}

pub(crate) fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

pub(crate) fn capture_headers(headers: &HeaderMap) -> Value {
    let mut map = serde_json::Map::new();
    for name in [
        "cf-connecting-ip",
        "x-forwarded-for",
        "true-client-ip",
        "accept-language",
        "referer",
        // Cloudflare's geo tag. Forwarded explicitly by the Worker (it is not
        // present on the origin request by default), and captured here so the
        // raw value survives even if the cf_ipcountry column is ever dropped.
        "cf-ipcountry",
        "cf-ray",
    ] {
        if let Some(v) = header_str(headers, name) {
            map.insert(name.to_owned(), Value::String(v.to_owned()));
        }
    }
    Value::Object(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefers_cf_connecting_ip() {
        let mut headers = HeaderMap::new();
        headers.insert("cf-connecting-ip", "203.0.113.5".parse().unwrap());
        headers.insert("x-forwarded-for", "198.51.100.1, 10.0.0.1".parse().unwrap());
        assert_eq!(extract_source_ip(&headers), "203.0.113.5");
    }

    #[test]
    fn falls_back_to_first_xff_hop() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "198.51.100.7, 10.0.0.1".parse().unwrap());
        assert_eq!(extract_source_ip(&headers), "198.51.100.7");
    }

    #[test]
    fn uses_true_client_ip_without_xff() {
        let mut headers = HeaderMap::new();
        headers.insert("true-client-ip", "198.51.100.9".parse().unwrap());
        assert_eq!(extract_source_ip(&headers), "198.51.100.9");
    }

    #[test]
    fn defaults_to_zero_when_no_proxy_header() {
        let headers = HeaderMap::new();
        assert_eq!(extract_source_ip(&headers), "0.0.0.0");
    }

    #[test]
    fn crawler_branding_on_a_secret_path_is_impersonation() {
        let mut h = HeaderMap::new();
        h.insert(
            "user-agent",
            "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot"
                .parse()
                .unwrap(),
        );
        assert!(is_impersonating_crawler(&h, "/.env"));
        assert!(is_impersonating_crawler(&h, "/.aws/credentials"));
        assert!(is_impersonating_crawler(&h, "/wp-login.php"));
    }

    #[test]
    fn crawler_branding_on_an_ordinary_path_is_not_flagged() {
        let mut h = HeaderMap::new();
        h.insert(
            "user-agent",
            "Mozilla/5.0 (compatible; Amazonbot/0.1)".parse().unwrap(),
        );
        // A real crawler may legitimately fetch these.
        assert!(!is_impersonating_crawler(&h, "/readme.html"));
        assert!(!is_impersonating_crawler(&h, "/index.php"));
    }

    #[test]
    fn ordinary_user_agents_are_never_impersonators() {
        let mut h = HeaderMap::new();
        h.insert("user-agent", "curl/8.7.1".parse().unwrap());
        assert!(!is_impersonating_crawler(&h, "/.env"));
        assert!(!is_impersonating_crawler(&HeaderMap::new(), "/.env"));
    }

    #[test]
    fn capture_skips_absent_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("accept-language", "en-US,en;q=0.9".parse().unwrap());
        headers.insert("referer", "https://example.com/".parse().unwrap());
        let v = capture_headers(&headers);
        let obj = v.as_object().expect("object");
        assert_eq!(obj.len(), 2);
        assert_eq!(
            obj.get("accept-language").and_then(Value::as_str),
            Some("en-US,en;q=0.9")
        );
        assert!(obj.get("cf-connecting-ip").is_none());
    }
}
