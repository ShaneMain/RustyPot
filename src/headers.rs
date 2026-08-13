//! Header-derived signal extraction for the honeypot. `extract_source_ip`
//! mirrors the trust chain in `rate_limit::client_ip` (CF-Connecting-IP →
//! first XFF hop → True-Client-IP), but returns the raw string instead of
//! parsing to `IpAddr` — the honeypot logs whatever the proxy sent, including
//! malformed values, for forensic completeness.

use axum::http::HeaderMap;
use serde_json::Value;

pub(super) fn extract_source_ip(headers: &HeaderMap) -> String {
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

pub(super) fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

pub(super) fn capture_headers(headers: &HeaderMap) -> Value {
    let mut map = serde_json::Map::new();
    for name in [
        "cf-connecting-ip",
        "x-forwarded-for",
        "true-client-ip",
        "accept-language",
        "referer",
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
