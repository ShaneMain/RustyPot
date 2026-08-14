//! Body parsers for the honeypot — pure functions, no I/O. Extracted to keep
//! the handler module under the LOC ceiling. None of these allocate except
//! where they have to return an owned `String` (percent-decode output and
//! credential values that outlive the borrowed body).

use axum::body::Bytes;

/// Lossy UTF-8 conversion of a request body. Most scanner payloads are ASCII
/// (form-urlencoded / XML); the lossy path only kicks in for hostile bytes,
/// where preserving exact code points buys nothing for credential capture.
pub(crate) fn body_to_string(body: &Bytes) -> String {
    String::from_utf8_lossy(body).into_owned()
}

/// Truncate at a UTF-8 char boundary at or before `max_bytes`. Plain
/// `&s[..max_bytes]` would panic on a multi-byte boundary; the honeypot's
/// 4 KiB cut can land mid-character for non-ASCII payloads.
pub(crate) fn truncate_to_boundary(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Parse `log` and `pwd` from a form-urlencoded body. Manual implementation
/// (no `form_urlencoded` in the dep tree) — `+` and `%XX` are decoded.
pub(crate) fn parse_form_creds(body: &str) -> (Option<String>, Option<String>) {
    (
        extract_form_field(body, "log"),
        extract_form_field(body, "pwd"),
    )
}

pub(crate) fn extract_form_field(body: &str, field: &str) -> Option<String> {
    for pair in body.split('&') {
        let mut parts = pair.splitn(2, '=');
        if parts.next().unwrap_or("") == field {
            return Some(percent_decode(parts.next().unwrap_or("")));
        }
    }
    None
}

/// Extract (user, pass) from an XML-RPC body. Across all common attack
/// patterns — direct `wp.getUsersBlogs`, `system.multicall` wrapping it, and
/// `wp.getOptions` — the credentials are the LAST two `<string>` values
/// (methodNames come first when present). With fewer than two `<string>`
/// tags there is nothing credential-shaped to log.
pub(crate) fn parse_xmlrpc_creds(body: &str) -> (Option<String>, Option<String>) {
    let mut strings: Vec<&str> = Vec::new();
    let mut rest = body;
    while let Some(start) = rest.find("<string>") {
        rest = &rest[start + "<string>".len()..];
        let Some(end) = rest.find("</string>") else {
            break;
        };
        strings.push(&rest[..end]);
        rest = &rest[end + "</string>".len()..];
    }
    if strings.len() < 2 {
        return (None, None);
    }
    let n = strings.len();
    (
        Some(strings[n - 2].to_owned()),
        Some(strings[n - 1].to_owned()),
    )
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if bytes.get(i + 1).is_some() && bytes.get(i + 2).is_some() => {
                let hi = hex(bytes[i + 1]);
                let lo = hex(bytes[i + 2]);
                match (hi, lo) {
                    (Some(h), Some(l)) => {
                        out.push(h * 16 + l);
                        i += 3;
                    }
                    _ => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_form_urlencoded_credentials() {
        let body =
            "log=admin&pwd=admin%40123&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1";
        let (user, pass) = parse_form_creds(body);
        assert_eq!(user.as_deref(), Some("admin"));
        assert_eq!(pass.as_deref(), Some("admin@123"));
        assert_eq!(
            extract_form_field(body, "wp-submit").as_deref(),
            Some("Log In")
        );
    }

    #[test]
    fn extracts_localized_submit_text() {
        let body = "log=admin&pwd=112233&wp-submit=%E7%99%BB%E5%BD%95&testcookie=1";
        assert_eq!(
            extract_form_field(body, "wp-submit").as_deref(),
            Some("登录")
        );
    }

    #[test]
    fn parses_plus_as_space_in_form_value() {
        // `+` must decode to a space, not survive literally.
        let body = "log=user&pwd=pass+word";
        let (_, pass) = parse_form_creds(body);
        assert_eq!(pass.as_deref(), Some("pass word"));
    }

    #[test]
    fn parses_xmlrpc_credentials_simple() {
        // Direct wp.getUsersBlogs: methodName is NOT a <string>; the two
        // <string> tags are user/pass in order.
        let body = r#"<?xml version="1.0"?>
<methodCall>
<methodName>wp.getUsersBlogs</methodName>
<params>
<param><value><string>admin</string></value></param>
<param><value><string>password123</string></value></param>
</params>
</methodCall>"#;
        let (user, pass) = parse_xmlrpc_creds(body);
        assert_eq!(user.as_deref(), Some("admin"));
        assert_eq!(pass.as_deref(), Some("password123"));
    }

    #[test]
    fn parses_xmlrpc_credentials_in_multicall() {
        // system.multicall wraps the inner call in an array; methodName
        // appears as a <string> first. The LAST two <string> values are still
        // the credentials.
        let body = r#"<?xml version="1.0"?>
<methodCall>
<methodName>system.multicall</methodName>
<params><param><value><array><data>
<value><struct>
<member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
<member><name>params</name><value><array><data>
<value><string>admin</string></value>
<value><string>password123</string></value>
</data></array></value></member>
</struct></value>
</data></array></value></param></params>
</methodCall>"#;
        let (user, pass) = parse_xmlrpc_creds(body);
        assert_eq!(user.as_deref(), Some("admin"));
        assert_eq!(pass.as_deref(), Some("password123"));
    }

    #[test]
    fn xmlrpc_without_two_strings_returns_none() {
        let body = "<methodCall><methodName>system.listMethods</methodName></methodCall>";
        let (user, pass) = parse_xmlrpc_creds(body);
        assert_eq!(user, None);
        assert_eq!(pass, None);
    }

    #[test]
    fn truncates_post_body_to_4kib_at_char_boundary() {
        // 10 KiB of ASCII → exactly 4 KiB stored.
        let big = "a".repeat(10 * 1024);
        let truncated = truncate_to_boundary(&big, crate::handlers::MAX_POST_BODY_BYTES);
        assert_eq!(truncated.len(), crate::handlers::MAX_POST_BODY_BYTES);

        // Non-ASCII: cut walks back to the prior char boundary so the slice
        // stays valid UTF-8. 2049 é (2 B each) + 10 ASCII bytes; the 4096-B
        // cut lands mid-character on the 2048th é, so we walk back 1 byte.
        let mut s = "é".repeat(2049);
        s.push_str(&"a".repeat(10));
        let t = truncate_to_boundary(&s, crate::handlers::MAX_POST_BODY_BYTES);
        assert!(t.len() <= crate::handlers::MAX_POST_BODY_BYTES);
        assert!(
            t.len().is_multiple_of(2),
            "walked back to a 2-byte é boundary"
        );
    }
}
