//! Wire-level PHP/WordPress facade.
//!
//! Every trap in this service is only as convincing as the response headers
//! carrying it. Before this module the honeypot answered `/wp-login.php` with
//! `server: Google Frontend`, no `X-Powered-By`, and no WordPress cookies — a
//! bot that reads headers knew the site was not PHP before it ever submitted a
//! credential. These helpers put the expected PHP/WP signalling on a response;
//! `cloudflare-worker.js` strips the Google-Frontend giveaways at the edge.

use axum::http::header::{HeaderName, HeaderValue};
use axum::response::Response;

/// The `Expires` value WordPress sends on admin/login pages. It is a fixed
/// date in the past — 11 Jan 1984 — and is one of the most recognisable
/// fingerprints of a real WP install.
const WP_EXPIRES: &str = "Wed, 11 Jan 1984 05:00:00 GMT";
const WP_CACHE_CONTROL: &str = "no-cache, must-revalidate, max-age=0";
const PHP_VERSION_HEADER: &str = "PHP/8.2.28";

/// Headers a real PHP-served WordPress page carries. Applied to every HTML
/// trap response.
pub fn apply_php_headers(resp: &mut Response) {
    let h = resp.headers_mut();
    for (name, value) in [
        ("x-powered-by", PHP_VERSION_HEADER),
        ("expires", WP_EXPIRES),
        ("cache-control", WP_CACHE_CONTROL),
        ("pragma", "no-cache"),
        ("x-frame-options", "SAMEORIGIN"),
        ("x-content-type-options", "nosniff"),
    ] {
        if let (Ok(n), Ok(v)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            h.insert(n, v);
        }
    }
}

/// The cookie WordPress sets on `wp-login.php` to check the client accepts
/// cookies. Its absence is a cheap tell that the login page is not real.
fn apply_login_cookie(resp: &mut Response) {
    if let Ok(v) = HeaderValue::from_str("wordpress_test_cookie=WP+Cookie+check; path=/") {
        resp.headers_mut().append(axum::http::header::SET_COOKIE, v);
    }
}

/// `Link: <...>; rel="https://api.w.org/"` — WordPress advertises its REST
/// root on every front-end response. Scanners use it to confirm WP and to
/// discover `/wp-json/`, which is itself a trap.
fn apply_rest_link(resp: &mut Response, host: Option<&str>) {
    // No configured hostname → no header. Deriving one from the request's
    // `Host` would publish the origin's own address; see Settings::public_hostname.
    let Some(host) = host else {
        return;
    };
    let value = format!("<https://{host}/wp-json/>; rel=\"https://api.w.org/\"");
    if let Ok(v) = HeaderValue::from_str(&value) {
        resp.headers_mut().insert("link", v);
    }
}

/// Response middleware: dress every HTML trap response as PHP-served
/// WordPress. Applied centrally rather than per-handler so a new trap cannot
/// forget it — the missing headers were a single tell that undermined every
/// trap at once.
pub async fn dress_as_wordpress(
    axum::extract::State(state): axum::extract::State<crate::HoneypotState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let path = req.uri().path().to_owned();
    let mut resp = next.run(req).await;

    // Static assets are cacheable and must keep their own cache headers; the
    // no-cache admin set on a .js file is itself a tell.
    let is_html = resp
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("text/html"));
    if !is_html {
        return resp;
    }

    apply_php_headers(&mut resp);
    apply_rest_link(&mut resp, state.settings.public_hostname.as_deref());
    if path == "/wp-login.php" {
        apply_login_cookie(&mut resp);
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::{Html, IntoResponse};

    #[test]
    fn php_headers_land_on_the_response() {
        let mut resp = Html("<html></html>").into_response();
        apply_php_headers(&mut resp);
        let h = resp.headers();
        assert_eq!(h.get("x-powered-by").unwrap(), "PHP/8.2.28");
        assert_eq!(h.get("expires").unwrap(), WP_EXPIRES);
        assert_eq!(h.get("cache-control").unwrap(), WP_CACHE_CONTROL);
        assert_eq!(h.get("x-frame-options").unwrap(), "SAMEORIGIN");
    }

    #[test]
    fn login_cookie_is_appended_not_replaced() {
        let mut resp = Html("<html></html>").into_response();
        resp.headers_mut().append(
            axum::http::header::SET_COOKIE,
            HeaderValue::from_static("existing=1"),
        );
        apply_login_cookie(&mut resp);
        let cookies: Vec<_> = resp
            .headers()
            .get_all(axum::http::header::SET_COOKIE)
            .iter()
            .collect();
        assert_eq!(cookies.len(), 2, "cookie bomb must survive alongside it");
    }

    #[test]
    fn rest_link_names_the_wp_json_root() {
        let mut resp = Html("<html></html>").into_response();
        apply_rest_link(&mut resp, Some("example.com"));
        let link = resp.headers().get("link").unwrap().to_str().unwrap();
        assert!(link.contains("https://example.com/wp-json/"));
        assert!(link.contains("rel=\"https://api.w.org/\""));
    }

    #[test]
    fn rest_link_is_omitted_without_a_configured_hostname() {
        // Regression: the header was built from the request Host, which behind
        // the edge is the Cloud Run origin — publishing the backend URL and
        // identifying the stack. Omitting it is the safe default.
        let mut resp = Html("<html></html>").into_response();
        apply_rest_link(&mut resp, None);
        assert!(resp.headers().get("link").is_none());
    }
}
