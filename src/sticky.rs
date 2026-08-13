//! Sticky-honeypot state: per-IP attempt counting + deterministic threshold
//! derivation + WP-shaped fake-success response builder.
//!
//! The threshold is derived from a hash of the IP + a compile-time salt, so it's
//! deterministic per IP (same attacker always needs the same number of attempts)
//! but unpredictable to the attacker (they can't detect the pattern). The
//! attempt count lives in a per-instance `Mutex<HashMap>` — same ephemeral
//! caveat as the rate limiter. On multi-instance deploys an attacker might need
//! more attempts than the threshold suggests (different instances count
//! independently), which is fine: the goal is "eventually let them in", not
//! "precisely on attempt N".

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};

use axum::http::header::SET_COOKIE;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

static STICKY_SALT: OnceLock<Box<[u8]>> = OnceLock::new();

fn sticky_salt() -> &'static [u8] {
    STICKY_SALT.get_or_init(|| {
        std::env::var("STICKY_SALT")
            .unwrap_or_else(|_| "rustypot-default".to_string())
            .into_bytes()
            .into_boxed_slice()
    })
}

/// Canary credential — submitting this pair immediately grants the fake success,
/// bypassing the threshold. Catches low-volume scanners that try 3-5 common
/// passwords then move on (the majority of automated bots).
const CANARY_USER: &str = "admin";
const CANARY_PASS: &str = "admin";

/// Range bounds for the per-IP threshold. The user chose 10-100.
const THRESHOLD_MIN: u32 = 10;
const THRESHOLD_MAX: u32 = 100;

/// Fake MD5-style hash for the WP cookie name. WP uses `md5(siteurl)`; the exact
/// value doesn't matter — scanners check for the `wordpress_logged_in_*` pattern.
const WP_COOKIE_HASH: &str = "d41d8cd98f00b204e9800998ecf8427e";

/// Per-instance attempt tracker. Keyed on source IP. The value is the running
/// POST count. When it crosses `threshold_for_ip(ip)`, the bot gets a fake
/// success. After that, ALL subsequent POSTs from that IP also succeed (so the
/// bot doesn't get suspicious if it re-submits).
pub type AttemptTracker = Mutex<HashMap<IpAddr, u32>>;

pub fn new_tracker() -> AttemptTracker {
    Mutex::new(HashMap::new())
}

/// Returns true if the submitted credential matches the canary pair.
/// Case-insensitive on the username; exact match on the password.
pub fn is_canary_credential(user: Option<&str>, pass: Option<&str>) -> bool {
    match (user, pass) {
        (Some(u), Some(p)) => u.eq_ignore_ascii_case(CANARY_USER) && p == CANARY_PASS,
        _ => false,
    }
}

/// Derive the threshold for an IP. Deterministic: same IP → same threshold.
/// Uses `DefaultHasher` (SipHash-1-3) with the IP + salt.
pub fn threshold_for_ip(ip: &IpAddr) -> u32 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    ip.hash(&mut hasher);
    hasher.write(sticky_salt());
    let h = hasher.finish();
    THRESHOLD_MIN + (h % (THRESHOLD_MAX - THRESHOLD_MIN + 1) as u64) as u32
}

/// Increment the attempt count for `ip` and return `true` if the threshold has
/// been reached (or was already passed). Once true, always returns true for
/// that IP — the "login" stays valid.
pub fn check_and_increment(tracker: &AttemptTracker, ip: &IpAddr) -> bool {
    let threshold = threshold_for_ip(ip);
    let mut map = tracker.lock().expect("honeypot tracker poisoned");
    let count = map.entry(*ip).or_insert(0);
    *count += 1;
    *count >= threshold
}

/// Build the fake WP login-success response: 302 redirect to `/wp-admin/` with
/// `Set-Cookie: wordpress_logged_in_<hash>=...`. The cookie value carries a
/// fake auth token that looks like a real WP session cookie to any scanner
/// checking for the `wordpress_logged_in_*` pattern.
pub fn fake_success_response() -> Response {
    let expiry = fake_cookie_expiry();
    let token = fake_auth_token();
    let cookie_val = format!("admin%7C{expiry}%7C{token}");
    let cookie_name = format!("wordpress_logged_in_{WP_COOKIE_HASH}");

    let mut resp = (StatusCode::FOUND, [("Location", "/wp-admin/")]).into_response();
    let headers = resp.headers_mut();
    headers.append(
        SET_COOKIE,
        HeaderValue::from_str(&format!("{cookie_name}={cookie_val}; path=/"))
            .expect("valid cookie"),
    );
    headers.append(
        SET_COOKIE,
        HeaderValue::from_str(&format!(
            "wordpress_sec_{WP_COOKIE_HASH}={cookie_val}; path=/wp-admin"
        ))
        .expect("valid cookie"),
    );
    resp
}

fn fake_cookie_expiry() -> u64 {
    // WP cookies expire in 14 days. Use a rough future timestamp.
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    now + 14 * 24 * 60 * 60
}

fn fake_auth_token() -> String {
    // 32-char hex — looks like a WP auth token. Derived from a UUID for
    // uniqueness without needing the `rand` crate.
    let uuid = uuid::Uuid::new_v4();
    format!("{:032x}", uuid.as_u128())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn threshold_is_in_range() {
        for ip in [
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(137, 184, 79, 235)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ] {
            let t = threshold_for_ip(&ip);
            assert!(
                (THRESHOLD_MIN..=THRESHOLD_MAX).contains(&t),
                "threshold {t} for {ip} not in [{THRESHOLD_MIN}, {THRESHOLD_MAX}]"
            );
        }
    }

    #[test]
    fn threshold_is_deterministic_per_ip() {
        let ip = IpAddr::V4(Ipv4Addr::new(137, 184, 79, 235));
        assert_eq!(threshold_for_ip(&ip), threshold_for_ip(&ip));
    }

    #[test]
    fn different_ips_get_different_thresholds() {
        let ip_a = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let ip_b = IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2));
        let ip_c = IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3));
        let thresholds: Vec<u32> = [ip_a, ip_b, ip_c].iter().map(threshold_for_ip).collect();
        let unique: std::collections::HashSet<u32> = thresholds.iter().copied().collect();
        assert!(
            unique.len() > 1,
            "thresholds should vary across IPs, got {thresholds:?}"
        );
    }

    #[test]
    fn check_and_increment_reaches_threshold_then_stays_true() {
        let tracker = new_tracker();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let threshold = threshold_for_ip(&ip);

        for i in 1..threshold {
            assert!(
                !check_and_increment(&tracker, &ip),
                "attempt {i} should not grant (threshold={threshold})"
            );
        }
        assert!(
            check_and_increment(&tracker, &ip),
            "attempt {threshold} should grant"
        );
        assert!(
            check_and_increment(&tracker, &ip),
            "attempt after threshold should stay granted"
        );
    }

    #[test]
    fn fake_success_response_has_wp_cookies() {
        let resp = fake_success_response();
        let cookies: Vec<&str> = resp
            .headers()
            .get_all(SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        assert!(
            cookies.iter().any(|c| c.contains("wordpress_logged_in_")),
            "missing logged-in cookie: {cookies:?}"
        );
        assert!(
            cookies.iter().any(|c| c.contains("wordpress_sec_")),
            "missing sec cookie: {cookies:?}"
        );
    }

    #[test]
    fn canary_credential_grants_immediately() {
        assert!(is_canary_credential(Some("admin"), Some("admin")));
        assert!(
            is_canary_credential(Some("Admin"), Some("admin")),
            "username should be case-insensitive"
        );
        assert!(is_canary_credential(Some("ADMIN"), Some("admin")));
    }

    #[test]
    fn non_canary_credentials_do_not_grant() {
        assert!(!is_canary_credential(Some("admin"), Some("password")));
        assert!(!is_canary_credential(Some("admin"), Some("admin123")));
        assert!(!is_canary_credential(Some("root"), Some("admin")));
        assert!(!is_canary_credential(None, Some("admin")));
        assert!(!is_canary_credential(Some("admin"), None));
    }
}
