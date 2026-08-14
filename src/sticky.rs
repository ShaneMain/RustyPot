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
use std::sync::Mutex;

use axum::http::header::SET_COOKIE;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

/// Compile-time salt for threshold derivation. Not a secret — just prevents the
/// attacker from computing thresholds if they learn the algorithm.
const STICKY_SALT: &[u8] = b"fk-honeypot-sticky-2026";

const WP_COOKIE_HASH: &str = "d41d8cd98f00b204e9800998ecf8427e";

pub type AttemptTracker = Mutex<HashMap<IpAddr, u32>>;
pub type GrantTracker = Mutex<HashMap<IpAddr, u32>>;

pub fn new_tracker() -> AttemptTracker {
    Mutex::new(HashMap::new())
}

pub fn new_grant_tracker() -> GrantTracker {
    Mutex::new(HashMap::new())
}

pub fn grant_count(tracker: &GrantTracker, ip: &IpAddr) -> u32 {
    tracker
        .lock()
        .expect("grant tracker poisoned")
        .get(ip)
        .copied()
        .unwrap_or(0)
}

pub fn increment_grants(tracker: &GrantTracker, ip: &IpAddr) {
    *tracker
        .lock()
        .expect("grant tracker poisoned")
        .entry(*ip)
        .or_insert(0) += 1;
}

/// Derive the threshold for an IP. Deterministic: same IP → same threshold.
/// Uses `DefaultHasher` (SipHash-1-3) with the IP + salt.
pub fn threshold_for_ip(ip: &IpAddr, min: u32, max: u32) -> u32 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    ip.hash(&mut hasher);
    hasher.write(STICKY_SALT);
    let h = hasher.finish();
    let span = u64::from(max.saturating_sub(min).saturating_add(1));
    min + (h % span) as u32
}

/// Increment the attempt count for `ip` and return `true` if the threshold has
/// been reached. Once at threshold, stays there (returns `true` on every call)
/// until `reset_counter` is called — so the attacker keeps getting checked
/// against the DB until they submit a NEW credential, at which point the
/// handler resets the counter for the next cycle.
pub fn check_and_increment(tracker: &AttemptTracker, ip: &IpAddr, min: u32, max: u32) -> bool {
    let threshold = threshold_for_ip(ip, min, max);
    let mut map = tracker.lock().expect("honeypot tracker poisoned");
    let count = map.entry(*ip).or_insert(0);
    if *count < threshold {
        *count += 1;
    }
    *count >= threshold
}

/// Reset the counter for `ip` to 0. Called by the handler after a successful
/// unique-credential grant, starting the next threshold cycle.
pub fn reset_counter(tracker: &AttemptTracker, ip: &IpAddr) {
    let mut map = tracker.lock().expect("honeypot tracker poisoned");
    if let Some(count) = map.get_mut(ip) {
        *count = 0;
    }
}

/// Generate a per-IP planted credential for the `.env` honeytoken. Deterministic
/// (same IP always gets the same credential) so correlation works across sessions.
/// The caller-supplied prefix makes honeypot-planted credentials identifiable
/// in queries without tying every deployment to the same marker.
pub fn planted_credential(ip: &IpAddr, prefix: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    ip.hash(&mut hasher);
    hasher.write(STICKY_SALT);
    let mut h = hasher.finish();

    let chars = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut result = String::with_capacity(prefix.len() + 12);
    result.push_str(prefix);
    for _ in 0..12 {
        result.push(chars[(h % 62) as usize] as char);
        h = h.rotate_right(5).wrapping_add(0x9E3779B97F4A7C15);
    }
    result
}

/// Build the fake WP login-success response: 302 redirect to `/wp-admin/` with
/// `Set-Cookie: wordpress_logged_in_<hash>=...`. The cookie value carries a
/// fake auth token that looks like a real WP session cookie to any scanner
/// checking for the `wordpress_logged_in_*` pattern.
pub fn fake_success_response(grants: u32, settings: &crate::config::Settings) -> Response {
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
    if grants == 0 && settings.cookie_bomb_enabled() {
        let val = "Z".repeat(settings.cookie_bomb_size);
        for i in 0..settings.cookie_bomb_count {
            headers.append(
                SET_COOKIE,
                HeaderValue::from_str(&format!("_fk_s_{i}={val}; path=/")).expect("valid cookie"),
            );
        }
    }
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
        let (min, max) = (10u32, 100u32);
        for ip in [
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(137, 184, 79, 235)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ] {
            let t = threshold_for_ip(&ip, min, max);
            assert!(
                (min..=max).contains(&t),
                "threshold {t} for {ip} not in [{min}, {max}]"
            );
        }
    }

    #[test]
    fn threshold_is_deterministic_per_ip() {
        let ip = IpAddr::V4(Ipv4Addr::new(137, 184, 79, 235));
        assert_eq!(
            threshold_for_ip(&ip, 10, 100),
            threshold_for_ip(&ip, 10, 100)
        );
    }

    #[test]
    fn different_ips_get_different_thresholds() {
        let ip_a = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let ip_b = IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2));
        let ip_c = IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3));
        let thresholds: Vec<u32> = [ip_a, ip_b, ip_c]
            .iter()
            .map(|ip| threshold_for_ip(ip, 10, 100))
            .collect();
        let unique: std::collections::HashSet<u32> = thresholds.iter().copied().collect();
        assert!(
            unique.len() > 1,
            "thresholds should vary across IPs, got {thresholds:?}"
        );
    }

    #[test]
    fn check_and_increment_pins_at_threshold_until_reset() {
        let tracker = new_tracker();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let threshold = threshold_for_ip(&ip, 10, 100);

        for i in 1..threshold {
            assert!(
                !check_and_increment(&tracker, &ip, 10, 100),
                "attempt {i} should not grant (threshold={threshold})"
            );
        }
        assert!(
            check_and_increment(&tracker, &ip, 10, 100),
            "attempt {threshold} should grant"
        );
        assert!(
            check_and_increment(&tracker, &ip, 10, 100),
            "counter pinned at threshold — should keep returning true"
        );
        reset_counter(&tracker, &ip);
        assert!(
            !check_and_increment(&tracker, &ip, 10, 100),
            "after reset, counter is 0 — first increment should not grant"
        );
    }

    #[test]
    fn fake_success_response_has_wp_cookies() {
        let settings = crate::config::Settings::default();
        let resp = fake_success_response(0, &settings);
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
}
