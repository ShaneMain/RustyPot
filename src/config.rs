use std::env;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrapFamily {
    WordPress,
    Drupal,
    Joomla,
    Django,
    Git,
    EnvHoneytoken,
    CloudKeys,
    Vcs,
    FrameworkDebug,
    ServiceExposure,
    PhpShells,
    DbAdmin,
}

impl TrapFamily {
    pub fn from_str(s: &str) -> Option<Self> {
        let lower = s.trim().to_ascii_lowercase();
        match lower.as_str() {
            "wordpress" | "wp" => Some(TrapFamily::WordPress),
            "drupal" => Some(TrapFamily::Drupal),
            "joomla" => Some(TrapFamily::Joomla),
            "django" => Some(TrapFamily::Django),
            "git" => Some(TrapFamily::Git),
            "env" | "env-honeytoken" => Some(TrapFamily::EnvHoneytoken),
            "cloud-keys" => Some(TrapFamily::CloudKeys),
            "vcs" => Some(TrapFamily::Vcs),
            "framework-debug" => Some(TrapFamily::FrameworkDebug),
            "service-exposure" => Some(TrapFamily::ServiceExposure),
            "php-shells" => Some(TrapFamily::PhpShells),
            "db-admin" => Some(TrapFamily::DbAdmin),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TrapConfig {
    pub enabled: Vec<TrapFamily>,
}

impl Default for TrapConfig {
    fn default() -> Self {
        TrapConfig {
            enabled: vec![
                TrapFamily::WordPress,
                TrapFamily::Drupal,
                TrapFamily::Joomla,
                TrapFamily::Django,
                TrapFamily::Git,
                TrapFamily::EnvHoneytoken,
                TrapFamily::CloudKeys,
                TrapFamily::Vcs,
                TrapFamily::FrameworkDebug,
                TrapFamily::ServiceExposure,
                TrapFamily::PhpShells,
                TrapFamily::DbAdmin,
            ],
        }
    }
}

impl TrapConfig {
    /// Parse from env: `ENABLED_TRAPS=wordpress,git,env-honeytoken`.
    /// Empty/missing env → all enabled. "all" → all enabled.
    /// "none" → empty (only /health responds).
    pub fn from_env() -> Self {
        let raw = env::var("ENABLED_TRAPS").unwrap_or_default();
        Self::parse(&raw)
    }

    pub fn parse(raw: &str) -> Self {
        let raw = raw.trim();
        if raw.is_empty() || raw.eq_ignore_ascii_case("all") {
            return Self::default();
        }
        if raw.eq_ignore_ascii_case("none") {
            return TrapConfig { enabled: vec![] };
        }
        let mut enabled = Vec::new();
        for token in raw.split(',') {
            match TrapFamily::from_str(token) {
                Some(f) => enabled.push(f),
                None => tracing::warn!("ENABLED_TRAPS: unknown family {token:?} — skipping"),
            }
        }
        TrapConfig { enabled }
    }

    pub fn is_enabled(&self, family: TrapFamily) -> bool {
        self.enabled.contains(&family)
    }
}

#[derive(Debug, Clone)]
pub struct Settings {
    pub tarpit_ladder: Vec<u64>,
    /// Delay ladder for recon traps (`.env`, `.git`) — indexed by how many
    /// recon paths this IP has already swept. Deliberately far shorter than
    /// `tarpit_ladder`: recon sweepers hit hundreds of paths, and holding each
    /// one open for 30-240s would pin every Cloud Run instance and starve the
    /// credential traps. Short-but-growing drags a 300-path sweep out from
    /// seconds to tens of minutes without exhausting the instance budget.
    pub recon_tarpit_ladder: Vec<u64>,
    /// Sweep count at which the recon ladder advances one rung.
    pub recon_tarpit_step: u32,
    pub threshold_min: u32,
    pub threshold_max: u32,
    pub rate_limit_per_minute: u32,
    pub honeytoken_prefix: String,
    pub cookie_bomb_count: usize,
    pub cookie_bomb_size: usize,
    /// A real AWS canary token to serve from `.aws/credentials`. When set, the
    /// same pair is served to everyone — a canary only alerts if the key is
    /// genuine, and a genuine key cannot be per-IP. Attribution then comes from
    /// the `honeypot_event` row recording who was served it, matched on time
    /// against the CloudTrail alarm. Unset → a deterministic per-IP fake.
    pub aws_canary_key_id: Option<String>,
    pub aws_canary_secret: Option<String>,
    /// Total bytes the fake `/actuator/heapdump` streams, and how long it takes
    /// to send them. Attackers expect a heapdump to be large and slow, so a
    /// trickle is credible — but every in-flight response pins a Cloud Run
    /// instance, and `--max-instances` is small. Keep the duration well under
    /// the 300 s request timeout and the byte count small enough that egress
    /// stays negligible.
    pub heapdump_bytes: usize,
    pub heapdump_seconds: u64,
    /// How many responses may be deliberately held open at once, across every
    /// trap. Cloud Run gives this service 80 concurrent requests per instance
    /// across at most 3 instances — 240 slots — and a held request occupies one
    /// for its full duration. The default leaves the large majority of that
    /// capacity free for recording new probes.
    pub slow_response_budget: usize,
    /// Public hostname to advertise in WordPress's REST `Link` header.
    ///
    /// MUST NOT be derived from the request's `Host`. Behind the edge Worker
    /// the origin sees the Cloud Run hostname, so echoing `Host` published
    /// `<https://fillerkiller-honeypot-….run.app/wp-json/>` on every response:
    /// it identified the stack as Cloud Run rather than PHP, and handed
    /// attackers the backend URL to bypass the edge entirely. Unset → the
    /// header is omitted, which is harmless; leaking the origin is not.
    pub public_hostname: Option<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            tarpit_ladder: vec![30, 60, 120, 240],
            recon_tarpit_ladder: vec![0, 2, 5, 10, 20],
            recon_tarpit_step: 10,
            threshold_min: 10,
            threshold_max: 100,
            rate_limit_per_minute: 240,
            honeytoken_prefix: "fk".to_owned(),
            cookie_bomb_count: 20,
            cookie_bomb_size: 400,
            aws_canary_key_id: None,
            aws_canary_secret: None,
            heapdump_bytes: 2 * 1024 * 1024,
            heapdump_seconds: 60,
            slow_response_budget: 64,
            public_hostname: None,
        }
    }
}

const MAX_TARPIT_SECONDS: u64 = 3600;

impl Settings {
    pub fn from_env() -> Self {
        let d = Settings::default();
        let mut s = d.clone();

        if let Ok(raw) = env::var("TARPIT_ESCALATION") {
            match parse_ladder(&raw) {
                Ok(ladder) => s.tarpit_ladder = ladder,
                Err(e) => tracing::warn!("TARPIT_ESCALATION: {e} — using default"),
            }
        }
        if let Ok(raw) = env::var("RECON_TARPIT_ESCALATION") {
            match parse_ladder(&raw) {
                Ok(ladder) => s.recon_tarpit_ladder = ladder,
                Err(e) => tracing::warn!("RECON_TARPIT_ESCALATION: {e} — using default"),
            }
        }
        s.recon_tarpit_step = env_num("RECON_TARPIT_STEP", d.recon_tarpit_step, 1, 100_000);
        s.threshold_min = env_num("THRESHOLD_MIN", d.threshold_min, 1, 100_000);
        s.threshold_max = env_num("THRESHOLD_MAX", d.threshold_max, 1, 100_000);
        if s.threshold_min > s.threshold_max {
            tracing::warn!(
                "THRESHOLD_MIN ({}) > THRESHOLD_MAX ({}) — swapping",
                s.threshold_min,
                s.threshold_max
            );
            std::mem::swap(&mut s.threshold_min, &mut s.threshold_max);
        }
        s.rate_limit_per_minute =
            env_num("RATE_LIMIT_PER_MINUTE", d.rate_limit_per_minute, 1, 100_000);
        if let Ok(raw) = env::var("HONEYTOKEN_PREFIX") {
            let raw = raw.trim();
            if !raw.is_empty() && raw.len() <= 8 && raw.chars().all(|c| c.is_ascii_alphanumeric()) {
                s.honeytoken_prefix = raw.to_owned();
            } else {
                tracing::warn!("HONEYTOKEN_PREFIX must be 1-8 alphanumeric chars — using default");
            }
        }
        s.cookie_bomb_count = env_num(
            "COOKIE_BOMB_COUNT",
            u32::try_from(d.cookie_bomb_count).unwrap_or(20),
            0,
            100,
        ) as usize;
        // Both halves or neither: a key id without its secret would be served
        // as a credential that cannot possibly alert.
        match (
            env::var("AWS_CANARY_ACCESS_KEY_ID").ok().filter(|v| !v.trim().is_empty()),
            env::var("AWS_CANARY_SECRET_ACCESS_KEY").ok().filter(|v| !v.trim().is_empty()),
        ) {
            (Some(k), Some(v)) => {
                s.aws_canary_key_id = Some(k.trim().to_owned());
                s.aws_canary_secret = Some(v.trim().to_owned());
            }
            (None, None) => {}
            _ => tracing::warn!(
                "AWS_CANARY_ACCESS_KEY_ID and AWS_CANARY_SECRET_ACCESS_KEY must both be set — serving a per-IP fake instead"
            ),
        }
        // Ceiling is 16 MiB, not the container's 256 MiB: each concurrent
        // stream holds one chunk buffer, so the worst case is
        // (bytes / chunks) * slow_response_budget resident at once.
        s.heapdump_bytes = env_num(
            "HEAPDUMP_BYTES",
            u32::try_from(d.heapdump_bytes).unwrap_or(2 * 1024 * 1024),
            0,
            16 * 1024 * 1024,
        ) as usize;
        s.heapdump_seconds = u64::from(env_num(
            "HEAPDUMP_SECONDS",
            u32::try_from(d.heapdump_seconds).unwrap_or(60),
            0,
            240,
        ));
        s.public_hostname = env::var("PUBLIC_HOSTNAME")
            .ok()
            .map(|v| v.trim().to_owned())
            .filter(|v| {
                // A hostname only: no scheme, path, or header-splitting bytes.
                !v.is_empty()
                    && v.len() <= 253
                    && v.chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
            });
        s.slow_response_budget = env_num(
            "SLOW_RESPONSE_BUDGET",
            u32::try_from(d.slow_response_budget).unwrap_or(64),
            0,
            240,
        ) as usize;
        s.cookie_bomb_size = env_num(
            "COOKIE_BOMB_SIZE",
            u32::try_from(d.cookie_bomb_size).unwrap_or(400),
            0,
            4000,
        ) as usize;
        s
    }

    /// Tarpit delay after `grants` fake-success grants. Indexes the ladder;
    /// values beyond the last entry repeat the last. 0 grants → first entry.
    pub fn tarpit_delay(&self, grants: u32) -> u64 {
        let idx = grants as usize;
        if idx >= self.tarpit_ladder.len() {
            *self.tarpit_ladder.last().unwrap_or(&0)
        } else {
            self.tarpit_ladder[idx]
        }
    }

    /// Recon-trap delay for an IP that has now hit `sweep` recon paths. Rung
    /// advances every `recon_tarpit_step` paths; values past the last entry
    /// repeat it. A one-off probe sits on rung 0 (no delay) so casual scanners
    /// aren't held; a sweeper climbs.
    pub fn recon_tarpit_delay(&self, sweep: u32) -> u64 {
        if self.recon_tarpit_ladder.is_empty() {
            return 0;
        }
        let idx = (sweep / self.recon_tarpit_step) as usize;
        let idx = idx.min(self.recon_tarpit_ladder.len() - 1);
        self.recon_tarpit_ladder[idx]
    }

    pub fn cookie_bomb_enabled(&self) -> bool {
        self.cookie_bomb_count > 0 && self.cookie_bomb_size > 0
    }
}

fn parse_ladder(raw: &str) -> Result<Vec<u64>, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("empty value".to_owned());
    }
    let mut ladder = Vec::new();
    for token in raw.split(',') {
        let v: u64 = token
            .trim()
            .parse()
            .map_err(|_| format!("invalid seconds {token:?}"))?;
        if v > MAX_TARPIT_SECONDS {
            return Err(format!("value {v} exceeds {MAX_TARPIT_SECONDS}s cap"));
        }
        ladder.push(v);
    }
    Ok(ladder)
}

fn env_num(name: &str, default: u32, min: u32, max: u32) -> u32 {
    match env::var(name) {
        Ok(raw) => match raw.trim().parse::<u32>() {
            Ok(v) if v >= min && v <= max => v,
            Ok(v) => {
                tracing::warn!("{name}={v} outside [{min}, {max}] — using default {default}");
                default
            }
            Err(_) => {
                tracing::warn!("{name}={raw:?} not a number — using default {default}");
                default
            }
        },
        Err(_) => default,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_enables_all() {
        let c = TrapConfig::parse("");
        assert!(c.is_enabled(TrapFamily::WordPress));
        assert!(c.is_enabled(TrapFamily::DbAdmin));
        assert_eq!(c.enabled.len(), 12);
    }

    #[test]
    fn all_keyword_enables_all() {
        let c = TrapConfig::parse("all");
        assert_eq!(c.enabled.len(), 12);
    }

    #[test]
    fn none_keyword_disables_everything() {
        let c = TrapConfig::parse("none");
        assert!(c.enabled.is_empty());
        assert!(!c.is_enabled(TrapFamily::WordPress));
    }

    #[test]
    fn selective_enable() {
        let c = TrapConfig::parse("wordpress,git,env-honeytoken");
        assert!(c.is_enabled(TrapFamily::WordPress));
        assert!(c.is_enabled(TrapFamily::Git));
        assert!(c.is_enabled(TrapFamily::EnvHoneytoken));
        assert!(!c.is_enabled(TrapFamily::Drupal));
        assert!(!c.is_enabled(TrapFamily::DbAdmin));
    }

    #[test]
    fn unknown_families_are_skipped() {
        let c = TrapConfig::parse("wordpress,bogus,git");
        assert_eq!(c.enabled.len(), 2);
        assert!(c.is_enabled(TrapFamily::WordPress));
        assert!(c.is_enabled(TrapFamily::Git));
    }

    #[test]
    fn aliases_work() {
        assert_eq!(TrapFamily::from_str("wp"), Some(TrapFamily::WordPress));
        assert_eq!(TrapFamily::from_str("WP"), Some(TrapFamily::WordPress));
        assert_eq!(TrapFamily::from_str("env"), Some(TrapFamily::EnvHoneytoken));
        assert_eq!(
            TrapFamily::from_str(" WordPress "),
            Some(TrapFamily::WordPress)
        );
    }

    #[test]
    fn preset_for_wordpress_site() {
        let c = TrapConfig::parse("git,env-honeytoken,cloud-keys,vcs,php-shells,db-admin");
        assert!(!c.is_enabled(TrapFamily::WordPress));
        assert!(!c.is_enabled(TrapFamily::Drupal));
        assert!(!c.is_enabled(TrapFamily::Joomla));
        assert!(!c.is_enabled(TrapFamily::Django));
        assert!(!c.is_enabled(TrapFamily::FrameworkDebug));
        assert!(!c.is_enabled(TrapFamily::ServiceExposure));
        assert!(c.is_enabled(TrapFamily::Git));
        assert!(c.is_enabled(TrapFamily::EnvHoneytoken));
    }

    #[test]
    fn default_tarpit_ladder() {
        let s = Settings::default();
        assert_eq!(s.tarpit_delay(0), 30);
        assert_eq!(s.tarpit_delay(1), 60);
        assert_eq!(s.tarpit_delay(2), 120);
        assert_eq!(s.tarpit_delay(3), 240);
        assert_eq!(s.tarpit_delay(99), 240);
    }

    #[test]
    fn custom_ladder_parse() {
        assert_eq!(parse_ladder("5").unwrap(), vec![5]);
        assert_eq!(parse_ladder("5,10,20").unwrap(), vec![5, 10, 20]);
        assert_eq!(parse_ladder(" 5 , 10 ").unwrap(), vec![5, 10]);
        assert!(parse_ladder("").is_err());
        assert!(parse_ladder("5,abc").is_err());
        assert!(parse_ladder("9999").is_err());
    }

    #[test]
    fn single_entry_ladder_repeats() {
        let s = Settings {
            tarpit_ladder: vec![45],
            ..Settings::default()
        };
        assert_eq!(s.tarpit_delay(0), 45);
        assert_eq!(s.tarpit_delay(7), 45);
    }

    #[test]
    fn cookie_bomb_toggle() {
        let mut s = Settings::default();
        assert!(s.cookie_bomb_enabled());
        s.cookie_bomb_count = 0;
        assert!(!s.cookie_bomb_enabled());
    }
    #[test]
    fn recon_ladder_climbs_with_sweep_depth() {
        let s = Settings::default();
        // Rung advances every recon_tarpit_step (10) paths.
        assert_eq!(s.recon_tarpit_delay(0), 0, "a single probe is not delayed");
        assert_eq!(s.recon_tarpit_delay(9), 0);
        assert_eq!(s.recon_tarpit_delay(10), 2);
        assert_eq!(s.recon_tarpit_delay(25), 5);
        assert_eq!(s.recon_tarpit_delay(30), 10);
        assert_eq!(s.recon_tarpit_delay(40), 20);
        // Past the last rung the delay holds, it does not wrap or grow.
        assert_eq!(s.recon_tarpit_delay(10_000), 20);
    }

    #[test]
    fn recon_ladder_stays_under_cloud_run_timeout() {
        // Cloud Run caps a request at 300s; a rung above that would surface as
        // a 504 and tell the attacker the delay is artificial.
        let s = Settings::default();
        assert!(s.recon_tarpit_ladder.iter().all(|&d| d < 300));
    }

    #[test]
    fn empty_recon_ladder_disables_the_delay() {
        let s = Settings {
            recon_tarpit_ladder: vec![],
            ..Settings::default()
        };
        assert_eq!(s.recon_tarpit_delay(500), 0);
    }
}
