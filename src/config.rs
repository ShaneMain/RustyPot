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
    pub threshold_min: u32,
    pub threshold_max: u32,
    pub rate_limit_per_minute: u32,
    pub honeytoken_prefix: String,
    pub cookie_bomb_count: usize,
    pub cookie_bomb_size: usize,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            tarpit_ladder: vec![30, 60, 120, 240],
            threshold_min: 10,
            threshold_max: 100,
            rate_limit_per_minute: 240,
            honeytoken_prefix: "fk".to_owned(),
            cookie_bomb_count: 20,
            cookie_bomb_size: 400,
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
}
