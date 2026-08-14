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
}
