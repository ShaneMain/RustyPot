//! Secret-bearing file honeytokens beyond `.env`.
//!
//! Secrets harvesting is the most common objective observed against this
//! service — roughly half of externally-originated traffic — and these paths
//! were the part of it that answered 404. Every file here is one an attacker
//! reads specifically to extract a credential, so every one of them is a
//! honeytoken vector on the same model as the `.env` trap: serve a plausible
//! file, plant a per-IP credential in it, record the plant, and correlate if
//! the credential is ever presented back to us.
//!
//! `.aws/credentials` is the highest-value member. A *real* AWS canary token
//! (a permissionless IAM user with a CloudTrail alarm) reports the attacker's
//! IP at the moment they USE the key — which is the only signal here that
//! survives their infrastructure rotation. Set `AWS_CANARY_ACCESS_KEY_ID` and
//! `AWS_CANARY_SECRET_ACCESS_KEY` to serve one. A real token is necessarily a
//! single fixed credential, so per-IP attribution comes from the
//! `honeypot_event` row that recorded serving it, matched on time. With no
//! canary configured the file carries a deterministic per-IP fake instead.

use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::sink;
use crate::sticky::planted_credential;
use crate::{Error, HoneypotState};
use std::net::IpAddr;

/// Which secret file a path maps to. Matched on suffix so subdirectory sweeps
/// (`/backend/.git-credentials`, `/app/.aws/credentials`) land here too.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretFile {
    AwsCredentials,
    AwsConfig,
    GitCredentials,
    GitConfig,
    GitlabCi,
    GithubWorkflow,
    NpmRc,
    DockerConfig,
}

pub fn classify(path: &str) -> Option<SecretFile> {
    let p = path.to_ascii_lowercase();
    // Ordered longest-first so `.aws/credentials` cannot be shadowed by a
    // shorter suffix.
    for (suffix, kind) in [
        ("/.aws/credentials", SecretFile::AwsCredentials),
        ("/.aws/config", SecretFile::AwsConfig),
        ("/.git-credentials", SecretFile::GitCredentials),
        ("/.gitconfig", SecretFile::GitConfig),
        ("/.gitlab-ci.yml", SecretFile::GitlabCi),
        ("/.npmrc", SecretFile::NpmRc),
        ("/.docker/config.json", SecretFile::DockerConfig),
    ] {
        if p.ends_with(suffix) {
            return Some(kind);
        }
    }
    if p.starts_with("/.github/workflows/") && (p.ends_with(".yml") || p.ends_with(".yaml")) {
        return Some(SecretFile::GithubWorkflow);
    }
    None
}

impl SecretFile {
    /// The account name recorded alongside the planted credential. Distinct
    /// per file so a credential presented back to us names the file it leaked
    /// from without a join.
    fn principal(self) -> &'static str {
        match self {
            SecretFile::AwsCredentials => "AKIA_DEPLOY",
            SecretFile::AwsConfig => "aws_profile_default",
            SecretFile::GitCredentials => "git_deploy",
            SecretFile::GitConfig => "git_user",
            SecretFile::GitlabCi => "gitlab_ci_runner",
            SecretFile::GithubWorkflow => "gha_deploy",
            SecretFile::NpmRc => "npm_publish",
            SecretFile::DockerConfig => "docker_registry",
        }
    }

    fn content_type(self) -> &'static str {
        match self {
            SecretFile::DockerConfig => "application/json; charset=utf-8",
            _ => "text/plain; charset=utf-8",
        }
    }
}

/// A deterministic, AWS-shaped access key id for this IP. Real key ids are
/// `AKIA` + 16 uppercase base32-ish characters; a shape mismatch is the first
/// thing a harvesting kit validates.
fn fake_access_key_id(ip: &IpAddr) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    format!(
        "AKIA{}",
        crate::sticky::derived_chars(ip, "/.aws/credentials#akid", ALPHABET, 16)
    )
}

fn render(
    kind: SecretFile,
    ip: &IpAddr,
    secret: &str,
    settings: &crate::config::Settings,
) -> String {
    match kind {
        SecretFile::AwsCredentials => {
            let (akid, sk) = match (&settings.aws_canary_key_id, &settings.aws_canary_secret) {
                (Some(k), Some(s)) => (k.clone(), s.clone()),
                _ => (fake_access_key_id(ip), format!("{secret}+wJalrXUtnFEMI")),
            };
            format!(
                "[default]\n\
                 aws_access_key_id = {akid}\n\
                 aws_secret_access_key = {sk}\n\
                 region = us-east-1\n\n\
                 [production]\n\
                 aws_access_key_id = {akid}\n\
                 aws_secret_access_key = {sk}\n\
                 region = us-east-1\n"
            )
        }
        SecretFile::AwsConfig => format!(
            "[default]\nregion = us-east-1\noutput = json\n\n\
             [profile production]\nregion = us-east-1\noutput = json\n\
             role_arn = arn:aws:iam::481626354019:role/deploy-{secret}\n\
             source_profile = default\n"
        ),
        SecretFile::GitCredentials => format!(
            "https://deploy-bot:{secret}@github.com\n\
             https://ci-runner:{secret}@gitlab.com\n"
        ),
        SecretFile::GitConfig => format!(
            "[user]\n\tname = Deploy Bot\n\temail = deploy@fillerkiller.app\n\
             [credential]\n\thelper = store\n\
             [http \"https://github.com\"]\n\textraheader = Authorization: Basic {secret}\n"
        ),
        // Indentation is embedded after each \n rather than at the start of a
        // continued line: Rust's line-continuation strips leading whitespace.
        SecretFile::GitlabCi => format!(
            "stages:\n  - build\n  - deploy\n\nvariables:\n  REGISTRY: registry.gitlab.com/fillerkiller/app\n\ndeploy:\n  stage: deploy\n  script:\n    - docker login -u gitlab-ci-token -p {secret} $REGISTRY\n    - ./deploy.sh\n  only:\n    - main\n"
        ),
        SecretFile::GithubWorkflow => format!(
            "name: Deploy\non:\n  push:\n    branches: [main]\n\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - name: Deploy\n        env:\n          DEPLOY_TOKEN: {secret}\n          AWS_SECRET_ACCESS_KEY: {secret}\n        run: ./deploy.sh\n"
        ),
        SecretFile::NpmRc => format!(
            "registry=https://registry.npmjs.org/\n\
             //registry.npmjs.org/:_authToken={secret}\n"
        ),
        SecretFile::DockerConfig => {
            let blob = format!("deploy:{secret}");
            format!(
                "{{\n  \"auths\": {{\n    \"registry.hub.docker.com\": {{\n      \"auth\": \"{}\"\n    }}\n  }}\n}}\n",
                base64_like(&blob)
            )
        }
    }
}

/// Docker stores registry auth as base64 of `user:password`. Implemented here
/// rather than pulling a dependency for one string.
fn base64_like(input: &str) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(TABLE[((n >> (18 - 6 * i)) & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

pub async fn secret_honeytrap(
    State(state): State<HoneypotState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    method: Method,
) -> Result<Response, Error> {
    let path = uri.path();
    let Some(kind) = classify(path) else {
        return crate::handlers::config_probe(State(state), OriginalUri(uri), headers, method)
            .await;
    };
    let ip_str = crate::headers::extract_source_ip(&headers);
    let ip: IpAddr = ip_str.parse().unwrap_or(IpAddr::from([0, 0, 0, 0]));

    let prefix =
        crate::sticky::honeytoken_prefix(&state.settings.honeytoken_prefix, &headers, path);
    let secret = planted_credential(&ip, path, &prefix);
    let body = render(kind, &ip, &secret, &state.settings);

    let _ = sink::record_granted_credential(
        &state.pool,
        kind.principal(),
        &secret,
        &ip_str,
        sink::ORIGIN_SECRET,
    )
    .await;

    // Recon ladder: these are swept alongside .env, so the sweep depth is
    // shared and the escalation compounds across both families.
    let sweep = crate::sticky::record_recon_hit(&state.recon_tracker, &ip);
    let desired_secs = state.settings.recon_tarpit_delay(sweep);
    let permit = crate::tarpit::try_reserve(&state.slow_budget);
    let delay_secs = crate::tarpit::effective_delay(desired_secs, &permit);

    sink::log_planted_event(
        &state,
        &headers,
        &method,
        path,
        uri.query(),
        Some(kind.principal()),
        Some(&secret),
        200,
        u32::try_from(delay_secs * 1000).unwrap_or(0),
    )
    .await?;

    if delay_secs > 0 {
        tokio::time::sleep(std::time::Duration::from_secs(delay_secs)).await;
    }
    drop(permit);

    Ok((
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, kind.content_type())],
        body,
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_the_observed_probe_paths() {
        assert_eq!(
            classify("/.aws/credentials"),
            Some(SecretFile::AwsCredentials)
        );
        assert_eq!(classify("/.aws/config"), Some(SecretFile::AwsConfig));
        assert_eq!(
            classify("/.git-credentials"),
            Some(SecretFile::GitCredentials)
        );
        assert_eq!(classify("/.gitconfig"), Some(SecretFile::GitConfig));
        assert_eq!(classify("/.gitlab-ci.yml"), Some(SecretFile::GitlabCi));
        assert_eq!(
            classify("/.github/workflows/deploy.yml"),
            Some(SecretFile::GithubWorkflow)
        );
    }

    #[test]
    fn matches_subdirectory_sweeps() {
        assert_eq!(
            classify("/backend/.aws/credentials"),
            Some(SecretFile::AwsCredentials)
        );
        assert_eq!(
            classify("/app/.git-credentials"),
            Some(SecretFile::GitCredentials)
        );
    }

    #[test]
    fn ignores_unrelated_paths() {
        assert_eq!(classify("/wp-login.php"), None);
        assert_eq!(classify("/.env"), None, ".env has its own trap");
        assert_eq!(classify("/.github/README.md"), None);
    }

    #[test]
    fn fake_access_key_has_aws_shape() {
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let k = fake_access_key_id(&ip);
        assert_eq!(k.len(), 20, "AKIA + 16");
        assert!(k.starts_with("AKIA"));
        assert!(k
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()));
        assert_eq!(k, fake_access_key_id(&ip), "deterministic per IP");
        // Regression: the generator once took 12 derived chars and padded the
        // rest with 'A', so every key on every host ended in the same tail.
        let other = fake_access_key_id(&"198.51.100.9".parse().unwrap());
        assert_ne!(k[16..], other[16..], "key tails must differ across IPs");
        assert!(!k.ends_with("AAAA"), "no constant padding tail");
    }

    #[test]
    fn configured_canary_replaces_the_fake_key() {
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let settings = crate::config::Settings {
            aws_canary_key_id: Some("AKIAREALCANARY000001".to_owned()),
            aws_canary_secret: Some("realsecret".to_owned()),
            ..crate::config::Settings::default()
        };
        let out = render(SecretFile::AwsCredentials, &ip, "planted", &settings);
        assert!(out.contains("AKIAREALCANARY000001"));
        assert!(out.contains("realsecret"));
        assert!(!out.contains(&fake_access_key_id(&ip)));
    }

    #[test]
    fn planted_secret_appears_in_every_rendered_file() {
        let ip: IpAddr = "198.51.100.4".parse().unwrap();
        let s = crate::config::Settings::default();
        for kind in [
            SecretFile::AwsConfig,
            SecretFile::GitCredentials,
            SecretFile::GitConfig,
            SecretFile::GitlabCi,
            SecretFile::GithubWorkflow,
            SecretFile::NpmRc,
        ] {
            assert!(
                render(kind, &ip, "fkPLANTED123", &s).contains("fkPLANTED123"),
                "{kind:?} must carry the honeytoken"
            );
        }
    }

    #[test]
    fn docker_config_encodes_the_secret() {
        let ip: IpAddr = "198.51.100.4".parse().unwrap();
        let s = crate::config::Settings::default();
        let out = render(SecretFile::DockerConfig, &ip, "fkPLANTED123", &s);
        assert!(out.contains("\"auths\""));
        assert!(out.contains(&base64_like("deploy:fkPLANTED123")));
    }

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(base64_like("man"), "bWFu");
        assert_eq!(base64_like("ma"), "bWE=");
        assert_eq!(base64_like("m"), "bQ==");
    }
}
