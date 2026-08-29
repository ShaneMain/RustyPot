use std::net::IpAddr;
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::Router;
use governor::{clock::DefaultClock, state::keyed::DefaultKeyedStateStore, Quota, RateLimiter};
use std::num::NonZeroU32;

mod actuator;
mod ajax;
mod assets;
mod canary;
mod cms;
mod config;
mod facade;
mod git;
mod handlers;
mod headers;
mod parsers;
mod php;
mod restapi;
mod secrets;
mod sink;
mod sticky;
mod tarpit;
mod templates;

use config::{Settings, TrapConfig, TrapFamily};

pub type IpRateLimiter = RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>;

#[derive(Clone)]
pub struct HoneypotState {
    pub pool: sqlx::PgPool,
    pub rate_limiter: Arc<IpRateLimiter>,
    pub honeypot_tracker: Arc<sticky::AttemptTracker>,
    pub grant_tracker: Arc<sticky::GrantTracker>,
    pub recon_tracker: Arc<sticky::ReconTracker>,
    pub canary_posts: Arc<canary::CanaryPosts>,
    pub slow_budget: tarpit::Budget,
    pub settings: Arc<Settings>,
}

pub enum Error {
    Db(sqlx::Error),
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        match self {
            Error::Db(e) => {
                tracing::error!("honeypot DB error: {e}");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
            }
        }
    }
}

impl From<sqlx::Error> for Error {
    fn from(e: sqlx::Error) -> Self {
        Error::Db(e)
    }
}

/// Abuse valve, not a scanner filter. Two rules matter here:
///
/// 1. **Always record.** The original version short-circuited before the
///    handlers, so a burst sweep — the single most interesting thing a scanner
///    does — produced no rows at all and the dashboards under-reported it.
/// 2. **Stay in character.** A `429` whose body is `rate limited` is not
///    something WordPress can emit; it fingerprints the honeypot in one
///    request. An overloaded WordPress serves the DB-connection error page.
async fn limit_honeypot(State(state): State<HoneypotState>, req: Request, next: Next) -> Response {
    let ip = client_ip(req.headers());
    if state.rate_limiter.check_key(&ip).is_ok() {
        return next.run(req).await;
    }
    let headers = req.headers().clone();
    let method = req.method().clone();
    let uri = req.uri().clone();
    if let Err(e) = sink::log_event(
        &state,
        &headers,
        &method,
        uri.path(),
        uri.query(),
        None,
        None,
        None,
        503,
        0,
    )
    .await
    {
        let Error::Db(e) = e;
        tracing::error!("failed to record over-quota probe: {e}");
    }
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Html(templates::WP_DB_ERROR_HTML),
    )
        .into_response()
}

fn client_ip(headers: &axum::http::HeaderMap) -> IpAddr {
    headers
        .get("cf-connecting-ip")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse().ok())
        .or_else(|| {
            headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.split(',').next())
                .and_then(|s| s.trim().parse().ok())
        })
        .unwrap_or(IpAddr::from([0, 0, 0, 0]))
}

async fn health() -> StatusCode {
    StatusCode::OK
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("failed to connect to Postgres");

    let trap_config = TrapConfig::from_env();
    tracing::info!("enabled trap families: {:?}", trap_config.enabled);
    let settings = Arc::new(Settings::from_env());

    let quota = Quota::per_minute(
        NonZeroU32::new(settings.rate_limit_per_minute).expect("rate limit validated >= 1"),
    );
    let rate_limiter = Arc::new(RateLimiter::keyed(quota));

    let state = HoneypotState {
        pool,
        rate_limiter,
        honeypot_tracker: Arc::new(sticky::new_tracker()),
        grant_tracker: Arc::new(sticky::new_grant_tracker()),
        recon_tracker: Arc::new(sticky::new_recon_tracker()),
        canary_posts: Arc::new(canary::new_canary_posts()),
        slow_budget: tarpit::new_budget(settings.slow_response_budget),
        settings: settings.clone(),
    };
    let cfg = &trap_config;

    let mut cred_routes = Router::new();

    if cfg.is_enabled(TrapFamily::WordPress) {
        cred_routes = cred_routes
            .route("/wp-login.php", any(handlers::wp_login))
            .route("/xmlrpc.php", post(handlers::xmlrpc))
            .route("/wp-json/", any(handlers::wp_json_catch))
            .route("/wp-json/{*rest}", any(handlers::wp_json_catch))
            .route("/wp-admin/admin-ajax.php", any(ajax::admin_ajax))
            .route("/wp-content/{*rest}", any(ajax::plugin_endpoint))
            // Core JS/CSS ahead of the probe handler: a real WordPress always
            // serves these, and 404ing them told any bot that checked that the
            // WordPress around them was fake.
            .route("/wp-includes/{*rest}", any(assets::wp_static))
            // Core's readme.html is the oldest WordPress version fingerprint
            // there is; config_probe serves it from the same bait table.
            .route("/readme.html", any(handlers::config_probe));
    }
    if cfg.is_enabled(TrapFamily::EnvHoneytoken) {
        cred_routes = cred_routes
            .route("/.env", any(handlers::env_honeytrap))
            .route("/.env.local", any(handlers::env_honeytrap))
            .route("/.env.production", any(handlers::env_honeytrap));
    }
    if cfg.is_enabled(TrapFamily::EnvHoneytoken) {
        cred_routes = cred_routes.route("/{*rest}", any(handlers::env_catch));
    }
    if cfg.is_enabled(TrapFamily::Git) {
        cred_routes = cred_routes.route("/.git/{*rest}", any(git::git_honeytrap));
    }
    if cfg.is_enabled(TrapFamily::Vcs) {
        cred_routes = cred_routes
            .route("/.svn/{*rest}", any(handlers::config_probe))
            .route("/.hg/{*rest}", any(handlers::config_probe));
    }
    if cfg.is_enabled(TrapFamily::CloudKeys) {
        cred_routes = cred_routes
            .route("/.aws/{*rest}", any(secrets::secret_honeytrap))
            .route("/.git-credentials", any(secrets::secret_honeytrap))
            .route("/.gitconfig", any(secrets::secret_honeytrap))
            .route("/.gitlab-ci.yml", any(secrets::secret_honeytrap))
            .route("/.npmrc", any(secrets::secret_honeytrap))
            .route("/.docker/config.json", any(secrets::secret_honeytrap))
            .route("/.github/workflows/{*rest}", any(secrets::secret_honeytrap))
            .route("/.ssh/{*rest}", any(handlers::config_probe));
    }
    if cfg.is_enabled(TrapFamily::FrameworkDebug) {
        cred_routes = cred_routes
            .route("/actuator", any(actuator::actuator))
            .route("/actuator/{*rest}", any(actuator::actuator))
            .route("/_ignition/{*rest}", any(handlers::config_probe));
    }
    if cfg.is_enabled(TrapFamily::ServiceExposure) {
        cred_routes = cred_routes
            .route("/solr/{*rest}", any(handlers::config_probe))
            .route("/server-status", any(handlers::config_probe))
            .route("/server-info", any(handlers::config_probe))
            .route("/composer.json", get(handlers::config_probe))
            .route("/composer.lock", get(handlers::config_probe))
            .route("/package.json", get(handlers::config_probe));
    }
    if cfg.is_enabled(TrapFamily::PhpShells) {
        cred_routes = cred_routes
            .route("/phpinfo.php", any(php::phpinfo))
            .route("/phpinfo", any(php::phpinfo))
            .route("/index.php", any(handlers::php_probe))
            .route("/shell.php", any(handlers::php_probe))
            .route("/c99.php", any(handlers::php_probe))
            .route("/r57.php", any(handlers::php_probe))
            .route("/webshell.php", any(handlers::php_probe));
    }
    if cfg.is_enabled(TrapFamily::DbAdmin) {
        for prefix in [
            "phpmyadmin",
            "phpMyAdmin",
            "phpmyadmin2",
            "phpMyAdmin2",
            "phpmyadmin-2",
            "phpMyAdmin-2",
            "phpmyadmin3",
            "phpmyadmin4",
            "PMA",
            "pma",
            "pmd",
            "dbadmin",
            "mysql",
            "sqlmanager",
            "myadmin",
        ] {
            cred_routes = cred_routes
                .route(&format!("/{prefix}"), any(cms::cms_login))
                .route(&format!("/{prefix}/"), any(cms::cms_login))
                .route(&format!("/{prefix}/{{*rest}}"), any(cms::cms_login));
        }
        cred_routes = cred_routes.route("/adminer.php", any(cms::cms_login));
    }

    let mut cms_routes = Router::new();
    if cfg.is_enabled(TrapFamily::Drupal) {
        cms_routes = cms_routes.route("/user/login", any(cms::cms_login));
    }
    if cfg.is_enabled(TrapFamily::Joomla) {
        cms_routes = cms_routes
            .route("/administrator/index.php", any(cms::cms_login))
            .route(
                "/administrator/{*rest}",
                any(handlers::post_exploit_capture),
            );
    }
    if cfg.is_enabled(TrapFamily::Django) {
        cms_routes = cms_routes
            .route("/admin/login", any(cms::cms_login))
            .route("/admin/login/", any(cms::cms_login))
            .route("/admin/{*rest}", any(handlers::post_exploit_capture));
    }

    let mut admin_routes = Router::new();
    if cfg.is_enabled(TrapFamily::WordPress) {
        admin_routes = admin_routes
            .route("/wp-admin/install.php", any(handlers::wp_admin_install))
            .route("/wp-admin/setup-config.php", any(handlers::wp_setup_config))
            .route("/wp-admin/index.php", get(handlers::wp_admin_index))
            .route("/wp-admin/", get(handlers::wp_admin_index))
            .route("/wp-admin/{*rest}", any(handlers::post_exploit_capture))
            // Batch sits here rather than with the credential routes: a real
            // 25-request batch exceeds the 4 KiB body limit, and a 413 would
            // end the engagement before the payload arrives. Write
            // amplification is bounded inside the handler instead.
            .route("/wp-json/batch/v1", any(restapi::batch))
            .route("/wp-json/batch/v1/", any(restapi::batch));
    }

    let app = Router::new()
        .route("/health", get(health))
        // Body limits are applied HERE, not at Router::new(): axum's
        // `Router::layer` wraps only the routes registered before the call, so
        // a limit set on an empty router is silently inert and every route
        // fell back to axum's 2 MiB default.
        .merge(cred_routes.layer(axum::extract::DefaultBodyLimit::max(
            handlers::MAX_POST_BODY_BYTES,
        )))
        .merge(cms_routes.layer(axum::extract::DefaultBodyLimit::max(
            handlers::MAX_EXPLOIT_BODY_BYTES,
        )))
        .merge(admin_routes.layer(axum::extract::DefaultBodyLimit::max(
            handlers::MAX_EXPLOIT_BODY_BYTES,
        )))
        // Unmatched path and unmatched method both used to answer straight out
        // of axum (404 / 405) with no row written. Both are attacker signal —
        // `GET /xmlrpc.php` and `/wp-config.php` are among the most probed
        // requests on the internet — so route them at a handler that records.
        .fallback(handlers::unrouted_probe)
        .method_not_allowed_fallback(handlers::unrouted_probe)
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            limit_honeypot,
        ))
        // Outermost, so it also dresses the rate-limiter's WP error page and
        // the unrouted-probe fallback.
        .layer(axum::middleware::from_fn(facade::dress_as_wordpress))
        .with_state(state);

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8080);

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .expect("failed to bind");
    tracing::info!("rustypot listening on :{port}");
    axum::serve(listener, app).await.expect("server error");
}
