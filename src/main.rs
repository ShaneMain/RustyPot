use std::net::IpAddr;
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::Router;
use governor::{clock::DefaultClock, state::keyed::DefaultKeyedStateStore, Quota, RateLimiter};
use std::num::NonZeroU32;

mod canary;
mod cms;
mod config;
mod git;
mod handlers;
mod headers;
mod parsers;
mod sink;
mod sticky;
mod templates;

use config::{Settings, TrapConfig, TrapFamily};

pub type IpRateLimiter = RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>;

#[derive(Clone)]
pub struct HoneypotState {
    pub pool: sqlx::PgPool,
    pub rate_limiter: Arc<IpRateLimiter>,
    pub honeypot_tracker: Arc<sticky::AttemptTracker>,
    pub grant_tracker: Arc<sticky::GrantTracker>,
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

async fn limit_honeypot(State(state): State<HoneypotState>, req: Request, next: Next) -> Response {
    let ip = client_ip(req.headers());
    match state.rate_limiter.check_key(&ip) {
        Ok(()) => next.run(req).await,
        Err(_) => (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response(),
    }
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
        settings: settings.clone(),
    };
    let cfg = &trap_config;

    let mut cred_routes = Router::new().layer(axum::extract::DefaultBodyLimit::max(
        handlers::MAX_POST_BODY_BYTES,
    ));

    if cfg.is_enabled(TrapFamily::WordPress) {
        cred_routes = cred_routes
            .route("/wp-login.php", any(handlers::wp_login))
            .route("/xmlrpc.php", post(handlers::xmlrpc))
            .route("/wp-json/", any(handlers::wp_json_catch))
            .route("/wp-json/{*rest}", any(handlers::wp_json_catch))
            .route("/wp-content/{*rest}", any(handlers::config_probe))
            .route("/wp-includes/{*rest}", any(handlers::config_probe));
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
            .route("/.aws/{*rest}", any(handlers::config_probe))
            .route("/.ssh/{*rest}", any(handlers::config_probe));
    }
    if cfg.is_enabled(TrapFamily::FrameworkDebug) {
        cred_routes = cred_routes
            .route("/actuator/{*rest}", any(handlers::config_probe))
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
            .route("/phpinfo.php", any(handlers::php_probe))
            .route("/index.php", any(handlers::php_probe))
            .route("/shell.php", any(handlers::php_probe))
            .route("/c99.php", any(handlers::php_probe))
            .route("/r57.php", any(handlers::php_probe))
            .route("/webshell.php", any(handlers::php_probe));
    }
    if cfg.is_enabled(TrapFamily::DbAdmin) {
        cred_routes = cred_routes
            .route("/phpmyadmin/{*rest}", any(handlers::config_probe))
            .route("/phpMyAdmin/{*rest}", any(handlers::config_probe))
            .route("/pma/{*rest}", any(handlers::config_probe))
            .route("/dbadmin/{*rest}", any(handlers::config_probe))
            .route("/mysql/{*rest}", any(handlers::config_probe))
            .route("/sqlmanager/{*rest}", any(handlers::config_probe))
            .route("/adminer.php", any(handlers::config_probe));
    }

    let mut cms_routes = Router::new().layer(axum::extract::DefaultBodyLimit::max(
        handlers::MAX_EXPLOIT_BODY_BYTES,
    ));
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

    let mut admin_routes = Router::new().layer(axum::extract::DefaultBodyLimit::max(
        handlers::MAX_EXPLOIT_BODY_BYTES,
    ));
    if cfg.is_enabled(TrapFamily::WordPress) {
        admin_routes = admin_routes
            .route("/wp-admin/install.php", get(handlers::wp_admin_install))
            .route("/wp-admin/index.php", get(handlers::wp_admin_index))
            .route("/wp-admin/", get(handlers::wp_admin_index))
            .route("/wp-admin/{*rest}", any(handlers::post_exploit_capture));
    }

    let app = Router::new()
        .route("/health", get(health))
        .merge(cred_routes)
        .merge(cms_routes)
        .merge(admin_routes)
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            limit_honeypot,
        ))
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
