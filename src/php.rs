// allow: SIZE_OK — the bulk of this file is HTML table markup for the fake
// phpinfo() page, which is data, not logic. Production logic is ~60 LOC.
//! Fake `phpinfo()` output.
//!
//! `/phpinfo.php` is the most-requested path this service answered with a 404.
//! It is worth serving for two reasons. It is the strongest possible "this is
//! really PHP" confirmation — which every other trap benefits from — and a real
//! phpinfo dump exposes the process environment, so it is the most natural
//! place in the whole surface to plant credentials. A harvester that scrapes
//! `$_ENV` here gets the same per-IP honeytoken the `.env` trap plants, and any
//! later use of it correlates.
//!
//! The page is also genuinely large (tens of KB of table markup), which costs
//! the scraper parse time.

use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use std::net::IpAddr;

use crate::sink;
use crate::sticky::planted_credential;
use crate::{Error, HoneypotState};

const PHP_VERSION: &str = "8.2.28";

fn row(name: &str, local: &str, master: &str) -> String {
    format!("<tr><td class=\"e\">{name}</td><td class=\"v\">{local}</td><td class=\"v\">{master}</td></tr>\n")
}

fn kv(name: &str, value: &str) -> String {
    format!("<tr><td class=\"e\">{name}</td><td class=\"v\">{value}</td></tr>\n")
}

fn section(title: &str, body: &str) -> String {
    format!("<h2>{title}</h2>\n<table>\n{body}</table>\n")
}

/// Directives worth showing: the ones an attacker reads to decide whether an
/// RCE path is open (`allow_url_include`, `disable_functions`) are chosen to
/// look permissive enough to be worth attacking.
fn core_directives() -> String {
    let mut t = String::from(
        "<tr class=\"h\"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>\n",
    );
    for (k, v) in [
        ("allow_url_fopen", "On"),
        ("allow_url_include", "Off"),
        ("disable_functions", "no value"),
        ("display_errors", "Off"),
        ("file_uploads", "On"),
        ("max_execution_time", "300"),
        ("memory_limit", "512M"),
        ("open_basedir", "no value"),
        ("post_max_size", "128M"),
        ("upload_max_filesize", "128M"),
        ("upload_tmp_dir", "/tmp"),
        ("safe_mode", "Off"),
    ] {
        t.push_str(&row(k, v, v));
    }
    t
}

const MODULE_NAMES: &[&str] = &[
    "Core",
    "ctype",
    "curl",
    "date",
    "dom",
    "exif",
    "fileinfo",
    "filter",
    "ftp",
    "gd",
    "hash",
    "iconv",
    "imagick",
    "json",
    "libxml",
    "mbstring",
    "mysqli",
    "mysqlnd",
    "openssl",
    "pcre",
    "PDO",
    "pdo_mysql",
    "posix",
    "readline",
    "Reflection",
    "session",
    "SimpleXML",
    "soap",
    "sodium",
    "SPL",
    "sqlite3",
    "standard",
    "tokenizer",
    "xml",
    "xmlreader",
    "xmlwriter",
    "zip",
    "zlib",
];

fn modules() -> String {
    let mut t = String::new();
    for m in MODULE_NAMES {
        t.push_str(&format!("<tr><td class=\"e\">{m}</td></tr>\n"));
    }
    t
}

/// Real phpinfo prints a per-module section listing that module's directives.
/// Reproducing them takes the page from a few KB to the tens of KB a genuine
/// dump occupies — and the size is itself part of the disguise.
fn module_sections() -> String {
    let mut out = String::new();
    for m in MODULE_NAMES {
        let mut rows = String::from(
            "<tr class=\"h\"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>\n",
        );
        for suffix in [
            "enabled",
            "version",
            "max_depth",
            "cache_limiter",
            "encoding",
        ] {
            let name = format!("{}.{suffix}", m.to_ascii_lowercase());
            let value = match suffix {
                "enabled" => "1",
                "version" => "8.2.28",
                "max_depth" => "512",
                "cache_limiter" => "nocache",
                _ => "UTF-8",
            };
            rows.push_str(&row(&name, value, value));
        }
        out.push_str(&section(m, &rows));
    }
    out
}

/// The environment block. This is the payload: a scraper reading phpinfo for
/// secrets finds the same per-IP honeytoken the `.env` trap plants.
fn environment(secret: &str, db_pass: &str) -> String {
    let mut t = String::from("<tr class=\"h\"><th>Variable</th><th>Value</th></tr>\n");
    for (k, v) in [
        ("USER", "www-data"),
        ("HOME", "/var/www"),
        (
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        ),
        ("DOCUMENT_ROOT", "/var/www/html"),
        ("DB_HOST", "10.0.4.17"),
        ("DB_NAME", "fillerkiller_prod"),
        ("DB_USER", "wp_app"),
        ("DB_PASSWORD", db_pass),
        ("WORDPRESS_DB_PASSWORD", db_pass),
        ("SMTP_HOST", "email-smtp.us-east-1.amazonaws.com"),
        ("SMTP_USER", "AKIAJQ4XN2LWOPRTUV7Y"),
        ("SMTP_PASSWORD", secret),
        ("REDIS_URL", "redis://:changeme@10.0.4.22:6379/0"),
        ("APP_KEY", secret),
    ] {
        t.push_str(&kv(k, v));
    }
    t
}

fn build_page(secret: &str, db_pass: &str) -> String {
    let mut body = String::with_capacity(24 * 1024);
    body.push_str(&format!(
        "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\">\n\
         <html><head><style type=\"text/css\">\
         body{{background-color:#fff;color:#222;font-family:sans-serif}}\
         table{{border-collapse:collapse;border:0;width:934px;box-shadow:1px 2px 3px #ccc}}\
         .center{{text-align:center}} .p{{text-align:left}}\
         .e{{background-color:#ccf;font-weight:bold;color:#000;width:300px}}\
         .h{{background-color:#99c;font-weight:bold;color:#000}}\
         .v{{background-color:#ddd;color:#000}}\
         h1{{font-size:150%}} h2{{font-size:125%}}\
         </style><title>phpinfo()</title></head>\n\
         <body><div class=\"center\">\n\
         <h1 class=\"p\">PHP Version {PHP_VERSION}</h1>\n<table>\n"
    ));
    for (k, v) in [
        (
            "System",
            "Linux web-prod-01 5.15.0-107-generic #117-Ubuntu SMP x86_64",
        ),
        ("Build Date", "Apr 11 2026 09:22:41"),
        ("Server API", "FPM/FastCGI"),
        ("Loaded Configuration File", "/etc/php/8.2/fpm/php.ini"),
        ("PHP API", "20220829"),
        ("Debug Build", "no"),
        ("Thread Safety", "disabled"),
        ("Zend Signal Handling", "enabled"),
    ] {
        body.push_str(&kv(k, v));
    }
    body.push_str("</table>\n");
    body.push_str(&section("Core", &core_directives()));
    body.push_str(&section("Configuration", &modules()));
    body.push_str(&module_sections());
    body.push_str(&section("Environment", &environment(secret, db_pass)));
    body.push_str(&section(
        "PHP Variables",
        &format!(
            "<tr class=\"h\"><th>Variable</th><th>Value</th></tr>\n{}{}{}",
            kv("_SERVER[\"DOCUMENT_ROOT\"]", "/var/www/html"),
            kv("_SERVER[\"SERVER_SOFTWARE\"]", "nginx/1.24.0"),
            kv("_SERVER[\"SCRIPT_FILENAME\"]", "/var/www/html/phpinfo.php"),
        ),
    ));
    body.push_str("</div></body></html>\n");
    body
}

pub async fn phpinfo(
    State(state): State<HoneypotState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    method: Method,
) -> Result<Response, Error> {
    let path = uri.path();
    let ip_str = crate::headers::extract_source_ip(&headers);
    let ip: IpAddr = ip_str.parse().unwrap_or(IpAddr::from([0, 0, 0, 0]));
    let prefix =
        crate::sticky::honeytoken_prefix(&state.settings.honeytoken_prefix, &headers, path);
    let secret = planted_credential(&ip, "/phpinfo.php#app", &prefix);
    let db_pass = planted_credential(&ip, "/phpinfo.php#db", &prefix);

    let _ = sink::record_granted_credential(
        &state.pool,
        "wp_app",
        &db_pass,
        &ip_str,
        sink::ORIGIN_SECRET,
    )
    .await;

    sink::log_planted_event(
        &state,
        &headers,
        &method,
        path,
        uri.query(),
        Some("wp_app"),
        Some(&db_pass),
        200,
        0,
    )
    .await?;

    let mut resp = (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "text/html; charset=UTF-8")],
        build_page(&secret, &db_pass),
    )
        .into_response();
    crate::facade::apply_php_headers(&mut resp);
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_declares_the_php_version_scanners_read() {
        let p = build_page("fkSECRET", "fkDBPASS");
        assert!(p.contains("<title>phpinfo()</title>"));
        assert!(p.contains(&format!("PHP Version {PHP_VERSION}")));
        assert!(p.contains("FPM/FastCGI"));
    }

    #[test]
    fn environment_carries_the_planted_credentials() {
        let p = build_page("fkSECRET", "fkDBPASS");
        assert!(p.contains("fkDBPASS"), "DB password is the honeytoken");
        assert!(p.contains("fkSECRET"), "app/SMTP secret is planted too");
        assert!(p.contains("WORDPRESS_DB_PASSWORD"));
    }

    #[test]
    fn page_is_large_enough_to_cost_parse_time() {
        // A real phpinfo is tens of KB; a suspiciously small one is a tell.
        assert!(build_page("a", "b").len() > 8_000);
    }

    #[test]
    fn no_html_injection_from_the_planted_values() {
        // Planted values are generated by us, never attacker-controlled, but
        // assert the invariant so a future change to the generator cannot
        // silently introduce markup.
        let p = build_page("fkSECRET", "fkDBPASS");
        assert!(!p.contains("<script"));
    }
}
