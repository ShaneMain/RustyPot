//! Honeypot HTML/XML response bodies — pure-data templates. Bot scanners
//! regex-grep for form fields; CSS fidelity buys nothing, so the styling is
//! minimal. Each template is well under 3 KiB.

// allow: SIZE_OK — production code is ~50 LOC (const decls + the success
// page builder and html_escape); the bulk is raw HTML/XML string literals
// (pure data, excluded from the LOC budget).

pub(super) const WP_LOGIN_FORM_HTML: &str = r##"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Log In &mdash; WordPress</title>
<style>
html{background:#f0f0f1;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen,sans-serif;}
#login{width:320px;margin:80px auto 0;padding:20px;}
#login h1{text-align:center;margin-bottom:24px;}
.login form{background:#fff;border:1px solid #c3c4c7;padding:26px 24px 34px;}
.login .input{width:100%;padding:3px 8px;border:1px solid #8c8f94;border-radius:4px;font-size:14px;margin:2px 0 6px;box-sizing:border-box;}
.login .button-primary{background:#2271b1;color:#fff;border:none;border-radius:3px;padding:7px 22px 8px;font-size:14px;cursor:pointer;}
.login p{margin:0 0 16px;font-size:14px;}
.forgetmenot{float:right;}
</style></head>
<body class="login">
<div id="login">
<h1><a href="https://wordpress.org/" title="Powered by WordPress" tabindex="-1">
<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg" width="84" height="84" role="img">
<circle cx="50" cy="50" r="50" fill="#000"/>
<path fill="#fff" d="M16.7 50c0 14.4 8.4 26.9 20.5 32.7L19.8 35.6c-2 4.4-3.1 9.3-3.1 14.4zm14.6-3.7c0-3.6 1.3-6.4 2.5-9.1l.2-.4c1.5-3.6 2.9-6.9 2.9-10.7 0-3.9-2.1-7.3-3.5-9.9C42.7 17.6 53 23.7 59.1 33.1c-2.1-.3-7.2-.9-7.5-.9-.8-.1-1.6-.1-1.6 1.1 0 1.4 1.4 1.3 1.4 1.3l7.4.4c-.2 4-1.6 7.1-3.3 10.4-1.8 3.4-3.5 6.6-3.5 10.9 0 4.3 1.7 7.7 3.5 11.1 1.7 3.3 3.4 6.7 3.4 11 0 5.3-2.1 9.3-4.4 13.6-1.7 3.1-3.5 6.4-4.7 10.5C41.1 89.7 31.3 75.6 31.3 46.3z"/>
</svg></a></h1>
<form name="loginform" id="loginform" action="/wp-login.php" method="post">
<p><label for="user_login">Username or Email Address</label>
<input type="text" name="log" id="user_login" class="input" value="" size="20" autocapitalize="none" autocomplete="username"></p>
<p><label for="user_pass">Password</label>
<input type="password" name="pwd" id="user_pass" class="input" value="" size="20" autocomplete="current-password"></p>
<p class="forgetmenot"><input name="rememberme" type="checkbox" id="rememberme" value="forever"> <label for="rememberme">Remember Me</label></p>
<input type="submit" name="wp-submit" id="wp-submit" class="button button-primary" value="Log In">
<input type="hidden" name="redirect_to" value="/wp-admin/">
<input type="hidden" name="testcookie" value="1">
</form>
<p id="nav"><a href="/wp-login.php?action=lostpassword">Lost your password?</a></p>
</div>
</body></html>"##;

pub(super) const WP_LOGIN_FORM_ERROR_HTML: &str = r##"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Log In &mdash; WordPress</title>
<style>
html{background:#f0f0f1;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen,sans-serif;}
#login{width:320px;margin:80px auto 0;padding:20px;}
#login h1{text-align:center;margin-bottom:24px;}
#login_error{border-left:4px solid #d63638;background:#fff;padding:12px;margin:0 0 16px;box-shadow:0 1px 1px rgba(0,0,0,.04);font-size:14px;}
.login form{background:#fff;border:1px solid #c3c4c7;padding:26px 24px 34px;}
.login .input{width:100%;padding:3px 8px;border:1px solid #8c8f94;border-radius:4px;font-size:14px;margin:2px 0 6px;box-sizing:border-box;}
.login .button-primary{background:#2271b1;color:#fff;border:none;border-radius:3px;padding:7px 22px 8px;font-size:14px;cursor:pointer;}
.login p{margin:0 0 16px;font-size:14px;}
.forgetmenot{float:right;}
</style></head>
<body class="login">
<div id="login">
<h1><a href="https://wordpress.org/" title="Powered by WordPress" tabindex="-1">
<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg" width="84" height="84" role="img">
<circle cx="50" cy="50" r="50" fill="#000"/>
<path fill="#fff" d="M16.7 50c0 14.4 8.4 26.9 20.5 32.7L19.8 35.6c-2 4.4-3.1 9.3-3.1 14.4zm55.5-1.7c0-4.5-1.6-7.6-3-10l-.1-.2c-1.8-2.9-3.3-5.4-3.3-8.3 0-3.3 2.5-6.3 5.8-6.3z"/>
</svg></a></h1>
<div id="login_error">Error: The password you entered for the username is incorrect. <a href="/wp-login.php?action=lostpassword">Lost your password?</a><br></div>
<form name="loginform" id="loginform" action="/wp-login.php" method="post">
<p><label for="user_login">Username or Email Address</label>
<input type="text" name="log" id="user_login" class="input" value="" size="20" autocapitalize="none" autocomplete="username"></p>
<p><label for="user_pass">Password</label>
<input type="password" name="pwd" id="user_pass" class="input" value="" size="20" autocomplete="current-password"></p>
<p class="forgetmenot"><input name="rememberme" type="checkbox" id="rememberme" value="forever"> <label for="rememberme">Remember Me</label></p>
<input type="submit" name="wp-submit" id="wp-submit" class="button button-primary" value="Log In">
<input type="hidden" name="redirect_to" value="/wp-admin/">
<input type="hidden" name="testcookie" value="1">
</form>
<p id="nav"><a href="/wp-login.php?action=lostpassword">Lost your password?</a></p>
</div>
</body></html>"##;

/// `wp-admin/setup-config.php` — the "Setup Configuration File" wizard's
/// database form. Real install.php never shows this page (it errors or
/// redirects to setup-config.php when wp-config.php is missing); kits that
/// walk the full wizard are funneled from here to install.php.
pub(super) const WP_SETUP_CONFIG_HTML: &str = r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>WordPress &rsaquo; Setup Configuration File</title>
<style>
html{background:#f1f1f1;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;}
body{max-width:560px;margin:60px auto;background:#fff;padding:30px;border:1px solid #dcdcde;}
h1{font-size:23px;font-weight:400;margin:0 0 16px;}
label{display:block;font-size:14px;margin:8px 0 4px;}
input[type=text],input[type=password]{width:100%;padding:6px 8px;border:1px solid #8c8f94;border-radius:4px;font-size:14px;box-sizing:border-box;}
input[type=submit]{background:#2271b1;color:#fff;border:none;border-radius:3px;padding:8px 18px;font-size:14px;margin-top:16px;cursor:pointer;}
.step{margin:8px 0;}
</style></head>
<body>
<h1>WordPress</h1>
<p>Welcome to WordPress. Before getting started, we need some information on the database. You will need to know the following items before proceeding.</p>
<form id="setup" method="post" action="/wp-admin/setup-config.php?step=2">
<p class="step"><label for="dbname">Database Name</label>
<input name="dbname" id="dbname" type="text" size="25" value=""></p>
<p class="step"><label for="uname">User Name</label>
<input name="uname" id="uname" type="text" size="25" value=""></p>
<p class="step"><label for="pwd">Password</label>
<input name="pwd" id="pwd" type="password" size="25" value=""></p>
<p class="step"><label for="dbhost">Database Host</label>
<input name="dbhost" id="dbhost" type="text" size="25" value="localhost"></p>
<p class="step"><label for="prefix">Table Prefix</label>
<input name="prefix" id="prefix" type="text" size="25" value="wp_"></p>
<p class="step"><input type="submit" value="Submit" class="button"></p>
</form>
</body></html>"#;

/// `setup-config.php`'s post-submit interstitial. Real WordPress shows this
/// after writing wp-config.php; the "Run the install" link funnels the kit
/// into install.php, where it chooses (and we capture) its admin credentials.
pub(super) const WP_SETUP_CONFIG_DONE_HTML: &str = r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>WordPress &rsaquo; Setup Configuration File</title>
<style>
html{background:#f1f1f1;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;}
body{max-width:560px;margin:60px auto;background:#fff;padding:30px;border:1px solid #dcdcde;font-size:14px;line-height:1.6;}
h1{font-size:23px;font-weight:400;margin:0 0 16px;}
a{color:#2271b1;}
</style></head>
<body>
<h1>All right, sparky!</h1>
<p>You've made it through this part of the installation. WordPress can now communicate with your database. If you are ready, time now to&hellip;</p>
<p><a href="/wp-admin/install.php" class="button button-large">Run the install</a></p>
</body></html>"#;

/// `wp-admin/install.php` GET — the "famous five-minute install" welcome
/// form. Field names match real WordPress core exactly (`weblog_title`,
/// `user_name`, `admin_password`, `admin_password2`, `pw_weak`,
/// `admin_email`, `blog_public`, `language`) so kits that fill the form by
/// name hit every field. The POST lands on `?step=2`, like the real thing.
pub(super) const WP_WELCOME_HTML: &str = r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>WordPress &rsaquo; Installation</title>
<style>
html{background:#f1f1f1;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;}
body{max-width:560px;margin:40px auto;background:#fff;padding:30px;border:1px solid #dcdcde;font-size:14px;line-height:1.6;}
h1{font-size:23px;font-weight:400;margin:0 0 16px;}
label{font-weight:600;}
input[type=text],input[type=password],input[type=email]{width:100%;padding:6px 8px;border:1px solid #8c8f94;border-radius:4px;font-size:14px;box-sizing:border-box;}
input[type=submit]{background:#2271b1;color:#fff;border:none;border-radius:3px;padding:8px 18px;font-size:14px;cursor:pointer;}
table.form-table{border-collapse:collapse;width:100%;}
table.form-table th{text-align:left;padding:10px 10px 10px 0;width:180px;vertical-align:top;}
table.form-table td{padding:10px 0;}
</style></head>
<body>
<h1>Welcome</h1>
<p>Welcome to the famous five-minute WordPress installation process! Just fill in the information below and you'll be on your way to using the most extendable and powerful personal publishing platform in the world.</p>
<h2>Information needed</h2>
<p>Please provide the following information. Don't worry, you can always change these later.</p>
<form id="setup" method="post" action="/wp-admin/install.php?step=2">
<table class="form-table">
<tr><th scope="row"><label for="weblog_title">Site Title</label></th>
<td><input name="weblog_title" id="weblog_title" type="text" size="25" value=""></td></tr>
<tr><th scope="row"><label for="user_name">Username</label></th>
<td><input name="user_name" id="user_name" type="text" size="25" value="" autocapitalize="none" autocorrect="off"></td></tr>
<tr><th scope="row"><label for="admin_password">Password</label></th>
<td><input name="admin_password" id="admin_password" type="password" size="25"><br>
<input type="checkbox" name="pw_weak" id="pw_weak" value="1" style="display:none">
<label for="admin_password2">Confirm Password</label>
<input name="admin_password2" id="admin_password2" type="password" size="25"></td></tr>
<tr><th scope="row"><label for="admin_email">Your Email Address</label></th>
<td><input name="admin_email" id="admin_email" type="email" size="25" value=""></td></tr>
<tr><th scope="row">Search Engine Visibility</th>
<td><label><input type="checkbox" name="blog_public" id="blog_public" value="0" checked> Allow search engines to index this site</label><br>
<code class="description">Discouraging search engines from indexing this site is not a privacy mechanism.</code></td></tr>
</table>
<input type="hidden" name="language" value="en_US">
<p class="step"><input type="submit" name="Submit" id="submit" class="button button-large" value="Install WordPress"></p>
</form>
</body></html>"#;

/// The `install.php?step=2` success page. Real WordPress lists the username
/// and masks a user-chosen password as "Your chosen password." — we mirror
/// that instead of echoing the password back (fidelity over flair). The Log
/// In link is where claim-verifying kits go next; wp-login grants their
/// claimed pair immediately (see `sink::credential_origin`).
pub(super) fn wp_install_success_html(username: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>WordPress &rsaquo; Success</title>
<style>
html{{background:#f1f1f1;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;}}
body{{max-width:560px;margin:40px auto;background:#fff;padding:30px;border:1px solid #dcdcde;font-size:14px;line-height:1.6;}}
h1{{font-size:23px;font-weight:400;margin:0 0 16px;}}
table.form-table{{border-collapse:collapse;width:100%;}}
table.form-table th{{text-align:left;padding:10px 10px 10px 0;width:180px;}}
table.form-table td{{padding:10px 0;}}
code{{background:#f0f0f1;padding:2px 6px;border-radius:3px;}}
.button{{display:inline-block;background:#2271b1;color:#fff;border:none;border-radius:3px;padding:8px 18px;font-size:14px;text-decoration:none;}}
</style></head>
<body>
<h1>Success!</h1>
<p>WordPress has been installed. Thank you, and enjoy!</p>
<table class="form-table install-success">
<tr><th>Username</th><td>{username}</td></tr>
<tr><th>Password</th><td><code>Your chosen password.</code></td></tr>
</table>
<p class="step"><a href="/wp-login.php" class="button button-large">Log In</a></p>
</body></html>"#,
        username = html_escape(username),
    )
}

/// Minimal HTML escaping for interpolating attacker-controlled values into
/// honeypot pages. The bytes come back to the attacker's own tooling, but
/// escaped output keeps our responses inert regardless of what they submit.
pub(super) fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

pub(super) const XMLRPC_FAULT_BODY: &str = r#"<?xml version="1.0"?>
<methodResponse><fault><value><struct>
<member><name>faultCode</name><value><int>403</int></value></member>
<member><name>faultString</name><value><string>Incorrect username or password.</string></value></member>
</struct></value></fault></methodResponse>"#;

/// Served instead of a bare `429 Too Many Requests` when a client blows past
/// the abuse quota. WordPress emits exactly this page when its DB is
/// unreachable, so an overloaded-looking site stays in character; a 429 with
/// the body "rate limited" is not something WordPress can produce and
/// fingerprints the honeypot in one request.
pub(super) const WP_DB_ERROR_HTML: &str = r#"<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml"><head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>WordPress &rsaquo; Error</title>
<style type="text/css">
html{background:#f1f1f1;}body{background:#fff;color:#444;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;margin:2em auto;padding:1em 2em;max-width:700px;box-shadow:0 1px 1px rgba(0,0,0,.04);}
h1{border-bottom:1px solid #dadada;clear:both;color:#666;font-size:24px;margin:30px 0 0;padding:0 0 7px;}
</style>
</head><body id="error-page"><h1>Error establishing a database connection</h1>
<p>This either means that the username and password information in your <code>wp-config.php</code> file is incorrect or that contact with the database server at <code>localhost</code> could not be established. This could mean your host&#8217;s database server is down.</p>
</body></html>"#;

/// `wp-includes/version.php` as served by a host whose PHP handler is broken —
/// the raw source, which is exactly what a fingerprinting scanner hopes for.
/// The version is deliberately an old, heavily-CVE'd release: a scanner that
/// believes it, escalates, and an escalation is far better telemetry than the
/// 404 this used to return.
pub(super) const WP_VERSION_PHP: &str = r#"<?php
/**
 * WordPress Version
 *
 * Contains version information for the current WordPress release.
 *
 * @package WordPress
 * @since 1.1.0
 */

/**
 * The WordPress version string.
 *
 * @global string $wp_version
 */
$wp_version = '5.8.1';

/**
 * Holds the WordPress DB revision, increments when changes are made to the WordPress DB schema.
 *
 * @global int $wp_db_version
 */
$wp_db_version = 49752;

/**
 * Holds the TinyMCE version.
 *
 * @global string $tinymce_version
 */
$tinymce_version = '49110-20201110';

/**
 * Holds the required PHP version.
 *
 * @global string $required_php_version
 */
$required_php_version = '5.6.20';

/**
 * Holds the required MySQL version.
 *
 * @global string $required_mysql_version
 */
$required_mysql_version = '5.0';
"#;

/// Plugins worth naming a specific version for, because a scanner that reads
/// this file does not stop at "installed" — it compares the `Stable tag:`
/// against the affected range of whatever bug it knows about, and only
/// escalates on a match. A generic version answers "installed" and ends the
/// conversation; these answer "installed *and* exploitable".
///
/// Each version sits inside the publicly-known-vulnerable range for that
/// plugin, biased deliberately *low*: an older tag is vulnerable to everything
/// later advisories list, so being wrong about an exact patch boundary costs a
/// missed escalation rather than a blown cover. The last group are ordinary
/// popular plugins at plausible old versions — a site running only
/// mass-exploited plugins and nothing else is not a credible site.
///
/// Refresh this list as exploitation trends move; the "Untrapped probes" and
/// "Fingerprint bait" dashboard panels show which slugs are actually asked for.
const KNOWN_PLUGINS: &[(&str, &str, &str)] = &[
    // Heavily exploited: unauthenticated SQLi, RCE or privilege escalation.
    ("wp-automatic", "WP Automatic", "3.92.0"),
    ("bookingpress-appointment-booking", "BookingPress", "1.0.10"),
    ("wp-fastest-cache", "WP Fastest Cache", "1.2.1"),
    ("wp-file-manager", "WP File Manager", "6.8"),
    ("duplicator", "Duplicator", "1.3.26"),
    ("wpdiscuz", "wpDiscuz", "7.0.4"),
    ("ultimate-member", "Ultimate Member", "2.6.6"),
    (
        "essential-addons-for-elementor-lite",
        "Essential Addons for Elementor",
        "5.7.1",
    ),
    ("litespeed-cache", "LiteSpeed Cache", "6.3.0.1"),
    ("really-simple-ssl", "Really Simple SSL", "9.0.0"),
    ("woocommerce-payments", "WooPayments", "5.6.1"),
    ("contact-form-7", "Contact Form 7", "5.3.1"),
    ("backup-backup", "Backup Migration", "1.3.6"),
    ("tatsu", "Tatsu", "3.3.12"),
    ("revslider", "Slider Revolution", "4.6.0"),
    ("mstore-api", "MStore API", "3.9.2"),
    ("forminator", "Forminator", "1.24.6"),
    ("wp-google-maps", "WP Go Maps", "9.0.15"),
    ("ninja-forms", "Ninja Forms", "3.6.10"),
    ("profile-builder", "Profile Builder", "3.9.0"),
    ("wp-user-avatar", "ProfilePress", "3.1.3"),
    (
        "beautiful-cookie-consent-banner",
        "Beautiful Cookie Consent Banner",
        "2.10.1",
    ),
    // Asked for by scanners we have already seen on this host.
    ("gamipress", "GamiPress", "6.6.0"),
    ("userswp", "UsersWP", "1.2.3"),
    ("wp-ticket", "WP Ticket", "5.0.4"),
    ("hellopress", "HelloPress", "1.0.0"),
    // Ordinary furniture, so the install reads as a real site.
    ("akismet", "Akismet Anti-Spam", "4.1.9"),
    ("wordpress-seo", "Yoast SEO", "16.7"),
    ("woocommerce", "WooCommerce", "5.5.0"),
    ("jetpack", "Jetpack", "9.8"),
    ("elementor", "Elementor", "3.5.4"),
    ("classic-editor", "Classic Editor", "1.6"),
    ("wp-super-cache", "WP Super Cache", "1.7.1"),
    ("all-in-one-wp-migration", "All-in-One WP Migration", "7.62"),
    ("wp-statistics", "WP Statistics", "13.1.5"),
];

/// Version served for a plugin we have no entry for. Low enough to precede any
/// advisory a scanner might hold, and stable per slug so repeat probes agree.
const UNKNOWN_PLUGIN_VERSION: &str = "1.0.2";

/// A WordPress plugin `readme.txt`. Scanners fingerprint installed plugins by
/// fetching this file and parsing `Stable tag:` — serving a plausible,
/// outdated tag converts a dead-end 404 probe into an exploit attempt we can
/// capture on the `/wp-content/` and `/wp-admin/` routes.
pub(super) fn plugin_readme_txt(slug: &str) -> String {
    let (name, version) = KNOWN_PLUGINS
        .iter()
        .find(|(s, _, _)| *s == slug)
        .map(|(_, n, v)| ((*n).to_owned(), *v))
        .unwrap_or_else(|| (pretty_slug(slug), UNKNOWN_PLUGIN_VERSION));
    let prev = previous_version(version);
    format!(
        "=== {name} ===\n\
         Contributors: {slug}\n\
         Tags: {slug}, wordpress, admin\n\
         Requires at least: 4.7\n\
         Tested up to: 5.8\n\
         Requires PHP: 5.6\n\
         Stable tag: {version}\n\
         License: GPLv2 or later\n\
         License URI: https://www.gnu.org/licenses/gpl-2.0.html\n\n\
         {name} for WordPress.\n\n\
         == Description ==\n\n\
         {name} adds functionality to your WordPress site.\n\n\
         == Installation ==\n\n\
         1. Upload the plugin files to `/wp-content/plugins/{slug}`.\n\
         2. Activate the plugin through the 'Plugins' screen in WordPress.\n\n\
         == Changelog ==\n\n\
         = {version} =\n* Maintenance release.\n\n\
         = {prev} =\n* Fixed a compatibility issue.\n"
    )
}

/// A WordPress theme `style.css` header. Theme fingerprinting is the same probe
/// as plugin fingerprinting with a different file, and reaches the honeypot on
/// the existing `/wp-content/` route.
pub(super) fn theme_style_css(slug: &str) -> String {
    let name = pretty_slug(slug);
    format!(
        "/*\n\
         Theme Name: {name}\n\
         Theme URI: https://wordpress.org/themes/{slug}/\n\
         Author: the WordPress team\n\
         Description: {name} theme.\n\
         Version: 1.4\n\
         Requires at least: 4.7\n\
         Tested up to: 5.8\n\
         Requires PHP: 5.6\n\
         License: GNU General Public License v2 or later\n\
         Text Domain: {slug}\n\
         */\n"
    )
}

/// WordPress core's `readme.html`, the oldest and most-probed version
/// fingerprint there is. Kept consistent with `WP_VERSION_PHP` — a scanner that
/// reads 5.8.1 here and something else there learns it is being played with.
pub(super) const WP_README_HTML: &str = r#"<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width" />
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>WordPress &rsaquo; ReadMe</title>
</head>
<body>
<h1 id="logo">WordPress</h1>
<p style="text-align: center">Semantic Personal Publishing Platform</p>
<h2>First Things First</h2>
<p>Welcome. WordPress is a very special project to me.</p>
<h2>Installation: Famous 5-minute install</h2>
<ol>
<li>Unzip the package in an empty directory and upload everything.</li>
<li>Open <span class="file">wp-admin/install.php</span> in your browser.</li>
</ol>
<p>Version 5.8.1</p>
</body>
</html>"#;

/// `bookingpress-appointment-booking` -> `Bookingpress Appointment Booking`.
fn pretty_slug(slug: &str) -> String {
    slug.split(['-', '_'])
        .filter(|s| !s.is_empty())
        .map(|w| {
            let mut c = w.chars();
            match c.next() {
                Some(f) => f.to_ascii_uppercase().to_string() + c.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// `1.2.1` -> `1.2.0`; anything that does not end in a number is returned with a
/// `.0` suffix so the changelog still lists two entries.
fn previous_version(version: &str) -> String {
    match version.rsplit_once('.') {
        Some((head, last)) => match last.parse::<u32>() {
            Ok(0) => head.to_string(),
            Ok(n) => format!("{head}.{}", n - 1),
            Err(_) => format!("{version}.0"),
        },
        None => format!("{version}.0"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wp_login_form_has_required_fields() {
        assert!(WP_LOGIN_FORM_HTML.contains(r#"form name="loginform""#));
        assert!(WP_LOGIN_FORM_HTML.contains(r#"name="log""#));
        assert!(WP_LOGIN_FORM_HTML.contains(r#"name="pwd""#));
        assert!(WP_LOGIN_FORM_HTML.contains(r#"name="wp-submit""#));
        assert!(WP_LOGIN_FORM_HTML.contains(r#"value="Log In""#));
        assert!(WP_LOGIN_FORM_HTML.contains(r#"name="redirect_to""#));
        assert!(WP_LOGIN_FORM_HTML.contains(r#"value="/wp-admin/""#));
        assert!(WP_LOGIN_FORM_HTML.contains(r#"name="testcookie""#));
        assert!(WP_LOGIN_FORM_HTML.contains(r#"action="/wp-login.php""#));
    }

    #[test]
    fn wp_login_error_has_error_div() {
        assert!(WP_LOGIN_FORM_ERROR_HTML.contains(r#"id="login_error""#));
        assert!(WP_LOGIN_FORM_ERROR_HTML.contains(r#"form name="loginform""#));
    }

    #[test]
    fn wp_setup_config_has_db_credential_fields() {
        assert!(WP_SETUP_CONFIG_HTML.contains(r#"name="dbname""#));
        assert!(WP_SETUP_CONFIG_HTML.contains(r#"name="uname""#));
        assert!(WP_SETUP_CONFIG_HTML.contains(r#"name="pwd""#));
        assert!(WP_SETUP_CONFIG_HTML.contains(r#"name="dbhost""#));
        assert!(WP_SETUP_CONFIG_HTML.contains(r#"action="/wp-admin/setup-config.php?step=2""#));
    }

    #[test]
    fn wp_setup_config_done_funnel_links_to_install() {
        assert!(WP_SETUP_CONFIG_DONE_HTML.contains(r#"href="/wp-admin/install.php""#));
        assert!(WP_SETUP_CONFIG_DONE_HTML.contains("Run the install"));
    }

    #[test]
    fn wp_welcome_form_matches_core_field_names() {
        // Kits fill the famous five-minute form by field NAME — these must
        // match WordPress core exactly.
        for field in [
            "weblog_title",
            "user_name",
            "admin_password2",
            "admin_password",
            "pw_weak",
            "admin_email",
            "blog_public",
            "language",
        ] {
            assert!(
                WP_WELCOME_HTML.contains(&format!(r#"name="{field}""#)),
                "welcome form missing field {field}"
            );
        }
        assert!(WP_WELCOME_HTML.contains(r#"action="/wp-admin/install.php?step=2""#));
        assert!(WP_WELCOME_HTML.contains(r#"value="Install WordPress""#));
    }

    #[test]
    fn install_success_page_echoes_username_and_masks_password() {
        let html = wp_install_success_html("k1tt3n_l0rd");
        assert!(html.contains("Success!"));
        assert!(html.contains("<td>k1tt3n_l0rd</td>"));
        assert!(html.contains("Your chosen password."));
        // The password is never echoed back — real WP masks a chosen password.
        assert!(html.contains(r#"href="/wp-login.php""#));
    }

    #[test]
    fn install_success_page_escapes_hostile_usernames() {
        let html = wp_install_success_html(r#"<script>alert(1)</script>"#);
        assert!(
            !html.contains("<script>alert"),
            "raw markup must not survive"
        );
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn html_escape_covers_the_dangerous_five() {
        assert_eq!(html_escape(r#"&<>"'"#), "&amp;&lt;&gt;&quot;&#39;");
        assert_eq!(html_escape("plain"), "plain");
    }

    #[test]
    fn xmlrpc_fault_body_is_valid_xml_shape() {
        assert!(XMLRPC_FAULT_BODY.contains("<methodResponse>"));
        assert!(XMLRPC_FAULT_BODY.contains("<fault>"));
        assert!(XMLRPC_FAULT_BODY.contains("<int>"));
        assert!(XMLRPC_FAULT_BODY.contains("<string>"));
    }
}
