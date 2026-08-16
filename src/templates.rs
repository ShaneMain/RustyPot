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
