use axum::body::Bytes;
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::parsers::{body_to_string, extract_form_field};
use crate::sink;
use crate::{Error, HoneypotState};

const DRUPAL_LOGIN_HTML: &str = r##"<html><head><title>Log in | Site</title></head><body>
<form class="user-login-form" action="/user/login" method="post" id="user-login-form" accept-charset="UTF-8">
<div><div class="form-item form-type-textfield form-item-name">
<label for="edit-name">Username <span class="form-required" title="This field is required.">*</span></label>
<input type="text" id="edit-name" name="name" value="" size="60" maxlength="60" class="form-text required" required="required" aria-required="true" autocorrect="none" autocapitalize="none" spellcheck="false" autofocus="autofocus" />
</div>
<div class="form-item form-type-password form-item-pass">
<label for="edit-pass">Password <span class="form-required" title="This field is required.">*</span></label>
<input type="password" id="edit-pass" name="pass" size="60" maxlength="128" class="form-text required" required="required" aria-required="true" />
</div>
<input autocomplete="off" type="hidden" name="form_build_id" value="form-QzR5nD8sVwYbAkLp3HxT" />
<input type="hidden" name="form_id" value="user_login_form" />
<input type="hidden" name="form_token" value="vK4R9gD8wYbAkLp3HxT" />
<div class="form-actions form-wrapper" id="edit-actions"><input type="submit" id="edit-submit" name="op" value="Log in" class="button js-form-submit form-submit" /></div>
</form></div></body></html>"##;

const JOOMLA_LOGIN_HTML: &str = r##"<html><head><title>Administration - Login</title></head><body>
<form action="/administrator/index.php" method="post" name="adminForm" id="form-login" class="form-inline">
<div class="control-group"><div class="controls">
<div class="input-prepend"><span class="add-on"><i class="icon-user"></i></span>
<input type="text" name="username" class="form-control" placeholder="Username" size="25" autocomplete="off" /></div></div></div>
<div class="control-group"><div class="controls">
<div class="input-prepend"><span class="add-on"><i class="icon-lock"></i></span>
<input type="password" name="passwd" class="form-control" placeholder="Password" size="25" autocomplete="off" /></div></div></div>
<input type="hidden" name="task" value="login" />
<input type="hidden" name="option" value="com_login" />
<input type="hidden" name="return" value="aW5kZXgucGhw" />
<input type="hidden" name="dead92e3e7d7419dba8b498009781b54" value="1" />
<div class="control-group"><div class="controls"><button type="submit" class="btn btn-primary btn-large">Log in</button></div></div>
</form></body></html>"##;

const DJANGO_LOGIN_HTML: &str = r##"<html><head><title>Log in | Django site admin</title></head><body>
<div id="content-main">
<form action="/admin/login/" method="post" id="login-form">
<input type="hidden" name="csrfmiddlewaretoken" value="abc123def456ghi789jkl012mno345pqr678stu" />
<input type="hidden" name="next" value="/admin/" />
<table>
<tr><td><label for="id_username">Username:</label></td>
<td><input type="text" name="username" autofocus autocapitalize="none" autocomplete="username" maxlength="150" required id="id_username" /></td></tr>
<tr><td><label for="id_password">Password:</label></td>
<td><input type="password" name="password" autocomplete="current-password" required id="id_password" />
<input type="hidden" name="next" value="/admin/" /></td></tr>
</table>
<div class="submit-row"><input type="submit" value="Log in" /></div>
</form></div></body></html>"##;

/// phpMyAdmin's login form. Seven spellings of the install path were probed
/// (`/phpmyadmin/`, `/pma/`, `/PMA/`, `/phpMyAdmin-2/`, ...), all answering
/// 404. Credentials submitted here are database credentials, which are worth
/// more than a WordPress admin login: they are commonly reused across hosts.
const PHPMYADMIN_LOGIN_HTML: &str = r##"<html><head><title>phpMyAdmin</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body class="loginform"><div class="container"><a href="#" class="logo">phpMyAdmin</a>
<h1>Welcome to <bdo dir="ltr" lang="en">phpMyAdmin</bdo></h1>
<form method="post" id="login_form" action="index.php?route=/" name="login_form" class="disableAjax login hide js-show">
<fieldset><legend lang="en" dir="ltr">Log in<a href="doc/html/index.html" target="documentation"></a></legend>
<div class="item"><label for="input_servername">Server:</label>
<input type="text" name="pma_servername" id="input_servername" value="localhost" size="24" class="textfield" /></div>
<div class="item"><label for="input_username">Username:</label>
<input type="text" name="pma_username" id="input_username" value="" size="24" class="textfield" autocomplete="username" /></div>
<div class="item"><label for="input_password">Password:</label>
<input type="password" name="pma_password" id="input_password" value="" size="24" class="textfield" autocomplete="current-password" /></div>
<input type="hidden" name="server" value="1" />
<input type="hidden" name="token" value="9f1c4e7a2b8d3f6019ae5c7b4d2f8a13" />
</fieldset><fieldset class="tblFooters"><input class="btn btn-primary" value="Go" type="submit" id="input_go" /></fieldset>
</form><div class="footer"><a href="https://www.phpmyadmin.net/">phpMyAdmin 5.2.1</a></div></div></body></html>"##;

/// True when this path is one of the phpMyAdmin install spellings scanners
/// sweep. Matched on the first segment so `/pma/index.php` and `/pma/` both
/// resolve.
pub fn is_phpmyadmin(path: &str) -> bool {
    let first = path.trim_start_matches('/').split('/').next().unwrap_or("");
    let f = first.to_ascii_lowercase();
    matches!(
        f.as_str(),
        "phpmyadmin"
            | "phpmyadmin2"
            | "phpmyadmin-2"
            | "phpmyadmin3"
            | "phpmyadmin4"
            | "pma"
            | "pmd"
            | "dbadmin"
            | "mysql"
            | "sqlmanager"
            | "myadmin"
    ) || path.eq_ignore_ascii_case("/adminer.php")
}

pub async fn cms_login(
    State(state): State<HoneypotState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    method: Method,
    body: Bytes,
) -> Result<Response, Error> {
    let path = uri.path();
    let (form_html, user_field, pass_field) = match path {
        "/user/login" => (DRUPAL_LOGIN_HTML, "name", "pass"),
        "/administrator/index.php" => (JOOMLA_LOGIN_HTML, "username", "passwd"),
        "/admin/login" | "/admin/login/" => (DJANGO_LOGIN_HTML, "username", "password"),
        p if is_phpmyadmin(p) => (PHPMYADMIN_LOGIN_HTML, "pma_username", "pma_password"),
        _ => return Ok(StatusCode::NOT_FOUND.into_response()),
    };

    match method {
        Method::GET | Method::HEAD => {
            sink::log_event(
                &state,
                &headers,
                &method,
                path,
                uri.query(),
                None,
                None,
                None,
                200,
                0,
            )
            .await?;
            Ok(axum::response::Html(form_html).into_response())
        }
        Method::POST => {
            let body_str = body_to_string(&body);
            let user = extract_form_field(&body_str, user_field);
            let pass = extract_form_field(&body_str, pass_field);
            sink::trap_and_record(&state, &headers, path, &body_str, user, pass, form_html).await
        }
        _ => Ok(StatusCode::METHOD_NOT_ALLOWED.into_response()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_the_probed_phpmyadmin_spellings() {
        for p in [
            "/phpmyadmin/index.php",
            "/phpMyAdmin/index.php",
            "/phpmyadmin2/index.php",
            "/phpMyAdmin-2/index.php",
            "/PMA/index.php",
            "/pma/index.php",
            "/dbadmin/",
            "/adminer.php",
        ] {
            assert!(is_phpmyadmin(p), "{p} should serve the pma form");
        }
    }

    #[test]
    fn does_not_claim_unrelated_paths() {
        for p in ["/wp-login.php", "/user/login", "/.env", "/phpinfo.php"] {
            assert!(!is_phpmyadmin(p), "{p} must not serve the pma form");
        }
    }

    #[test]
    fn phpmyadmin_form_has_the_real_field_names() {
        // Kits post pma_username/pma_password; wrong names mean no capture.
        assert!(PHPMYADMIN_LOGIN_HTML.contains(r#"name="pma_username""#));
        assert!(PHPMYADMIN_LOGIN_HTML.contains(r#"name="pma_password""#));
        assert!(PHPMYADMIN_LOGIN_HTML.contains(r#"name="pma_servername""#));
    }
}
