use std::net::IpAddr;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::headers;
use crate::parsers::{body_to_string, extract_form_field};
use crate::sink;
use crate::sticky;
use crate::{handlers::TARPIT_DELAY_SECS, Error, HoneypotState};

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

            let ip: IpAddr = headers::extract_source_ip(&headers)
                .parse()
                .unwrap_or(IpAddr::from([0, 0, 0, 0]));
            let ip_str = headers::extract_source_ip(&headers);
            let threshold_hit = sticky::check_and_increment(&state.honeypot_tracker, &ip);
            let granted = if threshold_hit {
                match (&user, &pass) {
                    (Some(u), Some(p)) => {
                        if sink::is_granted_credential(&state.pool, u, p).await? {
                            false
                        } else {
                            sticky::reset_counter(&state.honeypot_tracker, &ip);
                            true
                        }
                    }
                    _ => false,
                }
            } else {
                false
            };
            let delay_ms = if granted {
                0
            } else {
                u32::try_from(TARPIT_DELAY_SECS * 1000).unwrap_or(0)
            };
            sink::log_event(
                &state,
                &headers,
                &Method::POST,
                path,
                None,
                Some(body_str.as_str()),
                user.as_deref(),
                pass.as_deref(),
                if granted { 302 } else { 200 },
                delay_ms,
            )
            .await?;
            if granted {
                if let (Some(ref u), Some(ref p)) = (&user, &pass) {
                    let _ = sink::record_granted_credential(&state.pool, u, p, &ip_str).await;
                }
                return Ok(sticky::fake_success_response());
            }
            tokio::time::sleep(Duration::from_secs(TARPIT_DELAY_SECS)).await;
            Ok(axum::response::Html(form_html).into_response())
        }
        _ => Ok(StatusCode::METHOD_NOT_ALLOWED.into_response()),
    }
}
