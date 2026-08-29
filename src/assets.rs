//! Static WordPress assets.
//!
//! A real WordPress always serves `wp-includes/js/jquery/jquery.js` and the
//! core stylesheets. Scanners fetch them to confirm the install is genuine
//! before spending effort on it — and this service used to 404 them, which
//! told any bot that checked that the WordPress around it was fake. Serving
//! them is pure credibility: it costs nothing and protects every other trap.
//!
//! The payloads are plausible rather than byte-exact. Bots check status,
//! content-type and the leading banner; none of them diff the minified body.

use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::sink::log_event;
use crate::{Error, HoneypotState};

const JQUERY_VERSION: &str = "3.7.1";

/// jQuery's real banner, then enough plausible minified body to look like the
/// library. The banner is what a version-fingerprinting scanner reads.
fn jquery_js() -> String {
    format!(
        "/*! jQuery v{JQUERY_VERSION} | (c) OpenJS Foundation and other contributors | jquery.org/license */\n\
         !function(e,t){{\"use strict\";\"object\"==typeof module&&\"object\"==typeof module.exports?\
         module.exports=e.document?t(e,!0):function(e){{if(!e.document)throw new Error(\"jQuery requires a window with a document\");\
         return t(e)}}:t(e)}}(\"undefined\"!=typeof window?window:this,function(e,t){{\"use strict\";\
         var n=[],r=Object.getPrototypeOf,i=n.slice,o=n.flat?function(e){{return n.flat.call(e)}}:function(e){{return n.concat.apply([],e)}},\
         s=n.push,a=n.indexOf,u={{}},l=u.toString,c=u.hasOwnProperty,f=c.toString,p=f.call(Object),d={{}},\
         h=function(e){{return\"function\"==typeof e&&\"number\"!=typeof e.nodeType&&\"function\"!=typeof e.item}},\
         g=function(e){{return null!=e&&e===e.window}},v=e.document,y={{type:!0,src:!0,nonce:!0,noModule:!0}};\
         var m=\"{JQUERY_VERSION}\",b=function(e,t){{return new b.fn.init(e,t)}};\
         b.fn=b.prototype={{jquery:m,constructor:b,length:0}};return b}});\n"
    )
}

const JQUERY_MIGRATE_JS: &str = "/*! jQuery Migrate v3.4.1 | (c) OpenJS Foundation and other contributors | jquery.org/license */\n\
!function(e){\"use strict\";e.migrateVersion=\"3.4.1\"}(jQuery);\n";

const BUTTONS_CSS: &str = "/*! This file is auto-generated */\n\
.wp-core-ui .button,.wp-core-ui .button-primary,.wp-core-ui .button-secondary{\
display:inline-block;text-decoration:none;font-size:13px;line-height:2.15384615;\
min-height:30px;margin:0;padding:0 10px;cursor:pointer;border-width:1px;border-style:solid;\
-webkit-appearance:none;border-radius:3px;white-space:nowrap;box-sizing:border-box}\n\
.wp-core-ui .button-primary{background:#2271b1;border-color:#2271b1;color:#fff}\n";

const DASHICONS_CSS: &str = "/*! This file is auto-generated */\n\
@font-face{font-family:dashicons;src:url(../fonts/dashicons.eot);\
src:url(../fonts/dashicons.eot?#iefix) format(\"embedded-opentype\"),\
url(../fonts/dashicons.woff) format(\"woff\");font-weight:400;font-style:normal}\n";

const LOGIN_CSS: &str = "/*! This file is auto-generated */\n\
body.login{background:#f0f0f1;min-width:0;color:#3c434a}\n\
.login form{margin-top:20px;margin-left:0;padding:26px 24px;font-weight:400;\
overflow:hidden;background:#fff;border:1px solid #c3c4c7;box-shadow:0 1px 3px rgba(0,0,0,.04)}\n";

/// Known static assets, matched on the exact path. Anything not listed falls
/// through to the caller's existing behaviour.
fn asset_for(path: &str) -> Option<(&'static str, String)> {
    let js = "application/javascript; charset=UTF-8";
    let css = "text/css; charset=UTF-8";
    match path {
        "/wp-includes/js/jquery/jquery.js" | "/wp-includes/js/jquery/jquery.min.js" => {
            Some((js, jquery_js()))
        }
        "/wp-includes/js/jquery/jquery-migrate.js"
        | "/wp-includes/js/jquery/jquery-migrate.min.js" => {
            Some((js, JQUERY_MIGRATE_JS.to_owned()))
        }
        "/wp-includes/css/buttons.css" | "/wp-includes/css/buttons.min.css" => {
            Some((css, BUTTONS_CSS.to_owned()))
        }
        "/wp-includes/css/dashicons.css" | "/wp-includes/css/dashicons.min.css" => {
            Some((css, DASHICONS_CSS.to_owned()))
        }
        "/wp-admin/css/login.css" | "/wp-admin/css/login.min.css" => {
            Some((css, LOGIN_CSS.to_owned()))
        }
        _ => None,
    }
}

/// Serve a core asset if this path is one. Returns `Ok(None)` when it is not,
/// so the caller can fall back to its normal handling.
pub async fn try_serve(
    state: &HoneypotState,
    headers: &HeaderMap,
    method: &Method,
    uri: &OriginalUri,
) -> Result<Option<Response>, Error> {
    let path = uri.path();
    let Some((content_type, body)) = asset_for(path) else {
        return Ok(None);
    };
    log_event(
        state,
        headers,
        method,
        path,
        uri.query(),
        None,
        None,
        None,
        200,
        0,
    )
    .await?;
    // Real assets are cacheable; the no-cache headers the traps carry would be
    // conspicuous on a static file.
    Ok(Some(
        (
            StatusCode::OK,
            [
                (axum::http::header::CONTENT_TYPE, content_type),
                (
                    axum::http::header::CACHE_CONTROL,
                    "public, max-age=31536000",
                ),
            ],
            body,
        )
            .into_response(),
    ))
}

/// Route entry point: assets first, then the normal config-probe behaviour.
pub async fn wp_static(
    State(state): State<HoneypotState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    method: Method,
) -> Result<Response, Error> {
    let original = OriginalUri(uri.clone());
    if let Some(resp) = try_serve(&state, &headers, &method, &original).await? {
        return Ok(resp);
    }
    crate::handlers::config_probe(State(state), OriginalUri(uri), headers, method).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jquery_banner_names_a_real_version() {
        let (ct, body) = asset_for("/wp-includes/js/jquery/jquery.js").expect("jquery is served");
        assert!(ct.contains("javascript"));
        assert!(body.starts_with("/*! jQuery v3.7.1"));
        assert!(body.contains("jquery.org/license"));
    }

    #[test]
    fn minified_variants_resolve_too() {
        // Scanners request both spellings; a 404 on either is the same tell.
        for p in [
            "/wp-includes/js/jquery/jquery.min.js",
            "/wp-includes/css/buttons.min.css",
            "/wp-admin/css/login.css",
        ] {
            assert!(asset_for(p).is_some(), "{p} should be served");
        }
    }

    #[test]
    fn unknown_paths_fall_through() {
        assert!(asset_for("/wp-includes/version.php").is_none());
        assert!(asset_for("/wp-login.php").is_none());
    }
}
