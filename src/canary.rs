use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::Mutex;

/// Posts an XML-RPC content-injection probe asked us to publish.
///
/// The observed probes inject a unique hex token as the post title and body,
/// then search the web for it: if it turns up, the site accepts unauthenticated
/// publishing and gets added to a spam farm. Reporting success and then
/// actually serving the token back is what earns the follow-up visit — and the
/// follow-up is the real payload.
///
/// **The content is served only to the IP that injected it, and only with
/// `X-Robots-Tag: noindex`.** Attacker-supplied content reachable by anyone
/// else, or indexable, would make this service a spam relay for whatever they
/// inject next. It is also escaped, never rendered as markup.
pub type CanaryPosts = Mutex<HashMap<u32, (IpAddr, String)>>;

/// Bounded so a flood of injections cannot grow the map without limit.
const MAX_CANARY_POSTS: usize = 512;

pub fn new_canary_posts() -> CanaryPosts {
    Mutex::new(HashMap::new())
}

/// Store an injected post and return the id reported back to the caller.
pub fn store_post(store: &CanaryPosts, ip: &IpAddr, content: &str) -> u32 {
    let mut map = store.lock().expect("canary post store poisoned");
    if map.len() >= MAX_CANARY_POSTS {
        map.clear();
    }
    // WordPress post ids are small sequential integers; a random-looking one
    // would be the tell.
    let id = 1000 + u32::try_from(map.len()).unwrap_or(0) * 3 + 7;
    map.insert(id, (*ip, content.to_owned()));
    id
}

/// Retrieve an injected post — only for the IP that injected it.
pub fn fetch_post(store: &CanaryPosts, id: u32, ip: &IpAddr) -> Option<String> {
    let map = store.lock().expect("canary post store poisoned");
    map.get(&id)
        .filter(|(owner, _)| owner == ip)
        .map(|(_, content)| content.clone())
}

/// Render an injected post as a WordPress single-post page. The content is
/// HTML-escaped: it is attacker-supplied, and the point is that they can find
/// their token, not that they can execute markup.
pub fn render_post(id: u32, content: &str) -> String {
    let safe = crate::templates::html_escape(content);
    format!(
        r##"<!DOCTYPE html><html lang="en-US"><head><meta charset="UTF-8">
<meta name="robots" content="noindex, nofollow">
<title>{safe} &#8211; Site</title></head>
<body class="post-template-default single single-post postid-{id}">
<div id="page"><main id="main"><article id="post-{id}" class="post-{id} post type-post status-publish">
<header class="entry-header"><h1 class="entry-title">{safe}</h1></header>
<div class="entry-content"><p>{safe}</p></div>
</article></main></div></body></html>"##
    )
}

fn canary_token(ip: &IpAddr, label: &str) -> String {
    let mut h = DefaultHasher::new();
    ip.hash(&mut h);
    h.write(label.as_bytes());
    format!("{:016x}", h.finish())
}

pub fn admin_dashboard(ip: &IpAddr) -> String {
    let links = [
        ("Dashboard", "/wp-admin/index.php"),
        ("Posts", "/wp-admin/edit.php"),
        ("Media", "/wp-admin/upload.php"),
        ("Pages", "/wp-admin/edit.php?post_type=page"),
        ("Comments", "/wp-admin/edit-comments.php"),
        ("Appearance", "/wp-admin/themes.php"),
        ("Plugins", "/wp-admin/plugins.php"),
        ("Users", "/wp-admin/users.php"),
        ("Tools", "/wp-admin/tools.php"),
        ("Settings", "/wp-admin/options-general.php"),
        ("Plugin Editor", "/wp-admin/plugin-editor.php"),
        ("Theme Editor", "/wp-admin/theme-editor.php"),
    ];

    let menu: String = links
        .iter()
        .map(|(label, href)| {
            let token = canary_token(ip, label);
            format!(r#"<li><a href="{href}?fk={token}">{label}</a></li>"#)
        })
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r##"<!DOCTYPE html><html><head><title>Dashboard ‹ Site — WordPress</title>
<style>body{{font-family:sans-serif;margin:0}}#adminmenu{{list-style:none;padding:0;width:160px;background:#1d2327;min-height:100vh;position:fixed;top:0;left:0;margin:0}}#adminmenu a{{color:#ffffff;display:block;padding:10px 12px;text-decoration:none;border-bottom:1px solid rgba(255,255,255,.08)}}#adminmenu a:hover{{background:#2271b1}}#wpcontent{{margin-left:160px;padding:20px}}.wrap h1{{font-size:23px;font-weight:400}}</style></head>
<body>
<ul id="adminmenu">{menu}</ul>
<div id="wpcontent"><div class="wrap"><h1>Dashboard</h1><p>Welcome to your WordPress Dashboard!</p></div></div>
</body></html>"##
    )
}

#[cfg(test)]
mod canary_post_tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn post_is_served_only_to_the_injecting_ip() {
        let store = new_canary_posts();
        let attacker = ip("203.0.113.5");
        let id = store_post(&store, &attacker, "0x377fe0d7");
        assert_eq!(
            fetch_post(&store, id, &attacker).as_deref(),
            Some("0x377fe0d7")
        );
        assert_eq!(
            fetch_post(&store, id, &ip("198.51.100.9")),
            None,
            "must never serve injected content to a third party"
        );
        assert_eq!(fetch_post(&store, 999_999, &attacker), None);
    }

    #[test]
    fn store_is_bounded() {
        let store = new_canary_posts();
        let a = ip("203.0.113.5");
        for i in 0..(MAX_CANARY_POSTS + 10) {
            store_post(&store, &a, &format!("c{i}"));
        }
        assert!(store.lock().unwrap().len() <= MAX_CANARY_POSTS);
    }

    #[test]
    fn rendered_post_is_noindex_and_escaped() {
        let page = render_post(1007, "<script>alert(1)</script>");
        assert!(page.contains("noindex, nofollow"));
        assert!(
            !page.contains("<script>"),
            "attacker markup must not render"
        );
        assert!(page.contains("&lt;script&gt;"));
    }
}
