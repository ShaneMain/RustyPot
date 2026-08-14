use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;

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
