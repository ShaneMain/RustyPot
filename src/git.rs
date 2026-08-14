use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::sink;
use crate::{Error, HoneypotState};

const GIT_CONFIG: &str = "[core]\n\
\trepositoryformatversion = 0\n\
\tfilemode = true\n\
\tbare = false\n\
\tlogallrefupdates = true\n\
[remote \"origin\"]\n\
\turl = https://github.com/fake-org/fake-repo.git\n\
\tfetch = +refs/heads/*:refs/remotes/origin/*\n\
[branch \"main\"]\n\
\tremote = origin\n\
\tmerge = refs/heads/main\n";

const GIT_HEAD: &str = "ref: refs/heads/main\n";
const GIT_MAIN_SHA: &str = "3d8f2a1b9c4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a";

fn sha_from_seed(seed: &str) -> String {
    let mut h = DefaultHasher::new();
    seed.hash(&mut h);
    let v1 = h.finish();
    h.write(b"-salt");
    let v2 = h.finish();
    format!("{v1:016x}{v2:016x}0000000000")
}

fn html_listing(title: &str, entries: &[String]) -> String {
    let links: Vec<String> = entries
        .iter()
        .map(|e| format!(r#"<a href="{e}">{e}</a>"#))
        .collect();
    format!(
        "<html><head><title>Index of {title}</title></head><body bgcolor=\"white\">\n\
         <h1>Index of {title}</h1><hr><pre><a href=\"../\">../</a>\n{}\n</pre><hr>\n\
         <address>Apache/2.4.58 Server at localhost Port 80</address>\n</body></html>",
        links.join("\n")
    )
}

fn html_pre(text: &str) -> String {
    format!("<html><body bgcolor=\"white\"><pre>{text}</pre></body></html>")
}

pub async fn git_honeytrap(
    State(state): State<HoneypotState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    method: Method,
) -> Result<Response, Error> {
    let path = uri.path();
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

    if path.ends_with(".pack") || path.ends_with(".idx") {
        let mut data = vec![b'P', b'A', b'C', b'K', 0, 0, 0, 2];
        data.extend(&0u32.to_be_bytes());
        data.resize(8192, 0);
        return Ok((
            StatusCode::OK,
            [("content-type", "application/octet-stream")],
            data,
        )
            .into_response());
    }

    let body = match path {
        "/.git/config" => html_pre(GIT_CONFIG),
        "/.git/HEAD" => html_pre(GIT_HEAD),
        "/.git/refs/heads/main" => html_pre(&format!("{}\n", GIT_MAIN_SHA)),
        "/.git/description" => html_pre("Unnamed repository; edit this file 'description' to name the repository.\n"),
        "/.git/COMMIT_EDITMSG" => html_pre("Initial commit\n"),
        "/.git/logs/HEAD" => html_pre(&format!(
            "0000000000000000000000000000000000000000 {GIT_MAIN_SHA} 1700000000+0000\tUser <user@fake-repo.com>\tcommit: Initial commit\n"
        )),
        "/.git/" | "/.git" => html_listing(path, &["HEAD", "config", "description", "logs/", "objects/", "refs/"].into_iter().map(String::from).collect::<Vec<_>>()),
        "/.git/refs/" | "/.git/refs/heads/" => html_listing(path, &["main".to_string()]),
        "/.git/logs/" => html_listing(path, &["HEAD".to_string(), "refs/".to_string()]),
        "/.git/objects/" => {
            let entries: Vec<String> = (0..16).map(|i| format!("{i:02x}/")).collect();
            html_listing(path, &entries)
        }
        "/.git/objects/pack/" => {
            let s = sha_from_seed("pack-1");
            html_listing(path, &[format!("pack-{s}.idx"), format!("pack-{s}.pack")])
        }
        p if p.starts_with("/.git/objects/") && p.ends_with('/') => {
            let parent = p.trim_start_matches("/.git/objects/");
            let entries: Vec<String> = (0..10).map(|i| sha_from_seed(&format!("{parent}-{i}"))).collect();
            html_listing(path, &entries)
        }
        p if p.starts_with("/.git/objects/") => {
            let sha = p.rsplit('/').next().unwrap_or("0000");
            let d1 = &sha_from_seed(&format!("{sha}-1"))[..2];
            let d2 = &sha_from_seed(&format!("{sha}-2"))[..2];
            let d3 = &sha_from_seed(&format!("{sha}-3"))[..2];
            html_listing(path, &[format!("{d1}/"), format!("{d2}/"), format!("{d3}/")])
        }
        _ => return Ok(StatusCode::NOT_FOUND.into_response()),
    };

    Ok((
        StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        body,
    )
        .into_response())
}
