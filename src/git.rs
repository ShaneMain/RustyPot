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
    format!("{:040x}", h.finish())
}

fn listing(title: &str, entries: &[String]) -> String {
    let links: Vec<String> = entries
        .iter()
        .map(|e| format!(r#"<a href="{e}">{e}</a>"#))
        .collect();
    format!(
        "<html><head><title>Index of {title}</title></head><body>\n\
         <h1>Index of {title}</h1><hr><pre><a href=\"../\">../</a>\n{}\n</pre><hr></body></html>",
        links.join("\n")
    )
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
        return Ok((
            StatusCode::OK,
            [("content-type", "application/octet-stream")],
            vec![0u8; 4096],
        )
            .into_response());
    }

    let body = match path {
        "/.git/config" => GIT_CONFIG.to_owned(),
        "/.git/HEAD" => GIT_HEAD.to_owned(),
        "/.git/refs/heads/main" => format!("{}\n", GIT_MAIN_SHA),
        "/.git/description" => "Unnamed repository; edit this file 'description' to name the repository.\n".to_owned(),
        "/.git/COMMIT_EDITMSG" => "Initial commit\n".to_owned(),
        "/.git/logs/HEAD" => format!(
            "0000000000000000000000000000000000000000 {GIT_MAIN_SHA} 1700000000+0000\tUser <user@fake-repo.com>\tcommit: Initial commit\n"
        ),
        "/.git/" | "/.git" => listing(path, &["HEAD", "config", "description", "logs/", "objects/", "refs/"].into_iter().map(String::from).collect::<Vec<_>>()),
        "/.git/refs/" | "/.git/refs/heads/" => listing(path, &["main".to_string()]),
        "/.git/logs/" => listing(path, &["HEAD".to_string(), "refs/".to_string()]),
        "/.git/objects/" => {
            let entries: Vec<String> = (0..16).map(|i| format!("{i:02x}/")).collect();
            listing(path, &entries)
        }
        "/.git/objects/pack/" => {
            let s = sha_from_seed("pack-1");
            listing(path, &[format!("pack-{s}.idx"), format!("pack-{s}.pack")])
        }
        p if p.starts_with("/.git/objects/") && p.ends_with('/') => {
            let parent = p.trim_start_matches("/.git/objects/");
            let entries: Vec<String> = (0..10).map(|i| sha_from_seed(&format!("{parent}-{i}"))).collect();
            listing(path, &entries)
        }
        p if p.starts_with("/.git/objects/") => {
            let sha = p.rsplit('/').next().unwrap_or("0000");
            let d1 = &sha_from_seed(&format!("{sha}-1"))[..2];
            let d2 = &sha_from_seed(&format!("{sha}-2"))[..2];
            let d3 = &sha_from_seed(&format!("{sha}-3"))[..2];
            format!(
                "tree {GIT_MAIN_SHA}\n\
                 author User <user@fake-repo.com> 1700000000 +0000\n\
                 committer User <user@fake-repo.com> 1700000000 +0000\n\n\
                 objects: {d1}/ {d2}/ {d3}/\n"
            )
        }
        _ => return Ok(StatusCode::NOT_FOUND.into_response()),
    };

    Ok((
        StatusCode::OK,
        [("content-type", "text/plain; charset=utf-8")],
        body,
    )
        .into_response())
}
