//! Embedded web UI. `web/dist` is compiled into the binary at build time
//! (see build.rs — an empty dir is fine, the UI is then disabled unless
//! `server.web_dir` points at a real directory).

use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    response::Response,
};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "../../web/dist"]
struct WebAssets;

/// True when the binary actually contains UI assets.
pub fn has_assets() -> bool {
    WebAssets::iter().next().is_some()
}

/// SPA fallback handler: serve the requested file if embedded, otherwise
/// index.html. Registered as the router fallback so API routes always win.
pub async fn fallback(req: Request<Body>) -> Response {
    let path = req.uri().path().trim_start_matches('/');
    let file = WebAssets::get(path).or_else(|| WebAssets::get("index.html"));
    match file {
        Some(f) => {
            let mime = mime_guess::from_path(if path.is_empty() { "index.html" } else { path })
                .first_or_octet_stream();
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, mime.as_ref())
                .header(header::CACHE_CONTROL, "no-cache")
                .body(Body::from(f.data.into_owned()))
                .unwrap()
        }
        None => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::empty())
            .unwrap(),
    }
}
