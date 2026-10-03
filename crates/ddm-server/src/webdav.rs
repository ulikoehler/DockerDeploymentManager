//! WebDAV file surface (`/dav`) over the service directories.
//!
//! Why WebDAV: it is plain HTTP, so it reuses the same listener, TLS
//! termination, reverse proxy, JWT authentication, audit log and origin
//! rules as the REST API — and it speaks real filesystem semantics
//! (`MOVE`/`COPY`/`DELETE`/`MKCOL`/`Range`), which an object API cannot.
//! Windows Explorer, macOS Finder, GNOME/KDE (gvfs), `davfs2` and
//! `rclone webdav` can all mount it.
//!
//! # Rights model
//!
//! Every request authenticates with the *same* JWT as the REST API, via
//! `Authorization: Bearer <jwt>` or — for OS clients that only do HTTP
//! Basic — `Authorization: Basic base64(<user>:<jwt>)`.
//!
//! Layered gates, each enforced server-side *and* re-checked inside the
//! privileged agent (see `agent::core`):
//!
//! 1. `webdav.enabled` must be on (off by default — this is a second write
//!    path into the service directories).
//! 2. The caller needs the `mount_files` feature (or `admin`).
//! 3. Reads need service access; writes need `edit_files` (or `admin`).
//! 4. Writes to the compose file additionally need `edit_compose` plus the
//!    caller's compose policy and the configured floor — the *same* guard
//!    the JSON file API uses, so the two cannot drift apart.
//! 5. `meta.yaml`, `backup.sh`, `.restic_*` and `.git` are denied to every
//!    method, paths are confined to the service directory, and the service
//!    root itself can never be deleted.
//!
//! Locks are advisory: held in memory, expiring, and not shared across
//! restarts or between server instances.

use crate::agent::proto::{FileMeta, SyncVerb};
use crate::auth::{bad_request, error_response, forbidden, not_found};
use crate::files::FileNode;
use crate::permissions::{can_access_service, valid_service_name};
use crate::services as svc_ops;
use crate::users::User;
use crate::AppState;
use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::response::Response;
use futures::StreamExt;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Authentication: Bearer or Basic(user:jwt)
// ---------------------------------------------------------------------------

/// Authenticated WebDAV caller: the same JWT as the REST API, plus the
/// Basic form that OS file managers can produce.
pub struct DavUser {
    pub user: User,
    pub token: String,
}

#[axum::async_trait]
impl axum::extract::FromRequestParts<AppState> for DavUser {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let raw = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| error_response(StatusCode::UNAUTHORIZED, "missing credentials"))?;
        let token = if let Some(t) = raw.strip_prefix("Bearer ") {
            t.to_string()
        } else if let Some(b64) = raw.strip_prefix("Basic ") {
            // Basic base64(user:jwt) — the password field carries the JWT.
            use base64::Engine;
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(b64.trim())
                .map_err(|_| error_response(StatusCode::UNAUTHORIZED, "bad basic auth"))?;
            let decoded = String::from_utf8(decoded)
                .map_err(|_| error_response(StatusCode::UNAUTHORIZED, "bad basic auth"))?;
            decoded
                .split_once(':')
                .map(|(_, pw)| pw.to_string())
                .ok_or_else(|| error_response(StatusCode::UNAUTHORIZED, "bad basic auth"))?
        } else {
            return Err(error_response(
                StatusCode::UNAUTHORIZED,
                "unsupported authorization scheme",
            ));
        };
        if token.is_empty() {
            return Err(error_response(StatusCode::UNAUTHORIZED, "empty token"));
        }
        // Resolve through the agent: the privileged side owns the signing key
        // and the user store, and applies the token's scope.
        let verified: serde_json::Value = state
            .agent
            .crypto(crate::agent::proto::CryptoOp::Verify {
                token: token.clone(),
            })
            .await
            .map_err(|e| error_response(StatusCode::UNAUTHORIZED, e.to_string()))?;
        let claims: crate::auth::Claims = serde_json::from_value(verified["claims"].clone())
            .map_err(|_| error_response(StatusCode::UNAUTHORIZED, "invalid token"))?;
        let mut user: User = serde_json::from_value(verified["user"].clone())
            .map_err(|_| error_response(StatusCode::UNAUTHORIZED, "unknown user"))?;
        if let Some(scope) = &claims.scope {
            crate::auth::apply_token_scope(&mut user, scope);
        }
        Ok(DavUser { user, token })
    }
}

// ---------------------------------------------------------------------------
// Locks (advisory, in-memory)
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct DavLock {
    pub token: String,
    pub depth: String,
    pub owner: String,
    pub scope: String,
    pub expires: Instant,
}

/// In-memory lock table keyed by normalized `/dav/<service>/<path>`.
#[derive(Default)]
pub struct LockStore {
    inner: Mutex<HashMap<String, DavLock>>,
}

impl LockStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn sweep(&self, map: &mut HashMap<String, DavLock>) {
        let now = Instant::now();
        map.retain(|_, l| l.expires > now);
    }

    /// The lock covering `key` — directly, or via an ancestor held at
    /// depth infinity.
    pub fn covering(&self, key: &str) -> Option<DavLock> {
        let mut map = self.inner.lock().unwrap();
        self.sweep(&mut map);
        if let Some(l) = map.get(key) {
            return Some(l.clone());
        }
        let mut cur = key.to_string();
        while let Some(idx) = cur.rfind('/') {
            cur.truncate(idx);
            if cur.is_empty() || cur == "/dav" {
                break;
            }
            if let Some(l) = map.get(&cur) {
                if l.depth == "infinity" {
                    return Some(l.clone());
                }
            }
        }
        None
    }

    pub fn put(&self, key: &str, lock: DavLock) {
        let mut map = self.inner.lock().unwrap();
        self.sweep(&mut map);
        map.insert(key.to_string(), lock);
    }

    pub fn remove(&self, key: &str) -> bool {
        self.inner.lock().unwrap().remove(key).is_some()
    }

    pub fn refresh(&self, key: &str, timeout: Duration) -> bool {
        let mut map = self.inner.lock().unwrap();
        self.sweep(&mut map);
        match map.get_mut(key) {
            Some(l) => {
                l.expires = Instant::now() + timeout;
                true
            }
            None => false,
        }
    }
}

/// Does the request present `token` in `If:` or `Lock-Token:`? Lenient
/// parse: any `<...>` token in either header counts.
fn presents_token(headers: &HeaderMap, token: &str) -> bool {
    for name in [
        header::HeaderName::from_static("if"),
        header::HeaderName::from_static("lock-token"),
    ] {
        let Some(v) = headers.get(name).and_then(|v| v.to_str().ok()) else {
            continue;
        };
        for part in v.split(['<', '>']) {
            if part.trim() == token {
                return true;
            }
        }
    }
    false
}

/// 423 when a lock exists and the caller does not present its token.
fn lock_conflict(state: &AppState, key: &str, headers: &HeaderMap) -> Option<Response> {
    let lock = state.locks.covering(key)?;
    if presents_token(headers, &lock.token) {
        None
    } else {
        Some(status(StatusCode::LOCKED))
    }
}

// ---------------------------------------------------------------------------
// Response + XML helpers
// ---------------------------------------------------------------------------

fn status(code: StatusCode) -> Response {
    dav_headers(Response::builder().status(code))
        .body(Body::empty())
        .unwrap()
}

fn dav_headers(b: axum::http::response::Builder) -> axum::http::response::Builder {
    b.header("DAV", "1, 2")
        .header("MS-Author-Via", "DAV")
        .header("Accept-Ranges", "bytes")
}

fn xml_response(code: StatusCode, body: String) -> Response {
    dav_headers(Response::builder().status(code))
        .header(header::CONTENT_TYPE, "application/xml; charset=utf-8")
        .header(header::CONTENT_LENGTH, body.len())
        .body(Body::from(body))
        .unwrap()
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Percent-encode one path segment (RFC 3986 unreserved kept).
fn enc_seg(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// `/dav/<service>/<rel>` with every segment encoded.
fn href_for(service: Option<&str>, rel: &str) -> String {
    let mut out = String::from("/dav");
    if let Some(s) = service {
        out.push('/');
        out.push_str(&enc_seg(s));
    }
    for seg in rel.split('/').filter(|s| !s.is_empty()) {
        out.push('/');
        out.push_str(&enc_seg(seg));
    }
    if service.is_some() && rel.trim_end_matches('/').is_empty() {
        out.push('/'); // collections end in a slash
    }
    out
}

fn http_date(secs: i64) -> String {
    let t = std::time::UNIX_EPOCH + Duration::from_secs(secs.max(0) as u64);
    let dt: chrono::DateTime<chrono::Utc> = t.into();
    dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

fn parse_http_date(v: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc2822(v)
        .ok()
        .map(|d| d.timestamp())
}

fn etag(meta: &FileMeta) -> String {
    format!("\"{}-{}\"", meta.mtime, meta.size)
}

fn content_type(name: &str) -> String {
    let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "yml" | "yaml" => "application/yaml",
        "json" => "application/json",
        "txt" | "md" | "log" | "env" => "text/plain; charset=utf-8",
        "sh" => "text/x-shellscript",
        "html" | "htm" => "text/html; charset=utf-8",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "svg" => "image/svg+xml",
        "pdf" => "application/pdf",
        "gz" => "application/gzip",
        "tar" => "application/x-tar",
        _ => "application/octet-stream",
    }
    .to_string()
}

/// The property set this server supports.
const PROPS: &[&str] = &[
    "resourcetype",
    "getlastmodified",
    "getetag",
    "displayname",
    "getcontenttype",
    "getcontentlength",
    "supportedlock",
    "lockdiscovery",
];

/// Build the `<D:prop>` payloads for one resource. `requested` empty means
/// `allprop`; otherwise only the requested properties are returned and
/// anything unsupported lands in the 404 propstat.
fn props_for(
    meta: &FileMeta,
    is_collection: bool,
    name: &str,
    lock: Option<&DavLock>,
    requested: &[String],
) -> (String, String) {
    let wants = |p: &str| requested.is_empty() || requested.iter().any(|r| r == p);
    // (property, xml, present?) — a collection has no content length/type.
    let items: Vec<(&str, String, bool)> = vec![
        (
            "resourcetype",
            if is_collection {
                "<D:resourcetype><D:collection/></D:resourcetype>".to_string()
            } else {
                "<D:resourcetype/>".to_string()
            },
            true,
        ),
        (
            "getlastmodified",
            format!("<D:getlastmodified>{}</D:getlastmodified>", http_date(meta.mtime)),
            true,
        ),
        ("getetag", format!("<D:getetag>{}</D:getetag>", etag(meta)), true),
        (
            "displayname",
            format!("<D:displayname>{}</D:displayname>", esc(name)),
            true,
        ),
        (
            "getcontenttype",
            format!("<D:getcontenttype>{}</D:getcontenttype>", content_type(name)),
            !is_collection,
        ),
        (
            "getcontentlength",
            format!("<D:getcontentlength>{}</D:getcontentlength>", meta.size),
            !is_collection,
        ),
        (
            "supportedlock",
            "<D:supportedlock><D:lockentry><D:lockscope><D:exclusive/></D:lockscope>\
<D:locktype><D:write/></D:locktype></D:lockentry></D:supportedlock>"
                .to_string(),
            true,
        ),
        (
            "lockdiscovery",
            match lock {
                Some(l) => format!("<D:lockdiscovery>{}</D:lockdiscovery>", active_lock_xml(l)),
                None => "<D:lockdiscovery/>".to_string(),
            },
            true,
        ),
    ];
    let mut ok = String::new();
    let mut missing = String::new();
    for (prop, xml, present) in items {
        if !wants(prop) {
            continue;
        }
        if present {
            ok.push_str(&xml);
        } else {
            missing.push_str(&empty_element(&xml));
        }
    }
    // Requested names we do not implement.
    if !requested.is_empty() {
        for r in requested {
            if !PROPS.contains(&r.as_str()) {
                missing.push_str(&format!("<D:{}/>", esc(r)));
            }
        }
    }
    (ok, missing)
}

/// `<D:foo>…</D:foo>` → `<D:foo/>` (for the 404 propstat).
fn empty_element(xml: &str) -> String {
    match xml.find('>') {
        Some(idx) if !xml[..=idx].ends_with("/>") => format!("{}/>", &xml[..idx]),
        _ => xml.to_string(),
    }
}

fn active_lock_xml(l: &DavLock) -> String {
    format!(
        "<D:activelock><D:locktype><D:write/></D:locktype>\
<D:lockscope><D:{} /></D:lockscope><D:depth>{}</D:depth>\
<D:owner>{}</D:owner><D:timeout>Second-{}</D:timeout>\
<D:locktoken><D:href>{}</D:href></D:locktoken></D:activelock>",
        l.scope,
        l.depth,
        l.owner,
        l.expires.saturating_duration_since(Instant::now()).as_secs(),
        esc(&l.token)
    )
}

fn response_xml(
    service: Option<&str>,
    rel: &str,
    meta: &FileMeta,
    is_collection: bool,
    requested: &[String],
    lock: Option<&DavLock>,
) -> String {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    let name = if name.is_empty() { "dav" } else { name };
    let (ok, missing) = props_for(meta, is_collection, name, lock, requested);
    let mut out = format!(
        "<D:response><D:href>{}</D:href><D:propstat><D:prop>{}</D:prop>\
<D:status>HTTP/1.1 200 OK</D:status></D:propstat>",
        esc(&href_for(service, rel)),
        ok
    );
    if !missing.is_empty() {
        out.push_str(&format!(
            "<D:propstat><D:prop>{}</D:prop>\
<D:status>HTTP/1.1 404 Not Found</D:status></D:propstat>",
            missing
        ));
    }
    out.push_str("</D:response>");
    out
}

fn multistatus(inner: String) -> Response {
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<D:multistatus xmlns:D=\"DAV:\">{inner}</D:multistatus>"
    );
    xml_response(StatusCode::MULTI_STATUS, body)
}

// ---------------------------------------------------------------------------
// Targets + gates
// ---------------------------------------------------------------------------

enum Target {
    /// `/dav` — the services this caller may see.
    Root,
    /// `/dav/<service>/<rel>` (`rel` empty = the service root).
    Service { name: String, rel: String },
}

fn parse_target(raw: &str) -> Result<Target, Response> {
    let raw = raw.trim_matches('/');
    if raw.is_empty() {
        return Ok(Target::Root);
    }
    let (name, rest) = match raw.split_once('/') {
        Some((n, r)) => (n, r),
        None => (raw, ""),
    };
    if !valid_service_name(name) {
        return Err(not_found("no such service"));
    }
    if rest.contains('\0') {
        return Err(bad_request("invalid path"));
    }
    Ok(Target::Service {
        name: name.to_string(),
        rel: rest.to_string(),
    })
}

/// Lock key for a target (trailing slash normalized away).
fn lock_key(service: &str, rel: &str) -> String {
    let rel = rel.trim_end_matches('/');
    if rel.is_empty() {
        format!("/dav/{service}")
    } else {
        format!("/dav/{service}/{rel}")
    }
}

/// Gate 2: may this caller use the file protocol at all?
fn require_protocol(user: &User) -> Result<(), Response> {
    if user.is_admin() || user.features.mount_files {
        Ok(())
    } else {
        Err(forbidden())
    }
}

/// Gate 3 (reads): service access.
async fn require_read(state: &AppState, user: &User, name: &str) -> Result<(), Response> {
    let cfg = state.config.get().await;
    if !can_access_service(user, name, cfg.security.default_access) {
        return Err(forbidden());
    }
    svc_ops::get_service(&cfg, name).map_err(|_| not_found("no such service"))?;
    Ok(())
}

/// Gate 3 (writes): `edit_files`. The agent re-checks access + feature.
fn require_write(user: &User) -> Result<(), Response> {
    if user.is_admin() || user.features.edit_files {
        Ok(())
    } else {
        Err(forbidden())
    }
}

/// Map an agent-side rejection onto a WebDAV status code.
fn agent_err(e: anyhow::Error) -> Response {
    let msg = format!("{e:#}");
    let code = if msg.contains("exceeds") || msg.contains("too large") {
        StatusCode::PAYLOAD_TOO_LARGE
    } else if msg.contains("not a regular file") || msg.contains("already exists") {
        StatusCode::METHOD_NOT_ALLOWED
    } else if msg.contains("does not exist") || msg.contains("no such") {
        StatusCode::NOT_FOUND
    } else if msg.contains("required")
        || msg.contains("denied")
        || msg.contains("not allowed")
        || msg.contains("violations")
        || msg.contains("escapes")
        || msg.contains("forbidden")
    {
        StatusCode::FORBIDDEN
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };
    error_response(code, msg)
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/// `/dav` — the collection of services this caller may access.
pub async fn handle_root(State(state): State<AppState>, user: DavUser, req: Request) -> Response {
    dispatch(state, user, Target::Root, req).await
}

/// `/dav/*` — anything below the root.
pub async fn handle(
    State(state): State<AppState>,
    Path(path): Path<String>,
    user: DavUser,
    req: Request,
) -> Response {
    match parse_target(&path) {
        Ok(t) => dispatch(state, user, t, req).await,
        Err(r) => r,
    }
}

async fn dispatch(state: AppState, dav: DavUser, target: Target, req: Request) -> Response {
    // Gate 1: the surface is off unless explicitly enabled.
    if !state.config.get().await.webdav.enabled {
        return status(StatusCode::NOT_FOUND);
    }
    // Gate 2: the caller must be allowed to mount files at all.
    if let Err(r) = require_protocol(&dav.user) {
        return r;
    }
    let method = req.method().clone();
    let headers = req.headers().clone();
    // PROPFIND/MKCOL/MOVE/COPY/LOCK/UNLOCK are not `http::Method`
    // constants, so dispatch on the token itself.
    match method.as_str() {
        "OPTIONS" => dav_headers(Response::builder().status(StatusCode::OK))
            .header(header::ALLOW, ALLOWED)
            .body(Body::empty())
            .unwrap(),
        "PROPFIND" => propfind(state, dav, target, &headers, req).await,
        "GET" | "HEAD" => get(state, dav, target, &headers, method == Method::HEAD).await,
        "PUT" => put(state, dav, target, &headers, req).await,
        "MKCOL" => mkcol(state, dav, target, &headers).await,
        "DELETE" => delete(state, dav, target, &headers).await,
        "MOVE" | "COPY" => move_copy(state, dav, target, &headers, method.as_str() == "MOVE").await,
        "LOCK" => lock(state, dav, target, &headers, req).await,
        "UNLOCK" => unlock(state, dav, target, &headers).await,
        // Properties (dead props, custom metadata) are not settable here.
        "PROPPATCH" => status(StatusCode::FORBIDDEN),
        _ => dav_headers(Response::builder().status(StatusCode::METHOD_NOT_ALLOWED))
            .header(header::ALLOW, ALLOWED)
            .body(Body::empty())
            .unwrap(),
    }
}

const ALLOWED: &str =
    "OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, MKCOL, MOVE, COPY, LOCK, UNLOCK";

// ---------------------------------------------------------------------------
// PROPFIND
// ---------------------------------------------------------------------------

/// Requested property names (empty = allprop).
fn requested_props(body: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(body);
    if text.trim().is_empty() || text.contains("allprop") {
        return vec![];
    }
    let mut out = vec![];
    let mut rest = text.as_ref();
    while let Some(start) = rest.find('<') {
        rest = &rest[start + 1..];
        if rest.starts_with('/') || rest.starts_with('?') || rest.starts_with('!') {
            continue;
        }
        let Some(end) = rest.find(|c: char| c == '>' || c == '/' || c.is_whitespace()) else {
            break;
        };
        let raw = &rest[..end];
        let name = raw.rsplit(':').next().unwrap_or(raw);
        if matches!(
            name,
            "propfind" | "prop" | "allprop" | "propname" | "include" | "xml"
        ) || name.is_empty()
        {
            continue;
        }
        out.push(name.to_string());
    }
    out
}

async fn propfind(
    state: AppState,
    dav: DavUser,
    target: Target,
    headers: &HeaderMap,
    req: Request,
) -> Response {
    let depth = headers
        .get("depth")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("1")
        .to_ascii_lowercase();
    if depth == "infinity" {
        // Refused: an unbounded walk is a trivial DoS on a deep tree.
        return error_response(
            StatusCode::FORBIDDEN,
            "Depth: infinity is not supported; use Depth: 0 or 1",
        );
    }
    let body = axum::body::to_bytes(req.into_body(), 64 * 1024)
        .await
        .unwrap_or_default();
    let props = requested_props(&body);

    match target {
        Target::Root => {
            let names: Vec<String> = match state
                .agent
                .call_as::<Vec<svc_ops::Service>>(SyncVerb::ServicesList, &dav.token)
                .await
            {
                Ok(list) => list.into_iter().map(|s| s.name).collect(),
                Err(e) => return agent_err(e),
            };
            let cfg = state.config.get().await;
            let root_meta = FileMeta {
                kind: "dir".into(),
                size: 0,
                mtime: 0,
            };
            let mut inner = response_xml(None, "", &root_meta, true, &props, None);
            if depth != "0" {
                for name in names {
                    // A service the caller cannot access is simply absent —
                    // no existence oracle.
                    if !can_access_service(&dav.user, &name, cfg.security.default_access) {
                        continue;
                    }
                    let Ok(meta) = state.agent.file_stat(&name, "", &dav.token).await else {
                        continue;
                    };
                    let lock = state.locks.covering(&lock_key(&name, ""));
                    inner.push_str(&response_xml(
                        Some(&name),
                        "",
                        &meta,
                        true,
                        &props,
                        lock.as_ref(),
                    ));
                }
            }
            multistatus(inner)
        }
        Target::Service { name, rel } => {
            if let Err(r) = require_read(&state, &dav.user, &name).await {
                return r;
            }
            let meta = match state.agent.file_stat(&name, &rel, &dav.token).await {
                Ok(m) => m,
                Err(e) => return agent_err(e),
            };
            let is_col = meta.kind == "dir";
            let mut inner = response_xml(
                Some(&name),
                &rel,
                &meta,
                is_col,
                &props,
                state.locks.covering(&lock_key(&name, &rel)).as_ref(),
            );
            if depth != "0" && is_col {
                let entries = match state
                    .agent
                    .call_as(
                        SyncVerb::FileNode {
                            service: name.clone(),
                            path: rel.clone(),
                        },
                        &dav.token,
                    )
                    .await
                {
                    Ok(FileNode::Dir { entries, .. }) => entries,
                    Ok(_) => vec![],
                    Err(e) => return agent_err(e),
                };
                for e in entries {
                    let child_rel = if rel.trim_end_matches('/').is_empty() {
                        e.name.clone()
                    } else {
                        format!("{}/{}", rel.trim_end_matches('/'), e.name)
                    };
                    let child_meta = FileMeta {
                        kind: e.kind.clone(),
                        size: e.size,
                        mtime: e.mtime,
                    };
                    let child_lock = state.locks.covering(&lock_key(&name, &child_rel));
                    inner.push_str(&response_xml(
                        Some(&name),
                        &child_rel,
                        &child_meta,
                        e.kind == "dir",
                        &props,
                        child_lock.as_ref(),
                    ));
                }
            }
            multistatus(inner)
        }
    }
}

// ---------------------------------------------------------------------------
// GET / HEAD
// ---------------------------------------------------------------------------

enum RangeSpec {
    /// `bytes=start-end?`
    FromTo(u64, Option<u64>),
    /// `bytes=-n` — the last n bytes.
    Suffix(u64),
}

fn parse_range(v: &str) -> Option<RangeSpec> {
    let spec = v.strip_prefix("bytes=")?;
    if spec.contains(',') {
        return None; // multipart ranges unsupported → serve the whole file
    }
    let (a, b) = spec.split_once('-')?;
    let (a, b) = (a.trim(), b.trim());
    if a.is_empty() {
        let n: u64 = b.parse().ok()?;
        return (n > 0).then_some(RangeSpec::Suffix(n));
    }
    let start: u64 = a.parse().ok()?;
    if b.is_empty() {
        return Some(RangeSpec::FromTo(start, None));
    }
    let end: u64 = b.parse().ok()?;
    (end >= start).then_some(RangeSpec::FromTo(start, Some(end)))
}

async fn get(
    state: AppState,
    dav: DavUser,
    target: Target,
    headers: &HeaderMap,
    head_only: bool,
) -> Response {
    let (name, rel) = match target {
        Target::Root => {
            return dav_headers(Response::builder().status(StatusCode::OK))
                .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(if head_only {
                    Body::empty()
                } else {
                    Body::from("ddm WebDAV root\n")
                })
                .unwrap()
        }
        Target::Service { name, rel } => (name, rel),
    };
    if let Err(r) = require_read(&state, &dav.user, &name).await {
        return r;
    }
    // Metadata first: needed for Range resolution and conditionals.
    let meta = match state.agent.file_stat(&name, &rel, &dav.token).await {
        Ok(m) => m,
        Err(e) => return agent_err(e),
    };
    if meta.kind == "dir" {
        // Browsing is the JSON API / web UI's job.
        return dav_headers(Response::builder().status(StatusCode::METHOD_NOT_ALLOWED))
            .body(Body::empty())
            .unwrap();
    }
    let tag = etag(&meta);
    if let Some(inm) = headers.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()) {
        if inm.trim() == tag || inm.trim() == "*" {
            return dav_headers(Response::builder().status(StatusCode::NOT_MODIFIED))
                .header(header::ETAG, tag)
                .body(Body::empty())
                .unwrap();
        }
    }
    if let Some(ims) = headers
        .get(header::IF_MODIFIED_SINCE)
        .and_then(|v| v.to_str().ok())
        .and_then(parse_http_date)
    {
        if meta.mtime <= ims {
            return dav_headers(Response::builder().status(StatusCode::NOT_MODIFIED))
                .header(header::ETAG, tag)
                .body(Body::empty())
                .unwrap();
        }
    }
    let spec = headers
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .and_then(parse_range);
    let (offset, len) = match spec {
        None => (0u64, 0u64),
        Some(RangeSpec::FromTo(start, end)) => {
            if start >= meta.size {
                return dav_headers(Response::builder().status(StatusCode::RANGE_NOT_SATISFIABLE))
                    .header(header::CONTENT_RANGE, format!("bytes */{}", meta.size))
                    .body(Body::empty())
                    .unwrap();
            }
            match end {
                Some(e) => (start, (e.min(meta.size - 1)) - start + 1),
                None => (start, 0),
            }
        }
        Some(RangeSpec::Suffix(n)) => {
            let start = meta.size.saturating_sub(n);
            (start, meta.size - start)
        }
    };
    let (meta, sent, stream) = match state.agent.file_get(&name, &rel, offset, len, &dav.token).await
    {
        Ok(v) => v,
        Err(e) => return agent_err(e),
    };
    let ranged = spec.is_some();
    let code = if ranged {
        StatusCode::PARTIAL_CONTENT
    } else {
        StatusCode::OK
    };
    let mut b = dav_headers(Response::builder().status(code))
        .header(header::CONTENT_TYPE, content_type(&rel))
        .header(header::CONTENT_LENGTH, sent)
        .header(header::ETAG, tag)
        .header(header::LAST_MODIFIED, http_date(meta.mtime));
    if ranged {
        b = b.header(
            header::CONTENT_RANGE,
            format!(
                "bytes {}-{}/{}",
                offset,
                offset + sent.saturating_sub(1),
                meta.size
            ),
        );
    }
    if head_only {
        return b.body(Body::empty()).unwrap();
    }
    b.body(Body::from_stream(tokio_util::io::ReaderStream::new(stream)))
        .unwrap()
}

// ---------------------------------------------------------------------------
// PUT / MKCOL / DELETE
// ---------------------------------------------------------------------------

async fn put(
    state: AppState,
    dav: DavUser,
    target: Target,
    headers: &HeaderMap,
    req: Request,
) -> Response {
    let (name, rel) = match target {
        Target::Root => return status(StatusCode::METHOD_NOT_ALLOWED),
        Target::Service { name, rel } => (name, rel),
    };
    if rel.trim_end_matches('/').is_empty() {
        return status(StatusCode::METHOD_NOT_ALLOWED);
    }
    if let Err(r) = require_write(&dav.user) {
        return r;
    }
    if let Err(r) = require_read(&state, &dav.user, &name).await {
        return r;
    }
    if let Some(r) = lock_conflict(&state, &lock_key(&name, &rel), headers) {
        return r;
    }
    let existing = state.agent.file_stat(&name, &rel, &dav.token).await.ok();
    if let Some(inm) = headers.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()) {
        if inm.trim() == "*" && existing.is_some() {
            return status(StatusCode::PRECONDITION_FAILED);
        }
    }
    if let (Some(im), Some(e)) = (
        headers.get(header::IF_MATCH).and_then(|v| v.to_str().ok()),
        existing.as_ref(),
    ) {
        if im.trim() != etag(e) && im.trim() != "*" {
            return status(StatusCode::PRECONDITION_FAILED);
        }
    }
    let Some(len) = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
    else {
        // The agent authorizes against a declared length, so a chunked body
        // cannot be forwarded without spooling it to disk first.
        return error_response(
            StatusCode::LENGTH_REQUIRED,
            "Content-Length is required (chunked uploads are not supported)",
        );
    };
    let max = state.config.get().await.webdav.max_upload_bytes;
    if len > max {
        return error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("upload exceeds {max} bytes"),
        );
    }
    // Authorizes before the body is touched: a denied write costs nothing.
    let mut sink = match state.agent.file_put(&name, &rel, len, &dav.token).await {
        Ok(s) => s,
        Err(e) => return agent_err(e),
    };
    let mut body = req.into_body().into_data_stream();
    let mut written: u64 = 0;
    while let Some(chunk) = body.next().await {
        let chunk = match chunk {
            Ok(c) => c,
            Err(e) => return bad_request(format!("body read failed: {e}")),
        };
        written += chunk.len() as u64;
        if written > len {
            return bad_request("body exceeds the declared Content-Length");
        }
        if let Err(e) = sink.write(&chunk).await {
            return agent_err(e);
        }
    }
    if written != len {
        // Dropping the sink aborts the staged write — never commit a short body.
        return bad_request(format!("incomplete body: {written} of {len} bytes"));
    }
    match sink.finish().await {
        Ok(_) => {
            state
                .audit
                .record(&dav.user.name, "webdav_put", &format!("{name}:{rel}"), "");
            status(if existing.is_some() {
                StatusCode::NO_CONTENT
            } else {
                StatusCode::CREATED
            })
        }
        Err(e) => agent_err(e),
    }
}

async fn mkcol(state: AppState, dav: DavUser, target: Target, headers: &HeaderMap) -> Response {
    let (name, rel) = match target {
        Target::Root => return status(StatusCode::METHOD_NOT_ALLOWED),
        Target::Service { name, rel } => (name, rel),
    };
    if rel.trim_end_matches('/').is_empty() {
        return status(StatusCode::METHOD_NOT_ALLOWED);
    }
    if let Err(r) = require_write(&dav.user) {
        return r;
    }
    if let Err(r) = require_read(&state, &dav.user, &name).await {
        return r;
    }
    if let Some(r) = lock_conflict(&state, &lock_key(&name, &rel), headers) {
        return r;
    }
    // RFC 4918: MKCOL requires the parent collection to exist. (PUT is
    // deliberately lenient and creates parents, matching the JSON API.)
    let parent = rel
        .trim_end_matches('/')
        .rsplit_once('/')
        .map(|(p, _)| p.to_string())
        .unwrap_or_default();
    let parent_ok = state
        .agent
        .file_stat(&name, &parent, &dav.token)
        .await
        .map(|m| m.kind == "dir")
        .unwrap_or(false);
    if !parent_ok {
        return status(StatusCode::CONFLICT);
    }
    match state
        .agent
        .call(
            SyncVerb::FileMkdir {
                service: name.clone(),
                path: rel.clone(),
            },
            &dav.token,
        )
        .await
    {
        Ok(_) => {
            state
                .audit
                .record(&dav.user.name, "webdav_mkcol", &format!("{name}:{rel}"), "");
            status(StatusCode::CREATED)
        }
        Err(e) => agent_err(e),
    }
}

async fn delete(state: AppState, dav: DavUser, target: Target, headers: &HeaderMap) -> Response {
    let (name, rel) = match target {
        Target::Root => return status(StatusCode::METHOD_NOT_ALLOWED),
        Target::Service { name, rel } => (name, rel),
    };
    if rel.trim_end_matches('/').is_empty() {
        // Never the service root — that is the compose directory itself.
        return error_response(
            StatusCode::FORBIDDEN,
            "refusing to delete the service directory",
        );
    }
    if let Err(r) = require_write(&dav.user) {
        return r;
    }
    if let Err(r) = require_read(&state, &dav.user, &name).await {
        return r;
    }
    if let Some(r) = lock_conflict(&state, &lock_key(&name, &rel), headers) {
        return r;
    }
    match state
        .agent
        .call(
            SyncVerb::FileDelete {
                service: name.clone(),
                path: rel.clone(),
            },
            &dav.token,
        )
        .await
    {
        Ok(_) => {
            state
                .audit
                .record(&dav.user.name, "webdav_delete", &format!("{name}:{rel}"), "");
            status(StatusCode::NO_CONTENT)
        }
        Err(e) => agent_err(e),
    }
}

// ---------------------------------------------------------------------------
// MOVE / COPY
// ---------------------------------------------------------------------------

async fn move_copy(
    state: AppState,
    dav: DavUser,
    target: Target,
    headers: &HeaderMap,
    is_move: bool,
) -> Response {
    let (name, rel) = match target {
        Target::Root => return status(StatusCode::METHOD_NOT_ALLOWED),
        Target::Service { name, rel } => (name, rel),
    };
    if let Err(r) = require_write(&dav.user) {
        return r;
    }
    if let Err(r) = require_read(&state, &dav.user, &name).await {
        return r;
    }
    let Some(dest) = headers
        .get("destination")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_string())
    else {
        return bad_request("Destination header required");
    };
    // Destination may be an absolute URL or a bare path.
    let dest_path = match dest.find("/dav") {
        Some(idx) => dest[idx + 4..].to_string(),
        None => dest.clone(),
    };
    let (dname, drel) = match parse_target(&dest_path) {
        Ok(Target::Service { name, rel }) => (name, rel),
        Ok(Target::Root) => return status(StatusCode::METHOD_NOT_ALLOWED),
        Err(r) => return r,
    };
    if dname != name {
        return error_response(
            StatusCode::FORBIDDEN,
            "cross-service MOVE/COPY is not supported",
        );
    }
    if drel.trim_end_matches('/').is_empty() {
        return error_response(
            StatusCode::FORBIDDEN,
            "refusing to overwrite the service directory",
        );
    }
    if let Some(r) = lock_conflict(&state, &lock_key(&name, &rel), headers) {
        return r;
    }
    if let Some(r) = lock_conflict(&state, &lock_key(&name, &drel), headers) {
        return r;
    }
    let overwrite = headers
        .get("overwrite")
        .and_then(|v| v.to_str().ok())
        .map(|v| !v.eq_ignore_ascii_case("F"))
        .unwrap_or(true);
    let dest_exists = state.agent.file_stat(&name, &drel, &dav.token).await.is_ok();
    if dest_exists && !overwrite {
        return status(StatusCode::PRECONDITION_FAILED);
    }
    let verb = if is_move {
        SyncVerb::FileRename {
            service: name.clone(),
            from: rel.clone(),
            to: drel.clone(),
        }
    } else {
        SyncVerb::FileCopy {
            service: name.clone(),
            from: rel.clone(),
            to: drel.clone(),
        }
    };
    match state.agent.call(verb, &dav.token).await {
        Ok(_) => {
            state.audit.record(
                &dav.user.name,
                if is_move { "webdav_move" } else { "webdav_copy" },
                &format!("{name}:{rel}"),
                &drel,
            );
            status(if dest_exists {
                StatusCode::NO_CONTENT
            } else {
                StatusCode::CREATED
            })
        }
        Err(e) => agent_err(e),
    }
}

// ---------------------------------------------------------------------------
// LOCK / UNLOCK
// ---------------------------------------------------------------------------

fn lock_timeout(headers: &HeaderMap, max: u64) -> Duration {
    let req = headers
        .get("timeout")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    for part in req.split(',') {
        if let Some(n) = part.trim().strip_prefix("Second-") {
            if let Ok(n) = n.parse::<u64>() {
                return Duration::from_secs(n.clamp(1, max));
            }
        }
    }
    Duration::from_secs(max)
}

/// Pull the `<owner>` payload out of a LOCK body. Echoed back verbatim
/// (clients expect their own XML), but refused if it could break out of the
/// element.
fn extract_owner(body: &str) -> String {
    let lower = body.to_ascii_lowercase();
    let start = match lower.find("<d:owner") {
        Some(s) => s,
        None => match lower.find("<owner") {
            Some(s) => s,
            None => return String::new(),
        },
    };
    let Some(gt) = body[start..].find('>') else {
        return String::new();
    };
    let inner_start = start + gt + 1;
    let rest = &lower[inner_start..];
    let len = rest
        .find("</d:owner")
        .or_else(|| rest.find("</owner"))
        .unwrap_or(0);
    let owner = body[inner_start..inner_start + len].trim().to_string();
    // The slice stops at the first closing tag, so it cannot break out of
    // `<D:owner>`; only CDATA-ish payloads are dropped as a precaution.
    if owner.contains("]]>") {
        return String::new();
    }
    owner
}

async fn lock(
    state: AppState,
    dav: DavUser,
    target: Target,
    headers: &HeaderMap,
    req: Request,
) -> Response {
    let (name, rel) = match target {
        Target::Root => return status(StatusCode::METHOD_NOT_ALLOWED),
        Target::Service { name, rel } => (name, rel),
    };
    if let Err(r) = require_read(&state, &dav.user, &name).await {
        return r;
    }
    // Locking blocks other writers, so it needs write rights — otherwise a
    // read-only caller could deny service to everyone else.
    if let Err(r) = require_write(&dav.user) {
        return r;
    }
    let key = lock_key(&name, &rel);
    let body = axum::body::to_bytes(req.into_body(), 64 * 1024)
        .await
        .unwrap_or_default();
    let text = String::from_utf8_lossy(&body).to_string();
    let cfg = state.config.get().await;
    let timeout = lock_timeout(headers, cfg.webdav.lock_timeout_secs);

    // Empty body = refresh an existing lock.
    if text.trim().is_empty() {
        if let Some(mut existing) = state.locks.covering(&key) {
            if presents_token(headers, &existing.token) {
                state.locks.refresh(&key, timeout);
                existing.expires = Instant::now() + timeout;
                return lock_response(&existing, &key);
            }
        }
        return status(StatusCode::PRECONDITION_FAILED);
    }

    // LOCK on an unmapped URL creates an empty resource, so the common
    // "lock the new file, then PUT it" flow of Explorer/Finder works.
    if state.agent.file_stat(&name, &rel, &dav.token).await.is_err() {
        if rel.trim_end_matches('/').is_empty() {
            return status(StatusCode::METHOD_NOT_ALLOWED);
        }
        let sink = match state.agent.file_put(&name, &rel, 0, &dav.token).await {
            Ok(s) => s,
            Err(e) => return agent_err(e),
        };
        if let Err(e) = sink.finish().await {
            return agent_err(e);
        }
    }
    let depth = headers
        .get("depth")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("infinity")
        .to_ascii_lowercase();
    let l = DavLock {
        token: format!("opaquelocktoken:{}", uuid::Uuid::new_v4()),
        depth: if depth == "0" { "0" } else { "infinity" }.to_string(),
        owner: extract_owner(&text),
        // Shared locks are accepted but enforced exclusively (stricter than
        // the spec, never weaker).
        scope: if text.contains("shared") { "shared" } else { "exclusive" }.to_string(),
        expires: Instant::now() + timeout,
    };
    state.locks.put(&key, l.clone());
    state
        .audit
        .record(&dav.user.name, "webdav_lock", &format!("{name}:{rel}"), "");
    lock_response(&l, &key)
}

fn lock_response(l: &DavLock, key: &str) -> Response {
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<D:prop xmlns:D=\"DAV:\">\
<D:lockdiscovery>{}</D:lockdiscovery></D:prop>",
        active_lock_xml(l)
    );
    dav_headers(Response::builder().status(StatusCode::OK))
        .header(header::CONTENT_TYPE, "application/xml; charset=utf-8")
        .header(header::CONTENT_LENGTH, body.len())
        .header("Lock-Token", format!("<{}>", l.token))
        .header("X-Dav-Lockroot", key)
        .body(Body::from(body))
        .unwrap()
}

async fn unlock(state: AppState, dav: DavUser, target: Target, headers: &HeaderMap) -> Response {
    let (name, rel) = match target {
        Target::Root => return status(StatusCode::METHOD_NOT_ALLOWED),
        Target::Service { name, rel } => (name, rel),
    };
    if let Err(r) = require_read(&state, &dav.user, &name).await {
        return r;
    }
    let key = lock_key(&name, &rel);
    let Some(lock) = state.locks.covering(&key) else {
        return status(StatusCode::CONFLICT);
    };
    if !presents_token(headers, &lock.token) {
        return status(StatusCode::CONFLICT);
    }
    state.locks.remove(&key);
    state
        .audit
        .record(&dav.user.name, "webdav_unlock", &format!("{name}:{rel}"), "");
    status(StatusCode::NO_CONTENT)
}
