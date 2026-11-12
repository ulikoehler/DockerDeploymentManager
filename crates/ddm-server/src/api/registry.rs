//! OCI Distribution Spec endpoints (`/v2/`) — a minimal private registry
//! so images can be `docker push`ed straight to DDM without a registry
//! service. Pushed manifests are imported into the local docker daemon
//! via `ExecVerb::ImageLoad`.
//!
//! Auth: docker clients do the standard token dance — `GET /v2/` returns
//! a Bearer challenge, `GET /v2/token` accepts HTTP Basic (DDM user
//! credentials) and returns a session JWT. All other `/v2/*` routes take
//! `Authorization: Bearer <jwt>` via the normal `AuthUser` extractor.
//! Writes additionally require the `push_images` feature (or admin).

use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{header, HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{any, get},
    Router,
};
use base64::Engine;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use crate::agent::proto::ExecVerb;
use crate::auth::{self, AuthUser};
use crate::registry::{self, Registry};
use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v2/", get(v2_ping))
        .route("/v2/token", get(v2_token))
        .route("/v2/*rest", any(v2_api))
}

fn registry(state: &AppState) -> Registry {
    Registry::new(state.registry_root.clone())
}

/// Absolute base URL of this request, for the token `realm`.
fn base_url(headers: &HeaderMap) -> String {
    let host = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get(header::HOST))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("http");
    format!("{proto}://{host}")
}

fn challenge(headers: &HeaderMap) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(
            header::WWW_AUTHENTICATE,
            format!(
                "Bearer realm=\"{}/v2/token\",service=\"ddm\"",
                base_url(headers)
            ),
        )],
    )
        .into_response()
}

/// `GET /v2/` — registry ping. 200 when the bearer token verifies,
/// otherwise the Bearer challenge that starts docker's token flow.
async fn v2_ping(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_string);
    match token {
        Some(t) => {
            let v = state
                .agent
                .crypto(crate::agent::proto::CryptoOp::Verify { token: t })
                .await;
            if v.is_ok() {
                StatusCode::OK.into_response()
            } else {
                challenge(&headers)
            }
        }
        None => challenge(&headers),
    }
}

#[derive(Deserialize)]
struct TokenParams {
    #[allow(dead_code)]
    service: Option<String>,
    #[allow(dead_code)]
    scope: Option<String>,
}

/// `GET /v2/token` — HTTP Basic (DDM user:password) → session JWT.
/// Docker caches it until `expires_in`; each fetch is a normal login.
async fn v2_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(_q): Query<TokenParams>,
) -> Response {
    let Some(b64) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic "))
    else {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Basic realm=\"ddm\"")],
        )
            .into_response();
    };
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()
        .and_then(|b| String::from_utf8(b).ok());
    let Some(creds) = decoded else {
        return auth::error_response(StatusCode::UNAUTHORIZED, "bad credentials");
    };
    let Some((name, password)) = creds.split_once(':') else {
        return auth::error_response(StatusCode::UNAUTHORIZED, "bad credentials");
    };
    let v = state
        .agent
        .crypto(crate::agent::proto::CryptoOp::Authenticate {
            name: name.to_string(),
            password: password.to_string(),
            ip: None,
            ua: Some("docker-registry".to_string()),
        })
        .await;
    let Ok(v) = v else {
        return auth::error_response(StatusCode::UNAUTHORIZED, "authentication failed");
    };
    let token = v["token"].as_str().unwrap_or_default().to_string();
    let expires_at = v["expires_at"].as_i64().unwrap_or(0);
    let now = chrono::Utc::now().timestamp();
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "token": token,
            "access_token": token,
            "expires_in": (expires_at - now).max(60),
            "issued_at": chrono::Utc::now().to_rfc3339(),
        })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// /v2/<name>/... dispatch
// ---------------------------------------------------------------------------

enum Parsed {
    Catalog,
    Tags { name: String },
    Manifest { name: String, reference: String },
    Blob { name: String, digest: String },
    Upload { name: String, uuid: Option<String> },
}

fn parse_rest(rest: &str) -> Option<Parsed> {
    if rest == "_catalog" {
        return Some(Parsed::Catalog);
    }
    if let Some(name) = rest.strip_suffix("/tags/list") {
        return Some(Parsed::Tags {
            name: name.to_string(),
        });
    }
    if let Some(idx) = rest.find("/blobs/uploads") {
        let name = &rest[..idx];
        let tail = &rest[idx + "/blobs/uploads".len()..];
        let uuid = tail
            .trim_start_matches('/')
            .split('/')
            .next()
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        if uuid.as_deref().is_some_and(|u| u.contains('/')) {
            return None;
        }
        return Some(Parsed::Upload {
            name: name.to_string(),
            uuid,
        });
    }
    if let Some(idx) = rest.rfind("/manifests/") {
        return Some(Parsed::Manifest {
            name: rest[..idx].to_string(),
            reference: rest[idx + "/manifests/".len()..].to_string(),
        });
    }
    if let Some(idx) = rest.rfind("/blobs/") {
        return Some(Parsed::Blob {
            name: rest[..idx].to_string(),
            digest: rest[idx + "/blobs/".len()..].to_string(),
        });
    }
    None
}

fn sha256_hex(data: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(data)))
}

fn can_push(user: &AuthUser) -> bool {
    user.user.is_admin() || user.user.features.push_images
}

async fn v2_api(
    State(state): State<AppState>,
    Path(rest): Path<String>,
    method: Method,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
    user: AuthUser,
    body: Body,
) -> Response {
    let Some(parsed) = parse_rest(rest.trim_end_matches('/')) else {
        return auth::error_response(StatusCode::NOT_FOUND, "unknown registry path");
    };
    // name validation happens per-branch; reject traversal up front for
    // anything that carries a repo name
    let reg = registry(&state);

    match (method.as_str(), &parsed) {
        // ---- reads: any authenticated user ----
        ("GET", Parsed::Catalog) => match reg.catalog() {
            Ok(repos) => axum::Json(serde_json::json!({"repositories": repos})).into_response(),
            Err(e) => auth::internal(e.to_string()),
        },
        ("GET", Parsed::Tags { name }) if registry::valid_name(name) => match reg.list_tags(name) {
            Ok(tags) => axum::Json(serde_json::json!({"name": name, "tags": tags})).into_response(),
            Err(e) => auth::internal(e.to_string()),
        },
        ("GET" | "HEAD", Parsed::Manifest { name, reference })
            if registry::valid_name(name) && registry::valid_reference(reference) =>
        {
            match reg.get_manifest(name, reference) {
                Ok((bytes, ct)) => {
                    let digest = sha256_hex(&bytes);
                    let mut resp = if method == Method::HEAD {
                        Response::new(Body::empty())
                    } else {
                        Response::new(Body::from(bytes.clone()))
                    };
                    let h = resp.headers_mut();
                    h.insert(
                        header::CONTENT_TYPE,
                        ct.parse().unwrap_or(header::HeaderValue::from_static(
                            "application/octet-stream",
                        )),
                    );
                    h.insert("docker-content-digest", digest.parse().unwrap());
                    h.insert(
                        header::CONTENT_LENGTH,
                        bytes.len().to_string().parse().unwrap(),
                    );
                    resp
                }
                Err(_) => auth::error_response(StatusCode::NOT_FOUND, "manifest unknown"),
            }
        }
        ("GET" | "HEAD", Parsed::Blob { name, digest })
            if registry::valid_name(name) && registry::valid_digest(digest) =>
        {
            if !reg.has_blob(digest) {
                return auth::error_response(StatusCode::NOT_FOUND, "blob unknown");
            }
            let size = reg.blob_size(digest);
            let file = match reg.open_blob(digest) {
                Ok(f) => f,
                Err(_) => return auth::error_response(StatusCode::NOT_FOUND, "blob unknown"),
            };
            let stream = tokio_util::io::ReaderStream::new(tokio::fs::File::from_std(file));
            let mut resp = Response::new(Body::from_stream(stream));
            let h = resp.headers_mut();
            h.insert(header::CONTENT_LENGTH, size.to_string().parse().unwrap());
            h.insert("docker-content-digest", digest.parse().unwrap());
            h.insert(header::ACCEPT_RANGES, "bytes".parse().unwrap());
            if method == Method::HEAD {
                // strip the body for HEAD
                *resp.body_mut() = Body::empty();
            }
            resp
        }
        // ---- writes: push_images feature ----
        ("POST", Parsed::Upload { name, uuid: None }) if registry::valid_name(name) => {
            if !can_push(&user) {
                return auth::forbidden();
            }
            // monolithic upload when ?digest= is present
            if let Some(digest) = q.get("digest") {
                if !registry::valid_digest(digest) {
                    return auth::bad_request("invalid digest");
                }
                let bytes = match axum::body::to_bytes(body, 8 << 30).await {
                    Ok(b) => b,
                    Err(_) => return auth::bad_request("failed to read body"),
                };
                return match reg.store_blob(digest, &bytes) {
                    Ok(()) => {
                        let mut resp = StatusCode::CREATED.into_response();
                        let h = resp.headers_mut();
                        h.insert(
                            header::LOCATION,
                            format!("/v2/{name}/blobs/{digest}").parse().unwrap(),
                        );
                        h.insert("docker-content-digest", digest.parse().unwrap());
                        resp
                    }
                    Err(e) => auth::bad_request(e.to_string()),
                };
            }
            let id = uuid::Uuid::new_v4().to_string();
            if reg.begin_upload(&id).is_err() {
                return auth::internal("cannot start upload");
            }
            let mut resp = StatusCode::ACCEPTED.into_response();
            let h = resp.headers_mut();
            h.insert(
                header::LOCATION,
                format!("/v2/{name}/blobs/uploads/{id}").parse().unwrap(),
            );
            h.insert("docker-upload-uuid", id.parse().unwrap());
            h.insert(header::RANGE, "0-0".parse().unwrap());
            resp
        }
        ("PATCH", Parsed::Upload { uuid: Some(u), .. }) if registry::valid_uuid(u) => {
            if !can_push(&user) {
                return auth::forbidden();
            }
            let path = reg.root().join("uploads").join(u);
            if !path.is_file() {
                return auth::error_response(StatusCode::NOT_FOUND, "unknown upload");
            }
            match append_body(body, &path).await {
                Ok(()) => {
                    let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                    let mut resp = StatusCode::ACCEPTED.into_response();
                    let h = resp.headers_mut();
                    h.insert(
                        header::LOCATION,
                        format!("/v2/{}/blobs/uploads/{u}", upload_name(&rest))
                            .parse()
                            .unwrap(),
                    );
                    h.insert("docker-upload-uuid", u.parse().unwrap());
                    h.insert(
                        header::RANGE,
                        format!("0-{}", size.saturating_sub(1)).parse().unwrap(),
                    );
                    resp
                }
                Err(e) => auth::bad_request(e.to_string()),
            }
        }
        ("PUT", Parsed::Upload { uuid: Some(u), .. }) if registry::valid_uuid(u) => {
            if !can_push(&user) {
                return auth::forbidden();
            }
            let Some(digest) = q.get("digest") else {
                return auth::bad_request("missing digest query parameter");
            };
            if !registry::valid_digest(digest) {
                return auth::bad_request("invalid digest");
            }
            let path = reg.root().join("uploads").join(u);
            if !path.is_file() {
                return auth::error_response(StatusCode::NOT_FOUND, "unknown upload");
            }
            // final chunk may ride on the PUT body
            if let Err(e) = append_body(body, &path).await {
                return auth::bad_request(e.to_string());
            }
            match reg.finalize_upload(u, digest) {
                Ok(size) => {
                    let name = upload_name(&rest);
                    let mut resp = StatusCode::CREATED.into_response();
                    let h = resp.headers_mut();
                    h.insert(
                        header::LOCATION,
                        format!("/v2/{name}/blobs/{digest}").parse().unwrap(),
                    );
                    h.insert("docker-content-digest", digest.parse().unwrap());
                    h.insert(header::CONTENT_LENGTH, size.to_string().parse().unwrap());
                    resp
                }
                Err(e) => auth::bad_request(e.to_string()),
            }
        }
        ("DELETE", Parsed::Upload { uuid: Some(u), .. }) if registry::valid_uuid(u) => {
            if !can_push(&user) {
                return auth::forbidden();
            }
            reg.abort_upload(u);
            StatusCode::NO_CONTENT.into_response()
        }
        ("PUT", Parsed::Manifest { name, reference })
            if registry::valid_name(name) && registry::valid_reference(reference) =>
        {
            if !can_push(&user) {
                return auth::forbidden();
            }
            let bytes = match axum::body::to_bytes(body, 8 << 20).await {
                Ok(b) => b,
                Err(_) => return auth::bad_request("failed to read body"),
            };
            let ct = headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/vnd.oci.image.manifest.v1+json")
                .to_string();
            // manifest must parse and reference sha256 digests
            let single_arch = match registry::Registry::manifest_parts(&bytes) {
                Ok(Some((cfg, layers))) => {
                    for d in std::iter::once(&cfg).chain(layers.iter()) {
                        if !registry::valid_digest(d) {
                            return auth::bad_request(format!("invalid digest {d}"));
                        }
                    }
                    true
                }
                Ok(None) => false, // index / list — stored, not loaded
                Err(e) => return auth::bad_request(e.to_string()),
            };
            let digest = sha256_hex(&bytes);
            if let Err(e) = reg.store_manifest(name, reference, &bytes, &ct) {
                return auth::internal(e.to_string());
            }
            // OCI: manifests must also be retrievable by content digest —
            // docker resolves tag -> digest via HEAD, then GETs by digest.
            let is_digest_ref = reference.contains(':');
            if !is_digest_ref {
                if let Err(e) = reg.store_manifest(name, &digest, &bytes, &ct) {
                    return auth::internal(e.to_string());
                }
            }
            // import into the local docker daemon — only for tag pushes
            // of single-arch manifests (not digest refs / indexes)
            if !reference.contains(':') && single_arch {
                let cleanup = |reg: &registry::Registry| {
                    let dir = reg.root().join("manifests").join(name);
                    let _ = std::fs::remove_file(dir.join(reference));
                    let _ = std::fs::remove_file(dir.join(&digest));
                    let _ = std::fs::remove_file(dir.join(format!("{reference}.ct")));
                    let _ = std::fs::remove_file(dir.join(format!("{digest}.ct")));
                };
                match reg.assemble_load_tar(name, reference) {
                    Ok((tar_path, scratch)) => {
                        let loaded = state
                            .agent
                            .exec_collect(
                                ExecVerb::ImageLoad {
                                    path: tar_path.to_string_lossy().to_string(),
                                },
                                format!("registry load {name}:{reference}"),
                                None,
                                &user.token,
                                &user.user.name,
                                &state.exec,
                            )
                            .await;
                        let _ = std::fs::remove_dir_all(&scratch);
                        match loaded {
                            Ok(true) => {}
                            Ok(false) => {
                                cleanup(&reg);
                                return auth::error_response(
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    "docker load failed",
                                );
                            }
                            Err(e) => {
                                cleanup(&reg);
                                return auth::internal(format!("image load failed: {e}"));
                            }
                        }
                    }
                    Err(e) => {
                        // missing blobs etc. — a manifest whose image can't
                        // load is a broken push — drop it.
                        cleanup(&reg);
                        return auth::bad_request(e.to_string());
                    }
                }
            }
            let mut resp = StatusCode::CREATED.into_response();
            resp.headers_mut()
                .insert("docker-content-digest", digest.parse().unwrap());
            resp
        }
        _ => auth::error_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed"),
    }
}

/// Repo name embedded in a `/v2/<name>/blobs/uploads/...` path — used to
/// build Location headers on upload responses.
fn upload_name(rest: &str) -> &str {
    rest.find("/blobs/uploads")
        .map(|i| &rest[..i])
        .unwrap_or(rest)
}

/// Append a request body to a file (chunked upload support).
async fn append_body(body: Body, path: &std::path::Path) -> anyhow::Result<()> {
    use futures::StreamExt;
    use tokio::io::AsyncWriteExt;
    let mut f = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await?;
    let mut stream = body.into_data_stream();
    while let Some(chunk) = stream.next().await {
        let bytes = chunk?;
        f.write_all(&bytes).await?;
    }
    f.flush().await?;
    Ok(())
}
