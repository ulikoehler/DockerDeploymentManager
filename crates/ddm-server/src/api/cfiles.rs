//! Container and volume file transfers: download a single file raw, or a
//! tar(.gz) archive of a directory/multi-file set; upload the same shapes.
//!
//! Routes are scoped under a service for UX, but the agent re-derives
//! authorization itself: containers map to their compose project (managed
//! = that service's access rules, unmanaged = admin), volumes map via
//! their `com.docker.compose.project` label the same way.

use crate::agent::proto::{TarFormat, TarSource};
use crate::auth::{bad_request, ok, AuthUser};
use crate::AppState;
use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::header,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use tokio::io::AsyncReadExt;

use super::files::require_edit_files;
use super::services::require_service_access;

fn parse_format(s: Option<&str>, default: TarFormat) -> Result<TarFormat, Response> {
    match s.unwrap_or("") {
        "" => Ok(default),
        "raw" => Ok(TarFormat::Raw),
        "tar" => Ok(TarFormat::Tar),
        "targz" | "tar.gz" | "tgz" => Ok(TarFormat::Targz),
        other => Err(bad_request(format!("unknown format '{other}'"))),
    }
}

fn source_container(id: &str, path: &str) -> TarSource {
    TarSource::Container {
        id: id.to_string(),
        path: path.to_string(),
    }
}

fn source_volume(name: &str, path: &str) -> TarSource {
    TarSource::Volume {
        name: name.to_string(),
        path: path.to_string(),
    }
}

/// Stream a download payload to the client with a sane filename + type.
async fn stream_download(
    state: &AppState,
    user: &AuthUser,
    service: &str,
    source: TarSource,
    format: TarFormat,
    filename: String,
) -> Result<Response, Response> {
    let (_meta, _sent, mut stream) = state
        .agent
        .tar_get(service, &source, format, &user.token)
        .await
        .map_err(|e| bad_request(e.to_string()))?;
    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .await
        .map_err(|e| bad_request(format!("read failed: {e}")))?;
    let (mime, disp) = match format {
        TarFormat::Raw => (
            mime_guess::from_path(&filename)
                .first_or_octet_stream()
                .to_string(),
            format!("attachment; filename=\"{filename}\""),
        ),
        TarFormat::Tar => (
            "application/x-tar".to_string(),
            format!("attachment; filename=\"{filename}.tar\""),
        ),
        TarFormat::Targz => (
            "application/gzip".to_string(),
            format!("attachment; filename=\"{filename}.tar.gz\""),
        ),
    };
    let mut res = Body::from(buf).into_response();
    let h = res.headers_mut();
    h.insert(header::CONTENT_TYPE, mime.parse().unwrap());
    h.insert(header::CONTENT_DISPOSITION, disp.parse().unwrap());
    Ok(res)
}

const MAX_XFER_BYTES: usize = 2 * 1024 * 1024 * 1024;

async fn stream_upload(
    state: &AppState,
    user: &AuthUser,
    service: &str,
    source: TarSource,
    format: TarFormat,
    body: Body,
) -> Result<Json<crate::auth::SuccessResponse<serde_json::Value>>, Response> {
    let bytes = axum::body::to_bytes(body, MAX_XFER_BYTES)
        .await
        .map_err(|_| bad_request("upload too large or unreadable"))?;
    let len = bytes.len() as u64;
    let mut sink = state
        .agent
        .tar_put(service, &source, format, len, &user.token)
        .await
        .map_err(|e| bad_request(e.to_string()))?;
    sink.write(&bytes)
        .await
        .map_err(|e| bad_request(format!("upload failed: {e}")))?;
    let meta = sink
        .finish()
        .await
        .map_err(|e| bad_request(format!("upload failed: {e}")))?;
    state
        .audit
        .record(&user.user.name, "tar_put", service, format!("{source:?}"));
    Ok(ok(serde_json::json!({ "size": meta.size })))
}

// ---------------------------------------------------------------------------
// containers
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ContainerFilesQuery {
    #[serde(default)]
    pub path: String,
    pub format: Option<String>,
}

pub async fn container_download(
    user: AuthUser,
    State(state): State<AppState>,
    Path((name, cid)): Path<(String, String)>,
    Query(q): Query<ContainerFilesQuery>,
) -> Result<Response, Response> {
    require_service_access(&state, &user, &name).await?;
    let format = parse_format(q.format.as_deref(), TarFormat::Targz)?;
    let base = q
        .path
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("download")
        .to_string();
    stream_download(
        &state,
        &user,
        &name,
        source_container(&cid, &q.path),
        format,
        base,
    )
    .await
}

pub async fn container_upload(
    user: AuthUser,
    State(state): State<AppState>,
    Path((name, cid)): Path<(String, String)>,
    Query(q): Query<ContainerFilesQuery>,
    body: Body,
) -> Result<Json<crate::auth::SuccessResponse<serde_json::Value>>, Response> {
    require_edit_files(&user)?;
    require_service_access(&state, &user, &name).await?;
    let format = parse_format(q.format.as_deref(), TarFormat::Raw)?;
    stream_upload(
        &state,
        &user,
        &name,
        source_container(&cid, &q.path),
        format,
        body,
    )
    .await
}

// ---------------------------------------------------------------------------
// volumes
// ---------------------------------------------------------------------------

pub async fn volumes_list(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<crate::auth::SuccessResponse<Vec<String>>>, Response> {
    require_service_access(&state, &user, &name).await?;
    let vols: Vec<String> = state
        .agent
        .call_as(
            crate::agent::proto::SyncVerb::ProjectVolumes {
                service: name.clone(),
            },
            &user.token,
        )
        .await
        .map_err(|e| bad_request(e.to_string()))?;
    Ok(ok(vols))
}

#[derive(Deserialize)]
pub struct VolumeFilesQuery {
    #[serde(default)]
    pub path: String,
    pub format: Option<String>,
}

pub async fn volume_download(
    user: AuthUser,
    State(state): State<AppState>,
    Path((name, vol)): Path<(String, String)>,
    Query(q): Query<VolumeFilesQuery>,
) -> Result<Response, Response> {
    require_service_access(&state, &user, &name).await?;
    let format = parse_format(q.format.as_deref(), TarFormat::Targz)?;
    let base = q
        .path
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("volume")
        .to_string();
    stream_download(
        &state,
        &user,
        &name,
        source_volume(&vol, &q.path),
        format,
        base,
    )
    .await
}

pub async fn volume_upload(
    user: AuthUser,
    State(state): State<AppState>,
    Path((name, vol)): Path<(String, String)>,
    Query(q): Query<VolumeFilesQuery>,
    body: Body,
) -> Result<Json<crate::auth::SuccessResponse<serde_json::Value>>, Response> {
    require_edit_files(&user)?;
    require_service_access(&state, &user, &name).await?;
    let format = parse_format(q.format.as_deref(), TarFormat::Raw)?;
    stream_upload(
        &state,
        &user,
        &name,
        source_volume(&vol, &q.path),
        format,
        body,
    )
    .await
}
