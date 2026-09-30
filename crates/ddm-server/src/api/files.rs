use crate::auth::{bad_request, forbidden, not_found, ok, AuthUser};
use crate::exec::shell_item;
use crate::{files, gitops, AppState};
use axum::{
    extract::{Path, Query, State},
    response::Response,
    Json,
};
use serde::Deserialize;
use std::collections::HashMap;

use super::services::require_service_access;

/// Writes (file edits, git mutations) need admin or the `edit_files` feature.
#[allow(clippy::result_large_err)]
fn require_edit_files(user: &AuthUser) -> Result<(), Response> {
    if user.user.is_admin() || user.user.features.edit_files {
        Ok(())
    } else {
        Err(forbidden())
    }
}

// ---------------------------------------------------------------------------
// file tree
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct PathQuery {
    #[serde(default)]
    pub path: String,
}

pub async fn list_files(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(q): Query<PathQuery>,
) -> Result<Json<crate::auth::SuccessResponse<files::FileNode>>, Response> {
    let svc = require_service_access(&state, &user, &name).await?;
    files::read_node(&svc.dir, &q.path)
        .map(ok)
        .map_err(|e| bad_request(e.to_string()))
}

#[derive(Deserialize)]
pub struct WriteRequest {
    pub path: String,
    pub content: String,
}

pub async fn write_file(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(req): Json<WriteRequest>,
) -> Result<Json<crate::auth::SuccessResponse<bool>>, Response> {
    require_edit_files(&user)?;
    let svc = require_service_access(&state, &user, &name).await?;
    files::write_file(&svc.dir, &req.path, &req.content).map_err(|e| bad_request(e.to_string()))?;
    state
        .audit
        .record(&user.user.name, "file_write", &name, &req.path);
    Ok(ok(true))
}

#[derive(Deserialize)]
pub struct MkdirRequest {
    pub path: String,
}

pub async fn mkdir(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(req): Json<MkdirRequest>,
) -> Result<Json<crate::auth::SuccessResponse<bool>>, Response> {
    require_edit_files(&user)?;
    let svc = require_service_access(&state, &user, &name).await?;
    files::mkdir(&svc.dir, &req.path).map_err(|e| bad_request(e.to_string()))?;
    state
        .audit
        .record(&user.user.name, "mkdir", &name, &req.path);
    Ok(ok(true))
}

#[derive(Deserialize)]
pub struct RenameRequest {
    pub from: String,
    pub to: String,
}

pub async fn rename(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(req): Json<RenameRequest>,
) -> Result<Json<crate::auth::SuccessResponse<bool>>, Response> {
    require_edit_files(&user)?;
    let svc = require_service_access(&state, &user, &name).await?;
    files::rename(&svc.dir, &req.from, &req.to).map_err(|e| bad_request(e.to_string()))?;
    state.audit.record(
        &user.user.name,
        "file_rename",
        &name,
        format!("{} → {}", req.from, req.to),
    );
    Ok(ok(true))
}

pub async fn delete_file(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(q): Query<PathQuery>,
) -> Result<Json<crate::auth::SuccessResponse<bool>>, Response> {
    require_edit_files(&user)?;
    let svc = require_service_access(&state, &user, &name).await?;
    files::delete(&svc.dir, &q.path).map_err(|e| bad_request(e.to_string()))?;
    state
        .audit
        .record(&user.user.name, "file_delete", &name, &q.path);
    Ok(ok(true))
}

// ---------------------------------------------------------------------------
// git
// ---------------------------------------------------------------------------

pub async fn git_repos(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<crate::auth::SuccessResponse<Vec<gitops::RepoInfo>>>, Response> {
    let svc = require_service_access(&state, &user, &name).await?;
    Ok(ok(gitops::list_repos(&svc.dir).await))
}

pub async fn git_status(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(q): Query<PathQuery>,
) -> Result<Json<crate::auth::SuccessResponse<gitops::RepoStatus>>, Response> {
    let svc = require_service_access(&state, &user, &name).await?;
    let repo = gitops::resolve_repo(&svc.dir, &q.path).map_err(|e| not_found(e.to_string()))?;
    gitops::status(&repo, &svc.dir)
        .await
        .map(ok)
        .map_err(|e| bad_request(e.to_string()))
}

#[derive(Deserialize)]
pub struct LogQuery {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub n: Option<usize>,
}

pub async fn git_log(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(q): Query<LogQuery>,
) -> Result<Json<crate::auth::SuccessResponse<Vec<String>>>, Response> {
    let svc = require_service_access(&state, &user, &name).await?;
    let repo = gitops::resolve_repo(&svc.dir, &q.path).map_err(|e| not_found(e.to_string()))?;
    gitops::log(&repo, q.n.unwrap_or(30))
        .await
        .map(ok)
        .map_err(|e| bad_request(e.to_string()))
}

pub async fn git_branches(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(q): Query<PathQuery>,
) -> Result<Json<crate::auth::SuccessResponse<gitops::RepoBranches>>, Response> {
    let svc = require_service_access(&state, &user, &name).await?;
    let repo = gitops::resolve_repo(&svc.dir, &q.path).map_err(|e| not_found(e.to_string()))?;
    gitops::branches(&repo)
        .await
        .map(ok)
        .map_err(|e| bad_request(e.to_string()))
}

#[derive(Deserialize)]
pub struct CloneRequest {
    pub url: String,
    /// Directory (relative to service dir) to clone into; "" = service dir.
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub branch: Option<String>,
}

pub async fn git_clone(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(req): Json<CloneRequest>,
) -> Result<Json<crate::auth::SuccessResponse<serde_json::Value>>, Response> {
    require_edit_files(&user)?;
    let svc = require_service_access(&state, &user, &name).await?;
    let script = gitops::clone_script(&svc.dir, &req.url, &req.path, req.branch.as_deref())
        .map_err(|e| bad_request(e.to_string()))?;
    let id = state.exec.run_item(
        shell_item(&format!("git clone ({})", svc.name), &script, "."),
        HashMap::new(),
        &user.user.name,
        Some(svc.name.clone()),
        false,
    );
    state
        .audit
        .record(&user.user.name, "git_clone", &name, &req.url);
    Ok(ok(serde_json::json!({ "execution_id": id })))
}

#[derive(Deserialize)]
pub struct GitActionRequest {
    /// Repo path relative to the service dir ("." or "" = root).
    #[serde(default)]
    pub path: String,
    /// pull | fetch | checkout
    pub op: String,
    #[serde(default)]
    pub git_ref: Option<String>,
}

pub async fn git_action(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(req): Json<GitActionRequest>,
) -> Result<Json<crate::auth::SuccessResponse<serde_json::Value>>, Response> {
    require_edit_files(&user)?;
    let svc = require_service_access(&state, &user, &name).await?;
    let repo = gitops::resolve_repo(&svc.dir, &req.path).map_err(|e| not_found(e.to_string()))?;
    let script = gitops::op_script(&req.op, &repo, req.git_ref.as_deref())
        .map_err(|e| bad_request(e.to_string()))?;
    let id = state.exec.run_item(
        shell_item(
            &format!("git {} ({}/{})", req.op, svc.name, req.path),
            &script,
            ".",
        ),
        HashMap::new(),
        &user.user.name,
        Some(svc.name.clone()),
        false,
    );
    state.audit.record(
        &user.user.name,
        &format!("git_{}", req.op),
        &name,
        format!("{} {}", req.path, req.git_ref.clone().unwrap_or_default()),
    );
    Ok(ok(serde_json::json!({ "execution_id": id })))
}
