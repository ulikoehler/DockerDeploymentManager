use crate::auth::{bad_request, forbidden, ok, AuthUser};
use crate::{files, gitops, AppState};
use axum::{
    extract::{Path, Query, State},
    response::Response,
    Json,
};
use serde::Deserialize;

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
    let _ = svc;
    let node: files::FileNode = state
        .agent
        .call_as(
            crate::agent::proto::SyncVerb::FileNode {
                service: name.clone(),
                path: q.path.clone(),
            },
            &user.token,
        )
        .await
        .map_err(|e| bad_request(e.to_string()))?;
    Ok(ok(node))
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
    let _svc = require_service_access(&state, &user, &name).await?;
    state
        .agent
        .call(
            crate::agent::proto::SyncVerb::FileWrite {
                service: name.clone(),
                path: req.path.clone(),
                content: req.content.clone(),
            },
            &user.token,
        )
        .await
        .map_err(|e| bad_request(e.to_string()))?;
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
    let _svc = require_service_access(&state, &user, &name).await?;
    state
        .agent
        .call(
            crate::agent::proto::SyncVerb::FileMkdir {
                service: name.clone(),
                path: req.path.clone(),
            },
            &user.token,
        )
        .await
        .map_err(|e| bad_request(e.to_string()))?;
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
    let _svc = require_service_access(&state, &user, &name).await?;
    state
        .agent
        .call(
            crate::agent::proto::SyncVerb::FileRename {
                service: name.clone(),
                from: req.from.clone(),
                to: req.to.clone(),
            },
            &user.token,
        )
        .await
        .map_err(|e| bad_request(e.to_string()))?;
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
    let _svc = require_service_access(&state, &user, &name).await?;
    state
        .agent
        .call(
            crate::agent::proto::SyncVerb::FileDelete {
                service: name.clone(),
                path: q.path.clone(),
            },
            &user.token,
        )
        .await
        .map_err(|e| bad_request(e.to_string()))?;
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
    let repos: Vec<gitops::RepoInfo> = state
        .agent
        .call_as(
            crate::agent::proto::SyncVerb::GitRepos {
                service: svc.name.clone(),
            },
            &user.token,
        )
        .await
        .map_err(|e| bad_request(e.to_string()))?;
    Ok(ok(repos))
}

pub async fn git_status(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(q): Query<PathQuery>,
) -> Result<Json<crate::auth::SuccessResponse<gitops::RepoStatus>>, Response> {
    let svc = require_service_access(&state, &user, &name).await?;
    let st: gitops::RepoStatus = state
        .agent
        .call_as(
            crate::agent::proto::SyncVerb::GitStatus {
                service: svc.name.clone(),
                path: q.path.clone(),
            },
            &user.token,
        )
        .await
        .map_err(|e| bad_request(e.to_string()))?;
    Ok(ok(st))
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
    let log: Vec<String> = state
        .agent
        .call_as(
            crate::agent::proto::SyncVerb::GitLog {
                service: svc.name.clone(),
                path: q.path.clone(),
                n: q.n.unwrap_or(30),
            },
            &user.token,
        )
        .await
        .map_err(|e| bad_request(e.to_string()))?;
    Ok(ok(log))
}

pub async fn git_branches(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(q): Query<PathQuery>,
) -> Result<Json<crate::auth::SuccessResponse<gitops::RepoBranches>>, Response> {
    let svc = require_service_access(&state, &user, &name).await?;
    let br: gitops::RepoBranches = state
        .agent
        .call_as(
            crate::agent::proto::SyncVerb::GitBranches {
                service: svc.name.clone(),
                path: q.path.clone(),
            },
            &user.token,
        )
        .await
        .map_err(|e| bad_request(e.to_string()))?;
    Ok(ok(br))
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
    let id = state
        .agent
        .exec(
            crate::agent::proto::ExecVerb::GitClone {
                service: svc.name.clone(),
                url: req.url.clone(),
                path: req.path.clone(),
                branch: req.branch.clone(),
            },
            format!("git clone ({})", svc.name),
            Some(svc.name.clone()),
            &user.token,
            &user.user.name,
            &state.exec,
        )
        .await
        .map_err(|e| bad_request(e.to_string()))?;
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
    let id = state
        .agent
        .exec(
            crate::agent::proto::ExecVerb::GitOp {
                service: svc.name.clone(),
                path: req.path.clone(),
                op: req.op.clone(),
                git_ref: req.git_ref.clone(),
            },
            format!("git {} ({}/{})", req.op, svc.name, req.path),
            Some(svc.name.clone()),
            &user.token,
            &user.user.name,
            &state.exec,
        )
        .await
        .map_err(|e| bad_request(e.to_string()))?;
    state.audit.record(
        &user.user.name,
        &format!("git_{}", req.op),
        &name,
        format!("{} {}", req.path, req.git_ref.clone().unwrap_or_default()),
    );
    Ok(ok(serde_json::json!({ "execution_id": id })))
}
