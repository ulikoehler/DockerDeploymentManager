use crate::auth::{bad_request, forbidden, internal, not_found, ok, AuthUser};
use crate::config::{ServiceBackupConfig, ServiceMonitoringConfig};
use crate::logs::{CompiledFilter, LogFilter};
use crate::permissions::{can_access_service, valid_service_name};
use crate::policy::{self, PolicyViolation};
use crate::services as svc_ops;
use crate::AppState;
use axum::{
    extract::{Path, Query, State},
    response::Response,
    Json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path as FsPath;

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Check access to a service for the caller.
pub(crate) async fn require_service_access(
    state: &AppState,
    user: &AuthUser,
    name: &str,
) -> Result<svc_ops::Service, Response> {
    if !valid_service_name(name) {
        return Err(bad_request("invalid service name"));
    }
    let cfg = state.config.get().await;
    if !can_access_service(&user.user, name, cfg.security.default_access) {
        return Err(forbidden());
    }
    state
        .agent
        .call_as::<svc_ops::Service>(
            crate::agent::proto::SyncVerb::ServiceGet {
                name: name.to_string(),
            },
            &user.token,
        )
        .await
        .map_err(|e| not_found(e.to_string()))
}

/// The caller's compose policy name → the policy. `unrestricted` → None.
/// An unknown policy name must NOT disable checks: fall back to the
/// configured default policy (and ultimately to a deny-all default).
async fn caller_policy(state: &AppState, user: &AuthUser) -> Option<crate::config::ComposePolicy> {
    let cfg = state.config.get().await;
    resolve_policy(&cfg, user.user.compose_policy.as_deref())
}

/// Shared resolution used by `caller_policy` and `effective_policy`.
pub(crate) fn resolve_policy(
    cfg: &crate::config::AppConfig,
    user_policy: Option<&str>,
) -> Option<crate::config::ComposePolicy> {
    let name = user_policy.unwrap_or(&cfg.security.default_policy);
    if name == "unrestricted" {
        return None;
    }
    cfg.security
        .policies
        .get(name)
        .cloned()
        .or_else(|| {
            cfg.security
                .policies
                .get(&cfg.security.default_policy)
                .cloned()
        })
        // last resort: built-in strict policy — never fail open
        .or_else(|| Some(crate::config::ComposePolicy::strict_defaults()))
}

fn policy_error(violations: &[PolicyViolation]) -> Response {
    bad_request(format!(
        "compose policy violations: {}",
        violations
            .iter()
            .map(|v| format!("{}: {}", v.path, v.message))
            .collect::<Vec<_>>()
            .join("; ")
    ))
}

// ---------------------------------------------------------------------------
// list / detail
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct ServiceSummary {
    pub name: String,
    pub description: String,
    pub containers: Vec<crate::docker::ContainerInfo>,
    pub running: usize,
    pub total: usize,
    pub unit: UnitSummary,
    pub monitor_state: Option<String>,
}

#[derive(Serialize)]
pub struct UnitSummary {
    pub exists: bool,
    pub enabled: Option<String>,
    pub active: Option<String>,
}

pub async fn list(
    user: AuthUser,
    State(state): State<AppState>,
) -> Result<Json<crate::auth::SuccessResponse<Vec<ServiceSummary>>>, Response> {
    let cfg = state.config.get().await;
    let services: Vec<svc_ops::Service> = state
        .agent
        .call_as(crate::agent::proto::SyncVerb::ServicesList, &user.token)
        .await
        .unwrap_or_default();
    let monitor_states: serde_json::Value = state
        .agent
        .call(crate::agent::proto::SyncVerb::MonitorStatusAll, &user.token)
        .await
        .unwrap_or_else(|_| serde_json::json!({}));
    let mut out = vec![];
    for svc in services {
        if !can_access_service(&user.user, &svc.name, cfg.security.default_access) {
            continue;
        }
        let containers: Vec<crate::docker::ContainerInfo> = state
            .agent
            .call_as(
                crate::agent::proto::SyncVerb::ProjectContainers {
                    service: svc.name.clone(),
                },
                &user.token,
            )
            .await
            .unwrap_or_default();
        let unit = unit_summary(&state, &user, &svc.name).await;
        let monitor_state = monitor_states.get(&svc.name).map(|m| {
            let alerting = m["checks"]
                .as_array()
                .map(|cs| {
                    cs.iter().any(|c| {
                        c["state"].as_str() == Some("down") || c["state"].as_str() == Some("firing")
                    })
                })
                .unwrap_or(false);
            if alerting {
                "alerting".to_string()
            } else {
                "ok".to_string()
            }
        });
        out.push(ServiceSummary {
            name: svc.name.clone(),
            description: svc.meta.description.clone(),
            running: containers.iter().filter(|c| c.state == "running").count(),
            total: containers.len(),
            containers,
            unit,
            monitor_state,
        });
    }
    Ok(ok(out))
}

async fn unit_summary(state: &AppState, user: &AuthUser, name: &str) -> UnitSummary {
    let unit = format!("{name}.service");
    let exists: bool = state
        .agent
        .call_as(
            crate::agent::proto::SyncVerb::UnitPathExists {
                unit: name.to_string(),
            },
            &user.token,
        )
        .await
        .unwrap_or(false);
    let (enabled, active) = if exists {
        state
            .agent
            .call_as::<(Option<String>, Option<String>)>(
                crate::agent::proto::SyncVerb::UnitState { unit },
                &user.token,
            )
            .await
            .unwrap_or_default()
    } else {
        (None, None)
    };
    UnitSummary {
        exists,
        enabled,
        active,
    }
}

#[derive(Serialize)]
pub struct ServiceDetail {
    pub name: String,
    pub dir: String,
    pub host_dir: String,
    pub compose_file: String,
    pub meta: crate::config::ServiceMeta,
    pub containers: Vec<crate::docker::ContainerInfo>,
    pub unit: UnitSummary,
}

pub async fn detail(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<crate::auth::SuccessResponse<ServiceDetail>>, Response> {
    let svc = require_service_access(&state, &user, &name).await?;
    let containers: Vec<crate::docker::ContainerInfo> = state
        .agent
        .call_as(
            crate::agent::proto::SyncVerb::ProjectContainers {
                service: svc.name.clone(),
            },
            &user.token,
        )
        .await
        .unwrap_or_default();
    let unit = unit_summary(&state, &user, &svc.name).await;
    Ok(ok(ServiceDetail {
        name: svc.name.clone(),
        dir: svc.dir.to_string_lossy().to_string(),
        host_dir: svc.host_dir.to_string_lossy().to_string(),
        compose_file: svc
            .compose_path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default(),
        meta: svc.meta,
        containers,
        unit,
    }))
}

// ---------------------------------------------------------------------------
// create / delete
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct CreateService {
    pub name: String,
    /// Raw compose YAML (mutually exclusive with template_id).
    pub compose: Option<String>,
    /// Template id + vars.
    pub template_id: Option<String>,
    #[serde(default)]
    pub vars: HashMap<String, String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub create_unit: bool,
    #[serde(default)]
    pub enable: bool,
    #[serde(default)]
    pub start: bool,
}

pub async fn create(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<CreateService>,
) -> Result<Json<crate::auth::SuccessResponse<serde_json::Value>>, Response> {
    if !user.user.is_admin() && !user.user.features.create_services {
        return Err(forbidden());
    }
    if !valid_service_name(&req.name) {
        return Err(bad_request("invalid service name"));
    }
    let cfg = state.config.get().await;

    let compose_text = match (&req.compose, &req.template_id) {
        (Some(c), None) => c.clone(),
        (None, Some(tid)) => {
            let tpl = cfg
                .service_templates
                .iter()
                .find(|t| t.id == *tid)
                .ok_or_else(|| bad_request("unknown template_id"))?;
            let host_dir = FsPath::new(cfg.paths.host_services_root()).join(&req.name);
            crate::compose::render_template(tpl, &req.name, &host_dir.to_string_lossy(), &req.vars)
                .map_err(|e| bad_request(e.to_string()))?
        }
        _ => return Err(bad_request("provide exactly one of compose or template_id")),
    };
    crate::compose::parse_check(&compose_text).map_err(|e| bad_request(e.to_string()))?;

    // policy validation against caller's policy
    if let Some(pol) = caller_policy(&state, &user).await {
        let v = policy::validate_compose(&compose_text, &pol);
        if !v.is_empty() {
            state.audit.record(
                &user.user.name,
                "service_create_denied",
                &req.name,
                format!("{} violations", v.len()),
            );
            return Err(policy_error(&v));
        }
    }

    let ok_exec = state
        .agent
        .exec_collect(
            crate::agent::proto::ExecVerb::ServiceCreate {
                name: req.name.clone(),
                compose: compose_text,
                description: req.description.clone().unwrap_or_default(),
                template_id: req.template_id.clone(),
                created_by: user.user.name.clone(),
                create_unit: req.create_unit,
                enable: req.enable,
                start: req.start,
            },
            format!("create {}", req.name),
            Some(req.name.clone()),
            &user.token,
            &user.user.name,
            &state.exec,
        )
        .await
        .map_err(|e| internal(e.to_string()))?;
    if !ok_exec {
        return Err(internal("service creation failed"));
    }

    state
        .audit
        .record(&user.user.name, "service_create", &req.name, "");
    Ok(ok(serde_json::json!({ "name": req.name })))
}

#[derive(Deserialize)]
pub struct DeleteQuery {
    #[serde(default)]
    pub keep_dir: bool,
    #[serde(default)]
    pub down: bool,
}

pub async fn delete(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(q): Query<DeleteQuery>,
) -> Result<Json<crate::auth::SuccessResponse<bool>>, Response> {
    if !user.user.is_admin() {
        return Err(forbidden());
    }
    require_service_access(&state, &user, &name).await?;
    state
        .agent
        .exec_collect(
            crate::agent::proto::ExecVerb::ServiceDelete {
                name: name.clone(),
                down: q.down,
                keep_dir: q.keep_dir,
            },
            format!("delete {name}"),
            Some(name.clone()),
            &user.token,
            &user.user.name,
            &state.exec,
        )
        .await
        .map_err(|e| internal(e.to_string()))?;
    state
        .audit
        .record(&user.user.name, "service_delete", &name, "");
    Ok(ok(true))
}

// ---------------------------------------------------------------------------
// compose file get/put
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct ComposeResponse {
    pub content: String,
    pub violations: Vec<PolicyViolation>,
}

pub async fn get_compose(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<crate::auth::SuccessResponse<ComposeResponse>>, Response> {
    let svc = require_service_access(&state, &user, &name).await?;
    let _ = svc;
    let content: String = state
        .agent
        .call_as(
            crate::agent::proto::SyncVerb::ComposeRead {
                service: name.clone(),
            },
            &user.token,
        )
        .await
        .map_err(|e| internal(e.to_string()))?;
    let violations = caller_policy(&state, &user)
        .await
        .map(|p| policy::validate_compose(&content, &p))
        .unwrap_or_default();
    Ok(ok(ComposeResponse {
        content,
        violations,
    }))
}

#[derive(Deserialize)]
pub struct PutCompose {
    pub content: String,
    #[serde(default)]
    pub recreate: bool,
}

pub async fn put_compose(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(req): Json<PutCompose>,
) -> Result<Json<crate::auth::SuccessResponse<serde_json::Value>>, Response> {
    if !user.user.is_admin() && !user.user.features.edit_compose {
        return Err(forbidden());
    }
    let _svc = require_service_access(&state, &user, &name).await?;
    crate::compose::parse_check(&req.content).map_err(|e| bad_request(e.to_string()))?;
    if let Some(pol) = caller_policy(&state, &user).await {
        let v = policy::validate_compose(&req.content, &pol);
        if !v.is_empty() {
            state.audit.record(
                &user.user.name,
                "compose_write_denied",
                &name,
                format!("{} violations", v.len()),
            );
            return Err(policy_error(&v));
        }
    }
    state
        .agent
        .call(
            crate::agent::proto::SyncVerb::ComposeWrite {
                service: name.clone(),
                content: req.content.clone(),
            },
            &user.token,
        )
        .await
        .map_err(|e| internal(e.to_string()))?;
    state
        .audit
        .record(&user.user.name, "compose_write", &name, "");
    let mut exec_id = None;
    if req.recreate {
        exec_id = Some(
            state
                .agent
                .exec(
                    crate::agent::proto::ExecVerb::Compose {
                        service: name.clone(),
                        op: crate::agent::proto::ComposeOp::UpRecreate,
                    },
                    format!("recreate {name}"),
                    Some(name.clone()),
                    &user.token,
                    &user.user.name,
                    &state.exec,
                )
                .await
                .map_err(|e| internal(e.to_string()))?,
        );
    }
    Ok(ok(
        serde_json::json!({ "saved": true, "execution_id": exec_id }),
    ))
}

// ---------------------------------------------------------------------------
// unit file get/put/check/regenerate
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct UnitResponse {
    pub exists: bool,
    pub content: String,
    pub rendered_template: Option<String>,
    pub generated: bool,
}

pub async fn get_unit(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<crate::auth::SuccessResponse<UnitResponse>>, Response> {
    let _svc = require_service_access(&state, &user, &name).await?;
    let content: Option<String> = state
        .agent
        .call_as(
            crate::agent::proto::SyncVerb::UnitFileRead {
                service: name.clone(),
            },
            &user.token,
        )
        .await
        .unwrap_or(None);
    let rendered: Option<String> = state
        .agent
        .call_as(
            crate::agent::proto::SyncVerb::UnitRender {
                service: name.clone(),
            },
            &user.token,
        )
        .await
        .ok();
    let content = content.unwrap_or_default();
    Ok(ok(UnitResponse {
        exists: !content.is_empty(),
        generated: rendered
            .as_ref()
            .map(|r| r.trim_end() == content.trim_end())
            .unwrap_or(false),
        content,
        rendered_template: rendered,
    }))
}

#[derive(Deserialize)]
pub struct PutUnit {
    pub content: String,
    #[serde(default)]
    pub enable: Option<bool>,
    #[serde(default)]
    pub restart: bool,
}

pub async fn put_unit(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(req): Json<PutUnit>,
) -> Result<Json<crate::auth::SuccessResponse<bool>>, Response> {
    let cfg = state.config.get().await;
    let needed = cfg.security.unit_edit_requires.clone();
    // The `edit_units` feature may satisfy a non-admin requirement, but it
    // must never bypass a gate configured as `admin`.
    let feature_ok = user.user.features.edit_units && needed != "admin";
    if !user.user.has_role(&needed) && !feature_ok {
        return Err(forbidden());
    }
    drop(cfg);
    let _svc = require_service_access(&state, &user, &name).await?;
    crate::systemd::validate_unit(&req.content).map_err(|e| bad_request(e.to_string()))?;
    let ok_exec = state
        .agent
        .exec_collect(
            crate::agent::proto::ExecVerb::UnitWrite {
                service: name.clone(),
                content: req.content.clone(),
                enable: req.enable.unwrap_or(false),
                restart: req.restart,
            },
            format!("write unit {name}"),
            Some(name.clone()),
            &user.token,
            &user.user.name,
            &state.exec,
        )
        .await
        .map_err(|e| bad_request(e.to_string()))?;
    if !ok_exec {
        return Err(internal("unit write failed"));
    }
    state.audit.record(&user.user.name, "unit_write", &name, "");
    Ok(ok(true))
}

pub async fn check_unit(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<crate::auth::SuccessResponse<crate::systemd::UnitCheckReport>>, Response> {
    let _svc = require_service_access(&state, &user, &name).await?;
    let report: crate::systemd::UnitCheckReport = state
        .agent
        .call_as(
            crate::agent::proto::SyncVerb::UnitCheck {
                service: name.clone(),
            },
            &user.token,
        )
        .await
        .map_err(|e| internal(e.to_string()))?;
    Ok(ok(report))
}

#[derive(Deserialize)]
pub struct RegenerateRequest {
    #[serde(default)]
    pub enable: bool,
    #[serde(default)]
    pub start: bool,
}

pub async fn regenerate_unit(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(req): Json<RegenerateRequest>,
) -> Result<Json<crate::auth::SuccessResponse<bool>>, Response> {
    if !user.user.is_admin() && !user.user.features.edit_compose {
        return Err(forbidden());
    }
    let _svc = require_service_access(&state, &user, &name).await?;
    let ok_exec = state
        .agent
        .exec_collect(
            crate::agent::proto::ExecVerb::UnitRegen {
                service: name.clone(),
                enable: req.enable,
                start: req.start,
            },
            format!("regen unit {name}"),
            Some(name.clone()),
            &user.token,
            &user.user.name,
            &state.exec,
        )
        .await
        .map_err(|e| internal(e.to_string()))?;
    if !ok_exec {
        return Err(internal("unit regeneration failed"));
    }
    state
        .audit
        .record(&user.user.name, "unit_regenerate", &name, "");
    Ok(ok(true))
}

// ---------------------------------------------------------------------------
// actions
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ActionRequest {
    pub action: String, // pull|up|down|restart|update|start|stop|enable|disable
}

pub async fn action(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(req): Json<ActionRequest>,
) -> Result<Json<crate::auth::SuccessResponse<serde_json::Value>>, Response> {
    if !user.user.has_role("operator") {
        return Err(forbidden());
    }
    let svc = require_service_access(&state, &user, &name).await?;
    let _cfg = state.config.get().await;
    let op = match req.action.as_str() {
        "pull" => crate::agent::proto::ComposeOp::Pull,
        "up" => crate::agent::proto::ComposeOp::Up,
        "down" => crate::agent::proto::ComposeOp::Down,
        "restart" => crate::agent::proto::ComposeOp::Restart,
        "start" => crate::agent::proto::ComposeOp::Start,
        "stop" => crate::agent::proto::ComposeOp::Stop,
        "update" => crate::agent::proto::ComposeOp::Update,
        "enable" => crate::agent::proto::ComposeOp::Enable,
        "disable" => crate::agent::proto::ComposeOp::Disable,
        other => return Err(bad_request(format!("unknown action '{other}'"))),
    };
    let execution_id = state
        .agent
        .exec(
            crate::agent::proto::ExecVerb::Compose {
                service: svc.name.clone(),
                op,
            },
            format!("{} ({})", req.action, svc.name),
            Some(svc.name.clone()),
            &user.token,
            &user.user.name,
            &state.exec,
        )
        .await
        .map_err(|e| internal(e.to_string()))?;
    state.audit.record(
        &user.user.name,
        &format!("service_{}", req.action),
        &name,
        "",
    );
    Ok(ok(serde_json::json!({ "execution_id": execution_id })))
}

// ---------------------------------------------------------------------------
// logs
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct LogsQuery {
    #[serde(default)]
    pub tail: Option<usize>,
    #[serde(flatten)]
    pub filter: LogFilter,
}

pub async fn logs(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(q): Query<LogsQuery>,
) -> Result<Json<crate::auth::SuccessResponse<Vec<serde_json::Value>>>, Response> {
    let svc = require_service_access(&state, &user, &name).await?;
    let cfg = state.config.get().await;
    let tail = q
        .tail
        .unwrap_or(cfg.logging.default_tail)
        .min(cfg.logging.max_tail);
    let filter = CompiledFilter::compile(&q.filter)
        .map_err(|e| bad_request(format!("invalid filter regex: {e}")))?;
    let containers: Vec<crate::docker::ContainerInfo> = state
        .agent
        .call_as(
            crate::agent::proto::SyncVerb::ProjectContainers {
                service: svc.name.clone(),
            },
            &user.token,
        )
        .await
        .unwrap_or_default();
    let mut lines = vec![];
    for c in &containers {
        let logs: Vec<crate::docker::LogLine> = state
            .agent
            .call_as(
                crate::agent::proto::SyncVerb::ContainerLogsCollect {
                    id: c.id.clone(),
                    tail,
                    since: q.filter.since,
                },
                &user.token,
            )
            .await
            .map_err(|e| internal(e.to_string()))?;
        for l in logs {
            if filter.matches(&l.text, &l.stream, Some(&c.service)) {
                lines.push(serde_json::json!({
                    "container": c.name,
                    "service": c.service,
                    "stream": l.stream,
                    "text": l.text,
                }));
            }
        }
    }
    Ok(ok(lines))
}

// ---------------------------------------------------------------------------
// backup endpoints
// ---------------------------------------------------------------------------

pub async fn get_backup(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<crate::auth::SuccessResponse<serde_json::Value>>, Response> {
    let svc = require_service_access(&state, &user, &name).await?;
    let cfg = state.config.get().await;
    Ok(ok(serde_json::json!({
        "enabled_global": cfg.backup.enabled,
        "repository": crate::backup::repository_for(&cfg.backup, &svc.name),
        "config": svc.meta.backup,
    })))
}

pub async fn put_backup(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(bcfg): Json<ServiceBackupConfig>,
) -> Result<Json<crate::auth::SuccessResponse<bool>>, Response> {
    if !user.user.is_admin() && !user.user.features.manage_backup {
        return Err(forbidden());
    }
    let _svc = require_service_access(&state, &user, &name).await?;
    for p in &bcfg.paths {
        if !svc_ops::valid_rel_path(p) {
            return Err(bad_request(format!("invalid backup path '{p}'")));
        }
    }
    // stdin_dumps land in a root-run script — fail fast server-side too
    // (the agent re-validates against the real compose services).
    crate::backup::validate_dumps(&bcfg.stdin_dumps).map_err(|e| bad_request(e.to_string()))?;
    state
        .agent
        .call(
            crate::agent::proto::SyncVerb::BackupPut {
                service: name.clone(),
                cfg: bcfg,
            },
            &user.token,
        )
        .await
        .map_err(|e| internal(e.to_string()))?;
    state
        .audit
        .record(&user.user.name, "backup_config", &name, "");
    Ok(ok(true))
}

pub async fn backup_check(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<crate::auth::SuccessResponse<crate::backup::BackupCheckReport>>, Response> {
    let _svc = require_service_access(&state, &user, &name).await?;
    let report: crate::backup::BackupCheckReport = state
        .agent
        .call_as(
            crate::agent::proto::SyncVerb::BackupCheck {
                service: name.clone(),
            },
            &user.token,
        )
        .await
        .map_err(|e| internal(e.to_string()))?;
    Ok(ok(report))
}

pub async fn backup_provision(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<crate::auth::SuccessResponse<Vec<String>>>, Response> {
    if !user.user.is_admin() && !user.user.features.manage_backup {
        return Err(forbidden());
    }
    let _svc = require_service_access(&state, &user, &name).await?;
    let steps: Vec<String> = state
        .agent
        .call_as(
            crate::agent::proto::SyncVerb::BackupProvision {
                service: name.clone(),
            },
            &user.token,
        )
        .await
        .map_err(|e| internal(e.to_string()))?;
    state
        .audit
        .record(&user.user.name, "backup_provision", &name, "");
    Ok(ok(steps))
}

pub async fn backup_run(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<crate::auth::SuccessResponse<serde_json::Value>>, Response> {
    if !user.user.is_admin() && !user.user.features.manage_backup {
        return Err(forbidden());
    }
    let _svc = require_service_access(&state, &user, &name).await?;
    let id = state
        .agent
        .exec(
            crate::agent::proto::ExecVerb::BackupRun {
                service: name.clone(),
            },
            format!("backup run ({name})"),
            Some(name.clone()),
            &user.token,
            &user.user.name,
            &state.exec,
        )
        .await
        .map_err(|e| internal(e.to_string()))?;
    state.audit.record(&user.user.name, "backup_run", &name, "");
    Ok(ok(serde_json::json!({ "execution_id": id })))
}

pub async fn backup_snapshots(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<crate::auth::SuccessResponse<serde_json::Value>>, Response> {
    let _svc = require_service_access(&state, &user, &name).await?;
    let snaps: serde_json::Value = state
        .agent
        .call(
            crate::agent::proto::SyncVerb::BackupSnapshots {
                service: name.clone(),
            },
            &user.token,
        )
        .await
        .map_err(|e| internal(e.to_string()))?;
    Ok(ok(snaps))
}

pub async fn backup_forget(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<crate::auth::SuccessResponse<serde_json::Value>>, Response> {
    if !user.user.is_admin() && !user.user.features.manage_backup {
        return Err(forbidden());
    }
    let _svc = require_service_access(&state, &user, &name).await?;
    let id = state
        .agent
        .exec(
            crate::agent::proto::ExecVerb::BackupForget {
                service: name.clone(),
            },
            format!("backup forget ({name})"),
            Some(name.clone()),
            &user.token,
            &user.user.name,
            &state.exec,
        )
        .await
        .map_err(|e| internal(e.to_string()))?;
    state
        .audit
        .record(&user.user.name, "backup_forget", &name, "");
    Ok(ok(serde_json::json!({ "execution_id": id })))
}

#[derive(Deserialize)]
pub struct BackupLsQuery {
    pub snapshot: String,
    /// Optional subdir inside the snapshot to list.
    #[serde(default)]
    pub path: Option<String>,
}

/// `restic ls` — file listing inside a snapshot (browse a backup).
pub async fn backup_ls(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(q): Query<BackupLsQuery>,
) -> Result<Json<crate::auth::SuccessResponse<serde_json::Value>>, Response> {
    let _svc = require_service_access(&state, &user, &name).await?;
    let entries: serde_json::Value = state
        .agent
        .call(
            crate::agent::proto::SyncVerb::BackupLs {
                service: name.clone(),
                snapshot: q.snapshot.clone(),
                path: q.path.clone(),
            },
            &user.token,
        )
        .await
        .map_err(|e| bad_request(e.to_string()))?;
    Ok(ok(entries))
}

#[derive(Deserialize)]
pub struct RestoreRequest {
    pub snapshot: String,
    /// Target dir for the restore — relative to the service dir, or an
    /// absolute host path. Files land under `<target>/<snapshot-path>`.
    pub target_dir: String,
    /// Optional `restic --include` patterns for a selective restore;
    /// absent or empty restores the whole snapshot.
    #[serde(default)]
    pub include: Option<Vec<String>>,
}

pub async fn backup_restore(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(req): Json<RestoreRequest>,
) -> Result<Json<crate::auth::SuccessResponse<serde_json::Value>>, Response> {
    // restore is destructive-adjacent: admin or unrestricted policy only
    let unrestricted = user.user.compose_policy.as_deref() == Some("unrestricted");
    if !user.user.is_admin() && !unrestricted {
        return Err(forbidden());
    }
    let _svc = require_service_access(&state, &user, &name).await?;
    let id = state
        .agent
        .exec(
            crate::agent::proto::ExecVerb::BackupRestore {
                service: name.clone(),
                snapshot: req.snapshot.clone(),
                target_dir: req.target_dir.clone(),
                include: req.include.clone(),
            },
            format!("backup restore ({name})"),
            Some(name.clone()),
            &user.token,
            &user.user.name,
            &state.exec,
        )
        .await
        .map_err(|e| internal(e.to_string()))?;
    state.audit.record(
        &user.user.name,
        "backup_restore",
        &name,
        format!("{} → {}", req.snapshot, req.target_dir),
    );
    Ok(ok(serde_json::json!({ "execution_id": id })))
}

// ---------------------------------------------------------------------------
// monitoring endpoints
// ---------------------------------------------------------------------------

pub async fn get_monitoring(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<crate::auth::SuccessResponse<serde_json::Value>>, Response> {
    let _svc = require_service_access(&state, &user, &name).await?;
    let mon_cfg: Option<crate::config::ServiceMonitoringConfig> = state
        .agent
        .call_as(
            crate::agent::proto::SyncVerb::MonitoringGet {
                service: name.clone(),
            },
            &user.token,
        )
        .await
        .unwrap_or(None);
    let all: serde_json::Value = state
        .agent
        .call(crate::agent::proto::SyncVerb::MonitorStatusAll, &user.token)
        .await
        .unwrap_or_else(|_| serde_json::json!({}));
    Ok(ok(serde_json::json!({
        "config": mon_cfg,
        "state": all.get(&name).cloned(),
    })))
}

pub async fn put_monitoring(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(m): Json<ServiceMonitoringConfig>,
) -> Result<Json<crate::auth::SuccessResponse<bool>>, Response> {
    if !user.user.is_admin()
        && !user.user.features.manage_monitoring
        && !user.user.features.edit_compose
    {
        return Err(forbidden());
    }
    let cfg = state.config.get().await;
    validate_monitoring_cfg(&m, &cfg).map_err(bad_request)?;
    // exec_command actions fire host commands with no user context —
    // configuring them is admin-only.
    if monitoring_has_exec_actions(&m) && !user.user.is_admin() {
        return Err(forbidden());
    }
    let _svc = require_service_access(&state, &user, &name).await?;
    state
        .agent
        .call(
            crate::agent::proto::SyncVerb::MonitoringPut {
                service: name.clone(),
                cfg: m,
            },
            &user.token,
        )
        .await
        .map_err(|e| internal(e.to_string()))?;
    state
        .audit
        .record(&user.user.name, "monitoring_config", &name, "");
    Ok(ok(true))
}

pub async fn monitoring_test(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<crate::auth::SuccessResponse<serde_json::Value>>, Response> {
    let svc = require_service_access(&state, &user, &name).await?;
    let containers: Vec<crate::docker::ContainerInfo> = state
        .agent
        .call_as(
            crate::agent::proto::SyncVerb::ProjectContainers {
                service: svc.name.clone(),
            },
            &user.token,
        )
        .await
        .unwrap_or_default();
    let mut health = vec![];
    for c in &containers {
        health.push(serde_json::json!({
            "container": c.name,
            "state": c.state,
            "health": c.health,
        }));
    }
    Ok(ok(serde_json::json!({ "containers": health })))
}

/// Does this monitoring config contain `exec_command` auto-actions? Those
/// run configured command items with *no* user context inside the agent —
/// configuring them is admin-only, enforced by the API handler and the
/// agent-side precheck.
pub(crate) fn monitoring_has_exec_actions(m: &ServiceMonitoringConfig) -> bool {
    m.health
        .iter()
        .flat_map(|h| h.actions.iter())
        .chain(m.log_alerts.iter().flat_map(|a| a.actions.iter()))
        .any(|a| matches!(a, crate::config::AutoAction::ExecCommand { .. }))
}

/// Shared monitoring-config validation — enforced both in the API handler
/// and inside the agent (a hostile server can't bypass it).
pub(crate) fn validate_monitoring_cfg(
    m: &ServiceMonitoringConfig,
    cfg: &crate::config::AppConfig,
) -> Result<(), String> {
    let check_actions = |actions: &[crate::config::AutoAction]| -> Result<(), String> {
        for a in actions {
            if let crate::config::AutoAction::ExecCommand {
                section_index,
                item_index,
                ..
            } = a
            {
                let sec = cfg
                    .sections
                    .get(*section_index)
                    .ok_or_else(|| "exec_command action: bad section index".to_string())?;
                let it = sec
                    .items
                    .get(*item_index)
                    .ok_or_else(|| "exec_command action: bad item index".to_string())?;
                // Auto-actions run unattended with no caller — they must
                // never reach a command gated by a required_role, or
                // monitoring config becomes a role bypass.
                if sec.required_role.is_some() || it.required_role.is_some() {
                    return Err("exec_command action must not target a role-gated command".into());
                }
            }
        }
        Ok(())
    };
    if let Some(h) = &m.health {
        check_actions(&h.actions)?;
    }
    for a in &m.log_alerts {
        check_actions(&a.actions)?;
    }
    for a in &m.log_alerts {
        regex::Regex::new(&a.regex).map_err(|e| format!("invalid regex: {e}"))?;
        if let Some(x) = &a.exclude_regex {
            regex::Regex::new(x).map_err(|e| format!("invalid exclude_regex: {e}"))?;
        }
    }
    // health-check targets are probed by the agent — keep them sane:
    // http checks must be plain http(s) without credentials; tcp checks a
    // bare host[:port] (validated for charset, no spaces/schemes).
    if let Some(h) = &m.health {
        match (h.kind, h.target.as_deref()) {
            (crate::config::HealthCheckKind::Http, Some(t)) => {
                let authority = t
                    .split_once("://")
                    .map(|(_, rest)| rest.split(['/', '?', '#']).next().unwrap_or(""))
                    .unwrap_or("");
                let ok = (t.starts_with("http://") || t.starts_with("https://"))
                    && !authority.is_empty()
                    && !authority.contains('@')
                    && t.len() <= 2048;
                if !ok {
                    return Err(
                        "http health check target must be a credential-free http(s) URL".into(),
                    );
                }
            }
            (crate::config::HealthCheckKind::Tcp, Some(t)) => {
                let host = t.split(':').next().unwrap_or("");
                if host.is_empty()
                    || !host
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'))
                {
                    return Err("invalid tcp health check target".into());
                }
            }
            _ => {}
        }
    }
    Ok(())
}
