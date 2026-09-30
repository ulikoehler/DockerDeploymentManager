use crate::auth::{bad_request, forbidden, internal, not_found, ok, AuthUser};
use crate::config::{ServiceBackupConfig, ServiceMonitoringConfig};
use crate::docker::compose_argv;
use crate::exec::{host_shell_item, shell_item};
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
    svc_ops::get_service(&cfg, name).map_err(|e| not_found(e.to_string()))
}

/// The caller's compose policy name → the policy. `unrestricted` → None.
async fn caller_policy(state: &AppState, user: &AuthUser) -> Option<crate::config::ComposePolicy> {
    let cfg = state.config.get().await;
    let name = user
        .user
        .compose_policy
        .clone()
        .unwrap_or_else(|| cfg.security.default_policy.clone());
    if name == "unrestricted" {
        return None;
    }
    cfg.security.policies.get(&name).cloned()
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
    let services = svc_ops::discover_services(&cfg);
    let monitor_states = state.monitor.status().await;
    let mut out = vec![];
    for svc in services {
        if !can_access_service(&user.user, &svc.name, cfg.security.default_access) {
            continue;
        }
        let containers = state
            .docker
            .project_containers(&svc.name)
            .await
            .unwrap_or_default();
        let unit = unit_summary(&state, &svc.name).await;
        let monitor_state = monitor_states.get(&svc.name).map(|m| {
            if m.checks
                .iter()
                .any(|c| c.state == "down" || c.state == "firing")
            {
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

async fn unit_summary(state: &AppState, name: &str) -> UnitSummary {
    let cfg = state.config.get().await;
    let path = crate::systemd::unit_path(&cfg, name);
    let exists = path.is_file();
    let (enabled, active) = if exists {
        crate::systemd::unit_state(&state.host, &format!("{name}.service")).await
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
    let containers = state
        .docker
        .project_containers(&svc.name)
        .await
        .unwrap_or_default();
    let unit = unit_summary(&state, &svc.name).await;
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

    let dir =
        svc_ops::create_service_dir(&cfg, &req.name).map_err(|e| bad_request(e.to_string()))?;
    let compose_path = dir.join(&cfg.paths.compose_file);
    crate::compose::write_compose(&compose_path, &compose_text)
        .map_err(|e| internal(e.to_string()))?;

    let meta = crate::config::ServiceMeta {
        description: req.description.clone().unwrap_or_default(),
        created_by: Some(user.user.name.clone()),
        template: req.template_id.clone(),
        ..Default::default()
    };
    svc_ops::save_meta(&dir, &meta).map_err(|e| internal(e.to_string()))?;

    // optional systemd unit
    if req.create_unit {
        let svc = svc_ops::get_service(&cfg, &req.name).map_err(|e| internal(e.to_string()))?;
        let unit = crate::systemd::render_unit_for(&cfg, &state.host, &svc)
            .await
            .map_err(|e| internal(e.to_string()))?;
        crate::systemd::write_unit(&cfg, &state.host, &svc, &unit)
            .await
            .map_err(|e| internal(e.to_string()))?;
        if req.enable {
            let _ = state
                .host
                .run(
                    "systemctl",
                    &["enable".into(), format!("{}.service", svc.name)],
                )
                .await;
        }
        if req.start {
            let _ = state
                .host
                .run(
                    "systemctl",
                    &["start".into(), format!("{}.service", svc.name)],
                )
                .await;
        }
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
    let svc = require_service_access(&state, &user, &name).await?;
    if q.down {
        let _ = compose_exec(&state, &svc, &["down"]).await;
    }
    // remove unit
    let cfg = state.config.get().await;
    let unit = crate::systemd::unit_path(&cfg, &svc.name);
    if unit.exists() {
        let _ = state
            .host
            .run(
                "systemctl",
                &["disable".into(), "--now".into(), format!("{name}.service")],
            )
            .await;
        let _ = std::fs::remove_file(&unit);
        let _ = state.host.run("systemctl", &["daemon-reload".into()]).await;
    }
    if !q.keep_dir {
        std::fs::remove_dir_all(&svc.dir).map_err(|e| internal(e.to_string()))?;
    }
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
    let content =
        crate::compose::read_compose(&svc.compose_path).map_err(|e| internal(e.to_string()))?;
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
    let svc = require_service_access(&state, &user, &name).await?;
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
    crate::compose::write_compose(&svc.compose_path, &req.content)
        .map_err(|e| internal(e.to_string()))?;
    state
        .audit
        .record(&user.user.name, "compose_write", &name, "");
    let mut exec_id = None;
    if req.recreate {
        exec_id =
            Some(run_compose_action(&state, &svc, &user, &["up", "-d", "--remove-orphans"]).await);
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
    let svc = require_service_access(&state, &user, &name).await?;
    let cfg = state.config.get().await;
    let path = crate::systemd::unit_path(&cfg, &svc.name);
    let content = std::fs::read_to_string(&path).unwrap_or_default();
    let rendered = crate::systemd::render_unit_for(&cfg, &state.host, &svc)
        .await
        .ok();
    Ok(ok(UnitResponse {
        exists: path.is_file(),
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
    if !user.user.has_role(&needed) && !user.user.features.edit_units {
        return Err(forbidden());
    }
    drop(cfg);
    let svc = require_service_access(&state, &user, &name).await?;
    let cfg = state.config.get().await;
    crate::systemd::write_unit(&cfg, &state.host, &svc, &req.content)
        .await
        .map_err(|e| bad_request(e.to_string()))?;
    if req.enable == Some(true) {
        let _ = state
            .host
            .run("systemctl", &["enable".into(), format!("{name}.service")])
            .await;
    }
    if req.restart {
        let _ = state
            .host
            .run("systemctl", &["restart".into(), format!("{name}.service")])
            .await;
    }
    state.audit.record(&user.user.name, "unit_write", &name, "");
    Ok(ok(true))
}

pub async fn check_unit(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<crate::auth::SuccessResponse<crate::systemd::UnitCheckReport>>, Response> {
    let svc = require_service_access(&state, &user, &name).await?;
    let cfg = state.config.get().await;
    let report = crate::systemd::check_unit(&cfg, &state.host, &svc).await;
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
    let svc = require_service_access(&state, &user, &name).await?;
    let cfg = state.config.get().await;
    let unit = crate::systemd::render_unit_for(&cfg, &state.host, &svc)
        .await
        .map_err(|e| internal(e.to_string()))?;
    crate::systemd::write_unit(&cfg, &state.host, &svc, &unit)
        .await
        .map_err(|e| internal(e.to_string()))?;
    if req.enable {
        let _ = state
            .host
            .run("systemctl", &["enable".into(), format!("{name}.service")])
            .await;
    }
    if req.start {
        let _ = state
            .host
            .run("systemctl", &["start".into(), format!("{name}.service")])
            .await;
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

async fn compose_exec(
    state: &AppState,
    svc: &svc_ops::Service,
    args: &[&str],
) -> Result<std::process::Output, std::io::Error> {
    let cfg = state.config.get().await;
    let (prog, mut argv) = compose_argv(&cfg.docker.compose_command, &[]);
    argv.push("-f".into());
    argv.push(
        svc.compose_path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string(),
    );
    argv.extend(args.iter().map(|s| s.to_string()));
    tokio::process::Command::new(&prog)
        .args(&argv)
        .current_dir(&svc.dir)
        .output()
        .await
}

async fn run_compose_action(
    state: &AppState,
    svc: &svc_ops::Service,
    user: &AuthUser,
    args: &[&str],
) -> String {
    let cfg = state.config.get().await;
    let (prog, mut argv) = compose_argv(&cfg.docker.compose_command, &[]);
    argv.push("-f".into());
    argv.push(
        svc.compose_path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string(),
    );
    argv.extend(args.iter().map(|s| s.to_string()));
    let title = format!("compose {} ({})", args.join(" "), svc.name);
    let script = format!(
        "cd {} && {} {}",
        shell(&svc.dir.to_string_lossy()),
        prog,
        argv.join(" ")
    );
    let item = shell_item(&title, &script, ".");
    state.exec.run_item(
        item,
        HashMap::new(),
        &user.user.name,
        Some(svc.name.clone()),
        false,
    )
}

fn shell(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
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
    let cfg = state.config.get().await;
    let execution_id = match req.action.as_str() {
        // compose lifecycle
        "pull" => run_compose_action(&state, &svc, &user, &["pull"]).await,
        "up" => run_compose_action(&state, &svc, &user, &["up", "-d"]).await,
        "down" => run_compose_action(&state, &svc, &user, &["down"]).await,
        "restart" => run_compose_action(&state, &svc, &user, &["restart"]).await,
        "start" => run_compose_action(&state, &svc, &user, &["start"]).await,
        "stop" => run_compose_action(&state, &svc, &user, &["stop"]).await,
        "update" => {
            // pull + up -d --remove-orphans
            let cfg2 = state.config.get().await;
            let (prog, mut argv) = compose_argv(&cfg2.docker.compose_command, &[]);
            argv.push("-f".into());
            argv.push(
                svc.compose_path
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .to_string(),
            );
            let script = format!(
                "cd {dir} && {prog} {a} pull && {prog} {a} up -d --remove-orphans",
                dir = shell(&svc.dir.to_string_lossy()),
                prog = prog,
                a = argv.join(" "),
            );
            state.exec.run_item(
                shell_item(&format!("update ({})", svc.name), &script, "."),
                HashMap::new(),
                &user.user.name,
                Some(svc.name.clone()),
                false,
            )
        }
        // systemd enable/disable via host
        "enable" | "disable" => {
            let unit = format!("{}.service", svc.name);
            let script = format!("systemctl {} {}", req.action, shell(&unit));
            state.exec.run_item(
                host_shell_item(
                    &format!("systemctl {} ({})", req.action, svc.name),
                    &script,
                    cfg.paths.host_exec,
                    cfg.paths.nsenter_target,
                ),
                HashMap::new(),
                &user.user.name,
                Some(svc.name.clone()),
                true,
            )
        }
        other => return Err(bad_request(format!("unknown action '{other}'"))),
    };
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
    let containers = state
        .docker
        .project_containers(&svc.name)
        .await
        .unwrap_or_default();
    let mut lines = vec![];
    for c in &containers {
        let mut stream = state
            .docker
            .logs(&c.id, tail, q.filter.since, false)
            .await
            .map_err(|e| internal(e.to_string()))?;
        use futures::StreamExt;
        while let Some(line) = stream.next().await {
            if let Ok(l) = line {
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
    let mut svc = require_service_access(&state, &user, &name).await?;
    for p in &bcfg.paths {
        if !svc_ops::valid_rel_path(p) {
            return Err(bad_request(format!("invalid backup path '{p}'")));
        }
    }
    svc.meta.backup = Some(bcfg);
    svc_ops::save_meta(&svc.dir, &svc.meta).map_err(|e| internal(e.to_string()))?;
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
    let svc = require_service_access(&state, &user, &name).await?;
    let cfg = state.config.get().await;
    Ok(ok(crate::backup::check(&cfg, &state.host, &svc).await))
}

pub async fn backup_provision(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<crate::auth::SuccessResponse<Vec<String>>>, Response> {
    if !user.user.is_admin() && !user.user.features.manage_backup {
        return Err(forbidden());
    }
    let svc = require_service_access(&state, &user, &name).await?;
    let cfg = state.config.get().await;
    let bin = match cfg.backup.restic_binary.as_str() {
        "auto" => state
            .host
            .which("restic")
            .await
            .map_err(|e| internal(e.to_string()))?
            .unwrap_or_else(|| "restic".to_string()),
        b => b.to_string(),
    };
    let steps = crate::backup::provision(&cfg, &state.host, &svc, &bin)
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
    let svc = require_service_access(&state, &user, &name).await?;
    let cfg = state.config.get().await;
    let script = crate::backup::run_script(&svc);
    let id = state.exec.run_item(
        host_shell_item(
            &format!("backup run ({name})"),
            &script,
            cfg.paths.host_exec,
            cfg.paths.nsenter_target,
        ),
        HashMap::new(),
        &user.user.name,
        Some(name.clone()),
        true,
    );
    state.audit.record(&user.user.name, "backup_run", &name, "");
    Ok(ok(serde_json::json!({ "execution_id": id })))
}

pub async fn backup_snapshots(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<crate::auth::SuccessResponse<serde_json::Value>>, Response> {
    let svc = require_service_access(&state, &user, &name).await?;
    let cfg = state.config.get().await;
    let bin = match cfg.backup.restic_binary.as_str() {
        "auto" => state
            .host
            .which("restic")
            .await
            .map_err(|e| internal(e.to_string()))?
            .unwrap_or_else(|| "restic".to_string()),
        b => b.to_string(),
    };
    let snaps = crate::backup::snapshots(&cfg, &state.host, &svc, &bin)
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
    let svc = require_service_access(&state, &user, &name).await?;
    let cfg = state.config.get().await;
    let bin = match cfg.backup.restic_binary.as_str() {
        "auto" => state
            .host
            .which("restic")
            .await
            .map_err(|e| internal(e.to_string()))?
            .unwrap_or_else(|| "restic".to_string()),
        b => b.to_string(),
    };
    let script = crate::backup::forget_script(&cfg, &svc, &bin);
    let id = state.exec.run_item(
        host_shell_item(
            &format!("backup forget ({name})"),
            &script,
            cfg.paths.host_exec,
            cfg.paths.nsenter_target,
        ),
        HashMap::new(),
        &user.user.name,
        Some(name.clone()),
        true,
    );
    state
        .audit
        .record(&user.user.name, "backup_forget", &name, "");
    Ok(ok(serde_json::json!({ "execution_id": id })))
}

#[derive(Deserialize)]
pub struct RestoreRequest {
    pub snapshot: String,
    pub target_dir: String,
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
    let svc = require_service_access(&state, &user, &name).await?;
    let cfg = state.config.get().await;
    let bin = match cfg.backup.restic_binary.as_str() {
        "auto" => state
            .host
            .which("restic")
            .await
            .map_err(|e| internal(e.to_string()))?
            .unwrap_or_else(|| "restic".to_string()),
        b => b.to_string(),
    };
    let script = crate::backup::restore_script(&cfg, &svc, &bin, &req.snapshot, &req.target_dir)
        .map_err(|e| bad_request(e.to_string()))?;
    let id = state.exec.run_item(
        host_shell_item(
            &format!("backup restore ({name})"),
            &script,
            cfg.paths.host_exec,
            cfg.paths.nsenter_target,
        ),
        HashMap::new(),
        &user.user.name,
        Some(name.clone()),
        true,
    );
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
    let svc = require_service_access(&state, &user, &name).await?;
    Ok(ok(serde_json::json!({
        "config": svc.meta.monitoring,
        "state": state.monitor.status().await.get(&name).cloned(),
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
    // validate regexes eagerly
    for a in &m.log_alerts {
        regex::Regex::new(&a.regex).map_err(|e| bad_request(format!("invalid regex: {e}")))?;
        if let Some(x) = &a.exclude_regex {
            regex::Regex::new(x).map_err(|e| bad_request(format!("invalid exclude_regex: {e}")))?;
        }
    }
    let mut svc = require_service_access(&state, &user, &name).await?;
    svc.meta.monitoring = Some(m);
    svc_ops::save_meta(&svc.dir, &svc.meta).map_err(|e| internal(e.to_string()))?;
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
    let containers = state
        .docker
        .project_containers(&svc.name)
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
