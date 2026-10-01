use crate::auth::{bad_request, forbidden, not_found, ok, AuthUser};
use crate::config::AppConfig;
use crate::AppState;
use axum::{
    extract::{Path, Query, State},
    response::Response,
    Json,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct GroupInfo {
    pub id: String,
    pub title: String,
    pub unit_regex: String,
    pub custom_commands: Vec<CommandInfo>,
}

#[derive(Serialize)]
pub struct CommandInfo {
    pub id: String,
    pub label: String,
}

fn find_group<'a>(cfg: &'a AppConfig, id: &str) -> Option<&'a crate::config::SystemdGroup> {
    cfg.systemd.groups.iter().find(|g| g.id == id)
}

fn unit_matches_group(cfg: &AppConfig, unit: &str) -> Option<String> {
    for g in &cfg.systemd.groups {
        if let Ok(re) = regex::Regex::new(&g.unit_regex) {
            if re.is_match(unit) {
                return Some(g.id.clone());
            }
        }
    }
    None
}

/// Unit names are interpolated into shell scripts — only allow characters
/// systemd itself permits (alphanumerics plus `_.@-`), nothing that could
/// break out of quoting or carry path traversal.
fn valid_unit_name(unit: &str) -> bool {
    !unit.is_empty()
        && unit.len() <= 256
        && unit
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '@' | '-'))
}

/// Gate: systemd endpoints are for operator/admin by default.
#[allow(clippy::result_large_err)]
fn require_operator(user: &AuthUser) -> Result<(), Response> {
    if user.user.has_role("operator") {
        Ok(())
    } else {
        Err(forbidden())
    }
}

pub async fn groups(
    user: AuthUser,
    State(state): State<AppState>,
) -> Result<Json<crate::auth::SuccessResponse<Vec<GroupInfo>>>, Response> {
    require_operator(&user)?;
    let cfg = state.config.get().await;
    Ok(ok(cfg
        .systemd
        .groups
        .iter()
        .map(|g| GroupInfo {
            id: g.id.clone(),
            title: g.title.clone(),
            unit_regex: g.unit_regex.clone(),
            custom_commands: g
                .custom_commands
                .iter()
                .map(|c| CommandInfo {
                    id: c.id().to_string(),
                    label: c.label().to_string(),
                })
                .collect(),
        })
        .collect()))
}

pub async fn group_status(
    user: AuthUser,
    State(state): State<AppState>,
    Path(group): Path<String>,
) -> Result<Json<crate::auth::SuccessResponse<Vec<crate::systemd::SystemdUnitStatus>>>, Response> {
    require_operator(&user)?;
    let cfg = state.config.get().await;
    let g = find_group(&cfg, &group).ok_or_else(|| not_found("unknown group"))?;
    let units: Vec<crate::systemd::SystemdUnitStatus> = state
        .agent
        .call_as(
            crate::agent::proto::SyncVerb::ListUnits {
                regex: g.unit_regex.clone(),
            },
            &user.token,
        )
        .await
        .map_err(|e| bad_request(e.to_string()))?;
    Ok(ok(units))
}

pub async fn unit_restart(
    user: AuthUser,
    State(state): State<AppState>,
    Path(unit): Path<String>,
) -> Result<Json<crate::auth::SuccessResponse<serde_json::Value>>, Response> {
    require_operator(&user)?;
    checked_unit(&unit)?;
    let cfg = state.config.get().await;
    if unit_matches_group(&cfg, &unit).is_none() && !user.user.is_admin() {
        return Err(forbidden());
    }
    let id = state
        .agent
        .exec(
            crate::agent::proto::ExecVerb::SystemdRestart {
                target: crate::agent::proto::SystemdTarget::Unit(unit.clone()),
            },
            format!("systemctl restart {unit}"),
            None,
            &user.token,
            &user.user.name,
            &state.exec,
        )
        .await
        .map_err(|e| bad_request(e.to_string()))?;
    state
        .audit
        .record(&user.user.name, "unit_restart", &unit, "");
    Ok(ok(serde_json::json!({ "execution_id": id })))
}

pub async fn group_restart(
    user: AuthUser,
    State(state): State<AppState>,
    Path(group): Path<String>,
) -> Result<Json<crate::auth::SuccessResponse<serde_json::Value>>, Response> {
    require_operator(&user)?;
    let cfg = state.config.get().await;
    let g = find_group(&cfg, &group).ok_or_else(|| not_found("unknown group"))?;
    let _ = g;
    let id = state
        .agent
        .exec(
            crate::agent::proto::ExecVerb::SystemdRestart {
                target: crate::agent::proto::SystemdTarget::Group(group.clone()),
            },
            format!("restart group {group}"),
            None,
            &user.token,
            &user.user.name,
            &state.exec,
        )
        .await
        .map_err(|e| bad_request(e.to_string()))?;
    state
        .audit
        .record(&user.user.name, "group_restart", &group, "");
    Ok(ok(serde_json::json!({ "execution_id": id })))
}

#[derive(Deserialize)]
pub struct ExecuteRequest {
    pub command_id: String,
}

/// `unit` is user-controlled (path param): it must pass the charset check;
/// callers additionally enforce the group match / admin bypass.
#[allow(clippy::result_large_err)]
fn checked_unit(unit: &str) -> Result<(), Response> {
    if !valid_unit_name(unit) {
        return Err(bad_request("invalid unit name"));
    }
    Ok(())
}

pub async fn unit_execute(
    user: AuthUser,
    State(state): State<AppState>,
    Path(unit): Path<String>,
    Json(req): Json<ExecuteRequest>,
) -> Result<Json<crate::auth::SuccessResponse<serde_json::Value>>, Response> {
    require_operator(&user)?;
    checked_unit(&unit)?;
    let cfg = state.config.get().await;
    let _group_id = unit_matches_group(&cfg, &unit)
        .ok_or_else(|| bad_request("no systemd group matches this unit"))?;
    let id = state
        .agent
        .exec(
            crate::agent::proto::ExecVerb::SystemdCommand {
                target: crate::agent::proto::SystemdTarget::Unit(unit.clone()),
                command_id: req.command_id.clone(),
            },
            format!("{} ({})", req.command_id, unit),
            None,
            &user.token,
            &user.user.name,
            &state.exec,
        )
        .await
        .map_err(|e| bad_request(e.to_string()))?;
    state
        .audit
        .record(&user.user.name, "unit_execute", &unit, &req.command_id);
    Ok(ok(serde_json::json!({ "execution_id": id })))
}

pub async fn group_execute(
    user: AuthUser,
    State(state): State<AppState>,
    Path(group): Path<String>,
    Json(req): Json<ExecuteRequest>,
) -> Result<Json<crate::auth::SuccessResponse<serde_json::Value>>, Response> {
    require_operator(&user)?;
    let cfg = state.config.get().await;
    let g = find_group(&cfg, &group).ok_or_else(|| not_found("unknown group"))?;
    let _ = g;
    let id = state
        .agent
        .exec(
            crate::agent::proto::ExecVerb::SystemdCommand {
                target: crate::agent::proto::SystemdTarget::Group(group.clone()),
                command_id: req.command_id.clone(),
            },
            format!("{} on group {group}", req.command_id),
            None,
            &user.token,
            &user.user.name,
            &state.exec,
        )
        .await
        .map_err(|e| bad_request(e.to_string()))?;
    state
        .audit
        .record(&user.user.name, "group_execute", &group, &req.command_id);
    Ok(ok(serde_json::json!({ "execution_id": id })))
}

#[derive(Deserialize)]
pub struct LogsQuery {
    #[serde(default = "default_lines")]
    pub lines: usize,
}
fn default_lines() -> usize {
    200
}

pub async fn unit_logs(
    user: AuthUser,
    State(state): State<AppState>,
    Path(unit): Path<String>,
    Query(q): Query<LogsQuery>,
) -> Result<Json<crate::auth::SuccessResponse<String>>, Response> {
    require_operator(&user)?;
    checked_unit(&unit)?;
    let cfg = state.config.get().await;
    if unit_matches_group(&cfg, &unit).is_none() && !user.user.is_admin() {
        return Err(forbidden());
    }
    let text: String = state
        .agent
        .call_as(
            crate::agent::proto::SyncVerb::Journal {
                unit: unit.clone(),
                lines: q.lines,
            },
            &user.token,
        )
        .await
        .map_err(|e| bad_request(e.to_string()))?;
    Ok(ok(text))
}
