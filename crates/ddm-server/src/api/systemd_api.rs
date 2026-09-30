use crate::auth::{bad_request, forbidden, not_found, ok, AuthUser};
use crate::config::{AppConfig, SystemdCommand};
use crate::exec::host_shell_item;
use crate::AppState;
use axum::{
    extract::{Path, Query, State},
    response::Response,
    Json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
    let units = crate::systemd::list_units_matching(&state.host, &g.unit_regex)
        .await
        .map_err(|e| bad_request(e.to_string()))?;
    Ok(ok(units))
}

fn unit_shell(title: &str, unit: &str, op: &str, cfg: &AppConfig) -> crate::config::CommandItem {
    let script = format!("systemctl {op} '{}'", unit.replace('\'', ""));
    host_shell_item(
        title,
        &script,
        cfg.paths.host_exec,
        cfg.paths.nsenter_target,
    )
}

pub async fn unit_restart(
    user: AuthUser,
    State(state): State<AppState>,
    Path(unit): Path<String>,
) -> Result<Json<crate::auth::SuccessResponse<serde_json::Value>>, Response> {
    require_operator(&user)?;
    let cfg = state.config.get().await;
    if unit_matches_group(&cfg, &unit).is_none() && !user.user.is_admin() {
        return Err(forbidden());
    }
    let id = state.exec.run_item(
        unit_shell(&format!("systemctl restart {unit}"), &unit, "restart", &cfg),
        HashMap::new(),
        &user.user.name,
        None,
        true,
    );
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
    let units = crate::systemd::list_units_matching(&state.host, &g.unit_regex)
        .await
        .map_err(|e| bad_request(e.to_string()))?;
    let names: Vec<String> = units.iter().map(|u| u.unit.clone()).collect();
    let script = format!(
        "for u in {}; do systemctl restart \"$u\"; done",
        names
            .iter()
            .map(|u| format!("'{}'", u.replace('\'', "")))
            .collect::<Vec<_>>()
            .join(" ")
    );
    let id = state.exec.run_item(
        host_shell_item(
            &format!("restart group {group}"),
            &script,
            cfg.paths.host_exec,
            cfg.paths.nsenter_target,
        ),
        HashMap::new(),
        &user.user.name,
        None,
        true,
    );
    state
        .audit
        .record(&user.user.name, "group_restart", &group, "");
    Ok(ok(serde_json::json!({ "execution_id": id })))
}

#[derive(Deserialize)]
pub struct ExecuteRequest {
    pub command_id: String,
}

#[allow(clippy::result_large_err, clippy::type_complexity)]
fn build_custom_command(
    cfg: &AppConfig,
    group_id: &str,
    unit: &str,
    command_id: &str,
) -> Result<(String, Vec<(String, Vec<String>)>, String), Response> {
    let g = find_group(cfg, group_id).ok_or_else(|| not_found("unknown group"))?;
    let cmd = g
        .custom_commands
        .iter()
        .find(|c| c.id() == command_id)
        .ok_or_else(|| not_found("unknown command id"))?;
    let service = unit.strip_suffix(".service").unwrap_or(unit);
    let template = cmd
        .work_dir_template()
        .or(g.compose_dir_template.as_deref())
        .unwrap_or(".");
    let work_dir = template
        .replace("{unit}", unit)
        .replace("{service}", service);
    let subst = |s: &str| s.replace("${unit}", unit).replace("${service}", service);
    let title = format!("{} ({})", cmd.label(), unit);
    let compose = cfg.docker.compose_command.join(" ");
    let steps: Vec<(String, Vec<String>)> = match cmd {
        SystemdCommand::DockerComposePull { .. } => {
            vec![(
                "bash".into(),
                vec!["-c".into(), format!("cd '{work_dir}' && {compose} pull")],
            )]
        }
        SystemdCommand::DockerComposePullRestart { .. } => vec![
            (
                "bash".into(),
                vec!["-c".into(), format!("cd '{work_dir}' && {compose} pull")],
            ),
            ("systemctl".into(), vec!["restart".into(), unit.to_string()]),
        ],
        SystemdCommand::Shell { program, args, .. } => {
            vec![(subst(program), args.iter().map(|a| subst(a)).collect())]
        }
    };
    Ok((work_dir, steps, title))
}

pub async fn unit_execute(
    user: AuthUser,
    State(state): State<AppState>,
    Path(unit): Path<String>,
    Json(req): Json<ExecuteRequest>,
) -> Result<Json<crate::auth::SuccessResponse<serde_json::Value>>, Response> {
    require_operator(&user)?;
    let cfg = state.config.get().await;
    let group_id = unit_matches_group(&cfg, &unit)
        .ok_or_else(|| bad_request("no systemd group matches this unit"))?;
    let (_wd, steps, title) = build_custom_command(&cfg, &group_id, &unit, &req.command_id)?;
    let script = steps
        .iter()
        .map(|(prog, args)| {
            format!(
                "{} {}",
                prog,
                args.iter()
                    .map(|a| format!("'{}'", a.replace('\'', "'\\''")))
                    .collect::<Vec<_>>()
                    .join(" ")
            )
        })
        .collect::<Vec<_>>()
        .join(" && ");
    let id = state.exec.run_item(
        host_shell_item(
            &title,
            &script,
            cfg.paths.host_exec,
            cfg.paths.nsenter_target,
        ),
        HashMap::new(),
        &user.user.name,
        None,
        true,
    );
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
    let units = crate::systemd::list_units_matching(&state.host, &g.unit_regex)
        .await
        .map_err(|e| bad_request(e.to_string()))?;
    // build a single shell script running the command on each unit
    let mut parts = vec![];
    for u in &units {
        match build_custom_command(&cfg, &group, &u.unit, &req.command_id) {
            Ok((_wd, steps, _)) => {
                for (prog, args) in steps {
                    parts.push(format!(
                        "{} {}",
                        prog,
                        args.iter()
                            .map(|a| format!("'{}'", a.replace('\'', "'\\''")))
                            .collect::<Vec<_>>()
                            .join(" ")
                    ));
                }
            }
            Err(_) => parts.push(format!("echo 'error for {}'", u.unit)),
        }
    }
    let script = parts.join(" && ");
    let id = state.exec.run_item(
        host_shell_item(
            &format!("{} on group {group}", req.command_id),
            &script,
            cfg.paths.host_exec,
            cfg.paths.nsenter_target,
        ),
        HashMap::new(),
        &user.user.name,
        None,
        true,
    );
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
    let cfg = state.config.get().await;
    if unit_matches_group(&cfg, &unit).is_none() && !user.user.is_admin() {
        return Err(forbidden());
    }
    let text = crate::systemd::journal_logs(&state.host, &unit, q.lines)
        .await
        .map_err(|e| bad_request(e.to_string()))?;
    Ok(ok(text))
}
