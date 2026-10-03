//! Container exec endpoints — run commands inside docker containers.
//!
//! Output streams as execution frames, like every other exec verb, so it
//! appears in `/api/executions` and on `/ws/executions/:id`.
//!
//! Rights: `/api/services/:name/exec` requires the `exec_containers`
//! feature (or admin) plus access to the service, and the container must
//! belong to the service's compose project. `/api/containers/:id/exec`
//! targets any container and is admin-only. The agent independently
//! re-resolves the container's `com.docker.compose.project` label and
//! re-checks access against the fresh, scope-applied user — a compromised
//! server cannot relabel a foreign container into an allowed service.

use crate::agent::proto::{ExecVerb, SyncVerb};
use crate::auth::{bad_request, forbidden, ok, AuthUser};
use crate::docker::ContainerInfo;
use crate::AppState;
use axum::{
    extract::{Path, State},
    response::Response,
    Json,
};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
pub struct ExecRequest {
    /// Container id or name. Required on the service-scoped route; on the
    /// admin route it defaults to the path id.
    #[serde(default)]
    pub container: Option<String>,
    /// argv array, or a shell string executed via `sh -c`.
    pub command: Value,
}

/// `command` may be a JSON array (argv, no shell) or a string run via
/// `sh -c` — matching `docker exec <c> <argv...>` vs `sh -c "..."`.
fn command_argv(v: &Value) -> Result<Vec<String>, Response> {
    match v {
        Value::Array(items) => {
            let mut argv = Vec::with_capacity(items.len());
            for i in items {
                match i.as_str() {
                    Some(s) => argv.push(s.to_string()),
                    None => return Err(bad_request("command array must contain strings")),
                }
            }
            if argv.is_empty() {
                return Err(bad_request("empty command"));
            }
            Ok(argv)
        }
        Value::String(s) if !s.trim().is_empty() => {
            Ok(vec!["/bin/sh".into(), "-c".into(), s.clone()])
        }
        _ => Err(bad_request(
            "command must be a string or an array of strings",
        )),
    }
}

/// POST /api/services/:name/exec — exec inside one of the service's
/// containers (feature `exec_containers` + service access).
pub async fn service_exec(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(req): Json<ExecRequest>,
) -> Result<Json<crate::auth::SuccessResponse<Value>>, Response> {
    if !user.user.is_admin() && !user.user.features.exec_containers {
        return Err(forbidden());
    }
    let svc = super::services::require_service_access(&state, &user, &name).await?;
    let argv = command_argv(&req.command)?;
    let wanted = req
        .container
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| bad_request("container required"))?;
    // Resolve against the service's compose project — accepts id (or id
    // prefix) and container name, refuses foreign containers early. The
    // agent still re-resolves the project label authoritatively.
    let containers: Vec<ContainerInfo> = state
        .agent
        .call_as(
            SyncVerb::ProjectContainers {
                service: svc.name.clone(),
            },
            &user.token,
        )
        .await
        .map_err(|e| bad_request(e.to_string()))?;
    let Some(c) = containers.iter().find(|c| {
        c.id == wanted || c.name == wanted || c.service == wanted || c.id.starts_with(wanted)
    }) else {
        return Err(bad_request("container is not part of this service"));
    };
    let id = state
        .agent
        .exec(
            ExecVerb::ContainerExec {
                container: c.id.clone(),
                command: argv,
            },
            format!("exec {} ({})", c.name, svc.name),
            Some(svc.name.clone()),
            &user.token,
            &user.user.name,
            &state.exec,
        )
        .await
        .map_err(|e| bad_request(e.to_string()))?;
    state
        .audit
        .record(&user.user.name, "container_exec", &svc.name, wanted);
    Ok(ok(serde_json::json!({ "execution_id": id })))
}

/// POST /api/containers/:id/exec — exec in any container (admin only).
/// Containers outside a managed service have no service-scoped rights.
pub async fn container_exec(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<ExecRequest>,
) -> Result<Json<crate::auth::SuccessResponse<Value>>, Response> {
    if !user.user.is_admin() {
        return Err(forbidden());
    }
    let argv = command_argv(&req.command)?;
    let cid = req
        .container
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or(id);
    let eid = state
        .agent
        .exec(
            ExecVerb::ContainerExec {
                container: cid.clone(),
                command: argv,
            },
            format!("exec {cid}"),
            None,
            &user.token,
            &user.user.name,
            &state.exec,
        )
        .await
        .map_err(|e| bad_request(e.to_string()))?;
    state
        .audit
        .record(&user.user.name, "container_exec", &cid, "");
    Ok(ok(serde_json::json!({ "execution_id": eid })))
}
