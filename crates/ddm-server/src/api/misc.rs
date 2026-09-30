use crate::auth::{bad_request, forbidden, not_found, ok, AuthUser};
use crate::config::ServiceMatcher;
use crate::permissions::{can_access_service, matcher_matches};
use crate::AppState;
use axum::{
    extract::{Path, Query, State},
    response::Response,
    Json,
};
use serde::Deserialize;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// config
// ---------------------------------------------------------------------------

/// Redact secrets from the effective config before returning it.
fn redact(cfg: &crate::config::AppConfig) -> serde_json::Value {
    let mut v = serde_json::to_value(cfg).unwrap_or_default();
    if let Some(b) = v.pointer_mut("/backup/repository_base") {
        *b = redact_url_creds(b.as_str().unwrap_or_default());
    }
    if let Some(b) = v.pointer_mut("/backup/extra_env") {
        if let Some(m) = b.as_object_mut() {
            for (_k, val) in m.iter_mut() {
                *val = serde_json::Value::String("***".into());
            }
        }
    }
    if let Some(n) = v.pointer_mut("/monitoring/notifiers") {
        if let Some(arr) = n.as_array_mut() {
            for item in arr.iter_mut() {
                for key in ["url", "url_env", "bot_token_env", "password_env", "username_env"] {
                    if let Some(map) = item.as_object_mut() {
                        if let Some(val) = map.get_mut(key) {
                            if !val.is_null() {
                                *val = serde_json::Value::String("***".into());
                            }
                        }
                    }
                }
            }
        }
    }
    v
}

fn redact_url_creds(u: &str) -> serde_json::Value {
    // strip user:pass@ from URLs
    match url_creds(u) {
        Some((pre, post)) => serde_json::Value::String(format!("{pre}***:***@{post}")),
        None => serde_json::Value::String(u.to_string()),
    }
}

fn url_creds(u: &str) -> Option<(String, String)> {
    let (scheme, rest) = u.split_once("://")?;
    let (creds, host) = rest.split_once('@')?;
    Some((format!("{scheme}://"), host.to_string())).map(|(a, b)| {
        let _ = creds;
        (a, b)
    })
}

pub async fn get_config(
    user: AuthUser,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, Response> {
    if !user.user.is_admin() {
        return Err(forbidden());
    }
    let cfg = state.config.get().await;
    Ok(Json(redact(&cfg)))
}

pub async fn config_status(
    _user: AuthUser,
    State(state): State<AppState>,
) -> Json<crate::auth::SuccessResponse<crate::config::ReloadStatus>> {
    ok(state.config.reload_status().await)
}

pub async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

// ---------------------------------------------------------------------------
// policy introspection
// ---------------------------------------------------------------------------

pub async fn effective_policy(
    user: AuthUser,
    State(state): State<AppState>,
) -> Json<crate::auth::SuccessResponse<serde_json::Value>> {
    let cfg = state.config.get().await;
    let name = user
        .user
        .compose_policy
        .clone()
        .unwrap_or_else(|| cfg.security.default_policy.clone());
    let policy = if name == "unrestricted" {
        serde_json::Value::String("unrestricted".into())
    } else {
        serde_json::to_value(cfg.security.policies.get(&name)).unwrap_or(serde_json::Value::Null)
    };
    ok(serde_json::json!({ "policy": name, "rules": policy }))
}

pub async fn templates(
    _user: AuthUser,
    State(state): State<AppState>,
) -> Json<crate::auth::SuccessResponse<Vec<serde_json::Value>>> {
    let cfg = state.config.get().await;
    ok(cfg
        .service_templates
        .iter()
        .map(|t| {
            serde_json::json!({
                "id": t.id, "title": t.title, "description": t.description,
                "create_unit": t.create_unit, "vars": t.vars,
            })
        })
        .collect())
}

pub async fn audit_entries(
    user: AuthUser,
    State(state): State<AppState>,
) -> Result<Json<crate::auth::SuccessResponse<Vec<crate::audit::AuditEntry>>>, Response> {
    if !user.user.is_admin() {
        return Err(forbidden());
    }
    Ok(ok(state.audit.entries()))
}

// ---------------------------------------------------------------------------
// executions
// ---------------------------------------------------------------------------

pub async fn executions(
    _user: AuthUser,
    State(state): State<AppState>,
) -> Json<crate::auth::SuccessResponse<Vec<crate::protocol::ExecutionInfo>>> {
    ok(state.exec.history())
}

pub async fn execution(
    _user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<crate::auth::SuccessResponse<crate::protocol::ExecutionInfo>>, Response> {
    state
        .exec
        .get(&id)
        .map(ok)
        .ok_or_else(|| not_found("execution not found"))
}

// ---------------------------------------------------------------------------
// monitoring
// ---------------------------------------------------------------------------

pub async fn monitor_status_all(
    user: AuthUser,
    State(state): State<AppState>,
) -> Json<crate::auth::SuccessResponse<serde_json::Value>> {
    let cfg = state.config.get().await;
    let all = state.monitor.status().await;
    let filtered: HashMap<_, _> = all
        .into_iter()
        .filter(|(name, _)| can_access_service(&user.user, name, cfg.security.default_access))
        .collect();
    ok(serde_json::to_value(filtered).unwrap_or_default())
}

pub async fn monitor_status(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<crate::auth::SuccessResponse<serde_json::Value>>, Response> {
    let cfg = state.config.get().await;
    if !can_access_service(&user.user, &name, cfg.security.default_access) {
        return Err(forbidden());
    }
    let st = state.monitor.status().await;
    Ok(ok(serde_json::to_value(st.get(&name)).unwrap_or(serde_json::Value::Null)))
}

#[derive(Deserialize)]
pub struct EventsQuery {
    #[serde(default)]
    pub service: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
}

pub async fn monitor_events(
    user: AuthUser,
    State(state): State<AppState>,
    Query(q): Query<EventsQuery>,
) -> Json<crate::auth::SuccessResponse<Vec<crate::protocol::AlertEvent>>> {
    let cfg = state.config.get().await;
    let mut evs = state.monitor.events().await;
    evs.retain(|e| {
        let svc_ok = q.service.as_deref().map(|s| s == e.service).unwrap_or(true);
        svc_ok && can_access_service(&user.user, &e.service, cfg.security.default_access)
    });
    let limit = q.limit.unwrap_or(100);
    let tail: Vec<_> = evs.into_iter().rev().take(limit).rev().collect();
    ok(tail)
}

pub async fn notifiers(
    user: AuthUser,
    State(state): State<AppState>,
) -> Result<Json<crate::auth::SuccessResponse<Vec<serde_json::Value>>>, Response> {
    if !user.user.is_admin() {
        return Err(forbidden());
    }
    let cfg = state.config.get().await;
    Ok(ok(crate::notify::describe(&cfg.monitoring.notifiers)))
}

#[derive(Deserialize)]
pub struct NotifierTest {
    #[serde(default = "default_test_msg")]
    pub message: String,
}
fn default_test_msg() -> String {
    "ddm test notification".into()
}

pub async fn notifier_test(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<NotifierTest>,
) -> Result<Json<crate::auth::SuccessResponse<bool>>, Response> {
    if !user.user.is_admin() {
        return Err(forbidden());
    }
    let cfg = state.config.get().await;
    let n = cfg
        .monitoring
        .notifiers
        .iter()
        .find(|n| n.id() == id)
        .cloned()
        .ok_or_else(|| not_found("notifier not found"))?;
    let notif = crate::notify::Notification {
        title: "[ddm] test".into(),
        body: req.message,
        service: "test".into(),
        severity: "info".into(),
    };
    crate::notify::send(&n, &notif)
        .await
        .map_err(|e| bad_request(format!("send failed: {e:#}")))?;
    state
        .audit
        .record(&user.user.name, "notifier_test", &id, "");
    Ok(ok(true))
}

// ---------------------------------------------------------------------------
// matcher self-test helper used by the users UI (dry-run access check)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct AccessTestQuery {
    pub service: String,
    #[serde(flatten)]
    pub matcher: ServiceMatcher,
}

#[allow(dead_code)]
pub async fn access_test(Query(q): Query<AccessTestQuery>) -> Json<bool> {
    Json(matcher_matches(&q.matcher, &q.service))
}
