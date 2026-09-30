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
                for key in [
                    "url",
                    "url_env",
                    "bot_token",
                    "bot_token_env",
                    "username",
                    "password",
                    "password_env",
                    "username_env",
                ] {
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
    if let Some(g) = v.pointer_mut("/gitops") {
        for key in ["token", "token_env", "webhook_secret", "webhook_secret_env"] {
            if let Some(val) = g.get_mut(key) {
                if !val.is_null() {
                    *val = serde_json::Value::String("***".into());
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
    Ok(ok(
        serde_json::to_value(st.get(&name)).unwrap_or(serde_json::Value::Null)
    ))
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
// notifier CRUD — writes through to config.yaml via SharedConfig::mutate
// ---------------------------------------------------------------------------

const SECRET_KEYS: &[&str] = &[
    "url",
    "url_env",
    "bot_token",
    "bot_token_env",
    "username",
    "password",
    "password_env",
    "username_env",
];

fn valid_notifier_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_'))
}

#[allow(clippy::result_large_err)]
fn parse_notifier(v: &serde_json::Value) -> Result<crate::config::NotifierConfig, Response> {
    serde_json::from_value(v.clone()).map_err(|e| bad_request(format!("invalid notifier: {e}")))
}

/// On update, secret fields left empty or "***" keep the existing values.
fn merge_secrets(new: &mut serde_json::Value, old: Option<&serde_json::Value>) {
    let Some(old) = old else { return };
    for key in SECRET_KEYS {
        let keep = match new.get(*key) {
            None | Some(serde_json::Value::Null) => true,
            Some(serde_json::Value::String(s)) => s.is_empty() || s == "***",
            _ => false,
        };
        if keep {
            match old.get(*key) {
                Some(v) if !v.is_null() => {
                    new.as_object_mut()
                        .unwrap()
                        .insert(key.to_string(), v.clone());
                }
                _ => {
                    new.as_object_mut().unwrap().remove(*key);
                }
            }
        }
    }
}

pub async fn notifier_create(
    user: AuthUser,
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<crate::auth::SuccessResponse<bool>>, Response> {
    if !user.user.is_admin() {
        return Err(forbidden());
    }
    let n = parse_notifier(&body)?;
    if !valid_notifier_id(n.id()) {
        return Err(bad_request("id must be 1-64 chars of [a-z0-9_-]"));
    }
    let id = n.id().to_string();
    let idc = id.clone();
    state
        .config
        .mutate(move |c| {
            if c.monitoring.notifiers.iter().any(|x| x.id() == idc) {
                anyhow::bail!("notifier '{idc}' already exists");
            }
            c.monitoring.notifiers.push(n);
            Ok(())
        })
        .await
        .map_err(|e| bad_request(e.to_string()))?;
    state
        .audit
        .record(&user.user.name, "notifier_create", &id, "");
    Ok(ok(true))
}

pub async fn notifier_update(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<crate::auth::SuccessResponse<bool>>, Response> {
    if !user.user.is_admin() {
        return Err(forbidden());
    }
    let cfg = state.config.get().await;
    let old_v = cfg
        .monitoring
        .notifiers
        .iter()
        .find(|n| n.id() == id)
        .map(|n| serde_json::to_value(n).unwrap_or_default())
        .ok_or_else(|| not_found("notifier not found"))?;
    let mut merged = body.clone();
    merge_secrets(&mut merged, Some(&old_v));
    let n = parse_notifier(&merged)?;
    if n.id() != id {
        return Err(bad_request("id cannot be changed"));
    }
    let idc = id.clone();
    state
        .config
        .mutate(move |c| {
            let slot = c
                .monitoring
                .notifiers
                .iter_mut()
                .find(|x| x.id() == idc)
                .ok_or_else(|| anyhow::anyhow!("notifier not found"))?;
            *slot = n;
            Ok(())
        })
        .await
        .map_err(|e| bad_request(e.to_string()))?;
    state
        .audit
        .record(&user.user.name, "notifier_update", &id, "");
    Ok(ok(true))
}

pub async fn notifier_delete(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<crate::auth::SuccessResponse<bool>>, Response> {
    if !user.user.is_admin() {
        return Err(forbidden());
    }
    let idc = id.clone();
    state
        .config
        .mutate(move |c| {
            let before = c.monitoring.notifiers.len();
            c.monitoring.notifiers.retain(|x| x.id() != idc);
            if c.monitoring.notifiers.len() == before {
                anyhow::bail!("notifier '{idc}' not found");
            }
            Ok(())
        })
        .await
        .map_err(|e| not_found(e.to_string()))?;
    state
        .audit
        .record(&user.user.name, "notifier_delete", &id, "");
    Ok(ok(true))
}

// ---------------------------------------------------------------------------
// gitops
// ---------------------------------------------------------------------------

pub async fn gitops_status(
    _user: AuthUser,
    State(state): State<AppState>,
) -> Json<crate::auth::SuccessResponse<crate::gitsync::GitsyncStatus>> {
    ok(state.gitsync.status().await)
}

pub async fn gitops_sync(
    user: AuthUser,
    State(state): State<AppState>,
) -> Result<Json<crate::auth::SuccessResponse<bool>>, Response> {
    if !user.user.is_admin() {
        return Err(forbidden());
    }
    let cfg = state.config.get().await;
    let dir = state.config.dir();
    state
        .gitsync
        .sync(&cfg, &dir)
        .await
        .map_err(|e| bad_request(e.to_string()))?;
    state
        .audit
        .record(&user.user.name, "gitops_sync", "gitops", "");
    Ok(ok(true))
}

pub async fn gitops_push(
    user: AuthUser,
    State(state): State<AppState>,
) -> Result<Json<crate::auth::SuccessResponse<bool>>, Response> {
    if !user.user.is_admin() {
        return Err(forbidden());
    }
    let cfg = state.config.get().await;
    let dir = state.config.dir();
    let pushed = state
        .gitsync
        .push(&cfg, &dir)
        .await
        .map_err(|e| bad_request(e.to_string()))?;
    state
        .audit
        .record(&user.user.name, "gitops_push", "gitops", "");
    Ok(ok(pushed))
}

/// GitHub/GitLab webhook — unauthenticated but secret-verified.
/// GitHub: X-Hub-Signature-256: sha256=<hmac(body)>.
/// GitLab: X-Gitlab-Token: <secret>.
pub async fn gitops_webhook(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<crate::auth::SuccessResponse<bool>>, Response> {
    let cfg = state.config.get().await;
    if !cfg.gitops.enabled {
        return Err(not_found("gitops disabled"));
    }
    let sig = headers
        .get("x-hub-signature-256")
        .and_then(|v| v.to_str().ok());
    let gl = headers.get("x-gitlab-token").and_then(|v| v.to_str().ok());
    if !crate::gitsync::verify_webhook(
        &cfg.gitops.webhook_secret,
        &cfg.gitops.webhook_secret_env,
        sig,
        gl,
        &body,
    ) {
        return Err(forbidden());
    }
    let dir = state.config.dir();
    let gs = state.gitsync.clone();
    let cfga = cfg.clone();
    tokio::spawn(async move {
        if let Err(e) = gs.sync(&cfga, &dir).await {
            tracing::warn!("gitops webhook sync failed: {e:#}");
        }
    });
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn merge_secrets_keeps_old() {
        let old = json!({"type": "telegram", "id": "tg", "bot_token": "secret", "chat_id": "1"});
        let mut new = json!({"type": "telegram", "id": "tg", "chat_id": "2"});
        merge_secrets(&mut new, Some(&old));
        assert_eq!(new["bot_token"], "secret");
        assert_eq!(new["chat_id"], "2");
    }

    #[test]
    fn merge_secrets_stars_keep_old() {
        let old = json!({"type": "slack_webhook", "id": "s", "url": "https://x"});
        let mut new = json!({"type": "slack_webhook", "id": "s", "url": "***"});
        merge_secrets(&mut new, Some(&old));
        assert_eq!(new["url"], "https://x");
    }

    #[test]
    fn merge_secrets_new_value_wins() {
        let old = json!({"type": "slack_webhook", "id": "s", "url": "https://old"});
        let mut new = json!({"type": "slack_webhook", "id": "s", "url": "https://new"});
        merge_secrets(&mut new, Some(&old));
        assert_eq!(new["url"], "https://new");
    }

    #[test]
    fn valid_ids() {
        assert!(valid_notifier_id("slack-ops_1"));
        assert!(!valid_notifier_id("Bad Id"));
        assert!(!valid_notifier_id(""));
    }
}
