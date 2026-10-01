use crate::auth::{bad_request, ok, AuthUser};
use crate::AppState;
use axum::{extract::State, response::Response, Json};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct LoginRequest {
    pub name: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub name: String,
    pub roles: Vec<String>,
    pub expires_at: i64,
}

pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<crate::auth::SuccessResponse<LoginResponse>>, Response> {
    let user = state
        .users
        .authenticate(&req.name, &req.password)
        .await
        .ok_or_else(|| bad_request("invalid credentials"))?;
    let cfg = state.config.get().await;
    let token = state
        .jwt
        .issue(&user, cfg.server.token_ttl_minutes, None)
        .map_err(|e| crate::auth::internal(format!("token issue failed: {e}")))?;
    let expires_at = chrono::Utc::now().timestamp() + cfg.server.token_ttl_minutes * 60;
    state
        .audit
        .record(&user.name, "login", "session", "token issued");
    Ok(ok(LoginResponse {
        token,
        name: user.name,
        roles: user.roles,
        expires_at,
    }))
}

#[derive(Deserialize)]
pub struct TokenRequest {
    /// Lifetime in minutes. Clamped to [1, server.token_ttl_minutes].
    #[serde(default)]
    pub ttl_minutes: Option<i64>,
    /// If set, the token can only access these services.
    #[serde(default)]
    pub services: Option<Vec<String>>,
    /// If set, the token keeps only these capabilities (role names +
    /// feature flags + "unrestricted"). Can only narrow, never widen.
    #[serde(default)]
    pub actions: Option<Vec<String>>,
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub token: String,
    pub expires_at: i64,
}

/// Issue a time-limited, optionally scope-restricted token — e.g. for MCP
/// clients. Scoped tokens intersect with the caller's own permissions.
pub async fn issue_token(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<TokenRequest>,
) -> Result<Json<crate::auth::SuccessResponse<TokenResponse>>, Response> {
    let cfg = state.config.get().await;
    // A token cannot outlive the token that issued it.
    let now = chrono::Utc::now().timestamp();
    let remaining_min = ((user.claims.exp - now) / 60).max(1);
    let ttl = req
        .ttl_minutes
        .unwrap_or(60)
        .clamp(1, cfg.server.token_ttl_minutes.min(remaining_min));
    // Merge with the caller's own token scope: a scoped token can only mint
    // equally-or-more-restricted tokens, never escape its scope.
    let intersect = |parent: &Option<Vec<String>>, child: Option<Vec<String>>| match (parent, child)
    {
        (Some(p), Some(c)) => Some(p.iter().filter(|x| c.contains(x)).cloned().collect()),
        (Some(p), None) => Some(p.clone()),
        (None, c) => c,
    };
    let req_scope =
        (req.services.is_some() || req.actions.is_some()).then(|| crate::auth::TokenScope {
            services: req.services.clone(),
            actions: req.actions.clone(),
        });
    let scope = match (&user.claims.scope, req_scope) {
        (None, r) => r,
        (Some(parent), req) => Some(crate::auth::TokenScope {
            services: intersect(
                &parent.services,
                req.as_ref().and_then(|r| r.services.clone()),
            ),
            actions: intersect(
                &parent.actions,
                req.as_ref().and_then(|r| r.actions.clone()),
            ),
        }),
    };
    let token = state
        .jwt
        .issue(&user.user, ttl, scope)
        .map_err(|e| crate::auth::internal(format!("token issue failed: {e}")))?;
    let expires_at = chrono::Utc::now().timestamp() + ttl * 60;
    let fmt = |v: &Option<Vec<String>>| match v {
        Some(s) if !s.is_empty() => s.join(","),
        Some(_) => "none".into(),
        None => "*".into(),
    };
    let detail = format!(
        "ttl={ttl}m services={} actions={}",
        fmt(&req.services),
        fmt(&req.actions)
    );
    state
        .audit
        .record(&user.user.name, "token_issue", "session", &detail);
    Ok(ok(TokenResponse { token, expires_at }))
}

#[derive(Serialize)]
pub struct MeResponse {
    pub name: String,
    pub roles: Vec<String>,
    pub features: crate::users::UserFeatures,
    pub access: Vec<crate::users::AccessRule>,
    pub compose_policy: Option<String>,
}

pub async fn me(user: AuthUser) -> Json<crate::auth::SuccessResponse<MeResponse>> {
    ok(MeResponse {
        name: user.user.name,
        roles: user.user.roles,
        features: user.user.features,
        access: user.user.access,
        compose_policy: user.user.compose_policy,
    })
}

pub async fn logout_all(
    user: AuthUser,
    State(state): State<AppState>,
) -> Result<Json<crate::auth::SuccessResponse<bool>>, Response> {
    if !user.user.is_admin() {
        return Err(crate::auth::forbidden());
    }
    state.jwt.rotate();
    state.audit.record(
        &user.user.name,
        "logout_all",
        "sessions",
        "jwt secret rotated",
    );
    Ok(ok(true))
}
