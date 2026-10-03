use crate::auth::{bad_request, ok, AuthUser};
use crate::AppState;
use axum::{extract::State, http::StatusCode, response::Response, Json};
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
    addr: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<crate::auth::SuccessResponse<LoginResponse>>, Response> {
    // Authentication (argon2 verify + throttle + signing) happens entirely
    // inside the agent — the server never sees key material.
    let res: crate::agent::proto::AuthResult = match state
        .agent
        .crypto(crate::agent::proto::CryptoOp::Authenticate {
            name: req.name.clone(),
            password: req.password,
            ip: addr.map(|a| a.0.ip().to_string()),
        })
        .await
    {
        Ok(v) => match serde_json::from_value(v) {
            Ok(r) => r,
            Err(_) => return Err(bad_request("invalid credentials")),
        },
        Err(e) => {
            let msg = e.to_string();
            return if msg.contains("too many failed attempts") {
                Err(crate::auth::error_response(
                    axum::http::StatusCode::TOO_MANY_REQUESTS,
                    &msg,
                ))
            } else {
                Err(bad_request("invalid credentials"))
            };
        }
    };
    state
        .audit
        .record(&res.user.name, "login", "session", "token issued");
    Ok(ok(LoginResponse {
        token: res.token,
        name: res.user.name,
        roles: res.user.roles,
        expires_at: res.expires_at,
    }))
}

/// Mint a single-use WebSocket ticket for the caller's session — use
/// `?ticket=` on `/ws/*` instead of `?token=` so the JWT never appears
/// in a URL.
pub async fn ws_ticket(
    user: AuthUser,
    State(state): State<AppState>,
) -> Json<crate::auth::SuccessResponse<serde_json::Value>> {
    let ticket = state.ws_tickets.issue(&user.token);
    ok(serde_json::json!({"ticket": ticket, "expires_in": 60}))
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
    // The agent verifies the parent token, intersects scopes and caps the
    // lifetime itself — the server cannot widen or extend what it relays.
    let now = chrono::Utc::now().timestamp();
    let ttl_secs = req.ttl_minutes.unwrap_or(60).clamp(1, 10_000) * 60;
    let v = state
        .agent
        .crypto(crate::agent::proto::CryptoOp::Mint {
            token: user.token.clone(),
            ttl_minutes: req.ttl_minutes,
            services: req.services.clone(),
            actions: req.actions.clone(),
        })
        .await
        .map_err(|e| crate::auth::error_response(StatusCode::UNAUTHORIZED, format!("{e:#}")))?;
    let token = v["token"].as_str().unwrap_or_default().to_string();
    let expires_at = v["expires_at"].as_i64().unwrap_or(now);
    let fmt = |v: &Option<Vec<String>>| match v {
        Some(s) if !s.is_empty() => s.join(","),
        Some(_) => "none".into(),
        None => "*".into(),
    };
    let detail = format!(
        "ttl={ttl_secs}s services={} actions={}",
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
    state
        .agent
        .crypto(crate::agent::proto::CryptoOp::Rotate {
            token: user.token.clone(),
        })
        .await
        .map_err(|e| crate::auth::internal(format!("{e:#}")))?;
    state.audit.record(
        &user.user.name,
        "logout_all",
        "sessions",
        "jwt secret rotated",
    );
    Ok(ok(true))
}
