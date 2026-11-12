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
    ua_header: Option<axum_extra::TypedHeader<axum_extra::headers::UserAgent>>,
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
            ua: ua_header.map(|h| h.as_str().to_string()),
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

/// Unauthenticated: is first-run setup still needed (zero users)?
/// Safe to expose — it reveals nothing beyond "no users exist yet".
pub async fn setup_status(
    State(state): State<AppState>,
) -> Json<crate::auth::SuccessResponse<serde_json::Value>> {
    let v = state
        .agent
        .crypto(crate::agent::proto::CryptoOp::SetupNeeded)
        .await
        .unwrap_or_else(|_| serde_json::json!({"needed": false}));
    ok(v)
}

#[derive(Deserialize)]
pub struct SetupRequest {
    pub name: String,
    pub password: String,
}

/// Unauthenticated first-admin creation. The agent enforces the only
/// rule that matters: it succeeds solely while the user store is empty.
pub async fn setup_create(
    State(state): State<AppState>,
    Json(req): Json<SetupRequest>,
) -> Result<Json<crate::auth::SuccessResponse<bool>>, Response> {
    state
        .agent
        .crypto(crate::agent::proto::CryptoOp::SetupCreate {
            name: req.name,
            password: req.password,
        })
        .await
        .map_err(|e| bad_request(format!("{e:#}")))?;
    state
        .audit
        .record("setup", "user_create", "bootstrap", "first admin");
    Ok(ok(true))
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
    /// Lifetime in minutes. Clamped to [1, 10 years].
    #[serde(default)]
    pub ttl_minutes: Option<i64>,
    /// If set, the token can only access these services.
    #[serde(default)]
    pub services: Option<Vec<String>>,
    /// If set, the token keeps only these capabilities (role names +
    /// feature flags + "unrestricted"). Can only narrow, never widen.
    #[serde(default)]
    pub actions: Option<Vec<String>>,
    /// Optional operation categories the token may perform: read, logs,
    /// files, compose, meta, monitoring, backup, git, units, services,
    /// exec. Can only narrow, never widen.
    #[serde(default)]
    pub ops: Option<Vec<String>>,
    /// Optional human label shown in the token list (max 80 chars).
    #[serde(default)]
    pub name: Option<String>,
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
    let ttl_secs = req.ttl_minutes.unwrap_or(60).clamp(1, 5_256_000) * 60;
    let v = state
        .agent
        .crypto(crate::agent::proto::CryptoOp::Mint {
            token: user.token.clone(),
            ttl_minutes: req.ttl_minutes,
            services: req.services.clone(),
            actions: req.actions.clone(),
            ops: req.ops.clone(),
            name: req.name.clone(),
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
        "ttl={ttl_secs}s services={} actions={} ops={} name={}",
        fmt(&req.services),
        fmt(&req.actions),
        fmt(&req.ops),
        req.name.as_deref().unwrap_or("-")
    );
    state
        .audit
        .record(&user.user.name, "token_issue", "session", &detail);
    Ok(ok(TokenResponse { token, expires_at }))
}

/// List minted tokens: admins see all, other users only their own.
/// Session tokens are not registered and never appear here.
pub async fn tokens_list(
    user: AuthUser,
    State(state): State<AppState>,
) -> Result<Json<crate::auth::SuccessResponse<serde_json::Value>>, Response> {
    let v = state
        .agent
        .crypto(crate::agent::proto::CryptoOp::TokensList {
            token: user.token.clone(),
        })
        .await
        .map_err(|e| crate::auth::internal(format!("{e:#}")))?;
    Ok(ok(v))
}

/// Revoke a minted token by jti — takes effect on the next request.
pub async fn revoke_token(
    user: AuthUser,
    State(state): State<AppState>,
    axum::extract::Path(jti): axum::extract::Path<String>,
) -> Result<Json<crate::auth::SuccessResponse<bool>>, Response> {
    state
        .agent
        .crypto(crate::agent::proto::CryptoOp::RevokeToken {
            token: user.token.clone(),
            jti,
        })
        .await
        .map_err(|e| crate::auth::bad_request(format!("{e:#}")))?;
    Ok(ok(true))
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
