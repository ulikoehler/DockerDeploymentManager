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
        .issue(&user, cfg.server.token_ttl_minutes)
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
    state
        .audit
        .record(&user.user.name, "logout_all", "sessions", "jwt secret rotated");
    Ok(ok(true))
}
