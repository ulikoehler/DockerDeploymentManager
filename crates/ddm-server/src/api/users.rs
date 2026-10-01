use crate::auth::{bad_request, forbidden, not_found, ok, AuthUser};
use crate::users::{AccessRule, User, UserFeatures};
use crate::AppState;
use axum::{extract::Path, extract::State, response::Response, Json};
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct UserView {
    pub name: String,
    pub roles: Vec<String>,
    pub access: Vec<AccessRule>,
    pub features: UserFeatures,
    pub compose_policy: Option<String>,
}

fn view(u: &User) -> UserView {
    UserView {
        name: u.name.clone(),
        roles: u.roles.clone(),
        access: u.access.clone(),
        features: u.features.clone(),
        compose_policy: u.compose_policy.clone(),
    }
}

#[allow(clippy::result_large_err)]
fn require_admin(user: &AuthUser) -> Result<(), Response> {
    if user.user.is_admin() {
        Ok(())
    } else {
        Err(forbidden())
    }
}

pub async fn list(
    user: AuthUser,
    State(state): State<AppState>,
) -> Result<Json<crate::auth::SuccessResponse<Vec<UserView>>>, Response> {
    require_admin(&user)?;
    let users: Vec<crate::users::User> = state
        .agent
        .crypto(crate::agent::proto::CryptoOp::UsersList {
            token: user.token.clone(),
        })
        .await
        .and_then(|v| serde_json::from_value(v).map_err(|e| anyhow::anyhow!("{e}")))
        .map_err(|e| crate::auth::internal(e.to_string()))?;
    Ok(ok(users.iter().map(view).collect()))
}

pub async fn get_one(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<crate::auth::SuccessResponse<UserView>>, Response> {
    // users may read themselves; everything else is admin
    if !user.user.is_admin() && user.user.name != name {
        return Err(forbidden());
    }
    let u = state
        .users
        .get(&name)
        .await
        .ok_or_else(|| not_found("user not found"))?;
    Ok(ok(view(&u)))
}

#[derive(Deserialize)]
pub struct CreateUser {
    pub name: String,
    pub password: String,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub access: Vec<AccessRule>,
    #[serde(default)]
    pub features: Option<UserFeatures>,
    #[serde(default)]
    pub compose_policy: Option<String>,
}

pub async fn create(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<CreateUser>,
) -> Result<Json<crate::auth::SuccessResponse<UserView>>, Response> {
    require_admin(&user)?;
    if req.name.is_empty() || req.password.len() < 8 {
        return Err(bad_request("name required; password min 8 chars"));
    }
    for r in &req.access {
        crate::users::parse_access_spec(&format!("{}:{}", r.kind.as_str(), r.pattern), r.effect)
            .map_err(|e| bad_request(format!("invalid access rule: {e}")))?;
    }
    let v = state
        .agent
        .crypto(crate::agent::proto::CryptoOp::UserMutate {
            token: user.token.clone(),
            op: crate::agent::proto::UserMut::Create {
                name: req.name.clone(),
                password: req.password.clone(),
                roles: req.roles.clone(),
                access: req.access.clone(),
                features: req.features.clone(),
                compose_policy: req.compose_policy.clone(),
            },
        })
        .await
        .map_err(|e| bad_request(e.to_string()))?;
    state
        .audit
        .record(&user.user.name, "user_create", &req.name, "");
    let u: crate::users::User =
        serde_json::from_value(v).map_err(|e| crate::auth::internal(e.to_string()))?;
    Ok(ok(view(&u)))
}

#[derive(Deserialize)]
pub struct UpdateUser {
    pub roles: Option<Vec<String>>,
    pub features: Option<UserFeatures>,
    pub compose_policy: Option<Option<String>>,
}

pub async fn update(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(req): Json<UpdateUser>,
) -> Result<Json<crate::auth::SuccessResponse<UserView>>, Response> {
    require_admin(&user)?;
    let v = state
        .agent
        .crypto(crate::agent::proto::CryptoOp::UserMutate {
            token: user.token.clone(),
            op: crate::agent::proto::UserMut::Update {
                name: name.clone(),
                roles: req.roles.clone(),
                features: req.features.clone(),
                compose_policy: req.compose_policy.clone(),
            },
        })
        .await
        .map_err(|e| not_found(e.to_string()))?;
    state
        .audit
        .record(&user.user.name, "user_update", &name, "");
    let u: crate::users::User =
        serde_json::from_value(v).map_err(|e| crate::auth::internal(e.to_string()))?;
    Ok(ok(view(&u)))
}

pub async fn delete(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<crate::auth::SuccessResponse<bool>>, Response> {
    require_admin(&user)?;
    if name == user.user.name {
        return Err(bad_request("cannot delete yourself"));
    }
    state
        .agent
        .crypto(crate::agent::proto::CryptoOp::UserMutate {
            token: user.token.clone(),
            op: crate::agent::proto::UserMut::Delete { name: name.clone() },
        })
        .await
        .map_err(|e| not_found(e.to_string()))?;
    state
        .audit
        .record(&user.user.name, "user_delete", &name, "");
    Ok(ok(true))
}

#[derive(Deserialize)]
pub struct SetPassword {
    pub password: String,
    /// Required when a non-admin changes their own password.
    #[serde(default)]
    pub current_password: Option<String>,
}

pub async fn set_password(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(req): Json<SetPassword>,
) -> Result<Json<crate::auth::SuccessResponse<bool>>, Response> {
    // All rules (scope check, admin-or-self, current password) are
    // re-enforced inside the agent — do not weaken them here.
    state
        .agent
        .crypto(crate::agent::proto::CryptoOp::SetPassword {
            token: user.token.clone(),
            name: name.clone(),
            password: req.password.clone(),
            current_password: req.current_password.clone(),
        })
        .await
        .map_err(|e| match format!("{e:#}").as_str() {
            m if m.contains("scoped") => forbidden(),
            m if m.contains("another user") => forbidden(),
            m if m.contains("current password incorrect") => forbidden(),
            m if m.contains("required") => bad_request(m),
            m if m.contains("too short") => bad_request(m),
            m => not_found(m),
        })?;
    state
        .audit
        .record(&user.user.name, "user_password", &name, "");
    Ok(ok(true))
}

pub async fn set_access(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(rules): Json<Vec<AccessRule>>,
) -> Result<Json<crate::auth::SuccessResponse<bool>>, Response> {
    require_admin(&user)?;
    for r in &rules {
        crate::users::parse_access_spec(&format!("{}:{}", r.kind.as_str(), r.pattern), r.effect)
            .map_err(|e| bad_request(format!("invalid access rule: {e}")))?;
    }
    state
        .agent
        .crypto(crate::agent::proto::CryptoOp::UserMutate {
            token: user.token.clone(),
            op: crate::agent::proto::UserMut::SetAccess {
                name: name.clone(),
                access: rules.clone(),
            },
        })
        .await
        .map_err(|e| not_found(e.to_string()))?;
    state
        .audit
        .record(&user.user.name, "user_access", &name, "");
    Ok(ok(true))
}
