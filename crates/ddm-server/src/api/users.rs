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
    let users = state.users.list().await;
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
        crate::users::parse_access_spec(
            &format!("{}:{}", r.kind.as_str(), r.pattern),
            r.effect,
        )
        .map_err(|e| bad_request(format!("invalid access rule: {e}")))?;
    }
    state
        .users
        .mutate(|f| {
            crate::users::cli_add_user(f, &req.name, &req.password, req.roles.clone())?;
            let u = f.users.iter_mut().find(|u| u.name == req.name).unwrap();
            u.access = req.access.clone();
            if let Some(feat) = &req.features {
                u.features = feat.clone();
            }
            u.compose_policy = req.compose_policy.clone();
            Ok(())
        })
        .await
        .map_err(|e| bad_request(e.to_string()))?;
    state
        .audit
        .record(&user.user.name, "user_create", &req.name, "");
    let u = state.users.get(&req.name).await.unwrap();
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
    let n = name.clone();
    state
        .users
        .mutate(|f| {
            let u = f
                .users
                .iter_mut()
                .find(|u| u.name == n)
                .ok_or_else(|| anyhow::anyhow!("user not found"))?;
            if let Some(r) = &req.roles {
                u.roles = r.clone();
            }
            if let Some(feat) = &req.features {
                u.features = feat.clone();
            }
            if let Some(cp) = &req.compose_policy {
                u.compose_policy = cp.clone();
            }
            Ok(())
        })
        .await
        .map_err(|e| not_found(e.to_string()))?;
    state.audit.record(&user.user.name, "user_update", &name, "");
    Ok(ok(view(&state.users.get(&name).await.unwrap())))
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
        .users
        .mutate(|f| crate::users::cli_remove_user(f, &name))
        .await
        .map_err(|e| not_found(e.to_string()))?;
    state.audit.record(&user.user.name, "user_delete", &name, "");
    Ok(ok(true))
}

#[derive(Deserialize)]
pub struct SetPassword {
    pub password: String,
}

pub async fn set_password(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(req): Json<SetPassword>,
) -> Result<Json<crate::auth::SuccessResponse<bool>>, Response> {
    // users may change their own password; admins anyone's
    if !user.user.is_admin() && user.user.name != name {
        return Err(forbidden());
    }
    if req.password.len() < 8 {
        return Err(bad_request("password min 8 chars"));
    }
    state
        .users
        .mutate(|f| crate::users::cli_set_password(f, &name, &req.password))
        .await
        .map_err(|e| not_found(e.to_string()))?;
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
        crate::users::parse_access_spec(
            &format!("{}:{}", r.kind.as_str(), r.pattern),
            r.effect,
        )
        .map_err(|e| bad_request(format!("invalid access rule: {e}")))?;
    }
    let n = name.clone();
    state
        .users
        .mutate(|f| {
            let u = f
                .users
                .iter_mut()
                .find(|u| u.name == n)
                .ok_or_else(|| anyhow::anyhow!("user not found"))?;
            u.access = rules.clone();
            Ok(())
        })
        .await
        .map_err(|e| not_found(e.to_string()))?;
    state
        .audit
        .record(&user.user.name, "user_access", &name, "");
    Ok(ok(true))
}


