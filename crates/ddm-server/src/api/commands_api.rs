use crate::auth::{bad_request, forbidden, ok, AuthUser};
use crate::config::AppConfig;
use crate::AppState;
use axum::{extract::Path, extract::State, response::Response, Json};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize)]
pub struct SectionView {
    pub index: usize,
    pub title: String,
    pub collapsed: bool,
    pub items: Vec<ItemView>,
}

#[derive(Serialize)]
pub struct ItemView {
    pub index: usize,
    pub title: String,
    pub description: String,
    pub icon: String,
    pub button_label: String,
    pub parameters: Vec<crate::config::Parameter>,
}

fn visible_sections<'a>(
    cfg: &'a AppConfig,
    user: &crate::users::User,
) -> Vec<(usize, &'a crate::config::Section)> {
    cfg.sections
        .iter()
        .enumerate()
        .filter(|(_, s)| {
            s.required_role
                .as_deref()
                .map(|r| user.has_role(r))
                .unwrap_or(true)
        })
        .collect()
}

pub async fn list(
    user: AuthUser,
    State(state): State<AppState>,
) -> Result<Json<crate::auth::SuccessResponse<Vec<SectionView>>>, Response> {
    let cfg = state.config.get().await;
    let mut out = vec![];
    for (si, s) in visible_sections(&cfg, &user.user) {
        let items = s
            .items
            .iter()
            .enumerate()
            .filter(|(_, i)| {
                i.required_role
                    .as_deref()
                    .map(|r| user.user.has_role(r))
                    .unwrap_or(true)
            })
            .map(|(ii, i)| ItemView {
                index: ii,
                title: i.title.clone(),
                description: i.description.clone(),
                icon: i.icon.clone(),
                button_label: i.button_label.clone(),
                parameters: i.parameters.clone(),
            })
            .collect();
        out.push(SectionView {
            index: si,
            title: s.title.clone(),
            collapsed: s.collapsed,
            items,
        });
    }
    Ok(ok(out))
}

/// Shared authorization for running a config command item — used by the
/// REST handler and the WebSocket run channel so both enforce the same
/// rules: `run_commands` feature (or admin) plus section- and item-level
/// `required_role`. Returns the cloned item on success.
pub fn authorized_item(
    user: &crate::users::User,
    cfg: &AppConfig,
    si: usize,
    ii: usize,
) -> Result<crate::config::CommandItem, Response> {
    if !user.is_admin() && !user.features.run_commands {
        return Err(forbidden());
    }
    let section = cfg
        .sections
        .get(si)
        .ok_or_else(|| bad_request("invalid section index"))?;
    if let Some(r) = &section.required_role {
        if !user.has_role(r) {
            return Err(forbidden());
        }
    }
    let item = section
        .items
        .get(ii)
        .ok_or_else(|| bad_request("invalid item index"))?
        .clone();
    if let Some(r) = &item.required_role {
        if !user.has_role(r) {
            return Err(forbidden());
        }
    }
    Ok(item)
}

#[derive(Deserialize)]
pub struct RunRequest {
    #[serde(default)]
    pub params: HashMap<String, String>,
}

pub async fn run(
    user: AuthUser,
    State(state): State<AppState>,
    Path((si, ii)): Path<(usize, usize)>,
    Json(req): Json<RunRequest>,
) -> Result<Json<crate::auth::SuccessResponse<serde_json::Value>>, Response> {
    let cfg = state.config.get().await;
    let _item = authorized_item(&user.user, &cfg, si, ii)?;

    let id = state
        .agent
        .exec(
            crate::agent::proto::ExecVerb::SectionItem {
                section: si,
                item: ii,
                params: req.params.clone(),
            },
            format!("command {si}/{ii}"),
            None,
            &user.token,
            &user.user.name,
            &state.exec,
        )
        .await
        .map_err(|e| bad_request(e.to_string()))?;
    state
        .audit
        .record(&user.user.name, "command_run", &format!("{si}/{ii}"), "");
    Ok(ok(serde_json::json!({ "execution_id": id })))
}
