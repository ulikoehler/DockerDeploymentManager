use crate::auth::{bad_request, forbidden, ok, AuthUser};
use crate::config::AppConfig;
use crate::exec::host_shell_item;
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
    if !user.user.is_admin() && !user.user.features.run_commands {
        return Err(forbidden());
    }
    let cfg = state.config.get().await;
    let section = cfg
        .sections
        .get(si)
        .ok_or_else(|| bad_request("invalid section index"))?;
    if let Some(r) = &section.required_role {
        if !user.user.has_role(r) {
            return Err(forbidden());
        }
    }
    let item = section
        .items
        .get(ii)
        .ok_or_else(|| bad_request("invalid item index"))?
        .clone();
    if let Some(r) = &item.required_role {
        if !user.user.has_role(r) {
            return Err(forbidden());
        }
    }

    // host commands: wrap each command in `nsenter ... bash -c` equivalent —
    // we keep per-command structure by converting to a script when on_host.
    let id = if item.on_host {
        let script = item
            .command_sequence
            .iter()
            .map(|c| {
                let args = crate::exec::build_args(&c.args, &req.params);
                format!(
                    "cd '{}' && {} {}",
                    item.work_dir.replace('\'', ""),
                    c.program,
                    args.iter()
                        .map(|a| format!("'{}'", a.replace('\'', "'\\''")))
                        .collect::<Vec<_>>()
                        .join(" ")
                )
            })
            .collect::<Vec<_>>()
            .join(" && ");
        state.exec.run_item(
            host_shell_item(&item.title, &script, cfg.paths.host_exec, cfg.paths.nsenter_target),
            HashMap::new(),
            &user.user.name,
            None,
            true,
        )
    } else {
        state
            .exec
            .run_item(item, req.params, &user.user.name, None, false)
    };
    state
        .audit
        .record(&user.user.name, "command_run", &format!("{si}/{ii}"), "");
    Ok(ok(serde_json::json!({ "execution_id": id })))
}
