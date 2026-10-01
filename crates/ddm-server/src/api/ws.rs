use crate::auth::AuthUser;
use crate::logs::{CompiledFilter, LogFilter};
use crate::permissions::can_access_service;
use crate::protocol::ServerMessage;
use crate::AppState;
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, Query, State,
    },
    response::Response,
};
use futures::{SinkExt, StreamExt};
use serde::Deserialize;
use std::collections::HashSet;
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// /ws/executions/{id} — stream an execution; also accepts run requests
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ExecWsQuery {
    pub id: Option<String>,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientMsg {
    /// {"type":"run","section":0,"item":1,"params":{...}}
    Run {
        section: usize,
        item: usize,
        #[serde(default)]
        params: std::collections::HashMap<String, String>,
    },
}

pub async fn execute_ws(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
    ws: WebSocketUpgrade,
) -> Response {
    ws.on_upgrade(move |socket| stream_execution(socket, state, id, user.user, user.token.clone()))
}

/// /ws/execute — run-request channel without a preexisting execution id.
pub async fn execute_ws_root(
    user: AuthUser,
    State(state): State<AppState>,
    Query(q): Query<ExecWsQuery>,
    ws: WebSocketUpgrade,
) -> Response {
    let id = q.id.unwrap_or_default();
    ws.on_upgrade(move |socket| stream_execution(socket, state, id, user.user, user.token.clone()))
}

async fn stream_execution(
    socket: WebSocket,
    state: AppState,
    id: String,
    user: crate::users::User,
    token: String,
) {
    let (mut sender, mut receiver) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();

    // read task: run-request messages start new executions
    let cfg = state.config.clone();
    let exec = state.exec.clone();
    let agent = state.agent.clone();
    let tx2 = tx.clone();
    let read_user = user.clone();
    let read_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            let Message::Text(text) = msg else { continue };
            let Ok(req) = serde_json::from_str::<ClientMsg>(&text) else {
                continue;
            };
            let ClientMsg::Run {
                section,
                item: item_idx,
                params,
            } = req;
            let cfg = cfg.get().await;
            let item =
                crate::api::commands_api::authorized_item(&read_user, &cfg, section, item_idx);
            drop(cfg);
            match item {
                Ok(_item) => {
                    let eid = match agent
                        .exec(
                            crate::agent::proto::ExecVerb::SectionItem {
                                section,
                                item: item_idx,
                                params: params.clone(),
                            },
                            format!("command {section}/{item_idx}"),
                            None,
                            &token,
                            &read_user.name,
                            &exec,
                        )
                        .await
                    {
                        Ok(e) => e,
                        Err(e) => {
                            let _ = tx2.send(
                                serde_json::json!({"type":"error","message":format!("{e:#}")})
                                    .to_string(),
                            );
                            continue;
                        }
                    };
                    state.audit.record(
                        &read_user.name,
                        "command_run",
                        &format!("{section}/{item_idx}"),
                        "",
                    );
                    let _ = tx2.send(
                        serde_json::json!({"type": "started", "execution_id": eid}).to_string(),
                    );
                }
                Err(_) => {
                    let _ = tx2.send(
                        serde_json::json!({"type": "error", "message": "forbidden or invalid section/item"})
                            .to_string(),
                    );
                }
            }
        }
    });

    // subscribe to the requested execution's broadcast channel — only the
    // owner (or an admin) may stream another user's execution output.
    if !id.is_empty() {
        let owned = state
            .exec
            .get(&id)
            .map(|info| user.is_admin() || info.user == user.name)
            .unwrap_or(false);
        if !owned {
            let _ = tx.send(
                serde_json::json!({"type": "error", "message": "execution not found"}).to_string(),
            );
        } else if let Some(mut bcast) = state.exec.subscribe(&id) {
            let txh = tx.clone();
            tokio::spawn(async move {
                loop {
                    match bcast.recv().await {
                        Ok(msg) => {
                            let text = serde_json::to_string(&msg).unwrap_or_default();
                            if txh.send(text).is_err() {
                                break;
                            }
                            if matches!(msg, ServerMessage::ExecutionFinished { .. }) {
                                break;
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(_) => break,
                    }
                }
            });
        }
    }

    while let Some(text) = rx.recv().await {
        if sender.send(Message::Text(text)).await.is_err() {
            break;
        }
    }
    read_task.abort();
}

// ---------------------------------------------------------------------------
// /ws/services/{name}/logs — filtered follow stream
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct LogsWsQuery {
    #[serde(default)]
    pub tail: Option<usize>,
    #[serde(default = "def_follow")]
    pub follow: bool,
    #[serde(flatten)]
    pub filter: LogFilter,
}
fn def_follow() -> bool {
    true
}

pub async fn service_logs_ws(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(q): Query<LogsWsQuery>,
    ws: WebSocketUpgrade,
) -> Response {
    ws.on_upgrade(move |socket| async move {
        let cfg = state.config.get().await;
        if !can_access_service(&user.user, &name, cfg.security.default_access) {
            drop(cfg);
            let _ = socket.close().await;
            return;
        }
        drop(cfg);
        stream_service_logs(socket, state, name, q, user.token.clone()).await;
    })
}

async fn stream_service_logs(
    socket: WebSocket,
    state: AppState,
    name: String,
    q: LogsWsQuery,
    q_token: String,
) {
    let (mut sender, _recv) = socket.split();
    let cfg = state.config.get().await;
    let tail = q
        .tail
        .unwrap_or(cfg.logging.default_tail)
        .min(cfg.logging.max_tail);
    drop(cfg);
    let filter = match CompiledFilter::compile(&q.filter) {
        Ok(f) => f,
        Err(e) => {
            let _ = sender
                .send(Message::Text(format!(
                    "{{\"type\":\"error\",\"message\":\"invalid filter: {e}\"}}"
                )))
                .await;
            return;
        }
    };

    let containers: Vec<crate::docker::ContainerInfo> = state
        .agent
        .call_as(
            crate::agent::proto::SyncVerb::ProjectContainers {
                service: name.clone(),
            },
            &q_token,
        )
        .await
        .unwrap_or_default();

    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let mut seen: HashSet<String> = HashSet::new();
    for c in containers {
        let agent = state.agent.clone();
        let flt = filter.clone();
        let svcname = c.service.clone();
        let cname = c.name.clone();
        let cid = c.id.clone();
        let txc = tx.clone();
        let follow = q.follow;
        let since = q.filter.since;
        let tok2 = q_token.clone();
        tokio::spawn(async move {
            let mut stream = match agent
                .stream(
                    crate::agent::proto::ExecVerb::ContainerLogs {
                        id: cid,
                        tail: tail as u64,
                        since,
                        follow,
                    },
                    &tok2,
                )
                .await
            {
                Ok(s) => s,
                Err(e) => {
                    let _ = txc.send(format!(
                        "{{\"type\":\"error\",\"message\":\"logs for {cname}: {e}\"}}"
                    ));
                    return;
                }
            };
            while let Some(crate::protocol::ServerMessage::LogOutput { text, stream, .. }) =
                stream.recv().await
            {
                if flt.matches(&text, &stream, Some(&svcname)) {
                    let _ = txc.send(
                        serde_json::json!({
                            "container": cname, "service": svcname,
                            "stream": stream, "text": text,
                        })
                        .to_string(),
                    );
                }
            }
        });
    }
    drop(tx);

    while let Some(line) = rx.recv().await {
        if !seen.insert(line.clone()) && line.len() < 4096 {
            continue;
        }
        if seen.len() > 65536 {
            seen.clear();
        }
        if sender.send(Message::Text(line)).await.is_err() {
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// /ws/events — monitoring events broadcast
// ---------------------------------------------------------------------------

pub async fn events_ws(
    user: AuthUser,
    State(state): State<AppState>,
    ws: WebSocketUpgrade,
) -> Response {
    let rx = match state.agent.subscribe_events().await {
        Ok(r) => r,
        Err(_) => return crate::auth::internal("agent unavailable"),
    };
    ws.on_upgrade(move |socket| async move {
        let (mut sender, _recv) = socket.split();
        let mut rx = rx;
        loop {
            match rx.recv().await {
                Ok(ev) => {
                    // filter events by the caller's service access — same rule
                    // as GET /api/monitoring/events
                    use crate::protocol::EventMessage as E;
                    let service = match &ev {
                        E::MonitorState { service, .. } => Some(service.as_str()),
                        E::AlertFired { event } | E::AlertResolved { event } => {
                            Some(event.service.as_str())
                        }
                        E::AutoAction { service, .. } => Some(service.as_str()),
                        E::ConfigReloaded { .. } => None, // admin-relevant but harmless metadata
                    };
                    let visible = match service {
                        None => user.user.is_admin(),
                        Some(svc) => {
                            let cfg = state.config.get().await;
                            let v =
                                can_access_service(&user.user, svc, cfg.security.default_access);
                            drop(cfg);
                            v
                        }
                    };
                    if !visible {
                        continue;
                    }
                    let text = serde_json::to_string(&ev).unwrap_or_default();
                    if sender.send(Message::Text(text)).await.is_err() {
                        break;
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => break,
            }
        }
    })
}
