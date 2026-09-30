use crate::auth::AuthUser;
use crate::exec::host_shell_item;
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
    ws.on_upgrade(move |socket| stream_execution(socket, state, id, user.user.name))
}

/// /ws/execute — run-request channel without a preexisting execution id.
pub async fn execute_ws_root(
    user: AuthUser,
    State(state): State<AppState>,
    Query(q): Query<ExecWsQuery>,
    ws: WebSocketUpgrade,
) -> Response {
    let id = q.id.unwrap_or_default();
    ws.on_upgrade(move |socket| stream_execution(socket, state, id, user.user.name))
}

async fn stream_execution(socket: WebSocket, state: AppState, id: String, who: String) {
    let (mut sender, mut receiver) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();

    // read task: run-request messages start new executions
    let exec = state.exec.clone();
    let cfg = state.config.clone();
    let tx2 = tx.clone();
    let read_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            let Message::Text(text) = msg else { continue };
            let Ok(req) = serde_json::from_str::<ClientMsg>(&text) else {
                continue;
            };
            let ClientMsg::Run {
                section,
                item,
                params,
            } = req;
            let cfg = cfg.get().await;
            let item = cfg
                .sections
                .get(section)
                .and_then(|s| s.items.get(item))
                .cloned();
            drop(cfg);
            match item {
                Some(item) => {
                    let on_host = item.on_host;
                    let cfg2 = state.config.get().await;
                    let item = if on_host {
                        let script = item
                            .command_sequence
                            .iter()
                            .map(|c| {
                                let args = crate::exec::build_args(&c.args, &params);
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
                        host_shell_item(
                            &item.title,
                            &script,
                            cfg2.paths.host_exec,
                            cfg2.paths.nsenter_target,
                        )
                    } else {
                        item
                    };
                    drop(cfg2);
                    let eid = exec.run_item(item, params, &who, None, true);
                    let _ = tx2.send(
                        serde_json::json!({"type": "started", "execution_id": eid}).to_string(),
                    );
                }
                None => {
                    let _ = tx2.send(
                        serde_json::json!({"type": "error", "message": "invalid section/item"})
                            .to_string(),
                    );
                }
            }
        }
    });

    // subscribe to the requested execution's broadcast channel
    if !id.is_empty() {
        if let Some(mut bcast) = state.exec.subscribe(&id) {
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
        stream_service_logs(socket, state, name, q).await;
    })
}

async fn stream_service_logs(socket: WebSocket, state: AppState, name: String, q: LogsWsQuery) {
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

    let containers = state
        .docker
        .project_containers(&name)
        .await
        .unwrap_or_default();

    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let mut seen: HashSet<String> = HashSet::new();
    for c in containers {
        let docker = state.docker.clone();
        let flt = filter.clone();
        let svcname = c.service.clone();
        let cname = c.name.clone();
        let cid = c.id.clone();
        let txc = tx.clone();
        let follow = q.follow;
        let since = q.filter.since;
        tokio::spawn(async move {
            let mut stream = match docker.logs(&cid, tail, since, follow).await {
                Ok(s) => s,
                Err(e) => {
                    let _ = txc.send(format!(
                        "{{\"type\":\"error\",\"message\":\"logs for {cname}: {e}\"}}"
                    ));
                    return;
                }
            };
            while let Some(Ok(l)) = stream.next().await {
                if flt.matches(&l.text, &l.stream, Some(&svcname)) {
                    let _ = txc.send(
                        serde_json::json!({
                            "container": cname, "service": svcname,
                            "stream": l.stream, "text": l.text,
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
    _user: AuthUser,
    State(state): State<AppState>,
    ws: WebSocketUpgrade,
) -> Response {
    let rx = state.monitor.subscribe_events();
    ws.on_upgrade(move |socket| async move {
        let (mut sender, _recv) = socket.split();
        let mut rx = rx;
        loop {
            match rx.recv().await {
                Ok(ev) => {
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
