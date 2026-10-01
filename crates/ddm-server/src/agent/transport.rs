//! Unix-socket transport for the agent protocol. JSON lines: one
//! `AgentRequest` in, one `AgentResponse` out — for `Exec` the response is
//! `StreamStart` followed by one `ServerMessage` per line until the channel
//! closes.

use super::core::AgentCore;
use super::proto::*;
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tracing::{info, warn};

/// Serve the agent on a unix socket. Root-owned; peer credentials are
/// validated via SO_PEERCRED when `allowed_uid` is configured.
pub async fn serve(core: Arc<AgentCore>, socket_path: &Path) -> Result<()> {
    if socket_path.exists() {
        std::fs::remove_file(socket_path)?;
    }
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("binding agent socket {}", socket_path.display()))?;
    // Socket reachable only by root and the group — the server uid gets
    // access via group membership or an explicit peer-uid check.
    let _ = std::fs::set_permissions(
        socket_path,
        std::os::unix::fs::PermissionsExt::from_mode(0o660),
    );
    let allowed_uid = core.cfg.get().await.security.agent_peer_uid;
    info!("agent listening on {}", socket_path.display());
    // Bound concurrent connections — each spawns a task and buffers input.
    let permits = Arc::new(tokio::sync::Semaphore::new(64));
    loop {
        let (sock, _addr) = listener.accept().await?;
        let core = Arc::clone(&core);
        let permit = Arc::clone(&permits);
        tokio::spawn(async move {
            let _permit = match permit.try_acquire_owned() {
                Ok(p) => p,
                Err(_) => return, // saturated — drop the connection
            };
            if let Err(e) = handle_conn(core, sock, allowed_uid).await {
                warn!("agent connection error: {e:#}");
            }
        });
    }
}

async fn handle_conn(
    core: Arc<AgentCore>,
    sock: UnixStream,
    allowed_uid: Option<u32>,
) -> Result<()> {
    // Peer credential check (SO_PEERCRED).
    if let Some(want) = allowed_uid {
        let cred = sock.peer_cred().context("SO_PEERCRED")?;
        if cred.uid() != want && cred.uid() != 0 {
            bail!("peer uid {} not allowed", cred.uid());
        }
    }
    let (r, mut w) = sock.into_split();
    // Bound the read itself: a peer could otherwise send a newline-free
    // stream and exhaust agent memory before the size check ever ran.
    const MAX_REQ: u64 = 16 * 1024 * 1024;
    let mut lines = BufReader::new(tokio::io::AsyncReadExt::take(r, MAX_REQ + 1)).lines();
    let Some(line) = lines.next_line().await? else {
        return Ok(());
    };
    if line.len() as u64 > MAX_REQ {
        bail!("request too large");
    }
    let req: AgentRequest = serde_json::from_str(&line).context("bad request")?;
    match req {
        AgentRequest::Watch => {
            let mut rx = core.events.subscribe();
            loop {
                let ev = match rx.recv().await {
                    Ok(e) => e,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => break,
                };
                let mut buf = serde_json::to_vec(&ev)?;
                buf.push(b'\n');
                if w.write_all(&buf).await.is_err() {
                    break;
                }
            }
        }
        AgentRequest::Crypto { op } => {
            let resp = match core.crypto(op).await {
                Ok(data) => AgentResponse::Ok { data },
                Err(e) => AgentResponse::Err {
                    error: AgentError {
                        code: "crypto".into(),
                        message: format!("{e:#}"),
                    },
                },
            };
            write_resp(&mut w, &resp).await?;
        }
        AgentRequest::Call { verb, token } => {
            let resp = match core.call(verb, &token).await {
                Ok(data) => AgentResponse::Ok { data },
                Err(e) => AgentResponse::Err {
                    error: AgentError {
                        code: "call".into(),
                        message: format!("{e:#}"),
                    },
                },
            };
            write_resp(&mut w, &resp).await?;
        }
        AgentRequest::Exec {
            verb,
            eid,
            title,
            token,
            ..
        } => match core.exec(verb, eid.clone(), title, &token).await {
            Ok(mut rx) => {
                write_resp(&mut w, &AgentResponse::StreamStart { eid }).await?;
                while let Some(msg) = rx.recv().await {
                    let mut buf = serde_json::to_vec(&msg)?;
                    buf.push(b'\n');
                    w.write_all(&buf).await?;
                }
            }
            Err(e) => {
                write_resp(
                    &mut w,
                    &AgentResponse::Err {
                        error: AgentError {
                            code: "exec".into(),
                            message: format!("{e:#}"),
                        },
                    },
                )
                .await?;
            }
        },
    }
    Ok(())
}

async fn write_resp(w: &mut tokio::net::unix::OwnedWriteHalf, resp: &AgentResponse) -> Result<()> {
    let mut buf = serde_json::to_vec(resp)?;
    buf.push(b'\n');
    w.write_all(&buf).await?;
    Ok(())
}

/// Client half — used by the unprivileged server process.
#[derive(Debug, Clone)]
pub struct SocketAgent {
    pub path: PathBuf,
}

impl SocketAgent {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub(crate) async fn roundtrip(&self, req: &AgentRequest) -> Result<serde_json::Value> {
        let sock = UnixStream::connect(&self.path)
            .await
            .with_context(|| format!("connecting to agent at {}", self.path.display()))?;
        let (r, mut w) = sock.into_split();
        let mut buf = serde_json::to_vec(req)?;
        buf.push(b'\n');
        w.write_all(&buf).await?;
        drop(w);
        let mut lines = BufReader::new(r).lines();
        let line = lines
            .next_line()
            .await?
            .ok_or_else(|| anyhow::anyhow!("agent closed connection"))?;
        let resp: AgentResponse = serde_json::from_str(&line)?;
        match resp {
            AgentResponse::Ok { data } => Ok(data),
            AgentResponse::Err { error } => bail!("{}: {}", error.code, error.message),
            AgentResponse::StreamStart { .. } => bail!("unexpected stream"),
        }
    }
}
