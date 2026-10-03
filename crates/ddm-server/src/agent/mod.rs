//! Privilege-separated agent: the secure side of the process boundary.
//!
//! - [`core::AgentCore`] — the privileged implementation (crypto custody,
//!   secrets, host/docker/systemd/git/fs ops, justification log). Runs inside
//!   the `ddm-agent` process (root) or in-process for tests/development.
//! - [`transport`] — unix-socket framing + peer credential checks.
//! - [`Agent`] — the client handle used by the unprivileged server.
//!
//! The server never holds the JWT secret, the password pepper, or any other
//! secret — those live only in [`AgentCore`].

pub mod core;
pub mod proto;
pub mod transport;

pub use core::AgentCore;
pub use proto::*;

use crate::exec::ExecutionManager;
use crate::protocol::ServerMessage;
use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use uuid::Uuid;

/// The server's handle to the privileged agent.
#[derive(Clone)]
pub enum Agent {
    /// In-process (tests, development, single-process deployment).
    Local(Arc<AgentCore>),
    /// Unix-socket client of a `ddm-agent` process.
    Remote(transport::SocketAgent),
}

/// A streaming upload in flight. Bytes are written incrementally; the target
/// file only appears once `finish` succeeds.
pub enum UploadSink {
    /// In-process agent: the body is piped into the core over a duplex.
    Pipe {
        tx: tokio::io::DuplexStream,
        done: tokio::sync::oneshot::Receiver<Result<proto::FileMeta>>,
        remaining: u64,
    },
    /// Privileged agent: the body streams over the unix socket.
    Remote(transport::RemoteUpload),
}

impl UploadSink {
    pub fn remaining(&self) -> u64 {
        match self {
            UploadSink::Pipe { remaining, .. } => *remaining,
            UploadSink::Remote(r) => r.remaining(),
        }
    }

    /// Write the next chunk of the body (capped at the declared length).
    pub async fn write(&mut self, data: &[u8]) -> Result<()> {
        match self {
            UploadSink::Pipe { tx, remaining, .. } => {
                if data.len() as u64 > *remaining {
                    anyhow::bail!("upload exceeds the declared length");
                }
                tx.write_all(data).await?;
                *remaining -= data.len() as u64;
                Ok(())
            }
            UploadSink::Remote(r) => r.write(data).await,
        }
    }

    /// Complete the upload and return the committed file's metadata.
    pub async fn finish(self) -> Result<proto::FileMeta> {
        match self {
            UploadSink::Pipe { tx, done, .. } => {
                drop(tx); // EOF for the staging reader
                done.await
                    .map_err(|_| anyhow::anyhow!("agent task vanished"))?
            }
            UploadSink::Remote(r) => r.finish().await,
        }
    }
}

impl Agent {
    /// Crypto op — authenticate, verify, mint, rotate, password ops, webhook.
    pub async fn crypto(&self, op: CryptoOp) -> Result<serde_json::Value> {
        match self {
            Agent::Local(core) => core.crypto(op).await,
            Agent::Remote(s) => s.roundtrip(&AgentRequest::Crypto { op }).await,
        }
    }

    /// Single-response privileged op.
    pub async fn call(&self, verb: SyncVerb, token: &str) -> Result<serde_json::Value> {
        match self {
            Agent::Local(core) => core.call(verb, token).await,
            Agent::Remote(s) => {
                s.roundtrip(&AgentRequest::Call {
                    verb,
                    token: token.into(),
                })
                .await
            }
        }
    }

    /// Typed-call shorthand deserializing the result.
    pub async fn call_as<T: serde::de::DeserializeOwned>(
        &self,
        verb: SyncVerb,
        token: &str,
    ) -> Result<T> {
        let v = self.call(verb, token).await?;
        serde_json::from_value(v).context("decoding agent response")
    }

    /// Start a streamed execution. Registers the execution in `mgr`, spawns
    /// a forwarder from the agent frame stream into the broadcast channel,
    /// and returns the execution id.
    pub async fn exec(
        &self,
        verb: ExecVerb,
        title: impl Into<String>,
        service: Option<String>,
        token: &str,
        user: &str,
        mgr: &Arc<ExecutionManager>,
    ) -> Result<String> {
        let title = title.into();
        let eid = Uuid::new_v4().to_string();
        let tx = mgr.adopt(&eid, &title, service.clone(), user);
        let rx = match self {
            Agent::Local(core) => core.exec(verb, eid.clone(), title.clone(), token).await?,
            Agent::Remote(s) => exec_remote(s, &verb, &eid, &title, service, token).await?,
        };
        let mgr = Arc::clone(mgr);
        let id = eid.clone();
        tokio::spawn(async move {
            let mut rx = rx;
            while let Some(msg) = rx.recv().await {
                if let ServerMessage::ExecutionFinished { success, .. } = &msg {
                    mgr.note_finished(&id, *success);
                }
                let _ = tx.send(msg);
            }
            // keep the channel alive briefly so late subscribers see the end
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        });
        Ok(eid)
    }

    /// Run an exec verb and wait for completion. Registered in `mgr` so it
    /// shows up in execution history. Returns success.
    pub async fn exec_collect(
        &self,
        verb: ExecVerb,
        title: impl Into<String>,
        service: Option<String>,
        token: &str,
        user: &str,
        mgr: &Arc<ExecutionManager>,
    ) -> Result<bool> {
        let title = title.into();
        let eid = Uuid::new_v4().to_string();
        let _tx = mgr.adopt(&eid, &title, service.clone(), user);
        let mut rx = match self {
            Agent::Local(core) => core.exec(verb, eid.clone(), title, token).await?,
            Agent::Remote(s) => exec_remote(s, &verb, &eid, &title, service, token).await?,
        };
        let mut success = false;
        while let Some(msg) = rx.recv().await {
            if let ServerMessage::ExecutionFinished { success: ok, .. } = &msg {
                success = *ok;
            }
        }
        mgr.note_finished(&eid, success);
        Ok(success)
    }

    /// Raw exec stream without registering an execution in history —
    /// for passive streams like container-log follow.
    pub async fn stream(
        &self,
        verb: ExecVerb,
        token: &str,
    ) -> Result<mpsc::Receiver<ServerMessage>> {
        let eid = Uuid::new_v4().to_string();
        match self {
            Agent::Local(core) => core.exec(verb, eid, "stream".into(), token).await,
            Agent::Remote(s) => exec_remote(s, &verb, &eid, "stream", None, token).await,
        }
    }

    /// Metadata for one path inside a service dir (kind/size/mtime).
    pub async fn file_stat(
        &self,
        service: &str,
        path: &str,
        token: &str,
    ) -> Result<proto::FileMeta> {
        self.call_as(
            SyncVerb::FileStat {
                service: service.to_string(),
                path: path.to_string(),
            },
            token,
        )
        .await
    }

    /// Open a streaming upload of exactly `len` bytes. The agent authorizes
    /// *before* the body is accepted, so a denied write costs no bandwidth.
    pub async fn file_put(
        &self,
        service: &str,
        path: &str,
        len: u64,
        token: &str,
    ) -> Result<UploadSink> {
        match self {
            Agent::Local(core) => {
                let pending = core.file_put_begin(service, path, len, token).await?;
                // Pipe the body through a duplex so both agent flavours
                // present the same incremental interface to callers.
                let (tx, rx) = tokio::io::duplex(64 * 1024);
                let (done_tx, done) = tokio::sync::oneshot::channel();
                let core = core.clone();
                tokio::spawn(async move {
                    let cfg = core.cfg.get().await;
                    let mut rx = rx;
                    let res = core.file_put_stream(&cfg, pending, &mut rx).await;
                    let _ = done_tx.send(res);
                });
                Ok(UploadSink::Pipe {
                    tx,
                    done,
                    remaining: len,
                })
            }
            Agent::Remote(s) => Ok(UploadSink::Remote(s.file_put(service, path, len, token).await?)),
        }
    }

    /// Open a streaming download. `len == 0` means "to the end of the file".
    pub async fn file_get(
        &self,
        service: &str,
        path: &str,
        offset: u64,
        len: u64,
        token: &str,
    ) -> Result<(proto::FileMeta, u64, transport::DownloadStream)> {
        match self {
            Agent::Local(core) => {
                let (meta, sent, f) = core
                    .file_get_begin(service, path, offset, len, token)
                    .await?;
                Ok((
                    meta,
                    sent,
                    transport::DownloadStream::Local(tokio::io::AsyncReadExt::take(f, sent)),
                ))
            }
            Agent::Remote(s) => s.file_get(service, path, offset, len, token).await,
        }
    }

    /// Subscribe to monitor events. For a remote agent this opens a Watch
    /// connection and re-broadcasts locally.
    pub async fn subscribe_events(
        &self,
    ) -> Result<tokio::sync::broadcast::Receiver<crate::protocol::EventMessage>> {
        match self {
            Agent::Local(core) => Ok(core.events.subscribe()),
            Agent::Remote(s) => {
                let sock = UnixStream::connect(&s.path).await?;
                let (r, mut w) = sock.into_split();
                w.write_all(b"{\"kind\":\"watch\"}\n").await?;
                drop(w);
                let (tx, rx) = tokio::sync::broadcast::channel(256);
                tokio::spawn(async move {
                    let mut lines = BufReader::new(r).lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        if let Ok(ev) = serde_json::from_str::<crate::protocol::EventMessage>(&line)
                        {
                            let _ = tx.send(ev);
                        }
                    }
                });
                Ok(rx)
            }
        }
    }

    /// Test/dev escape hatch: access the in-process core (None for Remote).
    pub fn local_core(&self) -> Option<&Arc<AgentCore>> {
        match self {
            Agent::Local(c) => Some(c),
            Agent::Remote(_) => None,
        }
    }
}

/// Open a socket, send an Exec request, return the frame stream.
async fn exec_remote(
    s: &transport::SocketAgent,
    verb: &ExecVerb,
    eid: &str,
    title: &str,
    service: Option<String>,
    token: &str,
) -> Result<mpsc::Receiver<ServerMessage>> {
    let sock = UnixStream::connect(&s.path)
        .await
        .with_context(|| format!("connecting to agent at {}", s.path.display()))?;
    let (r, mut w) = sock.into_split();
    let req = AgentRequest::Exec {
        verb: verb.clone(),
        eid: eid.to_string(),
        title: title.to_string(),
        token: token.to_string(),
        service,
    };
    let mut buf = serde_json::to_vec(&req)?;
    buf.push(b'\n');
    w.write_all(&buf).await?;
    drop(w);
    let mut lines = BufReader::new(r).lines();
    let first = lines
        .next_line()
        .await?
        .ok_or_else(|| anyhow::anyhow!("agent closed connection"))?;
    let resp: AgentResponse = serde_json::from_str(&first)?;
    match resp {
        AgentResponse::Err { error } => anyhow::bail!("{}: {}", error.code, error.message),
        AgentResponse::Ok { .. } => anyhow::bail!("unexpected ok for exec"),
        AgentResponse::StreamStart { .. } => {}
    }
    let (tx, rx) = mpsc::channel(256);
    tokio::spawn(async move {
        while let Ok(Some(line)) = lines.next_line().await {
            match serde_json::from_str::<ServerMessage>(&line) {
                Ok(msg) => {
                    if tx.send(msg).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    tracing::warn!("bad agent frame: {e}");
                    break;
                }
            }
        }
    });
    Ok(rx)
}
