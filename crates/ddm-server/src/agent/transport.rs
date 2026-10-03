//! Unix-socket transport for the agent protocol. JSON lines: one
//! `AgentRequest` in, one `AgentResponse` out — for `Exec` the response is
//! `StreamStart` followed by one `ServerMessage` per line until the channel
//! closes.

use super::core::AgentCore;
use super::proto::*;
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader, ReadBuf,
};
use tokio::net::{UnixListener, UnixStream};
use tracing::{info, warn};

/// Read one newline-terminated line, refusing to buffer more than `cap`
/// bytes. `BufReader::lines` cannot be used for the streaming verbs: it
/// would happily buffer the payload that follows the request line.
async fn read_line_bounded<R>(r: &mut R, cap: usize) -> Result<Option<String>>
where
    R: AsyncBufRead + Unpin,
{
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let chunk = r.fill_buf().await?;
        if chunk.is_empty() {
            break; // EOF
        }
        if let Some(pos) = chunk.iter().position(|b| *b == b'\n') {
            buf.extend_from_slice(&chunk[..pos]);
            r.consume(pos + 1);
            if buf.len() > cap {
                bail!("request too large");
            }
            return Ok(Some(
                String::from_utf8(buf).context("request is not utf-8")?,
            ));
        }
        buf.extend_from_slice(chunk);
        let n = chunk.len();
        r.consume(n);
        if buf.len() > cap {
            bail!("request too large");
        }
    }
    if buf.is_empty() {
        return Ok(None);
    }
    Ok(Some(
        String::from_utf8(buf).context("request is not utf-8")?,
    ))
}

/// Bound on the JSON request line (payload bytes are not counted against it).
const MAX_REQ: usize = 16 * 1024 * 1024;

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
    // Bound the request line itself: a peer could otherwise send a
    // newline-free stream and exhaust agent memory before the size check.
    let mut reader = BufReader::new(r);
    let Some(line) = read_line_bounded(&mut reader, MAX_REQ).await? else {
        return Ok(());
    };
    let req: AgentRequest = serde_json::from_str(&line).context("bad request")?;
    match req {
        AgentRequest::Watch { token } => {
            // Monitor events can carry service names/state — require a
            // valid justification token before streaming.
            if let Err(e) = core.token_user(&token) {
                write_resp(
                    &mut w,
                    &AgentResponse::Err {
                        error: AgentError {
                            code: "watch".into(),
                            message: format!("{e:#}"),
                        },
                    },
                )
                .await?;
                return Ok(());
            }
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
                write_err(&mut w, "exec", e).await?;
            }
        },
        AgentRequest::FilePut {
            service,
            path,
            len,
            token,
        } => {
            // Authorize before accepting a single payload byte: a denied or
            // oversized write must never receive the body.
            let pending = match core.file_put_begin(&service, &path, len, &token).await {
                Ok(p) => p,
                Err(e) => {
                    write_err(&mut w, "file_put", e).await?;
                    return Ok(());
                }
            };
            write_resp(
                &mut w,
                &AgentResponse::Ok {
                    data: serde_json::json!({ "ready": true }),
                },
            )
            .await?;
            let cfg = core.cfg.get().await;
            let mut body = (&mut reader).take(len);
            let resp = match core.file_put_stream(&cfg, pending, &mut body).await {
                Ok(meta) => AgentResponse::Ok {
                    data: serde_json::to_value(meta)?,
                },
                Err(e) => AgentResponse::Err {
                    error: AgentError {
                        code: "file_put".into(),
                        message: format!("{e:#}"),
                    },
                },
            };
            write_resp(&mut w, &resp).await?;
        }
        AgentRequest::FileGet {
            service,
            path,
            offset,
            len,
            token,
        } => match core
            .file_get_begin(&service, &path, offset, len, &token)
            .await
        {
            Ok((meta, sent, mut f)) => {
                write_resp(
                    &mut w,
                    &AgentResponse::Ok {
                        data: serde_json::json!({
                            "kind": meta.kind,
                            "size": meta.size,
                            "mtime": meta.mtime,
                            "sent": sent,
                        }),
                    },
                )
                .await?;
                // Exactly `sent` raw bytes follow, then the connection ends.
                let mut limited = tokio::io::AsyncReadExt::take(&mut f, sent);
                tokio::io::copy(&mut limited, &mut w).await?;
                let _ = w.shutdown().await;
            }
            Err(e) => write_err(&mut w, "file_get", e).await?,
        },
    }
    Ok(())
}

async fn write_err(
    w: &mut tokio::net::unix::OwnedWriteHalf,
    code: &str,
    e: anyhow::Error,
) -> Result<()> {
    write_resp(
        w,
        &AgentResponse::Err {
            error: AgentError {
                code: code.into(),
                message: format!("{e:#}"),
            },
        },
    )
    .await
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

/// A download body: a local file (in-process agent) or the socket read half
/// (privileged agent) — already positioned at the requested offset and
/// length-bounded, so callers can just copy it out.
pub enum DownloadStream {
    Local(tokio::io::Take<tokio::fs::File>),
    Remote(tokio::io::Take<BufReader<tokio::net::unix::OwnedReadHalf>>),
}

impl AsyncRead for DownloadStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            DownloadStream::Local(f) => Pin::new(f).poll_read(cx, buf),
            DownloadStream::Remote(r) => Pin::new(r).poll_read(cx, buf),
        }
    }
}

/// An authorized upload in flight. Bytes are written incrementally; nothing
/// becomes visible under the final name until `finish` succeeds.
pub struct RemoteUpload {
    w: tokio::net::unix::OwnedWriteHalf,
    reader: BufReader<tokio::net::unix::OwnedReadHalf>,
    remaining: u64,
}

impl RemoteUpload {
    pub fn remaining(&self) -> u64 {
        self.remaining
    }

    /// Write payload bytes; the declared length is a hard cap.
    pub async fn write(&mut self, data: &[u8]) -> Result<()> {
        if data.len() as u64 > self.remaining {
            bail!("upload exceeds the declared length");
        }
        self.w.write_all(data).await?;
        self.remaining -= data.len() as u64;
        Ok(())
    }

    /// Half-close the body and collect the agent's verdict.
    pub async fn finish(mut self) -> Result<FileMeta> {
        self.w.shutdown().await?;
        let line = read_line_bounded(&mut self.reader, MAX_REQ)
            .await?
            .ok_or_else(|| anyhow::anyhow!("agent closed connection"))?;
        match serde_json::from_str::<AgentResponse>(&line)? {
            AgentResponse::Ok { data } => Ok(serde_json::from_value(data)?),
            AgentResponse::Err { error } => bail!("{}: {}", error.code, error.message),
            AgentResponse::StreamStart { .. } => bail!("unexpected stream"),
        }
    }
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

    /// Open a streaming upload: the agent authorizes before the body is sent.
    pub(crate) async fn file_put(
        &self,
        service: &str,
        path: &str,
        len: u64,
        token: &str,
    ) -> Result<RemoteUpload> {
        let sock = UnixStream::connect(&self.path)
            .await
            .with_context(|| format!("connecting to agent at {}", self.path.display()))?;
        let (r, mut w) = sock.into_split();
        let req = AgentRequest::FilePut {
            service: service.to_string(),
            path: path.to_string(),
            len,
            token: token.to_string(),
        };
        let mut buf = serde_json::to_vec(&req)?;
        buf.push(b'\n');
        w.write_all(&buf).await?;
        let mut reader = BufReader::new(r);
        let line = read_line_bounded(&mut reader, MAX_REQ)
            .await?
            .ok_or_else(|| anyhow::anyhow!("agent closed connection"))?;
        match serde_json::from_str::<AgentResponse>(&line)? {
            AgentResponse::Ok { .. } => Ok(RemoteUpload {
                w,
                reader,
                remaining: len,
            }),
            AgentResponse::Err { error } => bail!("{}: {}", error.code, error.message),
            AgentResponse::StreamStart { .. } => bail!("unexpected stream"),
        }
    }

    /// Open a streaming download for `offset`/`len` (`len == 0` → to EOF).
    pub(crate) async fn file_get(
        &self,
        service: &str,
        path: &str,
        offset: u64,
        len: u64,
        token: &str,
    ) -> Result<(FileMeta, u64, DownloadStream)> {
        let sock = UnixStream::connect(&self.path)
            .await
            .with_context(|| format!("connecting to agent at {}", self.path.display()))?;
        let (r, mut w) = sock.into_split();
        let req = AgentRequest::FileGet {
            service: service.to_string(),
            path: path.to_string(),
            offset,
            len,
            token: token.to_string(),
        };
        let mut buf = serde_json::to_vec(&req)?;
        buf.push(b'\n');
        w.write_all(&buf).await?;
        let mut reader = BufReader::new(r);
        let line = read_line_bounded(&mut reader, MAX_REQ)
            .await?
            .ok_or_else(|| anyhow::anyhow!("agent closed connection"))?;
        match serde_json::from_str::<AgentResponse>(&line)? {
            AgentResponse::Ok { data } => {
                let meta = FileMeta {
                    kind: data["kind"].as_str().unwrap_or("file").to_string(),
                    size: data["size"].as_u64().unwrap_or(0),
                    mtime: data["mtime"].as_i64().unwrap_or(0),
                };
                let sent = data["sent"].as_u64().unwrap_or(0);
                Ok((meta, sent, DownloadStream::Remote(reader.take(sent))))
            }
            AgentResponse::Err { error } => bail!("{}: {}", error.code, error.message),
            AgentResponse::StreamStart { .. } => bail!("unexpected stream"),
        }
    }
}
