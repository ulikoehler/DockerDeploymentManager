use crate::config::{CommandArg, CommandDefinition, CommandItem};
use crate::protocol::{ExecutionInfo, ServerMessage};
use anyhow::Result;
use std::collections::{HashMap, VecDeque};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::{broadcast, mpsc};
use tracing::warn;
use uuid::Uuid;

/// Central execution bookkeeping: broadcast channels per execution + history.
/// Each channel keeps a replay buffer so subscribers that connect slightly
/// after an execution starts still see its early output — broadcast alone
/// would silently drop everything emitted before `subscribe()`.
pub struct ExecutionManager {
    channels: Mutex<HashMap<String, ExecChannel>>,
    history: Mutex<VecDeque<ExecutionInfo>>,
    max_history: usize,
    path: Option<PathBuf>,
}

struct ExecChannel {
    tx: broadcast::Sender<ServerMessage>,
    replay: VecDeque<ServerMessage>,
}

const REPLAY_CAP: usize = 1000;

impl ExecutionManager {
    pub fn new(max_history: usize) -> Self {
        Self {
            channels: Mutex::new(HashMap::new()),
            history: Mutex::new(VecDeque::new()),
            max_history,
            path: None,
        }
    }

    /// Persist finished execution records to `path` (JSONL) and reload the
    /// last `max_history` on startup. Only completed records are written —
    /// running executions are ephemeral by nature. Best-effort: I/O
    /// failures never affect execution.
    pub fn with_file(mut self, path: PathBuf) -> Self {
        if let Ok(text) = std::fs::read_to_string(&path) {
            let entries: Vec<ExecutionInfo> = text
                .lines()
                .filter_map(|l| serde_json::from_str(l).ok())
                .collect();
            let skip = entries.len().saturating_sub(self.max_history);
            *self.history.lock().unwrap() = entries.into_iter().skip(skip).collect();
        }
        self.path = Some(path);
        self
    }

    fn persist(&self, e: &ExecutionInfo) {
        let Some(path) = &self.path else { return };
        let Ok(mut line) = serde_json::to_string(e) else {
            return;
        };
        line.push('\n');
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            let _ = f.write_all(line.as_bytes());
        }
        // Bound the file like the audit log: ~4× cap entries → rewrite.
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.len() > 4 * self.max_history as u64 * 512 {
                self.trim_file(path);
            }
        }
    }

    fn trim_file(&self, path: &Path) {
        let Ok(text) = std::fs::read_to_string(path) else {
            return;
        };
        let keep: Vec<&str> = text.lines().rev().take(self.max_history).collect();
        let mut out = keep.into_iter().rev().collect::<Vec<_>>().join("\n");
        out.push('\n');
        let _ = std::fs::write(path, out);
    }

    /// Create a channel for an execution id.
    pub fn register(&self, id: &str) -> broadcast::Sender<ServerMessage> {
        let (tx, _) = broadcast::channel(512);
        self.channels.lock().unwrap().insert(
            id.to_string(),
            ExecChannel {
                tx: tx.clone(),
                replay: VecDeque::new(),
            },
        );
        tx
    }

    /// Atomically snapshot the replay buffer and subscribe to live frames.
    /// Holding the lock across both operations guarantees no message is
    /// missed (appended after snapshot -> arrives via the receiver) and
    /// none is duplicated (sent before subscribe -> only in the snapshot).
    pub fn subscribe(
        &self,
        id: &str,
    ) -> Option<(Vec<ServerMessage>, broadcast::Receiver<ServerMessage>)> {
        let ch = self.channels.lock().unwrap();
        ch.get(id)
            .map(|c| (c.replay.iter().cloned().collect(), c.tx.subscribe()))
    }

    /// Append to the replay buffer and broadcast — call while NOT holding
    /// other locks; the channel lock is taken internally.
    pub fn publish(&self, id: &str, msg: ServerMessage) {
        let mut ch = self.channels.lock().unwrap();
        if let Some(c) = ch.get_mut(id) {
            if c.replay.len() >= REPLAY_CAP {
                c.replay.pop_front();
            }
            c.replay.push_back(msg.clone());
            let _ = c.tx.send(msg);
        }
    }

    pub fn history(&self) -> Vec<ExecutionInfo> {
        self.history.lock().unwrap().iter().cloned().collect()
    }

    pub fn get(&self, id: &str) -> Option<ExecutionInfo> {
        self.history
            .lock()
            .unwrap()
            .iter()
            .find(|e| e.id == id)
            .cloned()
    }

    /// Start a command-sequence execution in the background.
    /// Returns the execution id; output goes to the broadcast channel.
    pub fn run_item(
        self: &Arc<Self>,
        item: CommandItem,
        params: HashMap<String, String>,
        user: &str,
        service: Option<String>,
        on_host: bool,
    ) -> String {
        let id = Uuid::new_v4().to_string();
        self.register(&id);
        self.push_history(&id, &item.title, service, user);

        let (mpsc_tx, mut mpsc_rx) = mpsc::channel::<ServerMessage>(256);
        {
            let this = Arc::clone(self);
            let exec_id = id.clone();
            tokio::spawn(async move {
                while let Some(msg) = mpsc_rx.recv().await {
                    if let ServerMessage::ExecutionFinished { success, .. } = &msg {
                        this.mark_finished(&exec_id, *success);
                    }
                    this.publish(&exec_id, msg);
                }
                // keep channel alive briefly so late subscribers see the end
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            });
        }

        let exec_id = id.clone();
        tokio::spawn(async move {
            run_command_sequence(item, params, mpsc_tx, exec_id, on_host).await;
        });
        id
    }

    /// Register an externally-executed execution (the agent runs it; we
    /// forward its frames). Returns the broadcast sender for frames.
    pub fn adopt(
        &self,
        id: &str,
        title: &str,
        service: Option<String>,
        user: &str,
    ) -> broadcast::Sender<ServerMessage> {
        let tx = self.register(id);
        self.push_history(id, title, service, user);
        tx
    }

    /// Mark an adopted execution finished (frame forwarded by the caller).
    pub fn note_finished(&self, id: &str, success: bool) {
        self.mark_finished(id, success);
    }

    fn push_history(&self, id: &str, title: &str, service: Option<String>, user: &str) {
        let mut h = self.history.lock().unwrap();
        if h.len() >= self.max_history {
            h.pop_front();
        }
        h.push_back(ExecutionInfo {
            id: id.to_string(),
            title: title.to_string(),
            service,
            user: user.to_string(),
            started_at: chrono::Utc::now(),
            finished_at: None,
            success: None,
        });
    }

    fn mark_finished(&self, id: &str, success: bool) {
        let entry = {
            let mut h = self.history.lock().unwrap();
            if let Some(e) = h.iter_mut().find(|e| e.id == id) {
                e.finished_at = Some(chrono::Utc::now());
                e.success = Some(success);
                Some(e.clone())
            } else {
                None
            }
        };
        if let Some(e) = entry {
            self.persist(&e);
        }
    }
}

/// Build final argv for a command definition (ported from the original).
pub fn build_args(args: &[CommandArg], params: &HashMap<String, String>) -> Vec<String> {
    let mut out = Vec::new();
    for arg in args {
        match arg {
            CommandArg::Value { value } => {
                out.push(substitute(value, params));
            }
            CommandArg::Variable { name } => {
                if let Some(v) = params.get(name) {
                    if !v.is_empty() {
                        out.push(v.clone());
                    }
                }
            }
            CommandArg::Conditional {
                variable,
                true_args,
                false_args,
            } => {
                let is_true = params.get(variable).map(|v| v == "true").unwrap_or(false);
                for part in if is_true { true_args } else { false_args } {
                    out.push(substitute(part, params));
                }
            }
            CommandArg::Optional { flag, variable } => {
                if let Some(v) = params.get(variable) {
                    if !v.is_empty() {
                        out.push(flag.clone());
                        out.push(v.clone());
                    }
                }
            }
        }
    }
    out
}

fn substitute(s: &str, params: &HashMap<String, String>) -> String {
    let mut out = s.to_string();
    for (k, v) in params {
        out = out.replace(&format!("${{{k}}}"), v);
    }
    out
}

/// Run a command sequence, streaming output as ServerMessages.
/// `on_host` commands run via bash on the host (`nsenter` wrapped by the
/// caller's HostExec is handled at CommandItem level — here we spawn locally
/// and let host wrapping be a shell script when needed). For simplicity and
/// correct pipe behavior, host commands are turned into `nsenter ... bash -c`
/// by the caller; this engine only spawns processes.
pub async fn run_command_sequence(
    item: CommandItem,
    params: HashMap<String, String>,
    tx: mpsc::Sender<ServerMessage>,
    execution_id: String,
    _on_host: bool,
) {
    let _ = tx
        .send(ServerMessage::ExecutionStarted {
            id: execution_id.clone(),
            title: item.title.clone(),
        })
        .await;
    let ok = run_steps(item, params, tx.clone(), execution_id.clone()).await;
    let _ = tx
        .send(ServerMessage::ExecutionFinished {
            id: execution_id,
            success: ok,
        })
        .await;
}

/// Run only the command loop — no ExecutionStarted/Finished frames. Used by
/// the agent, which controls framing itself.
pub async fn run_steps(
    item: CommandItem,
    params: HashMap<String, String>,
    tx: mpsc::Sender<ServerMessage>,
    execution_id: String,
) -> bool {
    let mut overall_success = true;

    for cmd_def in &item.command_sequence {
        let final_args = build_args(&cmd_def.args, &params);
        let _ = tx
            .send(ServerMessage::LogOutput {
                id: execution_id.clone(),
                text: format!("> {} {}\n", cmd_def.program, final_args.join(" ")),
                stream: "stdout".to_string(),
            })
            .await;

        match spawn_and_stream(cmd_def, &final_args, &item.work_dir, &execution_id, &tx).await {
            Ok(true) => {}
            Ok(false) => {
                overall_success = false;
                break;
            }
            Err(e) => {
                warn!("spawn failed: {e:#}");
                let _ = tx
                    .send(ServerMessage::LogOutput {
                        id: execution_id.clone(),
                        text: format!("Failed to spawn command: {e}\n"),
                        stream: "stderr".to_string(),
                    })
                    .await;
                overall_success = false;
                break;
            }
        }
    }

    overall_success
}

async fn spawn_and_stream(
    cmd_def: &CommandDefinition,
    args: &[String],
    work_dir: &str,
    execution_id: &str,
    tx: &mpsc::Sender<ServerMessage>,
) -> Result<bool> {
    let mut cmd = tokio::process::Command::new(&cmd_def.program);
    cmd.args(args)
        .current_dir(work_dir)
        .env("TERM", "xterm-256color")
        .env("PYTHONUNBUFFERED", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn()?;
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();

    let mut out_reader = BufReader::new(stdout).lines();
    let mut err_reader = BufReader::new(stderr).lines();
    let id = execution_id.to_string();
    let txo = tx.clone();
    let h1 = tokio::spawn(async move {
        while let Ok(Some(line)) = out_reader.next_line().await {
            let _ = txo
                .send(ServerMessage::LogOutput {
                    id: id.clone(),
                    text: format!("{line}\n"),
                    stream: "stdout".to_string(),
                })
                .await;
        }
    });
    let id = execution_id.to_string();
    let txe = tx.clone();
    let h2 = tokio::spawn(async move {
        while let Ok(Some(line)) = err_reader.next_line().await {
            let _ = txe
                .send(ServerMessage::LogOutput {
                    id: id.clone(),
                    text: format!("{line}\n"),
                    stream: "stderr".to_string(),
                })
                .await;
        }
    });

    let status = child.wait().await?;
    let _ = h1.await;
    let _ = h2.await;
    if !status.success() {
        let _ = tx
            .send(ServerMessage::LogOutput {
                id: execution_id.to_string(),
                text: format!("Command failed with status: {status}\n"),
                stream: "stderr".to_string(),
            })
            .await;
    }
    Ok(status.success())
}

/// Convenience: run a shell script (in-container) through the engine.
pub fn shell_item(title: &str, script: &str, work_dir: &str) -> CommandItem {
    CommandItem {
        title: title.to_string(),
        description: String::new(),
        work_dir: work_dir.to_string(),
        icon: String::new(),
        parameters: vec![],
        button_label: "Run".to_string(),
        command_sequence: vec![CommandDefinition {
            program: "/bin/bash".to_string(),
            args: vec![
                CommandArg::Value {
                    value: "-euo".to_string(),
                },
                CommandArg::Value {
                    value: "pipefail".to_string(),
                },
                CommandArg::Value {
                    value: "-c".to_string(),
                },
                CommandArg::Value {
                    value: script.to_string(),
                },
            ],
        }],
        required_role: None,
        on_host: false,
    }
}

/// Same as shell_item but executed on the host via `nsenter bash -c`.
/// `host_exec` kind/target decide the wrapping; for nsenter we produce
/// `nsenter -t <t> -m -u -i -n -- bash -euo pipefail -c <script>`.
pub fn host_shell_item(
    title: &str,
    script: &str,
    kind: crate::config::HostExecKind,
    nsenter_target: u32,
) -> CommandItem {
    let inner_args = vec![
        "-euo".to_string(),
        "pipefail".to_string(),
        "-c".to_string(),
        script.to_string(),
    ];
    let (program, argv) = match kind {
        crate::config::HostExecKind::Nsenter => {
            let mut a = vec![
                "--target".to_string(),
                nsenter_target.to_string(),
                "--mount".to_string(),
                "--uts".to_string(),
                "--ipc".to_string(),
                "--net".to_string(),
                "--".to_string(),
                "bash".to_string(),
            ];
            a.extend(inner_args);
            ("nsenter".to_string(), a)
        }
        crate::config::HostExecKind::Local => ("bash".to_string(), inner_args),
    };
    CommandItem {
        title: title.to_string(),
        description: String::new(),
        work_dir: ".".to_string(),
        icon: String::new(),
        parameters: vec![],
        button_label: "Run".to_string(),
        command_sequence: vec![CommandDefinition {
            program,
            args: argv
                .into_iter()
                .map(|v| CommandArg::Value { value: v })
                .collect(),
        }],
        required_role: None,
        on_host: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(items: &[(&str, &str)]) -> HashMap<String, String> {
        items
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn arg_value_substitutes() {
        let args = vec![CommandArg::Value {
            value: "hello ${name}".into(),
        }];
        let out = build_args(&args, &p(&[("name", "world")]));
        assert_eq!(out, vec!["hello world"]);
    }

    #[test]
    fn arg_variable_skips_empty() {
        let args = vec![CommandArg::Variable { name: "x".into() }];
        assert!(build_args(&args, &p(&[("x", "")])).is_empty());
        assert_eq!(build_args(&args, &p(&[("x", "v")])), vec!["v"]);
        assert!(build_args(&args, &p(&[])).is_empty());
    }

    #[test]
    fn arg_conditional() {
        let args = vec![CommandArg::Conditional {
            variable: "flag".into(),
            true_args: vec!["-y".into(), "${other}".into()],
            false_args: vec!["-n".into()],
        }];
        assert_eq!(
            build_args(&args, &p(&[("flag", "true"), ("other", "o")])),
            vec!["-y", "o"]
        );
        assert_eq!(build_args(&args, &p(&[("flag", "false")])), vec!["-n"]);
    }

    #[test]
    fn arg_optional() {
        let args = vec![CommandArg::Optional {
            flag: "--name".into(),
            variable: "name".into(),
        }];
        assert_eq!(build_args(&args, &p(&[("name", "x")])), vec!["--name", "x"]);
        assert!(build_args(&args, &p(&[])).is_empty());
    }

    #[test]
    fn finished_executions_persist_and_reload() {
        let dir = std::env::temp_dir().join(format!("ddm-exec-test-{}", uuid::Uuid::new_v4()));
        let path = dir.join("executions.jsonl");
        let m = ExecutionManager::new(10).with_file(path.clone());
        let id = "exec-1".to_string();
        m.register(&id);
        m.push_history(&id, "test job", Some("svc".into()), "u");
        m.mark_finished(&id, true);
        drop(m);

        // reload: finished record comes back with success + finished_at
        let m2 = ExecutionManager::new(10).with_file(path.clone());
        let e = m2.get(&id).expect("persisted execution missing");
        assert_eq!(e.title, "test job");
        assert_eq!(e.success, Some(true));
        assert!(e.finished_at.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
