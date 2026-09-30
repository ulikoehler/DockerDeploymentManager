use crate::config::{CommandArg, CommandDefinition, CommandItem};
use crate::protocol::{ExecutionInfo, ServerMessage};
use anyhow::Result;
use std::collections::{HashMap, VecDeque};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::{broadcast, mpsc};
use tracing::warn;
use uuid::Uuid;

/// Central execution bookkeeping: broadcast channels per execution + history.
pub struct ExecutionManager {
    channels: Mutex<HashMap<String, broadcast::Sender<ServerMessage>>>,
    history: Mutex<VecDeque<ExecutionInfo>>,
    max_history: usize,
}

impl ExecutionManager {
    pub fn new(max_history: usize) -> Self {
        Self {
            channels: Mutex::new(HashMap::new()),
            history: Mutex::new(VecDeque::new()),
            max_history,
        }
    }

    /// Create a channel for an execution id.
    pub fn register(&self, id: &str) -> broadcast::Sender<ServerMessage> {
        let (tx, _) = broadcast::channel(512);
        self.channels
            .lock()
            .unwrap()
            .insert(id.to_string(), tx.clone());
        tx
    }

    pub fn subscribe(&self, id: &str) -> Option<broadcast::Receiver<ServerMessage>> {
        self.channels.lock().unwrap().get(id).map(|t| t.subscribe())
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
        let tx = self.register(&id);
        self.push_history(&id, &item.title, service, user);

        let (mpsc_tx, mut mpsc_rx) = mpsc::channel::<ServerMessage>(256);
        {
            let tx = tx.clone();
            let this = Arc::clone(self);
            let exec_id = id.clone();
            tokio::spawn(async move {
                while let Some(msg) = mpsc_rx.recv().await {
                    if let ServerMessage::ExecutionFinished { success, .. } = &msg {
                        this.mark_finished(&exec_id, *success);
                    }
                    let _ = tx.send(msg);
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
        let mut h = self.history.lock().unwrap();
        if let Some(e) = h.iter_mut().find(|e| e.id == id) {
            e.finished_at = Some(chrono::Utc::now());
            e.success = Some(success);
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

    let _ = tx
        .send(ServerMessage::ExecutionFinished {
            id: execution_id,
            success: overall_success,
        })
        .await;
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
}
