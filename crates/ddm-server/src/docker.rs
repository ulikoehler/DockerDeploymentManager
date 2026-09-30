use anyhow::{Context, Result};
use async_trait::async_trait;
use bollard::container::{ListContainersOptions, LogsOptions};
use bollard::Docker;
use futures::StreamExt;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Mutex;

/// A docker container belonging to a compose project.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ContainerInfo {
    pub id: String,
    pub name: String,
    pub service: String,        // compose service name (label)
    pub state: String,          // created|running|paused|restarting|exited|...
    pub status: String,         // human status incl. health
    pub health: Option<String>, // healthy|unhealthy|starting|none
}

/// Line from a container log stream.
#[derive(Debug, Clone)]
pub struct LogLine {
    pub text: String,
    pub stream: String, // stdout|stderr
}

pub type LogStream = Pin<Box<dyn futures::Stream<Item = Result<LogLine>> + Send>>;

/// Docker operations required by DDM. Abstracted so tests can mock.
#[async_trait]
pub trait DockerApi: Send + Sync {
    /// List containers of a compose project (label filter).
    async fn project_containers(&self, project: &str) -> Result<Vec<ContainerInfo>>;

    /// Health status string of a container ("healthy"/"unhealthy"/...).
    async fn container_health(&self, id: &str) -> Result<Option<String>>;

    /// Tail + optionally follow container logs.
    async fn logs(
        &self,
        id: &str,
        tail: usize,
        since: Option<i64>,
        follow: bool,
    ) -> Result<LogStream>;

    /// `docker exec` a command, returning captured stdout.
    async fn exec_capture(&self, id: &str, cmd: &[String]) -> Result<String>;
}

// ---------------------------------------------------------------------------
// Bollard implementation
// ---------------------------------------------------------------------------

pub struct BollardDocker {
    docker: Docker,
}

impl BollardDocker {
    pub fn from_socket(socket_path: &str) -> Result<Self> {
        let docker = if socket_path.starts_with('/') {
            Docker::connect_with_unix(socket_path, 120, bollard::API_DEFAULT_VERSION)
                .context("connecting to docker socket")?
        } else {
            Docker::connect_with_defaults().context("connecting to docker")?
        };
        Ok(Self { docker })
    }
}

fn map_container(c: bollard::models::ContainerSummary) -> ContainerInfo {
    let labels = c.labels.unwrap_or_default();
    let service = labels
        .get("com.docker.compose.service")
        .cloned()
        .unwrap_or_default();
    let name = c
        .names
        .unwrap_or_default()
        .first()
        .cloned()
        .unwrap_or_default()
        .trim_start_matches('/')
        .to_string();
    let status = c.status.unwrap_or_default();
    let health = if status.contains("(healthy)") {
        Some("healthy".to_string())
    } else if status.contains("(unhealthy)") {
        Some("unhealthy".to_string())
    } else if status.contains("health: starting") {
        Some("starting".to_string())
    } else {
        None
    };
    ContainerInfo {
        id: c.id.unwrap_or_default(),
        name,
        service,
        state: c.state.unwrap_or_default(),
        status,
        health,
    }
}

#[async_trait]
impl DockerApi for BollardDocker {
    async fn project_containers(&self, project: &str) -> Result<Vec<ContainerInfo>> {
        let mut filters = HashMap::new();
        filters.insert(
            "label".to_string(),
            vec![format!("com.docker.compose.project={project}")],
        );
        let opts = ListContainersOptions {
            all: true,
            filters,
            ..Default::default()
        };
        let list = self.docker.list_containers(Some(opts)).await?;
        Ok(list.into_iter().map(map_container).collect())
    }

    async fn container_health(&self, id: &str) -> Result<Option<String>> {
        let info = self.docker.inspect_container(id, None).await?;
        Ok(info
            .state
            .and_then(|s| s.health)
            .and_then(|h| h.status)
            .map(|s| s.to_string()))
    }

    async fn logs(
        &self,
        id: &str,
        tail: usize,
        since: Option<i64>,
        follow: bool,
    ) -> Result<LogStream> {
        let opts = LogsOptions::<String> {
            follow,
            stdout: true,
            stderr: true,
            tail: tail.to_string(),
            since: since.unwrap_or(0),
            timestamps: false,
            ..Default::default()
        };
        let stream = self
            .docker
            .logs(id, Some(opts))
            .filter_map(|item| async move {
                match item {
                    Ok(bollard::container::LogOutput::StdOut { message }) => Some(Ok(LogLine {
                        text: String::from_utf8_lossy(&message).to_string(),
                        stream: "stdout".to_string(),
                    })),
                    Ok(bollard::container::LogOutput::StdErr { message }) => Some(Ok(LogLine {
                        text: String::from_utf8_lossy(&message).to_string(),
                        stream: "stderr".to_string(),
                    })),
                    Ok(_) => None,
                    Err(e) => Some(Err(anyhow::anyhow!("log stream error: {e}"))),
                }
            });
        Ok(Box::pin(stream))
    }

    async fn exec_capture(&self, id: &str, cmd: &[String]) -> Result<String> {
        use bollard::exec::{CreateExecOptions, StartExecResults};
        let exec = self
            .docker
            .create_exec(
                id,
                CreateExecOptions {
                    attach_stdout: Some(true),
                    attach_stderr: Some(true),
                    cmd: Some(cmd.to_vec()),
                    ..Default::default()
                },
            )
            .await?;
        let mut out = String::new();
        if let StartExecResults::Attached { mut output, .. } =
            self.docker.start_exec(&exec.id, None).await?
        {
            while let Some(Ok(msg)) = output.next().await {
                out.push_str(&msg.to_string());
            }
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Compose CLI wrapper (runs in-container; talks to the mounted socket)
// ---------------------------------------------------------------------------

/// Build argv for `docker compose -f <file> <args...>` in a service dir.
pub fn compose_argv(compose_cmd: &[String], args: &[&str]) -> (String, Vec<String>) {
    let mut it = compose_cmd.iter();
    let program = it.next().cloned().unwrap_or_else(|| "docker".into());
    let mut a: Vec<String> = it.cloned().collect();
    a.extend(args.iter().map(|s| s.to_string()));
    (program, a)
}

// ---------------------------------------------------------------------------
// Mock for tests
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct MockDocker {
    pub containers: Mutex<Vec<ContainerInfo>>,
    pub health: Mutex<HashMap<String, Option<String>>>,
    pub log_lines: Mutex<Vec<LogLine>>,
    pub exec_outputs: Mutex<HashMap<String, String>>,
}

#[async_trait]
impl DockerApi for MockDocker {
    async fn project_containers(&self, _project: &str) -> Result<Vec<ContainerInfo>> {
        Ok(self.containers.lock().unwrap().clone())
    }
    async fn container_health(&self, id: &str) -> Result<Option<String>> {
        Ok(self.health.lock().unwrap().get(id).cloned().unwrap_or(None))
    }
    async fn logs(
        &self,
        _id: &str,
        _tail: usize,
        _since: Option<i64>,
        _follow: bool,
    ) -> Result<LogStream> {
        let lines = self.log_lines.lock().unwrap().clone();
        Ok(Box::pin(futures::stream::iter(lines.into_iter().map(Ok))))
    }
    async fn exec_capture(&self, id: &str, cmd: &[String]) -> Result<String> {
        let key = format!("{id} {}", cmd.join(" "));
        Ok(self
            .exec_outputs
            .lock()
            .unwrap()
            .get(&key)
            .cloned()
            .unwrap_or_default())
    }
}
