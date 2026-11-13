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
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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

    /// Names of volumes carrying the compose-project label.
    async fn project_volumes(&self, project: &str) -> Result<Vec<String>>;

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

    /// `docker exec` a command (argv, no shell), streaming output.
    /// Returns the output stream plus the exec id needed for
    /// [`DockerApi::exec_exit_code`].
    async fn exec_stream(&self, id: &str, cmd: &[String]) -> Result<(LogStream, String)>;

    /// Exit code of a finished exec instance started by `exec_stream`.
    async fn exec_exit_code(&self, exec_id: &str) -> Result<i64>;

    /// Compose project owning the container (`com.docker.compose.project`
    /// label), used to map a container id back to a managed service.
    async fn container_project(&self, id: &str) -> Result<Option<String>>;

    /// Tar archive of a path inside a container (docker archive API —
    /// works on running and stopped containers). Uncompressed tar in
    /// practice; callers sniff the compression magic.
    async fn container_archive(&self, id: &str, path: &str) -> Result<ArchiveStream>;

    /// Extract a tar stream into `path` inside a container (docker PUT
    /// archive — the daemon sanitizes entry paths itself).
    async fn container_extract(&self, id: &str, path: &str, tar: ArchiveStream) -> Result<()>;

    /// Mountpoint + compose project label of a named volume. `None` when
    /// the volume does not exist.
    async fn volume_info(&self, name: &str) -> Result<Option<VolumeInfo>>;
}

/// Byte stream of a container archive (tar, possibly compressed).
pub type ArchiveStream = Pin<Box<dyn futures::Stream<Item = Result<bytes::Bytes>> + Send>>;

/// What the agent needs to authorize and locate a named volume.
#[derive(Debug, Clone)]
pub struct VolumeInfo {
    /// Host path of the volume's `_data` dir.
    pub mountpoint: String,
    /// `com.docker.compose.project` label, if the volume belongs to a
    /// compose project.
    pub project: Option<String>,
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

    async fn project_volumes(&self, project: &str) -> Result<Vec<String>> {
        use bollard::volume::ListVolumesOptions;
        let mut filters = HashMap::new();
        filters.insert(
            "label".to_string(),
            vec![format!("com.docker.compose.project={project}")],
        );
        let opts = ListVolumesOptions { filters };
        let resp = self.docker.list_volumes(Some(opts)).await?;
        Ok(resp
            .volumes
            .unwrap_or_default()
            .into_iter()
            .map(|v| v.name)
            .collect())
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

    async fn exec_stream(&self, id: &str, cmd: &[String]) -> Result<(LogStream, String)> {
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
        let started = self.docker.start_exec(&exec.id, None).await?;
        let out = match started {
            StartExecResults::Attached { output, .. } => output,
            StartExecResults::Detached => return Ok((Box::pin(futures::stream::empty()), exec.id)),
        };
        let stream = out.filter_map(|item| async move {
            use bollard::container::LogOutput;
            match item {
                Ok(LogOutput::StdOut { message }) => Some(Ok(LogLine {
                    text: String::from_utf8_lossy(&message).to_string(),
                    stream: "stdout".to_string(),
                })),
                Ok(LogOutput::StdErr { message }) => Some(Ok(LogLine {
                    text: String::from_utf8_lossy(&message).to_string(),
                    stream: "stderr".to_string(),
                })),
                Ok(_) => None,
                Err(e) => Some(Err(anyhow::anyhow!("exec stream error: {e}"))),
            }
        });
        Ok((Box::pin(stream), exec.id))
    }

    async fn exec_exit_code(&self, exec_id: &str) -> Result<i64> {
        // The exit code may not be recorded the instant the attach stream
        // closes — poll briefly before giving up rather than reporting a
        // spurious failure for a fast command.
        for _ in 0..10 {
            let info = self.docker.inspect_exec(exec_id).await?;
            if let Some(code) = info.exit_code {
                return Ok(code);
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        Ok(-1)
    }

    async fn container_project(&self, id: &str) -> Result<Option<String>> {
        let info = self.docker.inspect_container(id, None).await?;
        Ok(info
            .config
            .and_then(|c| c.labels)
            .and_then(|l| l.get("com.docker.compose.project").cloned()))
    }

    async fn container_archive(&self, id: &str, path: &str) -> Result<ArchiveStream> {
        use bollard::container::DownloadFromContainerOptions;
        let opts = DownloadFromContainerOptions {
            path: path.to_string(),
        };
        Ok(Box::pin(
            self.docker
                .download_from_container(id, Some(opts))
                .map(|r| r.map_err(anyhow::Error::from)),
        ))
    }

    async fn container_extract(&self, id: &str, path: &str, tar: ArchiveStream) -> Result<()> {
        use bollard::container::UploadToContainerOptions;
        // bollard wants a plain Byte stream (no Result) — a mid-stream io
        // error truncates the tar and the daemon rejects it anyway.
        let bytes = tar.map(|r| r.unwrap_or_default());
        let opts = UploadToContainerOptions {
            path: path.to_string(),
            no_overwrite_dir_non_dir: "false".to_string(),
        };
        self.docker
            .upload_to_container_streaming(id, Some(opts), bytes)
            .await
            .map_err(anyhow::Error::from)
    }

    async fn volume_info(&self, name: &str) -> Result<Option<VolumeInfo>> {
        match self.docker.inspect_volume(name).await {
            Ok(v) => Ok(Some(VolumeInfo {
                mountpoint: v.mountpoint,
                project: v.labels.get("com.docker.compose.project").cloned(),
            })),
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("No such volume") || msg.contains("not found") {
                    Ok(None)
                } else {
                    Err(e.into())
                }
            }
        }
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
    /// container id -> compose project label, for container_project tests.
    pub projects: Mutex<HashMap<String, String>>,
    pub exec_exit: Mutex<i64>,
}

#[async_trait]
impl DockerApi for MockDocker {
    async fn project_containers(&self, project: &str) -> Result<Vec<ContainerInfo>> {
        let projects = self.projects.lock().unwrap();
        Ok(self
            .containers
            .lock()
            .unwrap()
            .iter()
            .filter(|c| projects.get(&c.id).map(|p| p == project).unwrap_or(false))
            .cloned()
            .collect())
    }
    async fn project_volumes(&self, _project: &str) -> Result<Vec<String>> {
        Ok(Vec::new())
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
    async fn exec_stream(&self, id: &str, cmd: &[String]) -> Result<(LogStream, String)> {
        let key = format!("{id} {}", cmd.join(" "));
        let out = self
            .exec_outputs
            .lock()
            .unwrap()
            .get(&key)
            .cloned()
            .unwrap_or_else(|| "mock exec output\n".to_string());
        let line = LogLine {
            text: out,
            stream: "stdout".to_string(),
        };
        Ok((
            Box::pin(futures::stream::iter(vec![Ok(line)])),
            "mock-exec".to_string(),
        ))
    }

    async fn exec_exit_code(&self, _exec_id: &str) -> Result<i64> {
        Ok(*self.exec_exit.lock().unwrap())
    }

    async fn container_project(&self, id: &str) -> Result<Option<String>> {
        Ok(self.projects.lock().unwrap().get(id).cloned())
    }

    async fn container_archive(&self, _id: &str, _path: &str) -> Result<ArchiveStream> {
        anyhow::bail!("container_archive not supported by mock")
    }

    async fn container_extract(&self, _id: &str, _path: &str, _tar: ArchiveStream) -> Result<()> {
        anyhow::bail!("container_extract not supported by mock")
    }

    async fn volume_info(&self, _name: &str) -> Result<Option<VolumeInfo>> {
        Ok(None)
    }
}
