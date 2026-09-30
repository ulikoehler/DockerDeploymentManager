use anyhow::Result;
use async_trait::async_trait;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::Mutex;

/// Output of a host command.
#[derive(Debug, Clone)]
pub struct HostOutput {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

impl HostOutput {
    pub fn success(&self) -> bool {
        self.status == 0
    }
}

/// Abstraction over "run a command in the host context".
/// In the container this is implemented via `nsenter -t 1 -m -u -i -n`.
/// On bare metal (or in tests) commands run directly.
#[async_trait]
pub trait HostExec: Send + Sync {
    /// Run `program args...`; returns output without interpreting exit codes.
    async fn run(&self, program: &str, args: &[String]) -> Result<HostOutput>;

    /// Run a shell script on the host (`bash -euo pipefail -c <script>`),
    /// streaming stdout/stderr lines to `on_line`.
    async fn run_streaming(
        &self,
        script: &str,
        on_line: &(dyn for<'a, 'b> Fn(&'a str, &'b str) + Send + Sync),
    ) -> Result<i32>;

    /// Resolve a binary on the host PATH. Returns absolute path or None.
    async fn which(&self, binary: &str) -> Result<Option<String>> {
        let out = self
            .run("sh", &["-c".to_string(), format!("command -v {binary}")])
            .await?;
        let path = out.stdout.trim().to_string();
        Ok(out.success().then_some(path).filter(|p| !p.is_empty()))
    }
}

// ---------------------------------------------------------------------------
// nsenter implementation (default in the privileged container)
// ---------------------------------------------------------------------------

pub struct NsenterExec {
    target: u32,
}

impl NsenterExec {
    pub fn new(target: u32) -> Self {
        Self { target }
    }

    fn wrap<'a>(&self, program: &'a str, args: &'a [String]) -> (String, Vec<String>) {
        let mut a: Vec<String> = vec![
            "--target".into(),
            self.target.to_string(),
            "--mount".into(),
            "--uts".into(),
            "--ipc".into(),
            "--net".into(),
            "--".into(),
            program.into(),
        ];
        a.extend(args.iter().cloned());
        ("nsenter".to_string(), a)
    }
}

#[async_trait]
impl HostExec for NsenterExec {
    async fn run(&self, program: &str, args: &[String]) -> Result<HostOutput> {
        let (p, a) = self.wrap(program, args);
        run_captured(&p, &a).await
    }

    async fn run_streaming(
        &self,
        script: &str,
        on_line: &(dyn for<'a, 'b> Fn(&'a str, &'b str) + Send + Sync),
    ) -> Result<i32> {
        let (p, a) = self.wrap(
            "bash",
            &[
                "-euo".into(),
                "pipefail".into(),
                "-c".into(),
                script.to_string(),
            ],
        );
        run_streaming(&p, &a, on_line).await
    }
}

// ---------------------------------------------------------------------------
// local implementation (bare metal / tests)
// ---------------------------------------------------------------------------

pub struct LocalExec;

#[async_trait]
impl HostExec for LocalExec {
    async fn run(&self, program: &str, args: &[String]) -> Result<HostOutput> {
        run_captured(program, args).await
    }

    async fn run_streaming(
        &self,
        script: &str,
        on_line: &(dyn for<'a, 'b> Fn(&'a str, &'b str) + Send + Sync),
    ) -> Result<i32> {
        run_streaming(
            "bash",
            &[
                "-euo".into(),
                "pipefail".into(),
                "-c".into(),
                script.to_string(),
            ],
            on_line,
        )
        .await
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

async fn run_captured(program: &str, args: &[String]) -> Result<HostOutput> {
    let out = tokio::process::Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await?;
    Ok(HostOutput {
        status: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
    })
}

async fn run_streaming(
    program: &str,
    args: &[String],
    on_line: &(dyn for<'a, 'b> Fn(&'a str, &'b str) + Send + Sync),
) -> Result<i32> {
    use tokio::io::{AsyncBufReadExt, BufReader};
    let mut child = tokio::process::Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut out_lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let mut err_lines = BufReader::new(child.stderr.take().unwrap()).lines();
    // Interleave stdout/stderr reasonably.
    loop {
        tokio::select! {
            l = out_lines.next_line() => match l? {
                Some(line) => on_line(&line, "stdout"),
                None => break,
            },
            l = err_lines.next_line() => if let Some(line) = l? { on_line(&line, "stderr") },
        }
    }
    while let Ok(Some(line)) = err_lines.next_line().await {
        on_line(&line, "stderr");
    }
    Ok(child.wait().await?.code().unwrap_or(-1))
}

// ---------------------------------------------------------------------------
// Mock for tests
// ---------------------------------------------------------------------------

#[allow(dead_code)]
type Script = Arc<dyn Fn(&str, &[String]) -> HostOutput + Send + Sync>;

/// Scripted mock: handlers are tried in order; first matching program prefix
/// wins. Unmatched commands fail with exit 127.
#[allow(dead_code)]
#[derive(Default)]
pub struct MockExec {
    handlers: Mutex<Vec<(String, Script)>>,
    pub calls: Mutex<Vec<(String, Vec<String>)>>,
}

#[allow(dead_code)]
impl MockExec {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a handler for a program name (exact match on argv[0]).
    pub fn on<F>(&self, program: &str, f: F) -> &Self
    where
        F: Fn(&str, &[String]) -> HostOutput + Send + Sync + 'static,
    {
        self.handlers
            .lock()
            .unwrap()
            .push((program.to_string(), Arc::new(f)));
        self
    }

    pub fn ok(program: &str, stdout: &str) -> Self {
        let m = Self::new();
        let s = stdout.to_string();
        m.on(program, move |_, _| HostOutput {
            status: 0,
            stdout: s.clone(),
            stderr: String::new(),
        });
        m
    }
}

#[async_trait]
impl HostExec for MockExec {
    async fn run(&self, program: &str, args: &[String]) -> Result<HostOutput> {
        self.calls
            .lock()
            .unwrap()
            .push((program.to_string(), args.to_vec()));
        let handlers = self.handlers.lock().unwrap();
        for (prog, f) in handlers.iter() {
            if prog == program {
                return Ok(f(program, args));
            }
        }
        Ok(HostOutput {
            status: 127,
            stdout: String::new(),
            stderr: format!("mock: no handler for {program}"),
        })
    }

    async fn run_streaming(
        &self,
        script: &str,
        on_line: &(dyn for<'a, 'b> Fn(&'a str, &'b str) + Send + Sync),
    ) -> Result<i32> {
        self.calls
            .lock()
            .unwrap()
            .push(("bash".to_string(), vec!["-c".into(), script.to_string()]));
        on_line(script, "stdout");
        Ok(0)
    }
}

/// Build the configured HostExec implementation.
pub fn build(kind: crate::config::HostExecKind, nsenter_target: u32) -> Arc<dyn HostExec> {
    match kind {
        crate::config::HostExecKind::Nsenter => Arc::new(NsenterExec::new(nsenter_target)),
        crate::config::HostExecKind::Local => Arc::new(LocalExec),
    }
}
