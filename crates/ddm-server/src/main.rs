mod agent;
mod api;
mod audit;
mod auth;
mod backup;
mod cli;
mod compose;
mod config;
mod docker;
mod exec;
mod files;
mod gitops;
mod gitsync;
mod hostexec;
mod logs;
mod mcp;
mod monitor;
mod notify;
mod permissions;
mod policy;
mod protocol;
mod services;
mod systemd;
mod users;

#[cfg(test)]
mod http_tests;

use clap::Parser;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{info, warn};

/// Shared application state (axum `State`).
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<config::SharedConfig>,
    pub users: Arc<users::UserStore>,
    /// Handle to the privileged agent (local in-process or unix socket).
    /// All crypto and host-touching ops go through it.
    pub agent: agent::Agent,
    pub exec: Arc<exec::ExecutionManager>,
    pub audit: Arc<audit::AuditLog>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = cli::Cli::parse();
    let config_path = cli.config.clone();

    match &cli.command {
        cli::Commands::Serve => serve(config_path).await,
        cli::Commands::Agent => serve_agent(config_path).await,
        cli::Commands::User { cmd } => cli::run_user_command(&config_path, cmd),
        cli::Commands::Hash { password } => cli::run_hash(password.clone()),
        cli::Commands::CheckConfig => cli::run_check_config(&config_path),
        cli::Commands::UnitTemplate { name, dir } => {
            cli::run_unit_template(&config_path, name, dir)
        }
    }
}

async fn serve(config_path: PathBuf) -> anyhow::Result<()> {
    let cfg = config::load_config(&config_path)?;
    let listen = cfg.server.listen.clone();
    let web_dir = cfg.server.web_dir.clone();
    let history = cfg.logging.history_executions;
    let users_path = config::resolve_users_path(&config_path, &cfg);
    let separated = cfg.security.agent_socket.is_some();

    // In privilege-separated mode this process holds only a redacted
    // config — secrets live exclusively in the agent.
    let shared = if separated {
        Arc::new(config::SharedConfig::new_redacted(cfg, config_path.clone()))
    } else {
        Arc::new(config::SharedConfig::new(cfg, config_path.clone()))
    };
    shared.spawn_watcher();

    // Separated mode: this process keeps only the public view (no hashes).
    let users = Arc::new(if separated {
        users::UserStore::load_public(&users_path)?
    } else {
        users::UserStore::load(&users_path)?
    });
    users.spawn_watcher();
    if users.list().await.is_empty() {
        warn!(
            "no users configured — create one with \
             `ddm-server --config {} user add <name> --role admin --generate`",
            config_path.display()
        );
    }

    let agent = if let Some(sock) = &shared.get().await.security.agent_socket {
        // Privilege-separated mode: crypto and host ops live in `ddm-agent`.
        // This process holds no JWT key, no pepper, no docker/systemd access.
        info!("connecting to privileged agent at {sock}");
        agent::Agent::Remote(agent::transport::SocketAgent::new(PathBuf::from(sock)))
    } else {
        warn!("no security.agent_socket configured — running in-process agent                (single-process mode; no privilege separation)");
        let core = build_core(&shared, &config_path, &users_path).await?;
        agent::Agent::Local(core)
    };

    let exec = Arc::new(exec::ExecutionManager::new(history));
    let audit = Arc::new(audit::AuditLog::new(2048));

    let state = AppState {
        config: shared,
        users,
        agent,
        exec,
        audit,
    };

    let mut app = api::api_router()
        .merge(mcp::router(state.clone()))
        .with_state(state.clone());

    // optional static web UI (SPA fallback → index.html)
    if let Some(dir) = web_dir {
        let dir = PathBuf::from(dir);
        if dir.is_dir() {
            info!("serving web UI from {}", dir.display());
            app =
                app.fallback_service(tower_http::services::ServeDir::new(&dir).not_found_service(
                    tower_http::services::ServeFile::new(dir.join("index.html")),
                ));
        } else {
            warn!("web_dir {} not found — UI disabled", dir.display());
        }
    }

    let listener = tokio::net::TcpListener::bind(&listen).await?;
    info!("ddm listening on {listen}");
    axum::serve(listener, app).await?;
    Ok(())
}

/// Load the JWT secret (env var, random fallback).
fn load_secret(env_name: &str) -> String {
    std::env::var(env_name).unwrap_or_else(|_| {
        let generated: String = (0..48)
            .map(|_| {
                use rand::Rng;
                const A: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
                A[rand::thread_rng().gen_range(0..A.len())] as char
            })
            .collect();
        warn!(
            "{env_name} not set — generated a random secret; all sessions \
             invalidate on restart. Set it for stable sessions."
        );
        generated
    })
}

/// Load the password pepper: `security.pepper_file` (root-only file in
/// agent mode). Empty when unset — verification still works, just without
/// peppering, so warn loudly.
fn load_pepper(cfg: &config::SecurityConfig) -> String {
    match &cfg.pepper_file {
        Some(p) => match std::fs::read_to_string(p) {
            Ok(s) => s.trim().to_string(),
            Err(e) => {
                warn!("cannot read pepper_file {p}: {e:#} — passwords unpeppered");
                String::new()
            }
        },
        None => {
            warn!("security.pepper_file not configured — passwords unpeppered");
            String::new()
        }
    }
}

/// Build the privileged agent core: crypto keys, pepper, docker, host exec,
/// gitsync, monitor. Runs inside `ddm-agent` (production) or in-process in
/// single-process/test mode.
async fn build_core(
    shared: &Arc<config::SharedConfig>,
    config_path: &Path,
    users_path: &Path,
) -> anyhow::Result<Arc<agent::AgentCore>> {
    let cfg = shared.get().await;
    let host = hostexec::build(cfg.paths.host_exec, cfg.paths.nsenter_target);
    let docker: Arc<dyn docker::DockerApi> =
        match docker::BollardDocker::from_socket(&cfg.docker.socket) {
            Ok(d) => Arc::new(d),
            Err(e) => {
                warn!("docker socket unavailable ({e:#}); docker features disabled");
                Arc::new(docker::MockDocker::default())
            }
        };
    let secret = load_secret(&cfg.server.jwt_secret_env);
    let pepper = load_pepper(&cfg.security);
    let gitsync = Arc::new(gitsync::Gitsync::new());
    let config_dir = config_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    let audit_path = config_dir.join("justification.log");
    let core = Arc::new(agent::AgentCore::new(
        shared.clone(),
        config_dir.clone(),
        users_path.to_path_buf(),
        auth::JwtKeys::new(secret),
        pepper,
        docker.clone(),
        host.clone(),
        gitsync.clone(),
        &audit_path,
    )?);
    drop(cfg);

    // The monitor lives inside the agent — it touches docker/systemd.
    let monitor = monitor::Monitor::new(
        shared.clone(),
        docker,
        host,
        core.events.clone(),
        core.clone(),
    );
    *core.monitor.lock().unwrap() = Some(monitor.clone());
    tokio::spawn(async move { monitor.run().await });

    // GitOps sync loop also lives in the agent (it mutates service dirs).
    {
        let gs = gitsync.clone();
        let sc = shared.clone();
        tokio::spawn(async move { gs.run(sc, config_dir).await });
    }
    Ok(core)
}

/// `ddm-server agent`: run the privileged security agent on the configured
/// unix socket. Intended to run as root (or a dedicated uid with docker +
/// systemd + host-exec capabilities) while `ddm-server serve` runs
/// unprivileged and connects via `security.agent_socket`.
async fn serve_agent(config_path: PathBuf) -> anyhow::Result<()> {
    let cfg = config::load_config(&config_path)?;
    let socket = cfg
        .security
        .agent_socket
        .clone()
        .unwrap_or_else(|| "/run/ddm/agent.sock".to_string());
    let users_path = config::resolve_users_path(&config_path, &cfg);
    let shared = Arc::new(config::SharedConfig::new(cfg, config_path.clone()));
    shared.spawn_watcher();
    let core = build_core(&shared, &config_path, &users_path).await?;
    agent::transport::serve(core, &PathBuf::from(socket)).await
}
