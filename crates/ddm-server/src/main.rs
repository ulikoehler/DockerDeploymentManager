mod api;
mod audit;
mod auth;
mod backup;
mod cli;
mod compose;
mod config;
mod docker;
mod exec;
mod hostexec;
mod logs;
mod monitor;
mod notify;
mod permissions;
mod policy;
mod protocol;
mod services;
mod systemd;
mod users;

use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, warn};

/// Shared application state (axum `State`).
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<config::SharedConfig>,
    pub users: Arc<users::UserStore>,
    pub jwt: Arc<auth::JwtKeys>,
    pub host: Arc<dyn hostexec::HostExec>,
    pub docker: Arc<dyn docker::DockerApi>,
    pub exec: Arc<exec::ExecutionManager>,
    pub monitor: Arc<monitor::Monitor>,
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
    let jwt_secret_env = cfg.server.jwt_secret_env.clone();
    let host_kind = cfg.paths.host_exec;
    let nsenter_target = cfg.paths.nsenter_target;
    let docker_socket = cfg.docker.socket.clone();
    let history = cfg.logging.history_executions;
    let users_path = config::resolve_users_path(&config_path, &cfg);

    // JWT secret: env var required; a random fallback would silently log
    // everyone out on restart, so warn loudly.
    let secret = std::env::var(&jwt_secret_env).unwrap_or_else(|_| {
        let generated: String = (0..48)
            .map(|_| {
                use rand::Rng;
                const A: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
                A[rand::thread_rng().gen_range(0..A.len())] as char
            })
            .collect();
        warn!(
            "{jwt_secret_env} not set — generated a random secret; all sessions \
             invalidate on restart. Set it for stable sessions."
        );
        generated
    });

    let shared = Arc::new(config::SharedConfig::new(cfg, config_path.clone()));
    shared.spawn_watcher();

    let users = Arc::new(users::UserStore::load(&users_path)?);
    users.spawn_watcher();
    if users.list().await.is_empty() {
        warn!(
            "no users configured — create one with \
             `ddm-server --config {} user add <name> --role admin --generate`",
            config_path.display()
        );
    }

    let host = hostexec::build(host_kind, nsenter_target);
    let docker: Arc<dyn docker::DockerApi> =
        match docker::BollardDocker::from_socket(&docker_socket) {
            Ok(d) => Arc::new(d),
            Err(e) => {
                warn!("docker socket unavailable ({e:#}); docker features disabled");
                Arc::new(docker::MockDocker::default())
            }
        };

    let exec = Arc::new(exec::ExecutionManager::new(history));
    let audit = Arc::new(audit::AuditLog::new(2048));
    let (events_tx, _) = tokio::sync::broadcast::channel(256);
    let monitor = monitor::Monitor::new(
        shared.clone(),
        docker.clone(),
        host.clone(),
        audit.clone(),
        events_tx,
        exec.clone(),
    );
    {
        let m = monitor.clone();
        tokio::spawn(async move { m.run().await });
    }

    let state = AppState {
        config: shared,
        users,
        jwt: Arc::new(auth::JwtKeys::new(secret)),
        host,
        docker,
        exec,
        monitor,
        audit,
    };

    let mut app = api::api_router().with_state(state.clone());

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
