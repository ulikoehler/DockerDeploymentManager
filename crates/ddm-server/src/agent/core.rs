//! The privileged core: every secret-touching or host-touching operation.
//! Shared verbatim by the standalone `ddm-agent` process and the in-process
//! `LocalAgent` used by tests/development.

use super::proto::*;
use crate::auth::{Claims, JwtKeys, LoginThrottle, TokenScope};
use crate::config::{AppConfig, CommandArg, CommandDefinition, CommandItem, SharedConfig};
use crate::docker::{compose_argv, DockerApi};
use crate::exec::{self, shell_item};
use crate::hostexec::HostExec;
use crate::protocol::{EventMessage, ServerMessage};
use crate::services::{self as svc_ops, Service};
use crate::users::{self, User, UsersFile};
use anyhow::{anyhow, bail, Context, Result};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

const MAX_FILE_WRITE: usize = 4 * 1024 * 1024;
/// Upper bound for minted-token lifetimes: 10 years in minutes.
const MAX_MINT_TTL_MINUTES: i64 = 5_256_000;

/// An authorized streaming upload: the target and the caller are resolved
/// and checked before any payload is accepted.
pub struct PendingPut {
    pub svc: Service,
    pub user: User,
    pub service: String,
    pub path: String,
    /// Declared payload length — a short body means the client vanished
    /// mid-upload and the staged bytes must not be committed.
    pub len: u64,
}

fn arg(v: &str) -> CommandArg {
    CommandArg::Value {
        value: v.to_string(),
    }
}

fn cmd(program: &str, args: &[&str]) -> CommandDefinition {
    CommandDefinition {
        program: program.to_string(),
        args: args.iter().map(|a| arg(a)).collect(),
    }
}

fn sq(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// When the agent runs inside a container (`host_exec = nsenter`), prefix
/// commands that must execute on the host (systemctl, unit management) with
/// `nsenter` into the host namespaces. Definitions containing non-literal
/// args (variables/conditionals) cannot be translated and are left as-is.
fn host_wrap(cfg: &AppConfig, defs: Vec<CommandDefinition>) -> Vec<CommandDefinition> {
    if !matches!(cfg.paths.host_exec, crate::config::HostExecKind::Nsenter) {
        return defs;
    }
    defs.into_iter()
        .map(|d| {
            if !d.args.iter().all(|a| matches!(a, CommandArg::Value { .. })) {
                return d;
            }
            let mut argv = vec![
                "--target".to_string(),
                cfg.paths.nsenter_target.to_string(),
                "--mount".to_string(),
                "--uts".to_string(),
                "--ipc".to_string(),
                "--net".to_string(),
                "--".to_string(),
                d.program,
            ];
            for a in d.args {
                if let CommandArg::Value { value } = a {
                    argv.push(value);
                }
            }
            CommandDefinition {
                program: "nsenter".to_string(),
                args: argv.iter().map(|s| arg(s)).collect(),
            }
        })
        .collect()
}

/// Wrap a `shell_item` script so it runs on the host under nsenter.
fn host_shell_item_for(cfg: &AppConfig, item: CommandItem) -> CommandItem {
    let mut item = item;
    item.command_sequence = host_wrap(cfg, std::mem::take(&mut item.command_sequence));
    item.on_host = true;
    item
}

/// Mirror of the server's group-membership check: a non-admin operator may
/// only touch systemd units covered by a configured group's regex.
fn unit_in_group(cfg: &AppConfig, unit: &str) -> bool {
    cfg.systemd.groups.iter().any(|g| {
        regex::Regex::new(&g.unit_regex)
            .map(|r| r.is_match(unit))
            .unwrap_or(false)
    })
}

pub struct AgentCore {
    pub cfg: Arc<SharedConfig>,
    pub config_dir: PathBuf,
    pub users_path: PathBuf,
    pub jwt: JwtKeys,
    pub throttle: LoginThrottle,
    pub pepper: String,
    pub docker: Arc<dyn DockerApi>,
    pub host: Arc<dyn HostExec>,
    pub gitsync: Arc<crate::gitsync::Gitsync>,
    /// Root-owned append-only justification log.
    audit: Mutex<std::fs::File>,
    /// Monitor events broadcast (server subscribes via Watch).
    pub events: tokio::sync::broadcast::Sender<EventMessage>,
    /// The monitor lives inside the agent — it touches docker/systemd.
    pub monitor: Mutex<Option<Arc<crate::monitor::Monitor>>>,
    /// Webhook replay cache: recent (signature-or-token, body-hash) pairs.
    webhook_seen: Mutex<HashMap<String, std::time::Instant>>,
    /// Last accepted webhook sync, for rate limiting.
    last_webhook_sync: Mutex<Option<std::time::Instant>>,
    /// Registry of minted tokens (`<config_dir>/tokens.json`) — revocation
    /// is checked on every token verification.
    tokens: Mutex<TokenBook>,
    /// Short opaque agent tokens (`<config_dir>/short-tokens.json`) mapped
    /// to the JWT they stand in for — long JWTs are error-prone to paste.
    short_tokens: Mutex<ShortTokenMap>,
}

/// A minted short token and the JWT it resolves to. `exp` mirrors the
/// JWT's expiry so dead entries can be pruned without verifying.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct ShortToken {
    jwt: String,
    exp: i64,
}

#[derive(Default)]
struct ShortTokenMap {
    path: PathBuf,
    map: HashMap<String, ShortToken>,
}

impl ShortTokenMap {
    fn load(path: PathBuf) -> Self {
        let map = std::fs::read_to_string(&path)
            .ok()
            .and_then(|t| serde_json::from_str::<HashMap<String, ShortToken>>(&t).ok())
            .unwrap_or_default();
        Self { path, map }
    }

    fn save(&self) -> Result<()> {
        if self.path.as_os_str().is_empty() {
            return Ok(());
        }
        if let Some(p) = self.path.parent() {
            std::fs::create_dir_all(p)?;
        }
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_string(&self.map)?)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

/// Persisted registry of minted tokens. Records carry no secrets — only
/// the jti, owner, scope summary and timestamps.
#[derive(Default)]
struct TokenBook {
    path: PathBuf,
    records: Vec<TokenRecord>,
}

impl TokenBook {
    fn load(path: PathBuf) -> Self {
        let records = std::fs::read_to_string(&path)
            .ok()
            .and_then(|t| serde_json::from_str::<Vec<TokenRecord>>(&t).ok())
            .unwrap_or_default();
        Self { path, records }
    }

    fn is_revoked(&self, jti: &str) -> bool {
        self.records.iter().any(|r| r.jti == jti && r.revoked)
    }

    /// Drop records that can never be useful again: expired and not
    /// revoked, or revoked longer than the display retention window.
    fn prune(&mut self, now: chrono::DateTime<chrono::Utc>) {
        self.records.retain(|r| {
            r.exp.with_timezone(&chrono::Utc) > now
                || (r.revoked
                    && r.revoked_at
                        .map(|t| now - t.with_timezone(&chrono::Utc) < chrono::Duration::days(30))
                        .unwrap_or(false))
        });
    }

    fn save(&self) -> Result<()> {
        if self.path.as_os_str().is_empty() {
            return Ok(());
        }
        if let Some(p) = self.path.parent() {
            std::fs::create_dir_all(p)?;
        }
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(&self.records)?)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

impl AgentCore {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cfg: Arc<SharedConfig>,
        config_dir: PathBuf,
        users_path: PathBuf,
        jwt: JwtKeys,
        pepper: String,
        docker: Arc<dyn DockerApi>,
        host: Arc<dyn HostExec>,
        gitsync: Arc<crate::gitsync::Gitsync>,
        audit_path: &Path,
    ) -> Result<Self> {
        if let Some(parent) = audit_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(audit_path)
            .with_context(|| format!("opening justification log {}", audit_path.display()))?;
        let tokens_path = config_dir.join("tokens.json");
        let short_tokens_path = config_dir.join("short-tokens.json");
        Ok(Self {
            cfg,
            config_dir,
            users_path,
            jwt,
            throttle: LoginThrottle::new(),
            pepper,
            docker,
            host,
            gitsync,
            audit: Mutex::new(file),
            events: tokio::sync::broadcast::channel(256).0,
            monitor: Mutex::new(None),
            webhook_seen: Mutex::new(HashMap::new()),
            last_webhook_sync: Mutex::new(None),
            tokens: Mutex::new(TokenBook::load(tokens_path)),
            short_tokens: Mutex::new(ShortTokenMap::load(short_tokens_path)),
        })
    }

    /// Internal (agent-side) justification — no token needed, the caller is
    /// the agent itself.
    pub fn justify_internal(&self, who: &str, verb: &str, detail: &str) {
        let rec = serde_json::json!({
            "ts": chrono::Utc::now().to_rfc3339(),
            "user": who,
            "internal": true,
            "verb": verb,
            "detail": detail,
        });
        let line = rec.to_string();
        let mut f = self.audit.lock().unwrap();
        if let Err(e) = f
            .write_all(line.as_bytes())
            .and_then(|_| f.write_all(b"\n"))
        {
            tracing::error!("justification log write failed: {e}");
        }
    }

    /// Run a configured command item internally (monitor auto-actions).
    /// Not reachable over the socket — no token required.
    pub fn exec_internal(
        self: &Arc<Self>,
        item: CommandItem,
        params: HashMap<String, String>,
        service: Option<String>,
        who: &str,
    ) -> String {
        let eid = uuid::Uuid::new_v4().to_string();
        self.justify_internal(
            who,
            &format!("exec:{}", item.title),
            service.as_deref().unwrap_or(""),
        );
        let (tx, mut rx) = mpsc::channel::<ServerMessage>(256);
        let eid2 = eid.clone();
        tokio::spawn(async move {
            let _ = exec::run_steps(item, params, tx, eid2).await;
        });
        // drain frames
        tokio::spawn(async move { while rx.recv().await.is_some() {} });
        eid
    }

    /// Build and start the monitor inside the agent (call once at startup).
    pub fn spawn_monitor(self: &Arc<Self>) -> Arc<crate::monitor::Monitor> {
        let m = crate::monitor::Monitor::new(
            self.cfg.clone(),
            self.docker.clone(),
            self.host.clone(),
            self.events.clone(),
            self.clone(),
        );
        *self.monitor.lock().unwrap() = Some(m.clone());
        let m2 = m.clone();
        tokio::spawn(async move { m2.run().await });
        m
    }

    fn peppered(&self, password: &str) -> String {
        if self.pepper.is_empty() {
            password.to_string()
        } else {
            format!("{}\u{1}{}", password, self.pepper)
        }
    }

    fn users_file(&self) -> Result<UsersFile> {
        if !self.users_path.exists() {
            return Ok(UsersFile::default());
        }
        let f = std::fs::File::open(&self.users_path)?;
        serde_yaml::from_reader(f).context("parsing users file")
    }

    fn write_users(&self, file: &UsersFile) -> Result<()> {
        users::write_users_atomic(&self.users_path, file)
    }

    /// Append a justification record. Never fails the op on I/O error but
    /// logs loudly — losing the trail silently would defeat the point.
    fn justify(&self, claims: &Claims, verb: &str, detail: &str) {
        let rec = serde_json::json!({
            "ts": chrono::Utc::now().to_rfc3339(),
            "user": claims.sub,
            "roles": claims.roles,
            "iat": claims.iat,
            "exp": claims.exp,
            "verb": verb,
            "detail": detail,
        });
        let line = rec.to_string();
        let mut f = self.audit.lock().unwrap();
        if let Err(e) = f
            .write_all(line.as_bytes())
            .and_then(|_| f.write_all(b"\n"))
        {
            tracing::error!("justification log write failed: {e}");
        }
    }

    /// Verify the justification token (signature + generation), confirm the
    /// user still exists in `users.yaml`, and log the request. The fresh
    /// user record is returned alongside the claims so role checks cannot
    /// rely on stale claims — a demoted admin loses agent privileges
    /// immediately, not when the token expires.
    fn justify_token(&self, token: &str, verb: &str, detail: &str) -> Result<(Claims, User)> {
        let (claims, user) = self.token_user(token)?;
        self.justify(&claims, verb, detail);
        Ok((claims, user))
    }

    /// Resolve a presented credential to the JWT it stands for. Minted
    /// agent tokens are 15-char opaque strings looked up in the short-token
    /// map; anything containing a `.` is treated as a JWT already.
    fn resolve_token(&self, token: &str) -> String {
        if token.contains('.') {
            return token.to_string();
        }
        self.short_tokens
            .lock()
            .unwrap()
            .map
            .get(token)
            .map(|s| s.jwt.clone())
            .unwrap_or_else(|| token.to_string())
    }

    /// Verify a caller-supplied credential (short token or JWT).
    fn verify_any(&self, token: &str) -> Option<Claims> {
        self.jwt.verify(&self.resolve_token(token))
    }

    /// Verify the justification token (signature + generation) and load the
    /// *fresh* user record — without writing a justification entry. Used by
    /// `precheck`/`scoped_user`, where the arm itself logs the op.
    pub(crate) fn token_user(&self, token: &str) -> Result<(Claims, User)> {
        let claims = self
            .verify_any(token)
            .ok_or_else(|| anyhow!("invalid justification token"))?;
        let file = self.users_file()?;
        let user = file
            .users
            .iter()
            .find(|u| u.name == claims.sub)
            .cloned()
            .ok_or_else(|| anyhow!("unknown user"))?;
        if claims.sv != user.token_version {
            bail!("token revoked (password changed)");
        }
        self.check_not_revoked(&claims)?;
        Ok((claims, user))
    }

    /// Minted tokens carry a `jti` registered in the token book; a revoked
    /// jti kills the token immediately, everywhere `token_user` runs.
    fn check_not_revoked(&self, claims: &Claims) -> Result<()> {
        if let Some(jti) = &claims.jti {
            if self.tokens.lock().unwrap().is_revoked(jti) {
                bail!("token revoked");
            }
        }
        Ok(())
    }

    /// Admin check against the *fresh* user record, not the signed claims —
    /// a compromised server may present an old token whose role set is stale.
    fn require_admin(user: &User) -> Result<()> {
        if user.roles.iter().any(|r| r == "admin") {
            Ok(())
        } else {
            bail!("admin role required")
        }
    }

    /// Verify the token (signature + generation), reload the fresh user,
    /// apply the token's scope, and return both. This is the *authoritative*
    /// user for agent-side authorization — narrower than the raw claims,
    /// never wider.
    fn scoped_user(
        &self,
        token: &str,
        default_access: crate::config::DefaultAccess,
    ) -> Result<(Claims, User)> {
        let (claims, mut user) = self.token_user(token)?;
        if let Some(scope) = &claims.scope {
            crate::auth::apply_token_scope(&mut user, scope, default_access);
        }
        Ok((claims, user))
    }

    /// For trust-root operations that must never run under a narrowed
    /// token: verify the token is *unscoped* and load the fresh user.
    /// A scoped (MCP/service/action) token cannot mutate users, list them,
    /// rotate keys, or change notifier config — scope only ever narrows.
    fn unscoped_admin(&self, token: &str) -> Result<(Claims, User)> {
        let (claims, user) = self.token_user(token)?;
        if claims.scope.is_some() {
            bail!("scoped tokens cannot perform this operation");
        }
        Self::require_admin(&user)?;
        Ok((claims, user))
    }

    /// Container-id → service authorization: resolve the owning compose
    /// project agent-side (same rule as `ContainerExec`) so arbitrary
    /// container ids cannot be read/touched by unrelated service users.
    /// Unmanaged containers are admin-only.
    async fn authorize_container(&self, cfg: &AppConfig, u: &User, container: &str) -> Result<()> {
        let project = self
            .docker
            .container_project(container)
            .await
            .context("inspect container")?;
        match project.as_deref() {
            Some(p) if svc_ops::get_service(cfg, p).is_ok() => {
                if crate::permissions::can_access_service(u, p, cfg.security.default_access) {
                    Ok(())
                } else {
                    bail!("service access denied: {p}")
                }
            }
            _ => Self::require_admin(u),
        }
    }

    /// `scoped_user` + service-access check — mirrors the server's
    /// `require_service_access` so a compromised server cannot send the
    /// agent a verb for a service the token's user may not touch.
    fn justify_service(
        &self,
        cfg: &AppConfig,
        token: &str,
        service: &str,
    ) -> Result<(Claims, User)> {
        let (claims, user) = self.scoped_user(token, cfg.security.default_access)?;
        if !crate::permissions::can_access_service(&user, service, cfg.security.default_access) {
            bail!("service access denied: {service}");
        }
        Ok((claims, user))
    }

    /// Enforce a token scope's `ops` allowlist: when present, the verb's
    /// operation category must be listed. Unscoped tokens are unaffected.
    fn enforce_ops(&self, token: &str, op: Option<&'static str>) -> Result<()> {
        let claims = self
            .verify_any(token)
            .ok_or_else(|| anyhow!("invalid token"))?;
        let Some(ops) = claims.scope.as_ref().and_then(|s| s.ops.as_ref()) else {
            return Ok(());
        };
        match op {
            Some(o) if ops.iter().any(|x| x == o) => Ok(()),
            _ => bail!("token scope does not permit this operation"),
        }
    }

    fn require_feature(user: &User, ok: bool, what: &str) -> Result<()> {
        if user.is_admin() || ok {
            Ok(())
        } else {
            bail!("{what} required")
        }
    }

    /// Agent-side mirror of the server's per-verb authorization for
    /// [`SyncVerb`]s. Runs before the verb body; each arm's `justify_*`
    /// still produces the justification-log entry.
    fn precheck(&self, cfg: &AppConfig, verb: &SyncVerb, token: &str) -> Result<Option<User>> {
        let out = self.precheck_inner(cfg, verb, token)?;
        self.enforce_ops(token, sync_verb_op(verb))?;
        Ok(out)
    }

    fn precheck_inner(
        &self,
        cfg: &AppConfig,
        verb: &SyncVerb,
        token: &str,
    ) -> Result<Option<User>> {
        use crate::users::UserFeatures as F;
        let feat = |f: fn(&F) -> bool, u: &User| f(&u.features);
        match verb {
            // ---- writes / mutations: feature + service access ----
            SyncVerb::FileWrite { service, .. }
            | SyncVerb::FileMkdir { service, .. }
            | SyncVerb::FileRename { service, .. }
            | SyncVerb::FileCopy { service, .. }
            | SyncVerb::FileDelete { service, .. } => {
                let (_c, u) = self.justify_service(cfg, token, service)?;
                Self::require_feature(&u, feat(|f| f.edit_files, &u), "edit_files")?;
                Ok(Some(u))
            }
            SyncVerb::MetaWrite { service, meta } => {
                let (_c, u) = self.justify_service(cfg, token, service)?;
                // meta.yaml can carry monitoring/backup config — require the
                // matching feature, and admin when exec actions are present.
                if let Some(m) = &meta.monitoring {
                    crate::api::services::validate_monitoring_cfg(m, cfg)
                        .map_err(|e| anyhow!(e))?;
                    Self::require_feature(
                        &u,
                        feat(|f| f.manage_monitoring, &u) || feat(|f| f.edit_compose, &u),
                        "manage_monitoring",
                    )?;
                    if crate::api::services::monitoring_has_exec_actions(m) {
                        Self::require_admin(&u)?;
                    }
                }
                if meta.backup.is_some() {
                    Self::require_feature(&u, feat(|f| f.manage_backup, &u), "manage_backup")?;
                }
                Ok(Some(u))
            }
            SyncVerb::ComposeWrite { service, .. } => {
                let (_c, u) = self.justify_service(cfg, token, service)?;
                Self::require_feature(&u, feat(|f| f.edit_compose, &u), "edit_compose")?;
                Ok(Some(u))
            }
            SyncVerb::MonitoringPut { service, cfg: m } => {
                let (_c, u) = self.justify_service(cfg, token, service)?;
                Self::require_feature(
                    &u,
                    feat(|f| f.manage_monitoring, &u) || feat(|f| f.edit_compose, &u),
                    "manage_monitoring",
                )?;
                if crate::api::services::monitoring_has_exec_actions(m) {
                    Self::require_admin(&u)?;
                }
                Ok(Some(u))
            }
            SyncVerb::BackupPut { service, cfg: b } => {
                let (_c, u) = self.justify_service(cfg, token, service)?;
                Self::require_feature(&u, feat(|f| f.manage_backup, &u), "manage_backup")?;
                crate::backup::validate_dumps(&b.stdin_dumps)?;
                Ok(Some(u))
            }
            SyncVerb::BackupProvision { service } => {
                let (_c, u) = self.justify_service(cfg, token, service)?;
                Self::require_feature(&u, feat(|f| f.manage_backup, &u), "manage_backup")?;
                Ok(Some(u))
            }
            SyncVerb::ComposeSync { service, .. } => {
                let (_c, u) = self.justify_service(cfg, token, service)?;
                Self::require_feature(&u, u.has_role("operator"), "operator role")?;
                Ok(Some(u))
            }
            // ---- reads on a service: access check only ----
            SyncVerb::ServiceGet { name } => {
                self.justify_service(cfg, token, name).map(|x| Some(x.1))
            }
            SyncVerb::FileNode { service, .. }
            | SyncVerb::FileStat { service, .. }
            | SyncVerb::GitRepos { service }
            | SyncVerb::GitStatus { service, .. }
            | SyncVerb::GitLog { service, .. }
            | SyncVerb::GitBranches { service, .. }
            | SyncVerb::GitDiff { service, .. }
            | SyncVerb::ProjectContainers { service }
            | SyncVerb::UnitFileRead { service }
            | SyncVerb::UnitCheck { service }
            | SyncVerb::UnitRender { service }
            | SyncVerb::ComposeRead { service }
            | SyncVerb::MonitoringGet { service }
            | SyncVerb::BackupGet { service }
            | SyncVerb::BackupCheck { service }
            | SyncVerb::BackupLs { service, .. }
            | SyncVerb::BackupSnapshots { service } => {
                self.justify_service(cfg, token, service).map(|x| Some(x.1))
            }
            // ---- systemd surface: operator, like the server ----
            // `ListUnits` backs the operator-only systemd API; `Journal`
            // additionally mirrors the server's group-membership gate so a
            // non-admin operator cannot read arbitrary unit logs.
            SyncVerb::ListUnits { .. } => {
                let (_c, u) = self.scoped_user(token, cfg.security.default_access)?;
                Self::require_feature(&u, u.has_role("operator"), "operator role")?;
                Ok(Some(u))
            }
            SyncVerb::Journal { unit, .. } => {
                let (_c, u) = self.scoped_user(token, cfg.security.default_access)?;
                Self::require_feature(&u, u.has_role("operator"), "operator role")?;
                if !u.is_admin() && !unit_in_group(cfg, unit) {
                    bail!("unit outside configured systemd groups");
                }
                Ok(Some(u))
            }
            // `UnitState`/`UnitPathExists` also back the unit summary shown
            // in service list/detail — reachable with plain service access —
            // so allow either operator, or access to the matching service.
            SyncVerb::UnitState { unit } | SyncVerb::UnitPathExists { unit } => {
                let (_c, u) = self.scoped_user(token, cfg.security.default_access)?;
                let svc = unit.strip_suffix(".service").unwrap_or(unit);
                if u.has_role("operator")
                    || crate::permissions::can_access_service(&u, svc, cfg.security.default_access)
                {
                    return Ok(Some(u));
                }
                bail!("operator role required")
            }
            // ---- execution cancel: same gate as running command items ----
            SyncVerb::ExecCancel { .. } => {
                let (_c, u) = self.scoped_user(token, cfg.security.default_access)?;
                Self::require_feature(
                    &u,
                    u.features.run_commands || u.has_role("operator"),
                    "run_commands",
                )?;
                Ok(Some(u))
            }
            // ---- gitops surface is admin-only server-side ----
            SyncVerb::GitSyncRun | SyncVerb::GitSyncPush | SyncVerb::GitSyncStatus => {
                let (_c, u) = self.scoped_user(token, cfg.security.default_access)?;
                Self::require_admin(&u)?;
                Ok(Some(u))
            }
            _ => Ok(None),
        }
    }

    /// Same mirror for [`ExecVerb`]s.
    async fn precheck_exec(&self, cfg: &AppConfig, verb: &ExecVerb, token: &str) -> Result<User> {
        let u = self.precheck_exec_inner(cfg, verb, token).await?;
        self.enforce_ops(token, exec_verb_op(verb))?;
        Ok(u)
    }

    async fn precheck_exec_inner(
        &self,
        cfg: &AppConfig,
        verb: &ExecVerb,
        token: &str,
    ) -> Result<User> {
        use crate::users::UserFeatures as F;
        let feat = |f: fn(&F) -> bool, u: &User| f(&u.features);
        match verb {
            ExecVerb::Compose { service, .. } => {
                let (_c, u) = self.justify_service(cfg, token, service)?;
                Self::require_feature(&u, u.has_role("operator"), "operator role")?;
                Ok(u)
            }
            ExecVerb::SectionItem { section, item, .. } => {
                let (_c, u) = self.scoped_user(token, cfg.security.default_access)?;
                // mirror api::commands_api::authorized_item on the fresh user
                if !u.is_admin() && !u.features.run_commands {
                    bail!("run_commands required");
                }
                let section_cfg = cfg
                    .sections
                    .get(*section)
                    .ok_or_else(|| anyhow!("invalid section index"))?;
                if let Some(r) = &section_cfg.required_role {
                    if !u.has_role(r) {
                        bail!("forbidden");
                    }
                }
                let it = section_cfg
                    .items
                    .get(*item)
                    .ok_or_else(|| anyhow!("invalid item index"))?;
                if let Some(r) = &it.required_role {
                    if !u.has_role(r) {
                        bail!("forbidden");
                    }
                }
                Ok(u)
            }
            ExecVerb::SystemdCommand { target, .. } | ExecVerb::SystemdRestart { target } => {
                let (_c, u) = self.scoped_user(token, cfg.security.default_access)?;
                Self::require_feature(&u, u.has_role("operator"), "operator role")?;
                // Mirror the server: non-admin operators may only touch
                // units covered by a configured group.
                if let SystemdTarget::Unit(unit) = target {
                    if !u.is_admin() && !unit_in_group(cfg, unit) {
                        bail!("unit outside configured systemd groups");
                    }
                }
                Ok(u)
            }
            ExecVerb::UnitRegen { service, .. } => {
                let (_c, u) = self.justify_service(cfg, token, service)?;
                Self::require_feature(&u, feat(|f| f.edit_compose, &u), "edit_compose")?;
                Ok(u)
            }
            ExecVerb::UnitWrite { service, .. } => {
                let (_c, u) = self.justify_service(cfg, token, service)?;
                let needed = cfg.security.unit_edit_requires.clone();
                let feature_ok = u.features.edit_units && needed != "admin";
                if !u.has_role(&needed) && !feature_ok {
                    bail!("{needed} required");
                }
                Ok(u)
            }
            ExecVerb::GitClone { service, .. } | ExecVerb::GitOp { service, .. } => {
                let (_c, u) = self.justify_service(cfg, token, service)?;
                Self::require_feature(&u, feat(|f| f.edit_files, &u), "edit_files")?;
                Ok(u)
            }
            ExecVerb::BackupRun { service } | ExecVerb::BackupForget { service } => {
                let (_c, u) = self.justify_service(cfg, token, service)?;
                Self::require_feature(&u, feat(|f| f.manage_backup, &u), "manage_backup")?;
                Ok(u)
            }
            ExecVerb::BackupRestore { service, .. } => {
                let (_c, u) = self.justify_service(cfg, token, service)?;
                let unrestricted = u.compose_policy.as_deref() == Some("unrestricted");
                Self::require_feature(&u, unrestricted, "admin or unrestricted policy")?;
                Ok(u)
            }
            ExecVerb::ServiceCreate { .. } => {
                let (_c, u) = self.scoped_user(token, cfg.security.default_access)?;
                Self::require_feature(&u, feat(|f| f.create_services, &u), "create_services")?;
                Ok(u)
            }
            ExecVerb::ServiceDelete { name, .. } => {
                let (_c, u) = self.justify_service(cfg, token, name)?;
                Self::require_admin(&u)?;
                Ok(u)
            }
            // Passive log streams still get the container→service check:
            // a compromised server could feed any container id here.
            ExecVerb::ContainerLogs { id, .. } => {
                let (_c, u) = self.scoped_user(token, cfg.security.default_access)?;
                self.authorize_container(cfg, &u, id).await?;
                Ok(u)
            }
            // Free-form docker exec: `exec_containers` feature (or admin),
            // then the container's owning service from its compose project
            // label — resolved agent-side, so a compromised server cannot
            // relabel a foreign container into an allowed service.
            ExecVerb::ContainerExec { container, command } => {
                if command.is_empty() {
                    bail!("empty command");
                }
                let (claims, u) = self.scoped_user(token, cfg.security.default_access)?;
                Self::require_feature(&u, feat(|f| f.exec_containers, &u), "exec_containers")?;
                let project = self
                    .docker
                    .container_project(container)
                    .await
                    .context("inspect container")?;
                match project.as_deref() {
                    Some(p) if svc_ops::get_service(cfg, p).is_ok() => {
                        if !crate::permissions::can_access_service(
                            &u,
                            p,
                            cfg.security.default_access,
                        ) {
                            bail!("service access denied: {p}");
                        }
                    }
                    // No label / unknown project: unmanaged container —
                    // it isn't covered by per-service rights, admin only.
                    _ => Self::require_admin(&u)?,
                }
                // Authorized: record the argv the agent is about to run.
                // The exec title comes from the server; this line is the
                // authoritative one (attempts are already logged by
                // `justify_token` in `exec`).
                self.justify(
                    &claims,
                    "container_exec",
                    &format!(
                        "{container} (project: {}) : {}",
                        project.as_deref().unwrap_or("unmanaged"),
                        command.join(" ")
                    ),
                );
                Ok(u)
            }
            ExecVerb::ImageLoad { .. } => {
                let (_c, u) = self.scoped_user(token, cfg.security.default_access)?;
                Self::require_feature(&u, feat(|f| f.push_images, &u), "push_images")?;
                Ok(u)
            }
        }
    }

    // ------------------------------------------------------------------
    // Crypto ops — the trust root.
    // ------------------------------------------------------------------

    pub async fn crypto(&self, op: CryptoOp) -> Result<serde_json::Value> {
        match op {
            CryptoOp::Authenticate {
                name,
                password,
                ip,
                ua,
            } => {
                self.do_authenticate(&name, &password, ip.as_deref(), ua.as_deref())
                    .await
            }
            CryptoOp::Verify { token } => {
                let claims = self
                    .verify_any(&token)
                    .ok_or_else(|| anyhow!("invalid token"))?;
                // The user record is authoritative and read fresh — a
                // deleted/disabled user's token dies immediately.
                let file = self.users_file()?;
                let user = file
                    .users
                    .iter()
                    .find(|u| u.name == claims.sub)
                    .cloned()
                    .ok_or_else(|| anyhow!("unknown user"))?;
                if claims.sv != user.token_version {
                    bail!("token revoked (password changed)");
                }
                self.check_not_revoked(&claims)?;
                let mut user = user;
                user.password_hash.clear();
                Ok(serde_json::json!({"claims": claims, "user": user}))
            }
            CryptoOp::Mint {
                token,
                ttl_minutes,
                services,
                actions,
                ops,
                name,
            } => {
                self.do_mint(&token, ttl_minutes, services, actions, ops, name)
                    .await
            }
            CryptoOp::Rotate { token } => {
                let (_claims, _user) = self.unscoped_admin(&token)?;
                self.justify(&_claims, "rotate", "");
                self.jwt.rotate();
                Ok(serde_json::json!(true))
            }
            CryptoOp::VerifyWebhook {
                sig256,
                gitlab_token,
                body,
            } => {
                let cfg = self.cfg.get().await;
                let g = &cfg.gitops;
                Ok(serde_json::json!(crate::gitsync::verify_webhook(
                    &g.webhook_secret,
                    &g.webhook_secret_env,
                    sig256.as_deref(),
                    gitlab_token.as_deref(),
                    &body,
                )))
            }
            CryptoOp::WebhookSync {
                sig256,
                gitlab_token,
                body,
            } => {
                let cfg = self.cfg.get().await;
                let g = &cfg.gitops;
                let ok = crate::gitsync::verify_webhook(
                    &g.webhook_secret,
                    &g.webhook_secret_env,
                    sig256.as_deref(),
                    gitlab_token.as_deref(),
                    &body,
                );
                if !ok {
                    bail!("invalid webhook signature");
                }
                // Replay protection: GitHub deliveries carry no timestamp,
                // so dedupe identical (signature, body) pairs for a window,
                // and rate-limit syncs so a captured/stolen delivery can't
                // keep the host in a git-fetch loop.
                {
                    use sha2::Digest;
                    let digest = hex::encode(sha2::Sha256::digest(&body));
                    let who = sig256
                        .clone()
                        .or_else(|| gitlab_token.clone())
                        .unwrap_or_default();
                    let key = format!("{who}:{digest}");
                    let mut seen = self.webhook_seen.lock().unwrap();
                    seen.retain(|_, t| t.elapsed() < std::time::Duration::from_secs(600));
                    if seen.insert(key, std::time::Instant::now()).is_some() {
                        bail!("duplicate webhook delivery");
                    }
                }
                {
                    let mut last = self.last_webhook_sync.lock().unwrap();
                    if last
                        .map(|t| t.elapsed() < std::time::Duration::from_secs(10))
                        .unwrap_or(false)
                    {
                        bail!("webhook rate limited");
                    }
                    *last = Some(std::time::Instant::now());
                }
                self.justify_internal("webhook", "gitsync", "");
                let gitsync = self.gitsync.clone();
                let cfga = cfg.clone();
                let dir = self.config_dir.clone();
                tokio::spawn(async move {
                    if let Err(e) = gitsync.sync(&cfga, &dir).await {
                        tracing::warn!("gitops webhook sync failed: {e:#}");
                    }
                });
                Ok(serde_json::json!(true))
            }
            CryptoOp::SetPassword {
                token,
                name,
                password,
                current_password,
            } => {
                self.do_set_password(&token, &name, &password, current_password.as_deref())
                    .await
            }
            CryptoOp::UsersList { token } => {
                let (_claims, _user) = self.unscoped_admin(&token)?;
                self.justify(&_claims, "users_list", "");
                let mut file = self.users_file()?;
                for u in &mut file.users {
                    u.password_hash.clear();
                }
                Ok(serde_json::to_value(file.users)?)
            }
            CryptoOp::UserMutate { token, op } => self.do_user_mutate(&token, op).await,
            CryptoOp::TokensList { token } => {
                let (claims, user) = self.token_user(&token)?;
                self.justify(&claims, "tokens_list", "");
                let book = self.tokens.lock().unwrap();
                let now = chrono::Utc::now();
                let mut recs: Vec<TokenRecord> = book
                    .records
                    .iter()
                    .filter(|r| {
                        // keep unexpired records plus recently revoked ones
                        // so the UI can show what was killed
                        r.exp > now || r.revoked
                    })
                    .filter(|r| user.is_admin() || r.user == claims.sub)
                    .cloned()
                    .collect();
                recs.sort_by_key(|r| r.iat);
                Ok(serde_json::to_value(recs)?)
            }
            CryptoOp::RevokeToken { token, jti } => {
                let (claims, user) = self.token_user(&token)?;
                let mut book = self.tokens.lock().unwrap();
                let rec = book
                    .records
                    .iter()
                    .find(|r| r.jti == jti)
                    .ok_or_else(|| anyhow!("token not found"))?;
                // Admins revoke anything; a user may revoke their own
                // tokens but only from an unscoped session — a scoped
                // (already-narrowed) token must not kill sibling tokens.
                let allowed = user.is_admin() || (claims.scope.is_none() && rec.user == claims.sub);
                if !allowed {
                    bail!("cannot revoke this token");
                }
                let slot = book.records.iter_mut().find(|r| r.jti == jti).unwrap();
                slot.revoked = true;
                slot.revoked_at = Some(chrono::Utc::now());
                book.save()?;
                self.justify(&claims, "token_revoke", &jti);
                Ok(serde_json::json!(true))
            }
            CryptoOp::SetupNeeded => {
                let file = self.users_file()?;
                Ok(serde_json::json!({ "needed": file.users.is_empty() }))
            }
            CryptoOp::SetupCreate { name, password } => {
                let mut file = self.users_file()?;
                if !file.users.is_empty() {
                    bail!("setup already completed — users exist");
                }
                if name.trim().is_empty() || name.len() > 64 {
                    bail!("invalid user name");
                }
                if password.len() < 8 {
                    bail!("password too short");
                }
                file.users.push(User {
                    name: name.clone(),
                    password_hash: users::hash_password(&self.peppered(&password))?,
                    roles: vec!["admin".to_string()],
                    access: vec![],
                    features: Default::default(),
                    compose_policy: None,
                    token_version: 0,
                    restrictions: Default::default(),
                });
                self.write_users(&file)?;
                self.justify_internal("setup", "user_create", &name);
                Ok(serde_json::json!(true))
            }
        }
    }

    async fn do_authenticate(
        &self,
        name: &str,
        password: &str,
        ip: Option<&str>,
        ua: Option<&str>,
    ) -> Result<serde_json::Value> {
        // Throttle first — the agent owns it, a hostile server can't skip
        // it. Per-username and per-IP buckets: the IP bound stops an
        // attacker rotating across usernames at full speed from one host.
        let ip_key = ip.map(|i| format!("ip:{i}"));
        let locked = self.throttle.is_locked(name)
            || ip_key
                .as_deref()
                .map(|k| self.throttle.is_locked(k))
                .unwrap_or(false);
        let file = self.users_file()?;
        let user = file.users.iter().find(|u| u.name == name);
        // Always one peppered argon2 verify to avoid a timing oracle.
        let ok = match user {
            Some(u) => users::verify_password(&self.peppered(password), &u.password_hash),
            None => users::verify_password(&self.peppered(password), &users::dummy_hash()),
        };
        // Throttle *failed* attempts only: at most 5 guesses per window
        // regardless of outcome, so guessing gains nothing — while a
        // correct password still works and clears the lockout. A hard
        // lockout would let any unauthenticated caller lock every account
        // out with 5 wrong guesses per minute (a trivial DoS).
        if !ok {
            if locked {
                bail!("too many failed attempts, try again later");
            }
            self.throttle.record_failure(name);
            if let Some(k) = &ip_key {
                self.throttle.record_failure(k);
            }
            bail!("invalid credentials");
        }
        self.throttle.record_success(name);
        let mut user = user.unwrap().clone();
        let cfg = self.cfg.get().await;
        let ttl = cfg.server.token_ttl_minutes.max(1) * 60;
        let jti = uuid::Uuid::new_v4().to_string();
        let token = self.jwt.issue_claims(
            &user.name,
            user.roles.clone(),
            ttl,
            None,
            user.token_version,
            Some(jti.clone()),
        )?;
        let claims = self.jwt.verify(&token).unwrap();
        // Register the session so it appears in the token list and can be
        // revoked individually (sign-out) — revocation is enforced in
        // token_user on every subsequent request.
        {
            let mut book = self.tokens.lock().unwrap();
            let now = chrono::Utc::now();
            book.prune(now);
            book.records.push(TokenRecord {
                jti,
                user: user.name.clone(),
                iat: chrono::DateTime::from_timestamp(claims.iat, 0).unwrap_or(now),
                exp: chrono::DateTime::from_timestamp(claims.exp, 0).unwrap_or(now),
                services: None,
                actions: None,
                ops: None,
                revoked: false,
                kind: "session".into(),
                name: None,
                revoked_at: None,
                ua: ua.map(|s| s.chars().take(160).collect()),
            });
            if let Err(e) = book.save() {
                tracing::error!("token registry write failed: {e}");
            }
        }
        self.justify(&claims, "authenticate", name);
        // Never let the hash cross into the unprivileged process.
        user.password_hash.clear();
        Ok(serde_json::to_value(AuthResult {
            user,
            token,
            expires_at: claims.exp,
        })?)
    }

    async fn do_mint(
        &self,
        parent: &str,
        ttl_minutes: Option<i64>,
        services: Option<Vec<String>>,
        actions: Option<Vec<String>>,
        ops: Option<Vec<String>>,
        name: Option<String>,
    ) -> Result<serde_json::Value> {
        let parent_claims = self
            .verify_any(parent)
            .ok_or_else(|| anyhow!("invalid parent token"))?;
        // The fresh user record is authoritative: a deleted user cannot
        // mint, and roles are intersected so a demoted user's children
        // cannot resurrect the old (wider) role set from stale claims.
        let file = self.users_file()?;
        let fresh = file
            .users
            .iter()
            .find(|u| u.name == parent_claims.sub)
            .ok_or_else(|| anyhow!("unknown user"))?;
        let now = chrono::Utc::now().timestamp();
        let remaining = parent_claims.exp - now;
        if remaining <= 0 {
            bail!("parent token expired");
        }
        let cfg = self.cfg.get().await;
        // Minted tokens may outlive the parent session — that is the point
        // of long-lived agent credentials. Lifetime is capped at 10 years;
        // revocation stays per-jti via the token book.
        let default_min = cfg.server.token_ttl_minutes.max(1);
        let ttl = ttl_minutes
            .unwrap_or(default_min)
            .clamp(1, MAX_MINT_TTL_MINUTES)
            * 60;
        // Intersect with the parent's scope — a child can only narrow.
        let scope = match (&parent_claims.scope, &services, &actions, &ops) {
            (None, None, None, None) => None,
            _ => Some(TokenScope {
                services: intersect(&parent_claims.scope, |s| &s.services, &services),
                actions: intersect(&parent_claims.scope, |s| &s.actions, &actions),
                ops: intersect(&parent_claims.scope, |s| &s.ops, &ops),
            }),
        };
        let mut roles: Vec<String> = parent_claims
            .roles
            .iter()
            .filter(|r| fresh.roles.contains(r))
            .cloned()
            .collect();
        // A service-scoped token can never be admin — `admin` bypasses
        // service-access rules and would void the scope entirely.
        if scope.as_ref().and_then(|s| s.services.as_ref()).is_some() {
            roles.retain(|r| r != "admin");
        }
        // A revoked parent must not mint children.
        self.check_not_revoked(&parent_claims)?;
        let jti = uuid::Uuid::new_v4().to_string();
        let token = self.jwt.issue_claims(
            &parent_claims.sub,
            roles,
            ttl,
            scope.clone(),
            fresh.token_version,
            Some(jti.clone()),
        )?;
        let claims = self.jwt.verify(&token).unwrap();
        // Hand out a short opaque token instead of the JWT itself — agents
        // mix up long strings. The mapping lives in short-tokens.json so
        // it survives restarts; revocation/expiry still ride on the JWT.
        let short = {
            use rand::Rng;
            const ALPHABET: &[u8] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
            let mut rng = rand::thread_rng();
            let mut book = self.short_tokens.lock().unwrap();
            let now = chrono::Utc::now().timestamp();
            book.map.retain(|_, s| s.exp > now);
            loop {
                let s: String = (0..15)
                    .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
                    .collect();
                if !book.map.contains_key(&s) {
                    book.map.insert(
                        s.clone(),
                        ShortToken {
                            jwt: token.clone(),
                            exp: claims.exp,
                        },
                    );
                    break s;
                }
            }
        };
        if let Err(e) = self.short_tokens.lock().unwrap().save() {
            tracing::error!("short-token map write failed: {e}");
        }
        // Register the minted token so it can be listed and revoked.
        {
            let mut book = self.tokens.lock().unwrap();
            let now = chrono::Utc::now();
            book.prune(now);
            book.records.push(TokenRecord {
                jti: jti.clone(),
                user: parent_claims.sub.clone(),
                iat: chrono::DateTime::from_timestamp(claims.iat, 0).unwrap_or(now),
                exp: chrono::DateTime::from_timestamp(claims.exp, 0).unwrap_or(now),
                services: scope.as_ref().and_then(|s| s.services.clone()),
                actions: scope.as_ref().and_then(|s| s.actions.clone()),
                ops: scope.as_ref().and_then(|s| s.ops.clone()),
                revoked: false,
                kind: "token".into(),
                name: name
                    .map(|n| n.trim().chars().take(80).collect::<String>())
                    .filter(|n| !n.is_empty()),
                revoked_at: None,
                ua: None,
            });
            if let Err(e) = book.save() {
                tracing::error!("token registry write failed: {e}");
            }
        }
        self.justify(&claims, "mint", &parent_claims.sub);
        Ok(serde_json::json!({ "token": short, "expires_at": claims.exp, "jti": jti }))
    }

    async fn do_set_password(
        &self,
        token: &str,
        name: &str,
        password: &str,
        current: Option<&str>,
    ) -> Result<serde_json::Value> {
        let (claims, caller) = self.justify_token(token, "set_password", name)?;
        // Scoped tokens must not be able to escape their scope.
        if claims.scope.is_some() {
            bail!("scoped tokens cannot change passwords");
        }
        let admin = caller.roles.iter().any(|r| r == "admin");
        if !admin {
            if claims.sub != name {
                bail!("cannot change another user's password");
            }
            let file = self.users_file()?;
            let u = file
                .users
                .iter()
                .find(|u| u.name == name)
                .ok_or_else(|| anyhow!("unknown user"))?;
            let cur = current.ok_or_else(|| anyhow!("current_password required"))?;
            if !users::verify_password(&self.peppered(cur), &u.password_hash) {
                bail!("current password incorrect");
            }
        }
        if password.len() < 8 {
            bail!("password too short");
        }
        let mut file = self.users_file()?;
        let u = file
            .users
            .iter_mut()
            .find(|u| u.name == name)
            .ok_or_else(|| anyhow!("unknown user"))?;
        u.password_hash = users::hash_password(&self.peppered(password))?;
        // Revoke every token issued before this change — including the
        // caller's own, which must re-authenticate with the new password.
        u.token_version = u.token_version.wrapping_add(1);
        self.write_users(&file)?;
        Ok(serde_json::json!(true))
    }

    async fn do_user_mutate(&self, token: &str, op: UserMut) -> Result<serde_json::Value> {
        let (claims, _caller) = self.unscoped_admin(token)?;
        self.justify(&claims, "user_mutate", "");
        let mut file = self.users_file()?;
        match op {
            UserMut::Create {
                name,
                password,
                roles,
                access,
                features,
                compose_policy,
                restrictions,
            } => {
                if file.users.iter().any(|u| u.name == name) {
                    bail!("user exists");
                }
                if password.len() < 8 {
                    bail!("password too short");
                }
                file.users.push(User {
                    name: name.clone(),
                    password_hash: users::hash_password(&self.peppered(&password))?,
                    roles,
                    access,
                    features: features.unwrap_or_default(),
                    compose_policy,
                    token_version: 0,
                    restrictions: restrictions.unwrap_or_default(),
                });
                let mut u = file.users.iter().find(|u| u.name == name).unwrap().clone();
                self.write_users(&file)?;
                u.password_hash.clear();
                Ok(serde_json::to_value(u)?)
            }
            UserMut::Update {
                name,
                roles,
                features,
                compose_policy,
                restrictions,
            } => {
                let u = file
                    .users
                    .iter_mut()
                    .find(|u| u.name == name)
                    .ok_or_else(|| anyhow!("unknown user"))?;
                if let Some(r) = roles {
                    u.roles = r;
                }
                if let Some(f) = features {
                    u.features = f;
                }
                if let Some(cp) = compose_policy {
                    u.compose_policy = cp;
                }
                if let Some(r) = restrictions {
                    u.restrictions = r;
                }
                let mut u = u.clone();
                self.write_users(&file)?;
                u.password_hash.clear();
                Ok(serde_json::to_value(u)?)
            }
            UserMut::Delete { name } => {
                if name == claims.sub {
                    bail!("cannot delete yourself");
                }
                file.users.retain(|u| u.name != name);
                self.write_users(&file)?;
                Ok(serde_json::Value::Null)
            }
            UserMut::SetAccess { name, access } => {
                let u = file
                    .users
                    .iter_mut()
                    .find(|u| u.name == name)
                    .ok_or_else(|| anyhow!("unknown user"))?;
                u.access = access;
                let mut u = u.clone();
                self.write_users(&file)?;
                u.password_hash.clear();
                Ok(serde_json::to_value(u)?)
            }
        }
    }

    // ------------------------------------------------------------------
    // Sync verbs
    // ------------------------------------------------------------------

    pub async fn call(&self, verb: SyncVerb, token: &str) -> Result<serde_json::Value> {
        let cfg = self.cfg.get().await;
        // Defense in depth: re-check authorization against the fresh,
        // scope-applied user — the server's gates alone are not the boundary.
        let pre = self.precheck(&cfg, &verb, token)?;
        match verb {
            SyncVerb::ServicesList => {
                let (claims, mut user) = self.justify_token(token, "services_list", "")?;
                if let Some(scope) = &claims.scope {
                    crate::auth::apply_token_scope(&mut user, scope, cfg.security.default_access);
                }
                let svcs: Vec<_> = svc_ops::discover_services(&cfg)
                    .into_iter()
                    .filter(|s| {
                        crate::permissions::can_access_service(
                            &user,
                            &s.name,
                            cfg.security.default_access,
                        )
                    })
                    .collect();
                Ok(serde_json::to_value(svcs)?)
            }
            SyncVerb::ServiceGet { name } => {
                self.justify_token(token, "service_get", &name)?;
                let svc = svc_ops::get_service(&cfg, &name)?;
                Ok(serde_json::to_value(svc)?)
            }
            SyncVerb::FileNode { service, path } => {
                self.justify_token(token, "file_node", &format!("{service}:{path}"))?;
                let svc = svc_ops::get_service(&cfg, &service)?;
                let node = crate::files::read_node(&svc.dir, &path)?;
                Ok(serde_json::to_value(node)?)
            }
            SyncVerb::FileStat { service, path } => {
                self.justify_token(token, "file_stat", &format!("{service}:{path}"))?;
                let svc = svc_ops::get_service(&cfg, &service)?;
                Ok(serde_json::to_value(crate::files::stat(&svc.dir, &path)?)?)
            }
            SyncVerb::FileWrite {
                service,
                path,
                content,
            } => {
                self.justify_token(token, "file_write", &format!("{service}:{path}"))?;
                if content.len() > MAX_FILE_WRITE {
                    bail!("file too large");
                }
                let svc = svc_ops::get_service(&cfg, &service)?;
                // The compose file carries a policy boundary — a raw file
                // write must enforce the same gates as `ComposeWrite`.
                let abs = crate::files::resolve(&svc.dir, &path)?;
                if Self::is_compose_file(&cfg, &svc, &abs)? {
                    let u = pre
                        .as_ref()
                        .ok_or_else(|| anyhow!("authorization state missing"))?;
                    self.guard_compose_write(&cfg, &svc.dir, &content, u)?;
                }
                crate::files::write_file(&svc.dir, &path, &content)?;
                Ok(serde_json::json!(true))
            }
            SyncVerb::FileMkdir { service, path } => {
                self.justify_token(token, "file_mkdir", &format!("{service}:{path}"))?;
                let svc = svc_ops::get_service(&cfg, &service)?;
                crate::files::mkdir(&svc.dir, &path)?;
                Ok(serde_json::json!(true))
            }
            SyncVerb::FileRename { service, from, to } => {
                self.justify_token(token, "file_rename", &format!("{service}:{from}"))?;
                let svc = svc_ops::get_service(&cfg, &service)?;
                // Renaming *onto* the compose file would bypass the
                // policy-checked `FileWrite` gate.
                let to_abs = crate::files::resolve(&svc.dir, &to)?;
                let compose_abs = svc.dir.canonicalize()?.join(&cfg.paths.compose_file);
                if to_abs == compose_abs {
                    bail!("rename onto compose file denied — use the compose endpoint");
                }
                crate::files::rename(&svc.dir, &from, &to)?;
                Ok(serde_json::json!(true))
            }
            SyncVerb::FileCopy { service, from, to } => {
                self.justify_token(token, "file_copy", &format!("{service}:{from}"))?;
                let svc = svc_ops::get_service(&cfg, &service)?;
                // Copying *onto* the compose file would bypass the
                // policy-checked write gate.
                let to_abs = crate::files::resolve(&svc.dir, &to)?;
                if Self::is_compose_file(&cfg, &svc, &to_abs)? {
                    bail!("copy onto compose file denied — use the compose endpoint");
                }
                crate::files::copy(&svc.dir, &from, &to)?;
                Ok(serde_json::json!(true))
            }
            SyncVerb::FileDelete { service, path } => {
                self.justify_token(token, "file_delete", &format!("{service}:{path}"))?;
                let svc = svc_ops::get_service(&cfg, &service)?;
                crate::files::delete(&svc.dir, &path)?;
                Ok(serde_json::json!(true))
            }
            SyncVerb::GitRepos { service } => {
                self.justify_token(token, "git_repos", &service)?;
                let svc = svc_ops::get_service(&cfg, &service)?;
                Ok(serde_json::to_value(
                    crate::gitops::list_repos(&svc.dir).await,
                )?)
            }
            SyncVerb::GitStatus { service, path } => {
                self.justify_token(token, "git_status", &format!("{service}:{path}"))?;
                let svc = svc_ops::get_service(&cfg, &service)?;
                let repo = crate::gitops::resolve_repo(&svc.dir, &path)?;
                Ok(serde_json::to_value(
                    crate::gitops::status(&repo, &svc.dir).await?,
                )?)
            }
            SyncVerb::GitLog { service, path, n } => {
                self.justify_token(token, "git_log", &format!("{service}:{path}"))?;
                let svc = svc_ops::get_service(&cfg, &service)?;
                let repo = crate::gitops::resolve_repo(&svc.dir, &path)?;
                Ok(serde_json::to_value(crate::gitops::log(&repo, n).await?)?)
            }
            SyncVerb::GitBranches { service, path } => {
                self.justify_token(token, "git_branches", &format!("{service}:{path}"))?;
                let svc = svc_ops::get_service(&cfg, &service)?;
                let repo = crate::gitops::resolve_repo(&svc.dir, &path)?;
                Ok(serde_json::to_value(crate::gitops::branches(&repo).await?)?)
            }
            SyncVerb::ExecCancel { execution_id } => {
                self.justify_token(token, "exec_cancel", &execution_id)?;
                crate::exec::request_cancel(&execution_id);
                Ok(serde_json::json!({ "cancelled": true }))
            }
            SyncVerb::GitDiff {
                service,
                path,
                base,
            } => {
                self.justify_token(token, "git_diff", &format!("{service}:{path}"))?;
                let svc = svc_ops::get_service(&cfg, &service)?;
                let repo = crate::gitops::resolve_repo(&svc.dir, &path)?;
                Ok(
                    serde_json::json!({ "diff": crate::gitops::diff(&repo, base.as_deref()).await? }),
                )
            }
            SyncVerb::ProjectContainers { service } => {
                self.justify_token(token, "project_containers", &service)?;
                Ok(serde_json::to_value(
                    self.docker.project_containers(&service).await?,
                )?)
            }
            SyncVerb::ContainerHealth { id } => {
                self.justify_token(token, "container_health", &id)?;
                // Container ids are arbitrary input here — re-resolve the
                // owning service and check access (unmanaged = admin-only).
                let (_c, u) = self.scoped_user(token, cfg.security.default_access)?;
                self.authorize_container(&cfg, &u, &id).await?;
                Ok(serde_json::to_value(
                    self.docker.container_health(&id).await?,
                )?)
            }
            SyncVerb::UnitFileRead { service } => {
                self.justify_token(token, "unit_read", &service)?;
                check_unit_name(&service)?;
                let p = crate::systemd::unit_path(&cfg, &service);
                let content = std::fs::read_to_string(&p).ok();
                Ok(serde_json::json!(content))
            }
            SyncVerb::UnitCheck { service } => {
                self.justify_token(token, "unit_check", &service)?;
                let svc = svc_ops::get_service(&cfg, &service)?;
                Ok(serde_json::to_value(
                    crate::systemd::check_unit(&cfg, &self.host, &svc).await,
                )?)
            }
            SyncVerb::UnitState { unit } => {
                self.justify_token(token, "unit_state", &unit)?;
                check_unit_name(&unit)?;
                Ok(serde_json::to_value(
                    crate::systemd::unit_state(&self.host, &unit).await,
                )?)
            }
            SyncVerb::UnitPathExists { unit } => {
                self.justify_token(token, "unit_path_exists", &unit)?;
                check_unit_name(&unit)?;
                let p = crate::systemd::unit_path(&cfg, &unit);
                Ok(serde_json::json!(p.exists()))
            }
            SyncVerb::ListUnits { regex } => {
                self.justify_token(token, "list_units", &regex)?;
                Ok(serde_json::to_value(
                    crate::systemd::list_units_matching(&self.host, &regex).await?,
                )?)
            }
            SyncVerb::Journal { unit, lines } => {
                self.justify_token(token, "journal", &unit)?;
                check_unit_name(&unit)?;
                Ok(serde_json::to_value(
                    crate::systemd::journal_logs(&self.host, &unit, lines.min(10_000)).await?,
                )?)
            }
            SyncVerb::NotifierMut { op } => {
                let (_claims, _caller) = self.unscoped_admin(token)?;
                self.justify(&_claims, "notifier_mut", "");
                self.cfg
                    .mutate(move |c| {
                        match op {
                            NotifierMut::Add { notifier } => {
                                let id = notifier.id().to_string();
                                if c.monitoring.notifiers.iter().any(|x| x.id() == id) {
                                    bail!("notifier '{id}' already exists");
                                }
                                c.monitoring.notifiers.push(notifier);
                            }
                            NotifierMut::Update { id, patch } => {
                                let slot = c
                                    .monitoring
                                    .notifiers
                                    .iter_mut()
                                    .find(|x| x.id() == id)
                                    .ok_or_else(|| anyhow!("notifier not found"))?;
                                // Merge against the real stored notifier:
                                // secret fields left empty or "***" keep
                                // their existing values. Done here — the
                                // server only ever sees redacted config.
                                let old_v = serde_json::to_value(&*slot).unwrap_or_default();
                                let mut merged = patch.clone();
                                merge_notifier_secrets(&mut merged, Some(&old_v));
                                let n: crate::config::NotifierConfig =
                                    serde_json::from_value(merged)
                                        .map_err(|e| anyhow!("invalid notifier: {e}"))?;
                                if n.id() != id {
                                    bail!("id cannot be changed");
                                }
                                *slot = n;
                            }
                            NotifierMut::Delete { id } => {
                                let before = c.monitoring.notifiers.len();
                                c.monitoring.notifiers.retain(|x| x.id() != id);
                                if c.monitoring.notifiers.len() == before {
                                    bail!("notifier '{id}' not found");
                                }
                            }
                        }
                        Ok(())
                    })
                    .await?;
                Ok(serde_json::json!(true))
            }
            SyncVerb::SectionsMut { op } => {
                let (_claims, _caller) = self.unscoped_admin(token)?;
                self.justify(&_claims, "sections_mut", "");
                self.cfg
                    .mutate(move |c| {
                        match op {
                            SectionMutOp::Add { section } => {
                                c.sections.push(section);
                            }
                            SectionMutOp::Update { index, section } => {
                                let slot = c
                                    .sections
                                    .get_mut(index)
                                    .ok_or_else(|| anyhow!("section index out of range"))?;
                                *slot = section;
                            }
                            SectionMutOp::Delete { index } => {
                                if index >= c.sections.len() {
                                    bail!("section index out of range");
                                }
                                c.sections.remove(index);
                            }
                            SectionMutOp::AddItem { section, item } => {
                                c.sections
                                    .get_mut(section)
                                    .ok_or_else(|| anyhow!("section index out of range"))?
                                    .items
                                    .push(item);
                            }
                            SectionMutOp::UpdateItem {
                                section,
                                index,
                                item,
                            } => {
                                let slot = c
                                    .sections
                                    .get_mut(section)
                                    .and_then(|s| s.items.get_mut(index))
                                    .ok_or_else(|| anyhow!("item index out of range"))?;
                                *slot = item;
                            }
                            SectionMutOp::DeleteItem { section, index } => {
                                let items = &mut c
                                    .sections
                                    .get_mut(section)
                                    .ok_or_else(|| anyhow!("section index out of range"))?
                                    .items;
                                if index >= items.len() {
                                    bail!("item index out of range");
                                }
                                items.remove(index);
                            }
                        }
                        Ok(())
                    })
                    .await?;
                Ok(serde_json::json!(true))
            }
            SyncVerb::GitOpsPut { cfg: patch } => {
                let (_claims, _caller) = self.unscoped_admin(token)?;
                self.justify(&_claims, "gitops_put", "");
                self.cfg
                    .mutate(move |c| {
                        // Merge secret fields against the stored config —
                        // the server only sees redacted values ("***" or
                        // empty), which mean "keep the existing secret".
                        let old_v = serde_json::to_value(&c.gitops).unwrap_or_default();
                        let mut merged = patch.clone();
                        merge_gitops_secrets(&mut merged, Some(&old_v));
                        c.gitops = serde_json::from_value(merged)
                            .map_err(|e| anyhow!("invalid gitops config: {e}"))?;
                        Ok(())
                    })
                    .await?;
                Ok(serde_json::json!(true))
            }
            SyncVerb::BackupCheck { service } => {
                self.justify_token(token, "backup_check", &service)?;
                let svc = svc_ops::get_service(&cfg, &service)?;
                Ok(serde_json::to_value(
                    crate::backup::check(&cfg, &self.host, &svc).await,
                )?)
            }
            SyncVerb::BackupSnapshots { service } => {
                self.justify_token(token, "backup_snapshots", &service)?;
                let svc = svc_ops::get_service(&cfg, &service)?;
                Ok(serde_json::to_value(
                    crate::backup::snapshots(&cfg, &self.host, &svc, &self.restic_bin(&cfg).await?)
                        .await?,
                )?)
            }
            SyncVerb::BackupLs {
                service,
                snapshot,
                path,
            } => {
                self.justify_token(
                    token,
                    "backup_ls",
                    &format!("{service}:{snapshot}:{}", path.as_deref().unwrap_or("/")),
                )?;
                let svc = svc_ops::get_service(&cfg, &service)?;
                let bin = self.restic_bin(&cfg).await?;
                let script =
                    crate::backup::ls_script(&cfg, &svc, &bin, &snapshot, path.as_deref())?;
                let out = self.host.run("bash", &["-c".into(), script]).await?;
                if !out.success() {
                    bail!("restic ls failed: {}", out.stderr.trim());
                }
                // --json emits ndjson node objects, one per line.
                let entries: Vec<serde_json::Value> = out
                    .stdout
                    .lines()
                    .filter_map(|l| serde_json::from_str(l).ok())
                    .collect();
                Ok(serde_json::to_value(entries)?)
            }
            SyncVerb::MetaWrite { service, meta } => {
                self.justify_token(token, "meta_write", &service)?;
                let svc = svc_ops::get_service(&cfg, &service)?;
                svc_ops::save_meta(&svc.dir, &meta)?;
                Ok(serde_json::json!(true))
            }
            SyncVerb::ComposeRead { service } => {
                self.justify_token(token, "compose_read", &service)?;
                let svc = svc_ops::get_service(&cfg, &service)?;
                Ok(serde_json::json!(crate::compose::read_compose(
                    &svc.compose_path
                )?))
            }
            SyncVerb::ComposeWrite { service, content } => {
                self.justify_token(token, "compose_write", &service)?;
                crate::compose::parse_check(&content)?;
                if content.len() > MAX_FILE_WRITE {
                    bail!("compose file too large");
                }
                let svc = svc_ops::get_service(&cfg, &service)?;
                let base = svc.compose_path.parent().map(|p| p.to_path_buf());
                // caller's own policy (put_compose applies this server-side)
                // in addition to the configured floor.
                if let Some(u) = &pre {
                    if let Some(p) = crate::api::services::effective_policy_for_user(&cfg, u) {
                        let violations =
                            crate::policy::validate_compose_in(&content, &p, base.as_deref());
                        if !violations.is_empty() {
                            let msg = violations
                                .iter()
                                .map(|v| format!("{}: {}", v.path, v.message))
                                .collect::<Vec<_>>()
                                .join("; ");
                            bail!("compose policy violations: {msg}");
                        }
                    }
                }
                self.enforce_policy_floor(&cfg, &content, base.as_deref())?;
                crate::compose::write_compose(&svc.compose_path, &content)?;
                Ok(serde_json::json!(true))
            }
            SyncVerb::MonitoringGet { service } => {
                self.justify_token(token, "monitoring_get", &service)?;
                let svc = svc_ops::get_service(&cfg, &service)?;
                Ok(serde_json::to_value(svc.meta.monitoring)?)
            }
            SyncVerb::MonitoringPut { service, cfg: m } => {
                self.justify_token(token, "monitoring_put", &service)?;
                crate::api::services::validate_monitoring_cfg(&m, &cfg).map_err(|e| anyhow!(e))?;
                let mut svc = svc_ops::get_service(&cfg, &service)?;
                svc.meta.monitoring = Some(m);
                svc_ops::save_meta(&svc.dir, &svc.meta)?;
                Ok(serde_json::json!(true))
            }
            SyncVerb::BackupGet { service } => {
                self.justify_token(token, "backup_get", &service)?;
                let svc = svc_ops::get_service(&cfg, &service)?;
                Ok(serde_json::to_value(svc.meta.backup)?)
            }
            SyncVerb::BackupPut { service, cfg: b } => {
                self.justify_token(token, "backup_put", &service)?;
                // stdin_dumps render unquoted into a root-run script —
                // structural validation + compose-service membership both
                // enforced here, fail closed.
                crate::backup::validate_dumps(&b.stdin_dumps)?;
                if !b.stdin_dumps.is_empty() {
                    let svc0 = svc_ops::get_service(&cfg, &service)?;
                    if let Ok(compose) = crate::compose::read_compose(&svc0.compose_path) {
                        crate::backup::validate_dump_services(&b.stdin_dumps, &compose)?;
                    }
                }
                let mut svc = svc_ops::get_service(&cfg, &service)?;
                svc.meta.backup = Some(b);
                svc_ops::save_meta(&svc.dir, &svc.meta)?;
                Ok(serde_json::json!(true))
            }
            SyncVerb::BackupGlobalGet => {
                let (_claims, _caller) = self.unscoped_admin(token)?;
                self.justify(&_claims, "backup_global_get", "");
                let b = &cfg.backup;
                Ok(serde_json::json!({
                    "enabled": b.enabled,
                    "scheduler": b.scheduler,
                    "on_calendar": b.on_calendar,
                    "excludes": b.excludes,
                    "retention": b.retention,
                }))
            }
            SyncVerb::BackupGlobalPut { patch } => {
                let (_claims, _caller) = self.unscoped_admin(token)?;
                self.justify(&_claims, "backup_global_put", "");
                self.cfg
                    .mutate(move |c| {
                        apply_backup_global_patch(&mut c.backup, &patch)?;
                        Ok(())
                    })
                    .await?;
                Ok(serde_json::json!(true))
            }
            SyncVerb::ResolveComposeBin => {
                self.justify_token(token, "resolve_compose_bin", "")?;
                Ok(serde_json::to_value(
                    crate::systemd::resolve_compose_bin(&cfg, &self.host).await?,
                )?)
            }
            SyncVerb::GitSyncStatus => {
                self.justify_token(token, "gitsync_status", "")?;
                Ok(serde_json::to_value(self.gitsync.status().await)?)
            }
            SyncVerb::GitSyncRun => {
                self.justify_token(token, "gitsync_run", "")?;
                self.gitsync.sync(&cfg, &self.config_dir).await?;
                Ok(serde_json::json!(true))
            }
            SyncVerb::GitSyncPush => {
                self.justify_token(token, "gitsync_push", "")?;
                Ok(serde_json::to_value(
                    self.gitsync.push(&cfg, &self.config_dir).await?,
                )?)
            }
            SyncVerb::UnitRender { service } => {
                self.justify_token(token, "unit_render", &service)?;
                let svc = svc_ops::get_service(&cfg, &service)?;
                Ok(serde_json::to_value(
                    crate::systemd::render_unit_for(&cfg, &self.host, &svc).await?,
                )?)
            }
            SyncVerb::MonitorStatusAll => {
                let (claims, mut user) = self.justify_token(token, "monitor_status", "")?;
                if let Some(scope) = &claims.scope {
                    crate::auth::apply_token_scope(&mut user, scope, cfg.security.default_access);
                }
                let m = self.monitor.lock().unwrap().clone();
                match m {
                    Some(m) => {
                        let mut status = m.status().await;
                        if !user.is_admin() {
                            status.retain(|name, _| {
                                crate::permissions::can_access_service(
                                    &user,
                                    name,
                                    cfg.security.default_access,
                                )
                            });
                        }
                        Ok(serde_json::to_value(status)?)
                    }
                    None => Ok(serde_json::json!({})),
                }
            }
            SyncVerb::MonitorEvents => {
                let (claims, mut user) = self.justify_token(token, "monitor_events", "")?;
                if let Some(scope) = &claims.scope {
                    crate::auth::apply_token_scope(&mut user, scope, cfg.security.default_access);
                }
                let m = self.monitor.lock().unwrap().clone();
                match m {
                    Some(m) => {
                        let mut events = m.events().await;
                        if !user.is_admin() {
                            events.retain(|e| {
                                crate::permissions::can_access_service(
                                    &user,
                                    &e.service,
                                    cfg.security.default_access,
                                )
                            });
                        }
                        Ok(serde_json::to_value(events)?)
                    }
                    None => Ok(serde_json::json!([])),
                }
            }
            SyncVerb::NotifyTest { id, message } => {
                let (_claims, _caller) = self.unscoped_admin(token)?;
                self.justify(&_claims, "notify_test", &id);
                // Fires real outbound webhooks to configured targets —
                // admin-only, unscoped tokens only (checked above).
                let n = cfg
                    .monitoring
                    .notifiers
                    .iter()
                    .find(|n| n.id() == id)
                    .cloned()
                    .ok_or_else(|| anyhow!("notifier not found"))?;
                let notif = crate::notify::Notification {
                    title: "[ddm] test".into(),
                    body: message,
                    service: "test".into(),
                    severity: "info".into(),
                };
                crate::notify::send(&n, &notif).await?;
                Ok(serde_json::json!(true))
            }
            SyncVerb::BackupProvision { service } => {
                self.justify_token(token, "backup_provision", &service)?;
                let svc = svc_ops::get_service(&cfg, &service)?;
                let bin = self.restic_bin(&cfg).await?;
                let cfg_dir = self.cfg.dir();
                let steps =
                    crate::backup::provision(&cfg, &self.host, &svc, &bin, &cfg_dir).await?;
                Ok(serde_json::to_value(steps)?)
            }
            SyncVerb::ContainerLogsCollect { id, tail, since } => {
                self.justify_token(token, "container_logs", &id)?;
                let (_c, u) = self.scoped_user(token, cfg.security.default_access)?;
                self.authorize_container(&cfg, &u, &id).await?;
                use futures::StreamExt;
                let mut stream = self.docker.logs(&id, tail, since, false).await?;
                let mut out = vec![];
                while let Some(l) = stream.next().await {
                    if let Ok(l) = l {
                        out.push(l);
                    }
                }
                Ok(serde_json::to_value(out)?)
            }
            SyncVerb::ComposeSync { service, action } => {
                self.justify_token(token, "compose_sync", &format!("{service} {action}"))?;
                match action.as_str() {
                    "pull" | "up" | "down" | "restart" | "start" | "stop" => {}
                    other => bail!("compose action '{other}' not allowed"),
                }
                let svc = svc_ops::get_service(&cfg, &service)?;
                let (prog, mut argv) = compose_argv(&cfg.docker.compose_command, &[]);
                argv.push("-f".into());
                argv.push(
                    svc.compose_path
                        .file_name()
                        .unwrap()
                        .to_string_lossy()
                        .to_string(),
                );
                argv.push(action);
                let out = tokio::process::Command::new(&prog)
                    .args(&argv)
                    .current_dir(&svc.dir)
                    .output()
                    .await?;
                Ok(serde_json::json!(format!(
                    "{}{}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                )))
            }
        }
    }

    // ------------------------------------------------------------------
    // File streaming (the bulk data plane — WebDAV PUT/GET)
    // ------------------------------------------------------------------
    //
    // Uploads and downloads are the only ops that move bulk bytes, so they
    // get a two-phase shape instead of the JSON `SyncVerb` channel:
    // authorize, hand back a handle, then stream. Authorization mirrors
    // `precheck`'s `FileWrite`/`FileNode` arms exactly — a second transport
    // must never become a second policy.

    /// Is `abs` the service's compose file? Compose files carry a policy
    /// boundary, so every write path (JSON file API, WebDAV PUT, rename
    /// target) has to recognize them.
    fn is_compose_file(cfg: &AppConfig, svc: &Service, abs: &Path) -> Result<bool> {
        Ok(abs == svc.dir.canonicalize()?.join(&cfg.paths.compose_file))
    }

    /// Enforce `edit_compose` + the caller's compose policy + the configured
    /// floor on a new compose file body. Shared by every write path so they
    /// cannot drift apart. `base_dir` is the directory containing the
    /// compose file (for resolving relative bind sources).
    fn guard_compose_write(
        &self,
        cfg: &AppConfig,
        base_dir: &std::path::Path,
        content: &str,
        user: &User,
    ) -> Result<()> {
        Self::require_feature(user, user.features.edit_compose, "edit_compose")?;
        if let Some(p) = crate::api::services::effective_policy_for_user(cfg, user) {
            let violations = crate::policy::validate_compose_in(content, &p, Some(base_dir));
            if !violations.is_empty() {
                let msg = violations
                    .iter()
                    .map(|v| format!("{}: {}", v.path, v.message))
                    .collect::<Vec<_>>()
                    .join("; ");
                bail!("compose policy violations: {msg}");
            }
        }
        crate::compose::parse_check(content)?;
        self.enforce_policy_floor(cfg, content, Some(base_dir))
    }

    /// Authorize a streaming upload and resolve its target. No payload is
    /// read until this returns, so a denied write never accepts bytes.
    pub async fn file_put_begin(
        &self,
        service: &str,
        path: &str,
        len: u64,
        token: &str,
    ) -> Result<PendingPut> {
        let cfg = self.cfg.get().await;
        let (claims, user) = self.scoped_user(token, cfg.security.default_access)?;
        if !crate::permissions::can_access_service(&user, service, cfg.security.default_access) {
            bail!("service access denied: {service}");
        }
        Self::require_feature(&user, user.features.edit_files, "edit_files")?;
        if len > cfg.webdav.max_upload_bytes {
            bail!("upload exceeds {} bytes", cfg.webdav.max_upload_bytes);
        }
        let svc = svc_ops::get_service(&cfg, service)?;
        let abs = crate::files::resolve(&svc.dir, path)?;
        if abs == svc.dir.canonicalize()? {
            bail!("refusing to overwrite the service directory itself");
        }
        if abs.is_dir() {
            bail!("'{path}' is a directory");
        }
        // The server's own view of the request is not trusted — record what
        // the agent is about to write, agent-side.
        self.justify(
            &claims,
            "file_put",
            &format!("{service}:{path} ({len} bytes)"),
        );
        Ok(PendingPut {
            svc,
            user,
            service: service.to_string(),
            path: path.to_string(),
            len,
        })
    }

    /// Stream the payload into a sibling temp file and commit it with an
    /// atomic rename. The compose-policy gate runs on the staged bytes
    /// before anything becomes visible under the final name.
    pub async fn file_put_stream(
        &self,
        cfg: &AppConfig,
        pending: PendingPut,
        reader: &mut (impl tokio::io::AsyncRead + Unpin),
    ) -> Result<crate::agent::proto::FileMeta> {
        let staged = crate::files::stage_write(
            &pending.svc.dir,
            &pending.path,
            reader,
            cfg.webdav.max_upload_bytes,
        )
        .await?;
        // A short body means the uploader disconnected mid-stream: never
        // commit a truncated file over a good one.
        if staged.written != pending.len {
            staged.abort();
            bail!(
                "incomplete upload: got {} of {} bytes",
                staged.written,
                pending.len
            );
        }
        if Self::is_compose_file(cfg, &pending.svc, &staged.abs)? {
            if staged.written > MAX_FILE_WRITE as u64 {
                staged.abort();
                bail!("compose file too large");
            }
            let content = match tokio::fs::read_to_string(&staged.tmp).await {
                Ok(c) => c,
                Err(e) => {
                    staged.abort();
                    return Err(e.into());
                }
            };
            if let Err(e) = self.guard_compose_write(cfg, &pending.svc.dir, &content, &pending.user)
            {
                staged.abort();
                return Err(e);
            }
        }
        crate::files::commit_staged(staged)?;
        crate::files::stat(&pending.svc.dir, &pending.path)
    }

    /// Authorize a download and open the requested range. Returns the full
    /// metadata, how many bytes will follow, and the reader. `len == 0`
    /// means "to the end of the file".
    pub async fn file_get_begin(
        &self,
        service: &str,
        path: &str,
        offset: u64,
        len: u64,
        token: &str,
    ) -> Result<(crate::agent::proto::FileMeta, u64, tokio::fs::File)> {
        let cfg = self.cfg.get().await;
        let (claims, _user) = self.justify_service(&cfg, token, service)?;
        let svc = svc_ops::get_service(&cfg, service)?;
        let meta = crate::files::stat(&svc.dir, path)?;
        if meta.kind != "file" {
            bail!("not a regular file");
        }
        let abs = crate::files::resolve(&svc.dir, path)?;
        let mut f = tokio::fs::File::open(&abs).await?;
        if offset > 0 {
            use tokio::io::AsyncSeekExt;
            f.seek(std::io::SeekFrom::Start(offset)).await?;
        }
        let available = meta.size.saturating_sub(offset);
        let sent = if len == 0 {
            available
        } else {
            len.min(available)
        };
        self.justify(
            &claims,
            "file_get",
            &format!("{service}:{path} [{offset}+{sent}]"),
        );
        Ok((meta, sent, f))
    }

    // ------------------------------------------------------------------
    // Exec verbs — streamed as ServerMessage frames.
    // ------------------------------------------------------------------

    /// Build the command item for a verb and stream execution frames.
    /// Returns a receiver; the caller registers/forwards frames.
    pub async fn exec(
        self: &Arc<Self>,
        verb: ExecVerb,
        eid: String,
        title: String,
        token: &str,
    ) -> Result<mpsc::Receiver<ServerMessage>> {
        let (_claims, _user) = self.justify_token(token, &title, "")?;
        let cfg = self.cfg.get().await;
        // Defense in depth: re-check the verb's authorization against the
        // fresh, scope-applied user before any command is assembled.
        let authorized = self.precheck_exec(&cfg, &verb, token).await?;
        let (tx, rx) = mpsc::channel::<ServerMessage>(256);
        let core = Arc::clone(self);
        tokio::spawn(async move {
            let _ = tx
                .send(ServerMessage::ExecutionStarted {
                    id: eid.clone(),
                    title: title.clone(),
                })
                .await;
            let ok = match core.exec_inner(&verb, &cfg, &eid, &tx, &authorized).await {
                Ok(ok) => ok,
                Err(e) => {
                    let _ = tx
                        .send(ServerMessage::LogOutput {
                            id: eid.clone(),
                            text: format!("error: {e:#}\n"),
                            stream: "stderr".into(),
                        })
                        .await;
                    false
                }
            };
            let _ = tx
                .send(ServerMessage::ExecutionFinished {
                    id: eid,
                    success: ok,
                })
                .await;
        });
        Ok(rx)
    }

    async fn exec_inner(
        &self,
        verb: &ExecVerb,
        cfg: &AppConfig,
        eid: &str,
        tx: &mpsc::Sender<ServerMessage>,
        user: &User,
    ) -> Result<bool> {
        match verb {
            ExecVerb::Compose { service, op } => {
                let svc = svc_ops::get_service(cfg, service)?;
                let item = self.compose_item(cfg, &svc, op)?;
                Ok(exec::run_steps(item, HashMap::new(), tx.clone(), eid.to_string()).await)
            }
            ExecVerb::SectionItem {
                section,
                item,
                params,
            } => {
                let it = cfg
                    .sections
                    .get(*section)
                    .and_then(|s| s.items.get(*item))
                    .cloned()
                    .ok_or_else(|| anyhow!("unknown command item"))?;
                if it.on_host && matches!(cfg.paths.host_exec, crate::config::HostExecKind::Nsenter)
                {
                    let script = it
                        .command_sequence
                        .iter()
                        .map(|c| {
                            let args = exec::build_args(&c.args, params);
                            format!(
                                "cd {} && {} {}",
                                sq(&it.work_dir),
                                c.program,
                                args.iter().map(|a| sq(a)).collect::<Vec<_>>().join(" ")
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(" && ");
                    let wrapped = exec::host_shell_item(
                        &it.title,
                        &script,
                        cfg.paths.host_exec,
                        cfg.paths.nsenter_target,
                    );
                    Ok(exec::run_steps(wrapped, HashMap::new(), tx.clone(), eid.to_string()).await)
                } else {
                    Ok(exec::run_steps(it, params.clone(), tx.clone(), eid.to_string()).await)
                }
            }
            ExecVerb::SystemdCommand { target, command_id } => {
                let item = self.systemd_command_item(cfg, target, command_id).await?;
                Ok(exec::run_steps(item, HashMap::new(), tx.clone(), eid.to_string()).await)
            }
            ExecVerb::SystemdRestart { target } => {
                let item = self.systemd_restart_item(cfg, target).await?;
                Ok(exec::run_steps(item, HashMap::new(), tx.clone(), eid.to_string()).await)
            }
            ExecVerb::UnitRegen {
                service,
                enable,
                start,
            } => {
                let svc = svc_ops::get_service(cfg, service)?;
                let unit = crate::systemd::render_unit_for(cfg, &self.host, &svc).await?;
                crate::systemd::write_unit(cfg, &self.host, &svc, &unit).await?;
                let uname = format!("{}.service", svc.name);
                let mut script = "systemctl daemon-reload".to_string();
                if *enable {
                    script += &format!(" && systemctl enable {}", sq(&uname));
                }
                if *start {
                    script += &format!(" && systemctl restart {}", sq(&uname));
                }
                let item = host_shell_item_for(
                    cfg,
                    shell_item(&format!("regen unit ({service})"), &script, "."),
                );
                Ok(exec::run_steps(item, HashMap::new(), tx.clone(), eid.to_string()).await)
            }
            ExecVerb::UnitWrite {
                service,
                content,
                enable,
                restart,
            } => {
                crate::systemd::validate_unit(content)?;
                let svc = svc_ops::get_service(cfg, service)?;
                crate::systemd::write_unit(cfg, &self.host, &svc, content).await?;
                let uname = format!("{}.service", svc.name);
                let mut script = "systemctl daemon-reload".to_string();
                if *enable {
                    script += &format!(" && systemctl enable {}", sq(&uname));
                }
                if *restart {
                    script += &format!(" && systemctl restart {}", sq(&uname));
                }
                let item = host_shell_item_for(
                    cfg,
                    shell_item(&format!("write unit ({service})"), &script, "."),
                );
                Ok(exec::run_steps(item, HashMap::new(), tx.clone(), eid.to_string()).await)
            }
            ExecVerb::GitClone {
                service,
                url,
                path,
                branch,
            } => {
                if !crate::gitops::valid_clone_url(url) {
                    bail!("invalid clone url");
                }
                if crate::gitops::is_local_clone_url(url) && !cfg.security.allow_local_git_clone {
                    bail!("local clone URLs disabled (security.allow_local_git_clone)");
                }
                if let Some(b) = branch {
                    if !crate::gitops::valid_ref(b) {
                        bail!("invalid branch");
                    }
                }
                let svc = svc_ops::get_service(cfg, service)?;
                let script = crate::gitops::clone_script(&svc.dir, url, path, branch.as_deref())?;
                let item = shell_item(
                    &format!("git clone ({service})"),
                    &script,
                    &svc.dir.to_string_lossy(),
                );
                let ok = exec::run_steps(item, HashMap::new(), tx.clone(), eid.to_string()).await;
                if ok {
                    // A clone is attacker-controlled content: strip escaping
                    // symlinks and denied privileged filenames.
                    if let Ok(target) = crate::files::resolve(&svc.dir, path) {
                        crate::files::sanitize_clone(&svc.dir, &target);
                    }
                    // A clone into the service root may deliver a compose
                    // file — enforce the caller's policy+restrictions and
                    // the global floor on it.
                    if let Ok(compose) = std::fs::read_to_string(&svc.compose_path) {
                        let base = svc.compose_path.parent().map(|p| p.to_path_buf());
                        if let Some(p) = crate::api::services::effective_policy_for_user(cfg, user)
                        {
                            let violations =
                                crate::policy::validate_compose_in(&compose, &p, base.as_deref());
                            if !violations.is_empty() {
                                let msg = violations
                                    .iter()
                                    .map(|v| format!("{}: {}", v.path, v.message))
                                    .collect::<Vec<_>>()
                                    .join("; ");
                                bail!("compose policy violations: {msg}");
                            }
                        }
                        self.enforce_policy_floor(cfg, &compose, base.as_deref())?;
                    }
                }
                Ok(ok)
            }
            ExecVerb::GitOp {
                service,
                path,
                op,
                git_ref,
            } => {
                let svc = svc_ops::get_service(cfg, service)?;
                let repo = crate::gitops::resolve_repo(&svc.dir, path)?;
                let script = crate::gitops::op_script(op, &repo, git_ref.as_deref())?;
                let item = shell_item(
                    &format!("git {op} ({service})"),
                    &script,
                    &svc.dir.to_string_lossy(),
                );
                Ok(exec::run_steps(item, HashMap::new(), tx.clone(), eid.to_string()).await)
            }
            ExecVerb::BackupRun { service } => {
                let svc = svc_ops::get_service(cfg, service)?;
                let script = crate::backup::run_script(&svc);
                let item = host_shell_item_for(
                    cfg,
                    shell_item(&format!("backup run ({service})"), &script, "."),
                );
                Ok(exec::run_steps(item, HashMap::new(), tx.clone(), eid.to_string()).await)
            }

            ExecVerb::BackupForget { service } => {
                let svc = svc_ops::get_service(cfg, service)?;
                let bin = self.restic_bin(cfg).await?;
                let script = crate::backup::forget_script(cfg, &svc, &bin);
                let item = host_shell_item_for(
                    cfg,
                    shell_item(&format!("backup forget ({service})"), &script, "."),
                );
                Ok(exec::run_steps(item, HashMap::new(), tx.clone(), eid.to_string()).await)
            }
            ExecVerb::BackupRestore {
                service,
                snapshot,
                target_dir,
                include,
            } => {
                if !snapshot
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                {
                    bail!("invalid snapshot id");
                }
                let target_ok = svc_ops::valid_rel_path(target_dir)
                    || (Path::new(target_dir).is_absolute() && !target_dir.contains(".."));
                if !target_ok {
                    bail!("invalid target dir");
                }
                let svc = svc_ops::get_service(cfg, service)?;
                let bin = self.restic_bin(cfg).await?;
                let script = crate::backup::restore_script(
                    cfg,
                    &svc,
                    &bin,
                    snapshot,
                    target_dir,
                    include.as_deref().unwrap_or(&[]),
                )?;
                let item = host_shell_item_for(
                    cfg,
                    shell_item(&format!("backup restore ({service})"), &script, "."),
                );
                Ok(exec::run_steps(item, HashMap::new(), tx.clone(), eid.to_string()).await)
            }
            ExecVerb::ServiceCreate {
                name,
                compose,
                description,
                template_id,
                created_by,
                create_unit,
                enable,
                start,
            } => {
                crate::compose::parse_check(compose)?;
                // caller's per-user policy + restrictions, then the floor
                if let Some(p) = crate::api::services::effective_policy_for_user(cfg, user) {
                    let base = Path::new(&cfg.paths.services_root).join(name);
                    let violations = crate::policy::validate_compose_in(compose, &p, Some(&base));
                    if !violations.is_empty() {
                        let msg = violations
                            .iter()
                            .map(|v| format!("{}: {}", v.path, v.message))
                            .collect::<Vec<_>>()
                            .join("; ");
                        bail!("compose policy violations: {msg}");
                    }
                }
                // prospective service dir — relative binds resolve there
                let base = Path::new(&cfg.paths.services_root).join(name);
                self.enforce_policy_floor(cfg, compose, Some(&base))?;
                let dir = svc_ops::create_service_dir(cfg, name)?;
                crate::compose::write_compose(&dir.join(&cfg.paths.compose_file), compose)?;
                svc_ops::save_meta(
                    &dir,
                    &crate::config::ServiceMeta {
                        description: description.clone(),
                        created_by: Some(created_by.clone()),
                        template: template_id.clone(),
                        ..Default::default()
                    },
                )?;
                let _ = tx
                    .send(ServerMessage::LogOutput {
                        id: eid.to_string(),
                        text: format!("created {name}\n"),
                        stream: "stdout".into(),
                    })
                    .await;
                if *create_unit {
                    let svc = svc_ops::get_service(cfg, name)?;
                    let unit = crate::systemd::render_unit_for(cfg, &self.host, &svc).await?;
                    crate::systemd::write_unit(cfg, &self.host, &svc, &unit).await?;
                    let uname = format!("{}.service", svc.name);
                    let mut script = "systemctl daemon-reload".to_string();
                    if *enable {
                        script += &format!(" && systemctl enable {}", sq(&uname));
                    }
                    if *start {
                        script += &format!(" && systemctl start {}", sq(&uname));
                    }
                    let item = host_shell_item_for(
                        cfg,
                        shell_item(&format!("unit setup ({name})"), &script, "."),
                    );
                    exec::run_steps(item, HashMap::new(), tx.clone(), eid.to_string()).await;
                }
                Ok(true)
            }
            ExecVerb::ServiceDelete {
                name,
                down,
                keep_dir,
            } => {
                let svc = svc_ops::get_service(cfg, name)?;
                let mut script = String::new();
                if *down {
                    let (prog, argv) = compose_argv(&cfg.docker.compose_command, &[]);
                    // best-effort: an invalid compose file must not block deletion
                    script += &format!(
                        "cd {} && {} {} down || true; ",
                        sq(&svc.dir.to_string_lossy()),
                        prog,
                        argv.join(" ")
                    );
                }
                let uname = format!("{}.service", svc.name);
                let unit_path = crate::systemd::unit_path(cfg, name);
                if unit_path.exists() {
                    script += &format!(
                        "systemctl disable --now {} >/dev/null 2>&1; rm -f {}; systemctl daemon-reload; ",
                        sq(&uname),
                        sq(&unit_path.to_string_lossy())
                    );
                }
                if !keep_dir {
                    script += &format!("rm -rf -- {}", sq(&svc.dir.to_string_lossy()));
                }
                let item =
                    host_shell_item_for(cfg, shell_item(&format!("delete ({name})"), &script, "."));
                Ok(exec::run_steps(item, HashMap::new(), tx.clone(), eid.to_string()).await)
            }
            ExecVerb::ContainerLogs {
                id,
                tail,
                since,
                follow,
            } => {
                let mut stream = self
                    .docker
                    .logs(id, *tail as usize, *since, *follow)
                    .await?;
                use futures::StreamExt;
                while let Some(line) = stream.next().await {
                    match line {
                        Ok(l) => {
                            let _ = tx
                                .send(ServerMessage::LogOutput {
                                    id: eid.to_string(),
                                    text: format!("{}\n", l.text),
                                    stream: l.stream,
                                })
                                .await;
                        }
                        Err(e) => {
                            let _ = tx
                                .send(ServerMessage::LogOutput {
                                    id: eid.to_string(),
                                    text: format!("log stream error: {e}\n"),
                                    stream: "stderr".into(),
                                })
                                .await;
                            break;
                        }
                    }
                }
                Ok(true)
            }
            ExecVerb::ContainerExec { container, command } => {
                // Authorization ran in precheck_exec (feature + project
                // label -> service access / admin for unmanaged).
                let (mut stream, exec_id) = self.docker.exec_stream(container, command).await?;
                use futures::StreamExt;
                while let Some(line) = stream.next().await {
                    match line {
                        Ok(l) => {
                            let _ = tx
                                .send(ServerMessage::LogOutput {
                                    id: eid.to_string(),
                                    text: l.text,
                                    stream: l.stream,
                                })
                                .await;
                        }
                        Err(e) => {
                            let _ = tx
                                .send(ServerMessage::LogOutput {
                                    id: eid.to_string(),
                                    text: format!("exec stream error: {e}\n"),
                                    stream: "stderr".into(),
                                })
                                .await;
                            return Ok(false);
                        }
                    }
                }
                let code = self.docker.exec_exit_code(&exec_id).await?;
                if code != 0 {
                    let _ = tx
                        .send(ServerMessage::LogOutput {
                            id: eid.to_string(),
                            text: format!("(exited with code {code})\n"),
                            stream: "stderr".into(),
                        })
                        .await;
                }
                Ok(code == 0)
            }
            ExecVerb::ImageLoad { path } => {
                // Authorization ran in precheck_exec (push_images feature).
                let item = host_shell_item_for(
                    cfg,
                    shell_item("docker load", &format!("docker load -i {}", sq(path)), "."),
                );
                Ok(exec::run_steps(item, HashMap::new(), tx.clone(), eid.to_string()).await)
            }
        }
    }

    /// docker compose action as argv (no shell) with work_dir = service dir.
    fn compose_item(&self, cfg: &AppConfig, svc: &Service, op: &ComposeOp) -> Result<CommandItem> {
        let compose_file = svc
            .compose_path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();
        let (prog, base) = compose_argv(&cfg.docker.compose_command, &[]);
        let mk = |extra: &[&str]| {
            let mut a = base.clone();
            a.push("-f".into());
            a.push(compose_file.clone());
            a.extend(extra.iter().map(|s| s.to_string()));
            CommandDefinition {
                program: prog.clone(),
                args: a.iter().map(|s| arg(s)).collect(),
            }
        };
        let (title, seq) = match op {
            ComposeOp::Pull => ("pull", vec![mk(&["pull"])]),
            ComposeOp::Up => ("up", vec![mk(&["up", "-d"])]),
            ComposeOp::Down => ("down", vec![mk(&["down"])]),
            ComposeOp::Restart => ("restart", vec![mk(&["restart"])]),
            ComposeOp::Start => ("start", vec![mk(&["start"])]),
            ComposeOp::Stop => ("stop", vec![mk(&["stop"])]),
            ComposeOp::Update => (
                "update",
                vec![mk(&["pull"]), mk(&["up", "-d", "--remove-orphans"])],
            ),
            ComposeOp::UpRecreate => ("recreate", vec![mk(&["up", "-d", "--remove-orphans"])]),
            ComposeOp::Enable | ComposeOp::Disable => {
                let op_name = if matches!(op, ComposeOp::Enable) {
                    "enable"
                } else {
                    "disable"
                };
                let uname = format!("{}.service", svc.name);
                let seq = host_wrap(cfg, vec![cmd("systemctl", &[op_name, &uname])]);
                (
                    Box::leak(format!("systemctl {op_name}").into_boxed_str()) as &'static str,
                    seq,
                )
            }
        };
        Ok(CommandItem {
            title: format!("{title} ({})", svc.name),
            description: String::new(),
            work_dir: svc.dir.to_string_lossy().to_string(),
            icon: String::new(),
            parameters: vec![],
            button_label: "Run".into(),
            command_sequence: seq,
            required_role: None,
            on_host: false,
        })
    }

    async fn systemd_command_item(
        &self,
        cfg: &AppConfig,
        target: &SystemdTarget,
        command_id: &str,
    ) -> Result<CommandItem> {
        let groups = &cfg.systemd.groups;
        match target {
            SystemdTarget::Group(gid) => {
                let g = groups
                    .iter()
                    .find(|g| g.id == *gid)
                    .ok_or_else(|| anyhow!("unknown group"))?;
                let cmddef = g
                    .custom_commands
                    .iter()
                    .find(|c| c.id() == command_id)
                    .ok_or_else(|| anyhow!("unknown command id"))?;
                let units = crate::systemd::list_units_matching(&self.host, &g.unit_regex).await?;
                let mut seq = vec![];
                for u in units {
                    seq.extend(self.systemd_cmd_steps(cfg, g, &u.unit, command_id)?);
                }
                let _ = cmddef;
                Ok(CommandItem {
                    title: format!("group command ({gid})"),
                    description: String::new(),
                    work_dir: ".".into(),
                    icon: String::new(),
                    parameters: vec![],
                    button_label: "Run".into(),
                    command_sequence: seq,
                    required_role: None,
                    on_host: true,
                })
            }
            SystemdTarget::Unit(unit) => {
                check_unit_name(unit)?;
                let g = groups
                    .iter()
                    .find(|g| {
                        regex::Regex::new(&g.unit_regex)
                            .map(|r| r.is_match(unit))
                            .unwrap_or(false)
                    })
                    .ok_or_else(|| anyhow!("unit matches no group"))?;
                let seq = self.systemd_cmd_steps(cfg, g, unit, command_id)?;
                Ok(CommandItem {
                    title: format!("unit command ({unit})"),
                    description: String::new(),
                    work_dir: ".".into(),
                    icon: String::new(),
                    parameters: vec![],
                    button_label: "Run".into(),
                    command_sequence: seq,
                    required_role: None,
                    on_host: true,
                })
            }
        }
    }

    /// Build the per-unit steps for a systemd custom command — argv-only.
    fn systemd_cmd_steps(
        &self,
        cfg: &AppConfig,
        g: &crate::config::SystemdGroup,
        unit: &str,
        command_id: &str,
    ) -> Result<Vec<CommandDefinition>> {
        use crate::config::SystemdCommand;
        let cmddef = g
            .custom_commands
            .iter()
            .find(|c| c.id() == command_id)
            .ok_or_else(|| anyhow!("unknown command id"))?;
        check_unit_name(unit)?;
        let service = unit.strip_suffix(".service").unwrap_or(unit);
        let service = service.to_string();
        let work_dir = cmddef
            .work_dir_template()
            .or(g.compose_dir_template.as_deref())
            .unwrap_or(".")
            .replace("{unit}", unit)
            .replace("{service}", &service);
        let subst = |s: &str| s.replace("${unit}", unit).replace("${service}", &service);
        let compose = cfg.docker.compose_command.join(" ");
        let steps: Vec<CommandDefinition> = match cmddef {
            SystemdCommand::DockerComposePull { .. } => vec![cmd(
                "bash",
                &["-c", &format!("cd {} && {compose} pull", sq(&work_dir))],
            )],
            SystemdCommand::DockerComposePullRestart { .. } => vec![
                cmd(
                    "bash",
                    &["-c", &format!("cd {} && {compose} pull", sq(&work_dir))],
                ),
                cmd("systemctl", &["restart", unit]),
            ],
            SystemdCommand::Shell { program, args, .. } => {
                let prog = subst(program);
                let argv: Vec<String> = args.iter().map(|a| subst(a)).collect();
                vec![CommandDefinition {
                    program: prog,
                    args: argv.iter().map(|s| arg(s)).collect(),
                }]
            }
        };
        Ok(host_wrap(cfg, steps))
    }

    async fn systemd_restart_item(
        &self,
        cfg: &AppConfig,
        target: &SystemdTarget,
    ) -> Result<CommandItem> {
        match target {
            SystemdTarget::Unit(unit) => {
                check_unit_name(unit)?;
                Ok(CommandItem {
                    title: format!("restart {unit}"),
                    description: String::new(),
                    work_dir: ".".into(),
                    icon: String::new(),
                    parameters: vec![],
                    button_label: "Run".into(),
                    command_sequence: host_wrap(cfg, vec![cmd("systemctl", &["restart", unit])]),
                    required_role: None,
                    on_host: true,
                })
            }
            SystemdTarget::Group(gid) => {
                let g = cfg
                    .systemd
                    .groups
                    .iter()
                    .find(|g| g.id == *gid)
                    .ok_or_else(|| anyhow!("unknown group"))?;
                let units = crate::systemd::list_units_matching(&self.host, &g.unit_regex).await?;
                let seq: Vec<CommandDefinition> = units
                    .iter()
                    .map(|u| cmd("systemctl", &["restart", &u.unit]))
                    .collect();
                Ok(CommandItem {
                    title: format!("restart group {gid}"),
                    description: String::new(),
                    work_dir: ".".into(),
                    icon: String::new(),
                    parameters: vec![],
                    button_label: "Run".into(),
                    command_sequence: host_wrap(cfg, seq),
                    required_role: None,
                    on_host: true,
                })
            }
        }
    }
}

impl AgentCore {
    /// Compose content floor: the agent always enforces the configured
    /// floor policy (`security.policy_floor`, defaulting to
    /// `security.default_policy`) on compose writes/creates, so a hostile
    /// server cannot skip policy checks entirely. Per-user stricter
    /// policies remain a server-side concern. `base_dir` is the directory
    /// containing the compose file, used to resolve relative bind sources.
    fn enforce_policy_floor(
        &self,
        cfg: &AppConfig,
        compose: &str,
        base_dir: Option<&std::path::Path>,
    ) -> Result<()> {
        let floor = cfg
            .security
            .policy_floor
            .as_deref()
            .unwrap_or(&cfg.security.default_policy);
        if let Some(policy) = crate::api::services::resolve_policy(cfg, Some(floor)) {
            let violations = crate::policy::validate_compose_in(compose, &policy, base_dir);
            if !violations.is_empty() {
                bail!("compose violates default policy: {violations:?}");
            }
        }
        Ok(())
    }

    async fn restic_bin(&self, cfg: &AppConfig) -> Result<String> {
        Ok(match cfg.backup.restic_binary.as_str() {
            "auto" => self
                .host
                .which("restic")
                .await?
                .unwrap_or_else(|| "restic".into()),
            b => b.to_string(),
        })
    }
}

fn intersect<F: Fn(&TokenScope) -> &Option<Vec<String>>>(
    parent: &Option<TokenScope>,
    f: F,
    req: &Option<Vec<String>>,
) -> Option<Vec<String>> {
    match (parent.as_ref().map(f), req) {
        (Some(Some(p)), Some(r)) => Some(p.iter().filter(|s| r.contains(s)).cloned().collect()),
        (Some(Some(p)), None) => Some(p.clone()),
        (None, r) => r.clone(),
        (Some(None), r) => r.clone(),
    }
}

/// Agent-side unit name validation (independent of server checks).
fn check_unit_name(unit: &str) -> Result<()> {
    if unit.is_empty()
        || unit.len() > 256
        || unit.contains("..")
        || unit.starts_with('.')
        || !unit
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@'))
    {
        bail!("invalid unit name");
    }
    Ok(())
}

/// Secret-bearing notifier fields — on update, values left empty or set to
/// "***" keep the stored value (the UI never sends real secrets back).
const NOTIFIER_SECRET_KEYS: &[&str] = &[
    "url",
    "url_env",
    "bot_token",
    "bot_token_env",
    "username",
    "password",
    "password_env",
    "username_env",
    "headers",
];

/// GitOps secret fields — same "***"/empty-means-keep semantics as
/// notifier secrets.
const GITOPS_SECRET_KEYS: &[&str] = &["token", "webhook_secret"];

/// Apply a UI patch to the global `backup:` config section. Only the
/// whitelisted keys are touched — repository paths, extra_env and other
/// sensitive/advanced fields stay file-managed. Unknown keys fail closed.
fn apply_backup_global_patch(
    b: &mut crate::config::BackupConfig,
    patch: &serde_json::Value,
) -> Result<()> {
    let obj = patch
        .as_object()
        .ok_or_else(|| anyhow!("backup patch must be an object"))?;
    for key in obj.keys() {
        if !matches!(
            key.as_str(),
            "enabled" | "scheduler" | "on_calendar" | "excludes" | "retention"
        ) {
            bail!("backup patch: unknown key '{key}'");
        }
    }
    if let Some(v) = obj.get("enabled") {
        b.enabled = v
            .as_bool()
            .ok_or_else(|| anyhow!("backup.enabled must be bool"))?;
    }
    if let Some(v) = obj.get("scheduler") {
        b.scheduler = serde_json::from_value(v.clone())
            .map_err(|_| anyhow!("backup.scheduler must be systemd_timer|internal|none"))?;
    }
    if let Some(v) = obj.get("on_calendar") {
        let s = v
            .as_str()
            .ok_or_else(|| anyhow!("backup.on_calendar must be a string"))?;
        if s.is_empty() || s.len() > 100 || s.contains('\n') {
            bail!("invalid on_calendar");
        }
        b.on_calendar = s.to_string();
    }
    if let Some(v) = obj.get("excludes") {
        b.excludes = serde_json::from_value(v.clone())
            .map_err(|_| anyhow!("backup.excludes must be a list of strings"))?;
    }
    if let Some(v) = obj.get("retention") {
        b.retention = if v.is_null() {
            None
        } else {
            Some(
                serde_json::from_value(v.clone())
                    .map_err(|_| anyhow!("invalid retention policy"))?,
            )
        };
    }
    Ok(())
}

fn merge_gitops_secrets(new: &mut serde_json::Value, old: Option<&serde_json::Value>) {
    let Some(old) = old else { return };
    for key in GITOPS_SECRET_KEYS {
        let keep = match new.get(*key) {
            None | Some(serde_json::Value::Null) => true,
            Some(serde_json::Value::String(s)) => s.is_empty() || s == "***",
            _ => false,
        };
        if keep {
            match old.get(*key) {
                Some(v) if !v.is_null() => {
                    new.as_object_mut()
                        .unwrap()
                        .insert(key.to_string(), v.clone());
                }
                _ => {
                    new.as_object_mut().unwrap().remove(*key);
                }
            }
        }
    }
}

fn merge_notifier_secrets(new: &mut serde_json::Value, old: Option<&serde_json::Value>) {
    let Some(old) = old else { return };
    for key in NOTIFIER_SECRET_KEYS {
        let keep = match new.get(*key) {
            None | Some(serde_json::Value::Null) => true,
            Some(serde_json::Value::String(s)) => s.is_empty() || s == "***",
            _ => false,
        };
        if keep {
            match old.get(*key) {
                Some(v) if !v.is_null() => {
                    new.as_object_mut()
                        .unwrap()
                        .insert(key.to_string(), v.clone());
                }
                _ => {
                    new.as_object_mut().unwrap().remove(*key);
                }
            }
        }
    }
}

/// Operation category for a [`SyncVerb`], used by token `ops` scopes.
/// `None` means the verb is outside the scoped-operation surface.
fn sync_verb_op(v: &SyncVerb) -> Option<&'static str> {
    use SyncVerb::*;
    Some(match v {
        ServicesList
        | ServiceGet { .. }
        | FileNode { .. }
        | FileStat { .. }
        | GitRepos { .. }
        | GitStatus { .. }
        | GitLog { .. }
        | GitBranches { .. }
        | GitDiff { .. }
        | ProjectContainers { .. }
        | ContainerHealth { .. }
        | UnitFileRead { .. }
        | UnitCheck { .. }
        | UnitState { .. }
        | UnitPathExists { .. }
        | ComposeRead { .. }
        | MonitoringGet { .. }
        | BackupGet { .. }
        | BackupCheck { .. }
        | BackupSnapshots { .. }
        | BackupLs { .. }
        | BackupGlobalGet
        | GitSyncStatus
        | UnitRender { .. }
        | MonitorStatusAll
        | MonitorEvents
        | ResolveComposeBin => "read",
        ContainerLogsCollect { .. } => "logs",
        FileWrite { .. }
        | FileMkdir { .. }
        | FileRename { .. }
        | FileCopy { .. }
        | FileDelete { .. } => "files",
        ComposeWrite { .. } | ComposeSync { .. } => "compose",
        MetaWrite { .. } => "meta",
        MonitoringPut { .. } | NotifierMut { .. } | NotifyTest { .. } => "monitoring",
        BackupPut { .. } | BackupGlobalPut { .. } | BackupProvision { .. } => "backup",
        GitOpsPut { .. } | GitSyncRun | GitSyncPush => "git",
        ListUnits { .. } | Journal { .. } => "units",
        SectionsMut { .. } | ExecCancel { .. } => "exec",
    })
}

/// Operation category for an [`ExecVerb`].
fn exec_verb_op(v: &ExecVerb) -> Option<&'static str> {
    use ExecVerb::*;
    Some(match v {
        Compose { .. } => "compose",
        SectionItem { .. } | ContainerExec { .. } => "exec",
        SystemdCommand { .. } | SystemdRestart { .. } | UnitRegen { .. } | UnitWrite { .. } => {
            "units"
        }
        GitClone { .. } | GitOp { .. } => "git",
        BackupRun { .. } | BackupForget { .. } | BackupRestore { .. } => "backup",
        ServiceCreate { .. } | ServiceDelete { .. } => "services",
        ContainerLogs { .. } => "logs",
        ImageLoad { .. } => "registry",
    })
}
