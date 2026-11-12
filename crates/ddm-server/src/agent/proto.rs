//! Wire protocol between the unprivileged `ddm-server` process and the
//! privileged `ddm-agent` process (or the in-process `LocalAgent`).
//!
//! One JSON value per line over a unix domain socket. Requests carrying a
//! `token` have it verified by the agent (signature + token generation) and
//! recorded in the agent's justification log before the op runs.

use crate::config::{ServiceBackupConfig, ServiceMeta, ServiceMonitoringConfig};
use crate::users::{AccessRule, User};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComposeOp {
    Pull,
    Up,
    Down,
    Restart,
    Start,
    Stop,
    Update,
    Enable,
    Disable,
    /// up -d --remove-orphans (compose recreate)
    UpRecreate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SystemdTarget {
    Group(String),
    Unit(String),
}

/// Operations that produce streamed execution output (ServerMessage frames).
/// Every variant is typed — the agent builds the actual command/script
/// internally from config, so no shell text crosses the boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExecVerb {
    /// docker compose action on a managed service.
    Compose { service: String, op: ComposeOp },
    /// A configured command item from `commands:` sections.
    SectionItem {
        section: usize,
        item: usize,
        params: HashMap<String, String>,
    },
    /// A custom command on a systemd unit or group.
    SystemdCommand {
        target: SystemdTarget,
        command_id: String,
    },
    /// Restart a systemd unit or all units in a group.
    SystemdRestart { target: SystemdTarget },
    /// Write the rendered unit file, daemon-reload, optionally enable/start.
    UnitRegen {
        service: String,
        enable: bool,
        start: bool,
    },
    /// Write a user-supplied unit file (validated), daemon-reload.
    UnitWrite {
        service: String,
        content: String,
        enable: bool,
        restart: bool,
    },
    /// Clone a git repository into a service dir.
    GitClone {
        service: String,
        url: String,
        path: String,
        branch: Option<String>,
    },
    /// fetch/pull/checkout/reset/stash on an existing repo.
    GitOp {
        service: String,
        path: String,
        op: String,
        git_ref: Option<String>,
    },
    /// Run a backup now.
    BackupRun { service: String },
    /// restic forget+prune according to retention.
    BackupForget { service: String },
    /// restic restore of a snapshot into a target dir.
    BackupRestore {
        service: String,
        snapshot: String,
        target_dir: String,
        /// Optional `restic --include` patterns — empty/absent = full restore.
        #[serde(default)]
        include: Option<Vec<String>>,
    },
    /// Create service dir, write compose file, write meta, optional unit+start.
    ServiceCreate {
        name: String,
        compose: String,
        description: String,
        template_id: Option<String>,
        created_by: String,
        create_unit: bool,
        enable: bool,
        start: bool,
    },
    /// compose down (unless keep) + remove dir + unit.
    ServiceDelete {
        name: String,
        down: bool,
        keep_dir: bool,
    },
    /// Container logs, streamed as LogOutput lines.
    ContainerLogs {
        id: String,
        tail: u64,
        since: Option<i64>,
        follow: bool,
    },
    /// `docker exec` inside a container, streamed as LogOutput lines.
    /// The agent resolves the owning service itself from the container's
    /// compose project label — the server cannot relabel a foreign
    /// container as belonging to a service the caller may access.
    ContainerExec {
        container: String,
        command: Vec<String>,
    },
    /// `docker load -i <path>` — used by the OCI registry endpoint to
    /// import a pushed image tar into the local daemon.
    ImageLoad { path: String },
}

/// Operations with a single JSON response. All privileged filesystem,
/// docker, systemd, git and secret-touching reads/writes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncVerb {
    ServicesList,
    ServiceGet {
        name: String,
    },
    FileNode {
        service: String,
        path: String,
    },
    FileWrite {
        service: String,
        path: String,
        content: String,
    },
    FileMkdir {
        service: String,
        path: String,
    },
    FileRename {
        service: String,
        from: String,
        to: String,
    },
    /// Copy a file or directory tree inside a service dir (WebDAV COPY).
    FileCopy {
        service: String,
        from: String,
        to: String,
    },
    FileDelete {
        service: String,
        path: String,
    },
    GitRepos {
        service: String,
    },
    GitStatus {
        service: String,
        path: String,
    },
    GitLog {
        service: String,
        path: String,
        n: usize,
    },
    GitBranches {
        service: String,
        path: String,
    },
    /// Working-tree diff vs HEAD, or a ref range when `base` is given
    /// (`<base>..HEAD` — e.g. a branch or `HEAD~3` for a commit range).
    GitDiff {
        service: String,
        path: String,
        #[serde(default)]
        base: Option<String>,
    },
    /// Request cancellation of a running execution hosted by this agent
    /// (fire-and-forget; the run loop checks the flag between steps and
    /// SIGKILLs the current child).
    ExecCancel {
        execution_id: String,
    },
    ProjectContainers {
        service: String,
    },
    ContainerHealth {
        id: String,
    },
    UnitFileRead {
        service: String,
    },
    UnitCheck {
        service: String,
    },
    UnitState {
        unit: String,
    },
    UnitPathExists {
        unit: String,
    },
    ListUnits {
        regex: String,
    },
    Journal {
        unit: String,
        lines: usize,
    },
    /// Admin: mutate monitoring.notifiers in config.yaml (agent owns the file).
    NotifierMut {
        op: NotifierMut,
    },
    /// Admin: mutate config sections (commands) in config.yaml.
    SectionsMut {
        op: SectionMutOp,
    },
    /// Admin: replace the gitops config. Secret fields (token,
    /// webhook_secret) left empty or "***" keep their stored values —
    /// the server only ever sees the redacted config.
    GitOpsPut {
        cfg: serde_json::Value,
    },
    BackupCheck {
        service: String,
    },
    BackupSnapshots {
        service: String,
    },
    /// `restic ls <snapshot>` — file listing inside a snapshot.
    BackupLs {
        service: String,
        snapshot: String,
        /// Optional subdir inside the snapshot to list.
        #[serde(default)]
        path: Option<String>,
    },
    MetaWrite {
        service: String,
        meta: ServiceMeta,
    },
    ComposeRead {
        service: String,
    },
    ComposeWrite {
        service: String,
        content: String,
    },
    MonitoringGet {
        service: String,
    },
    MonitoringPut {
        service: String,
        cfg: ServiceMonitoringConfig,
    },
    BackupGet {
        service: String,
    },
    BackupPut {
        service: String,
        cfg: ServiceBackupConfig,
    },
    /// Admin: read the global backup section (config.yaml `backup:`) —
    /// only the UI-editable subset is returned (no extra_env secrets).
    BackupGlobalGet,
    /// Admin: patch the global backup section. Only the fields present
    /// in `patch` are touched; unknown keys are rejected.
    BackupGlobalPut {
        patch: serde_json::Value,
    },
    ResolveComposeBin,
    GitSyncStatus,
    GitSyncRun,
    GitSyncPush,
    /// Render the systemd unit for a service (agent resolves compose binary).
    UnitRender {
        service: String,
    },
    /// docker compose <action> run synchronously, output returned (monitor).
    ComposeSync {
        service: String,
        action: String,
    },
    /// Container logs collected non-followed; returns Vec<LogLine>.
    ContainerLogsCollect {
        id: String,
        tail: usize,
        since: Option<i64>,
    },
    /// Provision restic repo + write password file + install units.
    BackupProvision {
        service: String,
    },
    /// Stat one path inside a service dir (kind/size/mtime).
    FileStat {
        service: String,
        path: String,
    },
    /// Monitor states for all services (agent-side monitor).
    MonitorStatusAll,
    /// Monitor alert history.
    MonitorEvents,
    /// Send a test notification through a configured notifier (agent holds secrets).
    NotifyTest {
        id: String,
        message: String,
    },
}

/// Crypto and credential ops. These never require a justification token —
/// they *are* the trust root. `Authenticate` issues a token only on a
/// successful (peppered) password check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CryptoOp {
    Authenticate {
        name: String,
        password: String,
        /// Client IP for per-source throttling (added to the per-name limit).
        #[serde(default)]
        ip: Option<String>,
        /// Client user-agent — recorded on the session record so users can
        /// tell their sessions apart in the token list.
        #[serde(default)]
        ua: Option<String>,
    },
    /// Mint a (possibly scoped) child token. Parent verified here.
    Mint {
        token: String,
        ttl_minutes: Option<i64>,
        services: Option<Vec<String>>,
        actions: Option<Vec<String>>,
        ops: Option<Vec<String>>,
        name: Option<String>,
    },
    Verify {
        token: String,
    },
    /// Admin: return all users (the agent owns users.yaml).
    UsersList {
        token: String,
    },
    /// Bump global token generation (logout-all). Requires admin claim.
    Rotate {
        token: String,
    },
    /// Verify GitHub/GitLab webhook secret for the given raw body.
    VerifyWebhook {
        sig256: Option<String>,
        gitlab_token: Option<String>,
        body: Vec<u8>,
    },
    /// Verify the webhook secret AND trigger a git sync atomically —
    /// used by the public webhook endpoint which has no user token.
    WebhookSync {
        sig256: Option<String>,
        gitlab_token: Option<String>,
        body: Vec<u8>,
    },
    /// Set a user's password — caller rules enforced agent-side.
    SetPassword {
        token: String,
        name: String,
        password: String,
        current_password: Option<String>,
    },
    /// User management ops — admin claim required, enforced agent-side.
    UserMutate {
        token: String,
        op: UserMut,
    },
    /// List minted (revocable) tokens: admins see all, others only their
    /// own (`sub` match). Session tokens are not registered and never
    /// appear here.
    TokensList {
        token: String,
    },
    /// Revoke a minted token by jti. Admins may revoke any; a user may
    /// revoke their own tokens but only from an unscoped session token.
    RevokeToken {
        token: String,
        jti: String,
    },
    /// Unauthenticated bootstrap check: true while users.yaml has zero
    /// users. Once any user exists this is permanently false.
    SetupNeeded,
    /// Unauthenticated first-admin creation — only succeeds while the
    /// user store is empty; afterwards it always fails. This is the
    /// sole unauthenticated write path and it closes itself.
    SetupCreate {
        name: String,
        password: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UserMut {
    Create {
        name: String,
        password: String,
        roles: Vec<String>,
        access: Vec<AccessRule>,
        features: Option<crate::users::UserFeatures>,
        compose_policy: Option<String>,
        restrictions: Option<crate::users::UserRestrictions>,
    },
    Update {
        name: String,
        roles: Option<Vec<String>>,
        features: Option<crate::users::UserFeatures>,
        compose_policy: Option<Option<String>>,
        restrictions: Option<crate::users::UserRestrictions>,
    },
    Delete {
        name: String,
    },
    SetAccess {
        name: String,
        access: Vec<AccessRule>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AgentRequest {
    Crypto {
        op: CryptoOp,
    },
    Call {
        verb: SyncVerb,
        token: String,
    },
    /// Subscribe to monitor events — streams `EventMessage` lines.
    /// Requires a valid justification token, verified before subscribing.
    Watch {
        token: String,
    },
    Exec {
        verb: ExecVerb,
        /// Server-assigned execution id; frames stream back.
        eid: String,
        title: String,
        token: String,
        service: Option<String>,
    },
    /// Stream a file into a service dir. After this request line the server
    /// writes exactly `len` raw bytes and half-closes. The agent authorizes
    /// first and answers with a JSON line before the byte phase begins, so a
    /// denied write never accepts payload.
    FilePut {
        service: String,
        path: String,
        len: u64,
        token: String,
    },
    /// Stream a file (or a byte range) out of a service dir. The agent
    /// authorizes, answers with `{ "size": n, "sent": m }` and then writes
    /// exactly `m` raw bytes.
    FileGet {
        service: String,
        path: String,
        offset: u64,
        len: u64,
        token: String,
    },
}

/// Metadata for one path inside a service dir — what a WebDAV PROPFIND or a
/// conditional request needs, without reading any content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMeta {
    /// "file" | "dir" | "symlink" | "other"
    pub kind: String,
    pub size: u64,
    /// Unix seconds.
    pub mtime: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentError {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AgentResponse {
    /// Single JSON payload.
    Ok {
        data: serde_json::Value,
    },
    Err {
        error: AgentError,
    },
    /// For Exec requests: stream follows as raw ServerMessage JSON lines.
    StreamStart {
        eid: String,
    },
}

/// Result of a successful Authenticate op.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResult {
    pub user: User,
    pub token: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum NotifierMut {
    Add {
        notifier: crate::config::NotifierConfig,
    },
    Update {
        id: String,
        /// Raw JSON body — the agent merges secret fields against the
        /// existing notifier itself (the server holds redacted config and
        /// cannot merge values it never sees).
        patch: serde_json::Value,
    },
    Delete {
        id: String,
    },
}

/// One registered minted token — persisted in `<config_dir>/tokens.json`.
/// Never contains the token itself or any secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRecord {
    pub jti: String,
    /// User the token was minted for (`sub` claim).
    pub user: String,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub iat: chrono::DateTime<chrono::Utc>,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub exp: chrono::DateTime<chrono::Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub services: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actions: Option<Vec<String>>,
    /// Operation-category allowlist (read/files/compose/...) — same
    /// narrowing semantics as `actions`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ops: Option<Vec<String>>,
    #[serde(default)]
    pub revoked: bool,
    /// "session" (login JWT) or "token" (minted for agents/scopes).
    /// Records written before this field existed deserialize as "" —
    /// treat empty as "token".
    #[serde(default)]
    pub kind: String,
    /// Optional human label so tokens are identifiable in the list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "chrono::serde::ts_seconds_option"
    )]
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Client user-agent recorded at login (sessions only), truncated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ua: Option<String>,
}

/// Section (command group) mutations applied to `config.sections`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum SectionMutOp {
    Add {
        section: crate::config::Section,
    },
    Update {
        index: usize,
        section: crate::config::Section,
    },
    Delete {
        index: usize,
    },
    AddItem {
        section: usize,
        item: crate::config::CommandItem,
    },
    UpdateItem {
        section: usize,
        index: usize,
        item: crate::config::CommandItem,
    },
    DeleteItem {
        section: usize,
        index: usize,
    },
}
