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
    BackupCheck {
        service: String,
    },
    BackupSnapshots {
        service: String,
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
    },
    /// Mint a (possibly scoped) child token. Parent verified here.
    Mint {
        token: String,
        ttl_minutes: Option<i64>,
        services: Option<Vec<String>>,
        actions: Option<Vec<String>>,
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
    },
    Update {
        name: String,
        roles: Option<Vec<String>>,
        features: Option<crate::users::UserFeatures>,
        compose_policy: Option<Option<String>>,
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
    Watch,
    Exec {
        verb: ExecVerb,
        /// Server-assigned execution id; frames stream back.
        eid: String,
        title: String,
        token: String,
        service: Option<String>,
    },
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
