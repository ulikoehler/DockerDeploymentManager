use anyhow::{Context, Result};
use notify::{Config as NotifyConfig, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, RwLock};
use tracing::{error, info};

// ---------------------------------------------------------------------------
// Config schema
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub paths: PathsConfig,
    #[serde(default)]
    pub docker: DockerConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub backup: BackupConfig,
    #[serde(default)]
    pub monitoring: MonitoringConfig,
    #[serde(default)]
    pub service_templates: Vec<ServiceTemplate>,
    #[serde(default)]
    pub systemd: SystemdConfig,
    #[serde(default)]
    pub sections: Vec<Section>,
    /// Path to the users file (relative to config dir if not absolute).
    #[serde(default = "default_users_file")]
    pub users_file: String,
}

fn default_users_file() -> String {
    "users.yaml".to_string()
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            paths: PathsConfig::default(),
            docker: DockerConfig::default(),
            logging: LoggingConfig::default(),
            security: SecurityConfig::default(),
            backup: BackupConfig::default(),
            monitoring: MonitoringConfig::default(),
            service_templates: vec![],
            systemd: SystemdConfig::default(),
            sections: vec![],
            users_file: default_users_file(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default = "default_jwt_secret_env")]
    pub jwt_secret_env: String,
    #[serde(default = "default_token_ttl")]
    pub token_ttl_minutes: i64,
    #[serde(default)]
    pub cors_origins: Vec<String>,
    /// Directory containing built web assets (index.html + bundle). Optional.
    #[serde(default)]
    pub web_dir: Option<String>,
}

fn default_listen() -> String {
    "0.0.0.0:8080".to_string()
}
fn default_jwt_secret_env() -> String {
    "DDM_JWT_SECRET".to_string()
}
fn default_token_ttl() -> i64 {
    720
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            jwt_secret_env: default_jwt_secret_env(),
            token_ttl_minutes: default_token_ttl(),
            cors_origins: vec![],
            web_dir: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathsConfig {
    /// Path inside the container where service directories live.
    #[serde(default = "default_services_root")]
    pub services_root: String,
    /// Same directory as seen by the host (used in unit files / backup.sh).
    /// Defaults to services_root (correct when running bare-metal).
    #[serde(default)]
    pub host_services_root: Option<String>,
    #[serde(default = "default_compose_file")]
    pub compose_file: String,
    #[serde(default = "default_host_systemd_dir")]
    pub host_systemd_dir: String,
    #[serde(default)]
    pub host_exec: HostExecKind,
    #[serde(default = "default_nsenter_target")]
    pub nsenter_target: u32,
}

fn default_services_root() -> String {
    "/services".to_string()
}
fn default_compose_file() -> String {
    "docker-compose.yml".to_string()
}
fn default_host_systemd_dir() -> String {
    "/host/systemd".to_string()
}
fn default_nsenter_target() -> u32 {
    1
}

impl Default for PathsConfig {
    fn default() -> Self {
        Self {
            services_root: default_services_root(),
            host_services_root: None,
            compose_file: default_compose_file(),
            host_systemd_dir: default_host_systemd_dir(),
            host_exec: HostExecKind::default(),
            nsenter_target: default_nsenter_target(),
        }
    }
}

impl PathsConfig {
    /// Host-side path of the services root.
    pub fn host_services_root(&self) -> &str {
        self.host_services_root
            .as_deref()
            .unwrap_or(&self.services_root)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum HostExecKind {
    #[default]
    Nsenter,
    Local,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerConfig {
    #[serde(default = "default_docker_socket")]
    pub socket: String,
    /// In-container compose invocation, e.g. ["docker", "compose"].
    #[serde(default = "default_compose_command")]
    pub compose_command: Vec<String>,
}

fn default_docker_socket() -> String {
    "/var/run/docker.sock".to_string()
}
fn default_compose_command() -> Vec<String> {
    vec!["docker".to_string(), "compose".to_string()]
}

impl Default for DockerConfig {
    fn default() -> Self {
        Self {
            socket: default_docker_socket(),
            compose_command: default_compose_command(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_tail")]
    pub default_tail: usize,
    #[serde(default = "default_max_tail")]
    pub max_tail: usize,
    #[serde(default = "default_history")]
    pub history_executions: usize,
}

fn default_tail() -> usize {
    200
}
fn default_max_tail() -> usize {
    5000
}
fn default_history() -> usize {
    200
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            default_tail: default_tail(),
            max_tail: default_max_tail(),
            history_executions: default_history(),
        }
    }
}

// ---------------------------------------------------------------------------
// Security
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Default access decision for users without any matching rule.
    #[serde(default)]
    pub default_access: DefaultAccess,
    /// Name of the policy applied to users without an explicit one.
    #[serde(default = "default_policy_name")]
    pub default_policy: String,
    #[serde(default)]
    pub policies: HashMap<String, ComposePolicy>,
    /// Role required to write raw unit files. Default admin.
    #[serde(default = "default_unit_edit_role")]
    pub unit_edit_requires: String,
}

fn default_policy_name() -> String {
    "strict".to_string()
}
fn default_unit_edit_role() -> String {
    "admin".to_string()
}

impl Default for SecurityConfig {
    fn default() -> Self {
        let mut policies = HashMap::new();
        policies.insert("strict".to_string(), ComposePolicy::strict_defaults());
        policies.insert(
            "relaxed".to_string(),
            ComposePolicy {
                deny_privileged: true,
                deny_host_namespaces: true,
                deny_docker_socket: true,
                ..ComposePolicy::strict_defaults()
            },
        );
        Self {
            default_access: DefaultAccess::default(),
            default_policy: default_policy_name(),
            policies,
            unit_edit_requires: default_unit_edit_role(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum DefaultAccess {
    Allow,
    #[default]
    Deny,
}

/// Rules applied to docker-compose files. `mode: allowlist` on list fields
/// means only listed entries are permitted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComposePolicy {
    #[serde(default = "bool_true")]
    pub deny_privileged: bool,
    #[serde(default = "bool_true")]
    pub deny_host_namespaces: bool,
    #[serde(default = "bool_true")]
    pub deny_docker_socket: bool,
    #[serde(default = "bool_true")]
    pub deny_devices: bool,
    /// cap_add: if mode=allowlist, only entries in `list` allowed;
    /// mode=denylist means entries in `list` are forbidden, rest allowed.
    #[serde(default)]
    pub cap_add: ListRule,
    #[serde(default)]
    pub sysctls: ListRule,
    /// Glob patterns of allowed bind-mount source paths (host side).
    /// Empty list = deny all bind mounts. Supports `**`.
    #[serde(default)]
    pub allowed_bind_sources: Vec<String>,
    /// Glob patterns of forbidden bind-mount container targets.
    #[serde(default)]
    pub deny_bind_targets: Vec<String>,
    /// [min, max] allowed published host ports.
    #[serde(default = "default_port_range")]
    pub allowed_port_range: (u16, u16),
    /// Allowed image registries (prefix match). Empty = any.
    #[serde(default)]
    pub allowed_registries: Vec<String>,
    #[serde(default = "default_max_services")]
    pub max_services_per_compose: usize,
    /// Also deny `user: root` / `user: "0"`.
    #[serde(default)]
    pub deny_root_user: bool,
    /// Deny host userns_mode / cgroup_parent / security_opt overrides.
    #[serde(default = "bool_true")]
    pub deny_isolation_overrides: bool,
}

fn bool_true() -> bool {
    true
}
fn default_port_range() -> (u16, u16) {
    (1024, 65535)
}
fn default_max_services() -> usize {
    20
}

impl ComposePolicy {
    pub fn strict_defaults() -> Self {
        Self {
            deny_privileged: true,
            deny_host_namespaces: true,
            deny_docker_socket: true,
            deny_devices: true,
            cap_add: ListRule::allowlist(vec![]),
            sysctls: ListRule::allowlist(vec![]),
            allowed_bind_sources: vec![],
            deny_bind_targets: vec![
                "/".to_string(),
                "/etc/**".to_string(),
                "/root/**".to_string(),
                "/var/run/**".to_string(),
                "/proc/**".to_string(),
                "/sys/**".to_string(),
            ],
            allowed_port_range: default_port_range(),
            allowed_registries: vec![],
            max_services_per_compose: default_max_services(),
            deny_root_user: false,
            deny_isolation_overrides: true,
        }
    }
}

impl Default for ComposePolicy {
    fn default() -> Self {
        Self::strict_defaults()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ListRule {
    #[serde(default)]
    pub mode: ListRuleMode,
    #[serde(default)]
    pub list: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ListRuleMode {
    #[default]
    Allowlist,
    Denylist,
}

impl ListRule {
    pub fn allowlist(list: Vec<String>) -> Self {
        Self {
            mode: ListRuleMode::Allowlist,
            list,
        }
    }
    /// Returns Some(item) if `item` is not permitted.
    pub fn rejected<'a>(&self, item: &'a str) -> Option<&'a str> {
        let in_list = self.list.iter().any(|e| e == item);
        match self.mode {
            ListRuleMode::Allowlist if !in_list => Some(item),
            ListRuleMode::Denylist if in_list => Some(item),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Backup
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupConfig {
    #[serde(default)]
    pub enabled: bool,
    /// resolved on the host via `which` when "auto".
    #[serde(default = "default_auto")]
    pub restic_binary: String,
    /// Per-service repo = base + service name.
    #[serde(default)]
    pub repository_base: String,
    /// Optional override; {base} and {service} substituted.
    #[serde(default)]
    pub repository_template: Option<String>,
    #[serde(default)]
    pub password_mode: PasswordMode,
    #[serde(default)]
    pub extra_env: HashMap<String, String>,
    #[serde(default)]
    pub excludes: Vec<String>,
    #[serde(default)]
    pub retention: Option<RetentionPolicy>,
    #[serde(default)]
    pub scheduler: BackupScheduler,
    #[serde(default = "default_on_calendar")]
    pub on_calendar: String,
    #[serde(default = "default_backup_unit_prefix")]
    pub unit_prefix: String,
}

fn default_auto() -> String {
    "auto".to_string()
}
fn default_on_calendar() -> String {
    "daily".to_string()
}
fn default_backup_unit_prefix() -> String {
    "ddm-backup".to_string()
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            restic_binary: default_auto(),
            repository_base: String::new(),
            repository_template: None,
            password_mode: PasswordMode::default(),
            extra_env: HashMap::new(),
            excludes: vec![],
            retention: None,
            scheduler: BackupScheduler::default(),
            on_calendar: default_on_calendar(),
            unit_prefix: default_backup_unit_prefix(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum PasswordMode {
    /// .restic_password file inside the service dir (0600).
    #[default]
    PerServiceFile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    #[serde(default)]
    pub keep_last: Option<u32>,
    #[serde(default)]
    pub keep_daily: Option<u32>,
    #[serde(default)]
    pub keep_weekly: Option<u32>,
    #[serde(default)]
    pub keep_monthly: Option<u32>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum BackupScheduler {
    #[default]
    SystemdTimer,
    Internal,
    None,
}

// ---------------------------------------------------------------------------
// Monitoring
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "bool_true")]
    pub allow_auto_actions: bool,
    #[serde(default = "default_check_interval")]
    pub check_interval_secs: u64,
    #[serde(default = "default_state_dir")]
    pub state_dir: String,
    #[serde(default)]
    pub notifiers: Vec<NotifierConfig>,
    #[serde(default)]
    pub defaults: MonitorDefaults,
    #[serde(default)]
    pub rules: Vec<MonitorRule>,
}

fn default_check_interval() -> u64 {
    30
}
fn default_state_dir() -> String {
    "/var/lib/ddm".to_string()
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allow_auto_actions: true,
            check_interval_secs: default_check_interval(),
            state_dir: default_state_dir(),
            notifiers: vec![],
            defaults: MonitorDefaults::default(),
            rules: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NotifierConfig {
    SlackWebhook {
        id: String,
        #[serde(default)]
        url: Option<String>,
        #[serde(default)]
        url_env: Option<String>,
    },
    Telegram {
        id: String,
        #[serde(default)]
        bot_token_env: Option<String>,
        chat_id: String,
    },
    Email {
        id: String,
        smtp_host: String,
        #[serde(default = "default_smtp_port")]
        smtp_port: u16,
        #[serde(default)]
        smtp_tls: SmtpTls,
        #[serde(default)]
        username_env: Option<String>,
        #[serde(default)]
        password_env: Option<String>,
        from: String,
        to: Vec<String>,
    },
    Webhook {
        id: String,
        url: String,
        #[serde(default)]
        headers: HashMap<String, String>,
    },
}

fn default_smtp_port() -> u16 {
    587
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum SmtpTls {
    None,
    #[default]
    Starttls,
    Tls,
}

impl NotifierConfig {
    pub fn id(&self) -> &str {
        match self {
            Self::SlackWebhook { id, .. } => id,
            Self::Telegram { id, .. } => id,
            Self::Email { id, .. } => id,
            Self::Webhook { id, .. } => id,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MonitorDefaults {
    #[serde(default)]
    pub notify: Vec<String>,
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,
    #[serde(default = "default_cooldown")]
    pub cooldown_secs: u64,
}

fn default_failure_threshold() -> u32 {
    3
}
fn default_cooldown() -> u64 {
    300
}

/// A global monitoring rule applied to all services matching `services`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorRule {
    pub services: ServiceMatcher,
    #[serde(default)]
    pub log_alerts: Vec<LogAlertConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceMatcher {
    #[serde(default)]
    pub glob: Option<String>,
    #[serde(default)]
    pub regex: Option<String>,
    #[serde(default)]
    pub exact: Option<String>,
}

// ---------------------------------------------------------------------------
// Service templates
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceTemplate {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub description: String,
    /// Path to a compose file template (supports ${var} substitution with
    /// `vars` defaults; {service}/{dir} also substituted).
    pub compose_template: String,
    #[serde(default)]
    pub create_unit: bool,
    /// Variables that can/must be provided; rendered into the template.
    #[serde(default)]
    pub vars: Vec<TemplateVar>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateVar {
    pub name: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub default: Option<String>,
    #[serde(default)]
    pub placeholder: Option<String>,
}

// ---------------------------------------------------------------------------
// Systemd
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemdConfig {
    /// Optional path to a custom unit template. If absent, the built-in
    /// TechOverflow-style template is used. Substitutions: {service} {dir}
    /// {compose_file} {compose_bin}.
    #[serde(default)]
    pub unit_template: Option<String>,
    /// Compose binary on the host: "auto" | path | "docker compose".
    #[serde(default = "default_auto")]
    pub compose_binary: String,
    #[serde(default = "bool_true")]
    pub daemon_reload_after_change: bool,
    #[serde(default)]
    pub parallel_group_actions: Option<bool>,
    #[serde(default)]
    pub max_group_concurrency: Option<usize>,
    #[serde(default)]
    pub groups: Vec<SystemdGroup>,
}

impl Default for SystemdConfig {
    fn default() -> Self {
        Self {
            unit_template: None,
            compose_binary: default_auto(),
            daemon_reload_after_change: true,
            parallel_group_actions: None,
            max_group_concurrency: None,
            groups: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemdGroup {
    pub id: String,
    pub title: String,
    /// Regex matched against full unit name, e.g. "^my.*\\.service$"
    pub unit_regex: String,
    #[serde(default)]
    pub compose_dir_template: Option<String>,
    #[serde(default)]
    pub parallel_group_actions: Option<bool>,
    #[serde(default)]
    pub max_group_concurrency: Option<usize>,
    #[serde(default)]
    pub custom_commands: Vec<SystemdCommand>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SystemdCommand {
    DockerComposePull {
        id: String,
        label: String,
        #[serde(default)]
        work_dir_template: Option<String>,
    },
    DockerComposePullRestart {
        id: String,
        label: String,
        #[serde(default)]
        work_dir_template: Option<String>,
    },
    Shell {
        id: String,
        label: String,
        program: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        work_dir_template: Option<String>,
    },
}

impl SystemdCommand {
    pub fn id(&self) -> &str {
        match self {
            Self::DockerComposePull { id, .. } => id,
            Self::DockerComposePullRestart { id, .. } => id,
            Self::Shell { id, .. } => id,
        }
    }
    pub fn label(&self) -> &str {
        match self {
            Self::DockerComposePull { label, .. } => label,
            Self::DockerComposePullRestart { label, .. } => label,
            Self::Shell { label, .. } => label,
        }
    }
    pub fn work_dir_template(&self) -> Option<&str> {
        match self {
            Self::DockerComposePull {
                work_dir_template, ..
            } => work_dir_template.as_deref(),
            Self::DockerComposePullRestart {
                work_dir_template, ..
            } => work_dir_template.as_deref(),
            Self::Shell {
                work_dir_template, ..
            } => work_dir_template.as_deref(),
        }
    }
}

// ---------------------------------------------------------------------------
// Generic command sections (parity with NoxecoDeploymentManager)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Section {
    pub title: String,
    #[serde(default)]
    pub collapsed: bool,
    #[serde(default)]
    pub items: Vec<CommandItem>,
    /// Optional role required to see/run items in this section.
    #[serde(default)]
    pub required_role: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandItem {
    pub title: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_work_dir")]
    pub work_dir: String,
    #[serde(default)]
    pub icon: String,
    #[serde(default)]
    pub parameters: Vec<Parameter>,
    #[serde(default = "default_button_label")]
    pub button_label: String,
    pub command_sequence: Vec<CommandDefinition>,
    #[serde(default)]
    pub required_role: Option<String>,
    /// Whether commands run on the host via HostExec (default) or inside
    /// the container.
    #[serde(default = "bool_true")]
    pub on_host: bool,
}

fn default_work_dir() -> String {
    ".".to_string()
}
fn default_button_label() -> String {
    "Run".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Parameter {
    String {
        name: String,
        label: String,
        #[serde(default)]
        required: bool,
        #[serde(default)]
        placeholder: String,
        #[serde(default)]
        validation_regex: Option<String>,
        #[serde(default)]
        help: String,
        #[serde(default)]
        default: Option<String>,
    },
    Boolean {
        name: String,
        label: String,
        #[serde(default)]
        default: bool,
        #[serde(default)]
        help: String,
    },
    Number {
        name: String,
        label: String,
        #[serde(default)]
        required: bool,
        #[serde(default)]
        min: Option<f64>,
        #[serde(default)]
        max: Option<f64>,
        #[serde(default)]
        default: Option<f64>,
        #[serde(default)]
        help: String,
    },
}

impl Parameter {
    pub fn name(&self) -> &str {
        match self {
            Self::String { name, .. } => name,
            Self::Boolean { name, .. } => name,
            Self::Number { name, .. } => name,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandDefinition {
    pub program: String,
    #[serde(default)]
    pub args: Vec<CommandArg>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CommandArg {
    Value {
        value: String,
    },
    Variable {
        name: String,
    },
    Conditional {
        variable: String,
        #[serde(default)]
        true_args: Vec<String>,
        #[serde(default)]
        false_args: Vec<String>,
    },
    Optional {
        flag: String,
        variable: String,
    },
}

// ---------------------------------------------------------------------------
// Per-service meta.yaml (stored next to compose file)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServiceMeta {
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub created_by: Option<String>,
    #[serde(default)]
    pub template: Option<String>,
    #[serde(default)]
    pub backup: Option<ServiceBackupConfig>,
    #[serde(default)]
    pub monitoring: Option<ServiceMonitoringConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceBackupConfig {
    #[serde(default = "bool_true")]
    pub enabled: bool,
    /// Paths relative to the service dir. Defaults to compose file + backup.sh.
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub excludes: Vec<String>,
    #[serde(default)]
    pub stdin_dumps: Vec<StdinDump>,
    #[serde(default = "bool_true")]
    pub schedule_enabled: bool,
}

impl Default for ServiceBackupConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            paths: vec![],
            excludes: vec![],
            stdin_dumps: vec![],
            schedule_enabled: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StdinDump {
    /// Filename inside the repo for the streamed backup.
    pub filename: String,
    /// Compose service to exec into.
    pub service: String,
    /// Command + args; ${VAR} expanded from env_file / service .env.
    pub command: Vec<String>,
    /// Optional env file (e.g. ".env") sourced for ${VAR} expansion.
    #[serde(default)]
    pub env_file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServiceMonitoringConfig {
    #[serde(default)]
    pub health: Option<HealthCheckConfig>,
    #[serde(default)]
    pub log_alerts: Vec<LogAlertConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    #[serde(default = "bool_true")]
    pub enabled: bool,
    #[serde(default)]
    pub kind: HealthCheckKind,
    /// http: URL. tcp: host. Unused for docker_healthcheck/container_running.
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub expect_status: Option<u16>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
    #[serde(default)]
    pub interval_secs: Option<u64>,
    #[serde(default)]
    pub failure_threshold: Option<u32>,
    #[serde(default)]
    pub recovery_threshold: Option<u32>,
    #[serde(default)]
    pub notify: Vec<String>,
    #[serde(default)]
    pub actions: Vec<AutoAction>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum HealthCheckKind {
    #[default]
    DockerHealthcheck,
    Http,
    Tcp,
    ContainerRunning,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogAlertConfig {
    pub id: String,
    pub regex: String,
    #[serde(default)]
    pub exclude_regex: Option<String>,
    /// Compose service filter; "*" = all.
    #[serde(default = "default_star")]
    pub container: String,
    #[serde(default)]
    pub notify: Vec<String>,
    #[serde(default)]
    pub cooldown_secs: Option<u64>,
    #[serde(default)]
    pub max_per_cooldown: Option<u32>,
    #[serde(default)]
    pub context_lines: Option<usize>,
    #[serde(default)]
    pub actions: Vec<AutoAction>,
}

fn default_star() -> String {
    "*".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AutoAction {
    Restart {
        #[serde(default)]
        after_failures: Option<u32>,
        #[serde(default)]
        cooldown_secs: Option<u64>,
        #[serde(default)]
        max_attempts: Option<u32>,
        #[serde(default)]
        window_secs: Option<u64>,
    },
    Stop {
        #[serde(default)]
        cooldown_secs: Option<u64>,
    },
    ExecCommand {
        section_index: usize,
        item_index: usize,
        #[serde(default)]
        cooldown_secs: Option<u64>,
    },
}

// ---------------------------------------------------------------------------
// Loading + hot reload
// ---------------------------------------------------------------------------

/// Load and validate config from a YAML file.
pub fn load_config(path: &Path) -> Result<AppConfig> {
    let f = std::fs::File::open(path)
        .with_context(|| format!("opening config {}", path.display()))?;
    let cfg: AppConfig = serde_yaml::from_reader(f)
        .with_context(|| format!("parsing config {}", path.display()))?;
    validate_config(&cfg)?;
    Ok(cfg)
}

/// Semantic validation that serde can't express.
pub fn validate_config(cfg: &AppConfig) -> Result<()> {
    if !cfg.security.policies.contains_key(&cfg.security.default_policy) {
        anyhow::bail!(
            "security.default_policy '{}' is not defined in security.policies",
            cfg.security.default_policy
        );
    }
    let ids: Vec<&str> = cfg
        .monitoring
        .notifiers
        .iter()
        .map(|n| n.id())
        .collect();
    let mut seen = std::collections::HashSet::new();
    for id in &ids {
        if !seen.insert(*id) {
            anyhow::bail!("duplicate notifier id '{id}'");
        }
    }
    for t in &cfg.service_templates {
        if t.id.is_empty() {
            anyhow::bail!("service template with empty id");
        }
    }
    Ok(())
}

/// Shared config holder with hot-reload broadcast.
#[derive(Clone)]
pub struct SharedConfig {
    inner: Arc<RwLock<AppConfig>>,
    pub changes: broadcast::Sender<Arc<AppConfig>>,
    /// Path of the loaded file (for status reporting).
    path: PathBuf,
    /// Last reload outcome.
    last_reload: Arc<RwLock<ReloadStatus>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReloadStatus {
    pub ok: bool,
    pub error: Option<String>,
    #[serde(with = "chrono::serde::ts_seconds_option")]
    pub at: Option<chrono::DateTime<chrono::Utc>>,
}

impl SharedConfig {
    pub fn new(cfg: AppConfig, path: PathBuf) -> Self {
        let (tx, _) = broadcast::channel(8);
        Self {
            inner: Arc::new(RwLock::new(cfg)),
            changes: tx,
            path,
            last_reload: Arc::new(RwLock::new(ReloadStatus {
                ok: true,
                error: None,
                at: Some(chrono::Utc::now()),
            })),
        }
    }

    pub async fn get(&self) -> Arc<AppConfig> {
        self.inner.read().await.clone().into()
    }

    /// Cheap synchronous snapshot for use inside non-async contexts is not
    /// needed elsewhere; handlers use `get().await`.
    pub async fn reload_status(&self) -> ReloadStatus {
        self.last_reload.read().await.clone()
    }

    /// Spawn a file watcher that hot-reloads the config on change.
    /// Invalid reloads are rejected; the previous config stays live.
    pub fn spawn_watcher(self: &Arc<Self>) {
        let this = self.clone();
        let path = self.path.clone();
        tokio::spawn(async move {
            if let Err(e) = watch_loop(this, path).await {
                error!("config watcher terminated: {e}");
            }
        });
    }
}

async fn watch_loop(state: Arc<SharedConfig>, path: PathBuf) -> Result<()> {
    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    let mut watcher = RecommendedWatcher::new(
        move |res| {
            let _ = tx.blocking_send(res);
        },
        NotifyConfig::default(),
    )?;
    watcher.watch(&path, RecursiveMode::NonRecursive)?;
    info!("watching config file {}", path.display());

    while rx.recv().await.is_some() {
        // debounce — editors often write in several steps
        tokio::time::sleep(Duration::from_millis(150)).await;
        while rx.try_recv().is_ok() {}
        info!("config file changed, reloading");
        match load_config(&path) {
            Ok(new_cfg) => {
                let arc = Arc::new(new_cfg);
                *state.inner.write().await = (*arc).clone();
                *state.last_reload.write().await = ReloadStatus {
                    ok: true,
                    error: None,
                    at: Some(chrono::Utc::now()),
                };
                let _ = state.changes.send(arc);
            }
            Err(e) => {
                error!("config reload failed: {e:#}");
                *state.last_reload.write().await = ReloadStatus {
                    ok: false,
                    error: Some(format!("{e:#}")),
                    at: Some(chrono::Utc::now()),
                };
            }
        }
    }
    Ok(())
}

/// Resolve `users_file` relative to the config file's directory.
pub fn resolve_users_path(config_path: &Path, cfg: &AppConfig) -> PathBuf {
    let p = Path::new(&cfg.users_file);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        config_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(p)
    }
}
