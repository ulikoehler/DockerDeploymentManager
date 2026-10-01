//! MCP (Model Context Protocol) server, mounted at `/mcp`.
//!
//! Exposes the full ddm API surface as MCP tools over streamable HTTP.
//! Authentication reuses the existing JWT bearer tokens (same as the REST
//! API); an axum middleware verifies the token and injects [`AuthUser`] into
//! the request extensions, which rmcp forwards to tool handlers via
//! `http::request::Parts`.
//!
//! Tool calls run the same handler functions as the REST endpoints, so
//! permission checks, policy validation and audit logging are identical.

use crate::api;
use crate::auth::{AuthUser, SuccessResponse};
use crate::AppState;
use axum::body::Body;
use axum::extract::{Path, Query, Request, State};
use axum::http::request::Parts;
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::{Json, Router};
use rmcp::handler::server::common::{AsRequestContext, FromContextPart};
use rmcp::handler::server::wrapper::{Json as McpJson, Parameters};
use rmcp::model::{Implementation, ServerCapabilities, ServerConfig};
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{tool, tool_handler, tool_router, ErrorData, ServerHandler};
use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Router + auth middleware
// ---------------------------------------------------------------------------

/// Router serving MCP over streamable HTTP at `/mcp` (requires bearer auth).
pub fn router(state: AppState) -> Router<AppState> {
    let handler_state = state.clone();
    // Host validation defaults to loopback-only, which would break real
    // deployments behind a hostname — JWT auth is the actual boundary here.
    // Origin enforcement rejects any browser-originated request instead.
    let config = StreamableHttpServerConfig::default()
        .disable_allowed_hosts()
        .enforce_origin_validation();
    let service = StreamableHttpService::new(
        move || Ok(DdmMcp::new(handler_state.clone())),
        Arc::new(LocalSessionManager::default()),
        config,
    );
    Router::new()
        .nest_service("/mcp", service)
        .layer(middleware::from_fn_with_state(state, mcp_auth))
}

/// Verify the JWT bearer token and store the authenticated user in the
/// request extensions, where tool handlers can pick it up.
async fn mcp_auth(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, Response> {
    let (mut parts, body) = req.into_parts();
    let auth = crate::auth::authenticate(&parts, &state).await?;
    parts.extensions.insert(auth);
    Ok(next.run(Request::from_parts(parts, body)).await)
}

/// Tool-parameter extractor: pulls the authenticated user out of the HTTP
/// request extensions (inserted by [`mcp_auth`]).
pub struct McpUser(pub AuthUser);

impl<C> FromContextPart<C> for McpUser
where
    C: AsRequestContext,
{
    fn from_context_part(context: &mut C) -> Result<Self, ErrorData> {
        let parts = context
            .as_request_context()
            .extensions
            .get::<Parts>()
            .ok_or_else(|| ErrorData::internal_error("missing http request parts", None))?;
        parts
            .extensions
            .get::<AuthUser>()
            .cloned()
            .map(McpUser)
            .ok_or_else(|| ErrorData::internal_error("unauthenticated", None))
    }
}

// ---------------------------------------------------------------------------
// Result conversion helpers
// ---------------------------------------------------------------------------

async fn resp_err(resp: Response) -> ErrorData {
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 16)
        .await
        .unwrap_or_default();
    let msg = serde_json::from_slice::<Value>(&bytes)
        .ok()
        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(String::from))
        .unwrap_or_else(|| format!("HTTP {status}"));
    ErrorData::internal_error(msg, None)
}

fn to_data<T: Serialize>(j: Json<SuccessResponse<T>>) -> Result<McpJson<Value>, ErrorData> {
    Ok(McpJson(
        serde_json::to_value(&j.data).unwrap_or(Value::Null),
    ))
}

async fn finish<T: Serialize>(
    r: Result<Json<SuccessResponse<T>>, Response>,
) -> Result<McpJson<Value>, ErrorData> {
    match r {
        Ok(j) => to_data(j),
        Err(resp) => Err(resp_err(resp).await),
    }
}

fn parse<T: for<'de> Deserialize<'de>>(v: Value) -> Result<T, ErrorData> {
    serde_json::from_value(v)
        .map_err(|e| ErrorData::invalid_params(format!("invalid arguments: {e}"), None))
}

// ---------------------------------------------------------------------------
// Tool parameter structs
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct NameArg {
    /// Service / unit / user / group / execution id (context-dependent).
    pub name: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ServiceActionArgs {
    pub name: String,
    /// pull | up | down | restart | update | start | stop | enable | disable
    pub action: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ServiceCreateArgs {
    pub name: String,
    /// Raw docker-compose YAML (mutually exclusive with `template_id`).
    #[serde(default)]
    pub compose: Option<String>,
    /// Service template id (mutually exclusive with `compose`).
    #[serde(default)]
    pub template_id: Option<String>,
    /// Template variable values.
    #[serde(default)]
    pub vars: std::collections::HashMap<String, String>,
    #[serde(default)]
    pub description: Option<String>,
    /// Generate a systemd unit for the service.
    #[serde(default)]
    pub create_unit: bool,
    /// systemctl enable the unit.
    #[serde(default)]
    pub enable: bool,
    /// systemctl start the unit.
    #[serde(default)]
    pub start: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ServiceDeleteArgs {
    pub name: String,
    /// Run `compose down` first.
    #[serde(default)]
    pub down: bool,
    /// Keep the service directory on disk.
    #[serde(default)]
    pub keep_dir: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PutComposeArgs {
    pub name: String,
    /// Full new compose file content.
    pub content: String,
    /// Recreate containers after writing.
    #[serde(default)]
    pub recreate: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PutUnitArgs {
    pub name: String,
    /// Full new unit file content.
    pub content: String,
    /// Enable/disable override (omit to leave unchanged).
    #[serde(default)]
    pub enable: Option<bool>,
    /// Restart the unit after writing.
    #[serde(default)]
    pub restart: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RegenerateArgs {
    pub name: String,
    #[serde(default)]
    pub enable: bool,
    #[serde(default)]
    pub start: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct LogsArgs {
    pub name: String,
    #[serde(default)]
    pub tail: Option<usize>,
    /// Case-insensitive substring filter.
    #[serde(default)]
    pub grep: Option<String>,
    #[serde(default)]
    pub regex: Option<String>,
    #[serde(default)]
    pub exclude_regex: Option<String>,
    /// "stdout" | "stderr" | omit for both.
    #[serde(default)]
    pub stream: Option<String>,
    /// Only entries after this unix timestamp.
    #[serde(default)]
    pub since: Option<i64>,
    /// Compose service / container name filter.
    #[serde(default)]
    pub container: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PathArg {
    pub name: String,
    /// Path relative to the service dir ("" = dir itself).
    #[serde(default)]
    pub path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct WriteFileArgs {
    pub name: String,
    /// Path relative to the service dir.
    pub path: String,
    pub content: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RenameArgs {
    pub name: String,
    pub from: String,
    pub to: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GitLogArgs {
    pub name: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub n: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GitCloneArgs {
    pub name: String,
    pub url: String,
    /// Directory (relative to service dir) to clone into; "" = service dir.
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub branch: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GitActionArgs {
    pub name: String,
    /// Repo path relative to service dir ("" = root).
    #[serde(default)]
    pub path: String,
    /// pull | fetch | checkout
    pub op: String,
    /// Required for op=checkout.
    #[serde(default)]
    pub git_ref: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct JsonConfigArgs {
    pub name: String,
    /// JSON config object matching the endpoint's schema
    /// (ServiceBackupConfig / ServiceMonitoringConfig / notifier config).
    pub config: Value,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RestoreArgs {
    pub name: String,
    pub snapshot: String,
    pub target_dir: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct EventsArgs {
    #[serde(default)]
    pub service: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct NotifierTestArgs {
    pub id: String,
    #[serde(default)]
    pub message: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct NotifierConfigArgs {
    /// JSON notifier config, e.g. {"type":"telegram","id":"tg",...}.
    pub config: Value,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct NotifierUpdateArgs {
    pub id: String,
    /// JSON notifier config; empty/"***" secret fields keep current values.
    pub config: Value,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct IdArg {
    pub id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UserCreateArgs {
    pub name: String,
    pub password: String,
    #[serde(default)]
    pub roles: Vec<String>,
    /// [{"type":"exact|glob|regex","pattern":"...","effect":"allow|deny"}]
    #[serde(default)]
    pub access: Vec<Value>,
    #[serde(default)]
    pub features: Option<Value>,
    #[serde(default)]
    pub compose_policy: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UserUpdateArgs {
    pub name: String,
    #[serde(default)]
    pub roles: Option<Vec<String>>,
    #[serde(default)]
    pub features: Option<Value>,
    /// Outer null = leave unchanged; inner null = clear the override.
    #[serde(default)]
    pub compose_policy: Option<Option<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PasswordArgs {
    pub name: String,
    pub password: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AccessArgs {
    pub name: String,
    /// [{"type":"exact|glob|regex","pattern":"...","effect":"allow|deny"}]
    pub rules: Vec<Value>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExecuteArgs {
    /// systemd group id or unit name (context-dependent).
    pub target: String,
    /// Custom command id defined on the group.
    pub command_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UnitLogsArgs {
    pub unit: String,
    #[serde(default)]
    pub lines: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CommandRunArgs {
    pub section: usize,
    pub item: usize,
    #[serde(default)]
    pub params: std::collections::HashMap<String, String>,
}

// ---------------------------------------------------------------------------
// MCP server handler
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct DdmMcp {
    state: AppState,
}

impl DdmMcp {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }

    fn st(&self) -> State<AppState> {
        State(self.state.clone())
    }
}

#[tool_router]
impl DdmMcp {
    // -- auth ---------------------------------------------------------------

    #[tool(description = "Current authenticated user, roles, features and access rules")]
    async fn me(&self, McpUser(user): McpUser) -> Result<McpJson<Value>, ErrorData> {
        to_data(api::auth::me(user).await)
    }

    #[tool(description = "Rotate JWT secret, invalidating all sessions (admin)")]
    async fn logout_all(&self, McpUser(user): McpUser) -> Result<McpJson<Value>, ErrorData> {
        finish(api::auth::logout_all(user, self.st()).await).await
    }

    // -- users (admin) -------------------------------------------------------

    #[tool(description = "List all users (admin)")]
    async fn users_list(&self, McpUser(user): McpUser) -> Result<McpJson<Value>, ErrorData> {
        finish(api::users::list(user, self.st()).await).await
    }

    #[tool(description = "Get a user by name (admin)")]
    async fn user_get(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<NameArg>,
    ) -> Result<McpJson<Value>, ErrorData> {
        finish(api::users::get_one(user, self.st(), Path(p.name)).await).await
    }

    #[tool(description = "Create a user (admin)")]
    async fn user_create(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<UserCreateArgs>,
    ) -> Result<McpJson<Value>, ErrorData> {
        let req = api::users::CreateUser {
            name: p.name,
            password: p.password,
            roles: p.roles,
            access: parse(Value::Array(p.access))?,
            features: p.features.map(parse).transpose()?,
            compose_policy: p.compose_policy,
        };
        finish(api::users::create(user, self.st(), Json(req)).await).await
    }

    #[tool(description = "Update a user's roles/features/compose_policy (admin)")]
    async fn user_update(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<UserUpdateArgs>,
    ) -> Result<McpJson<Value>, ErrorData> {
        let req = api::users::UpdateUser {
            roles: p.roles,
            features: p.features.map(parse).transpose()?,
            compose_policy: p.compose_policy,
        };
        finish(api::users::update(user, self.st(), Path(p.name), Json(req)).await).await
    }

    #[tool(description = "Delete a user (admin)")]
    async fn user_delete(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<NameArg>,
    ) -> Result<McpJson<Value>, ErrorData> {
        finish(api::users::delete(user, self.st(), Path(p.name)).await).await
    }

    #[tool(description = "Set a user's password (admin or self)")]
    async fn user_set_password(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<PasswordArgs>,
    ) -> Result<McpJson<Value>, ErrorData> {
        finish(
            api::users::set_password(
                user,
                self.st(),
                Path(p.name),
                Json(api::users::SetPassword {
                    password: p.password,
                }),
            )
            .await,
        )
        .await
    }

    #[tool(description = "Replace a user's service access rules (admin)")]
    async fn user_set_access(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<AccessArgs>,
    ) -> Result<McpJson<Value>, ErrorData> {
        let rules: Vec<crate::users::AccessRule> = parse(Value::Array(p.rules))?;
        finish(api::users::set_access(user, self.st(), Path(p.name), Json(rules)).await).await
    }

    // -- services -------------------------------------------------------------

    #[tool(description = "List all compose services")]
    async fn services_list(&self, McpUser(user): McpUser) -> Result<McpJson<Value>, ErrorData> {
        finish(api::services::list(user, self.st()).await).await
    }

    #[tool(description = "Service details: containers, unit state, meta")]
    async fn service_get(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<NameArg>,
    ) -> Result<McpJson<Value>, ErrorData> {
        finish(api::services::detail(user, self.st(), Path(p.name)).await).await
    }

    #[tool(description = "Create a service from compose YAML or a template")]
    async fn service_create(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<ServiceCreateArgs>,
    ) -> Result<McpJson<Value>, ErrorData> {
        let req = api::services::CreateService {
            name: p.name,
            compose: p.compose,
            template_id: p.template_id,
            vars: p.vars,
            description: p.description,
            create_unit: p.create_unit,
            enable: p.enable,
            start: p.start,
        };
        finish(api::services::create(user, self.st(), Json(req)).await).await
    }

    #[tool(description = "Delete a service (admin)")]
    async fn service_delete(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<ServiceDeleteArgs>,
    ) -> Result<McpJson<Value>, ErrorData> {
        let q = api::services::DeleteQuery {
            keep_dir: p.keep_dir,
            down: p.down,
        };
        finish(api::services::delete(user, self.st(), Path(p.name), Query(q)).await).await
    }

    #[tool(
        description = "Run a lifecycle action on a service (pull|up|down|restart|update|start|stop|enable|disable)"
    )]
    async fn service_action(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<ServiceActionArgs>,
    ) -> Result<McpJson<Value>, ErrorData> {
        let req = api::services::ActionRequest { action: p.action };
        finish(api::services::action(user, self.st(), Path(p.name), Json(req)).await).await
    }

    #[tool(description = "Get a service's compose file content")]
    async fn service_get_compose(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<NameArg>,
    ) -> Result<McpJson<Value>, ErrorData> {
        finish(api::services::get_compose(user, self.st(), Path(p.name)).await).await
    }

    #[tool(description = "Replace a service's compose file")]
    async fn service_put_compose(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<PutComposeArgs>,
    ) -> Result<McpJson<Value>, ErrorData> {
        let req = api::services::PutCompose {
            content: p.content,
            recreate: p.recreate,
        };
        finish(api::services::put_compose(user, self.st(), Path(p.name), Json(req)).await).await
    }

    #[tool(description = "Get a service's systemd unit file")]
    async fn service_get_unit(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<NameArg>,
    ) -> Result<McpJson<Value>, ErrorData> {
        finish(api::services::get_unit(user, self.st(), Path(p.name)).await).await
    }

    #[tool(description = "Replace a service's systemd unit file")]
    async fn service_put_unit(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<PutUnitArgs>,
    ) -> Result<McpJson<Value>, ErrorData> {
        let req = api::services::PutUnit {
            content: p.content,
            enable: p.enable,
            restart: p.restart,
        };
        finish(api::services::put_unit(user, self.st(), Path(p.name), Json(req)).await).await
    }

    #[tool(description = "Check a service's systemd unit health/configuration")]
    async fn service_check_unit(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<NameArg>,
    ) -> Result<McpJson<Value>, ErrorData> {
        finish(api::services::check_unit(user, self.st(), Path(p.name)).await).await
    }

    #[tool(description = "Regenerate a service's systemd unit from its compose file")]
    async fn service_regenerate_unit(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<RegenerateArgs>,
    ) -> Result<McpJson<Value>, ErrorData> {
        let req = api::services::RegenerateRequest {
            enable: p.enable,
            start: p.start,
        };
        finish(api::services::regenerate_unit(user, self.st(), Path(p.name), Json(req)).await).await
    }

    #[tool(description = "Fetch container logs for a service")]
    async fn service_logs(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<LogsArgs>,
    ) -> Result<McpJson<Value>, ErrorData> {
        let q = api::services::LogsQuery {
            tail: p.tail,
            filter: crate::logs::LogFilter {
                grep: p.grep,
                regex: p.regex,
                exclude_regex: p.exclude_regex,
                stream: p.stream,
                since: p.since,
                container: p.container,
            },
        };
        finish(api::services::logs(user, self.st(), Path(p.name), Query(q)).await).await
    }

    // -- files ----------------------------------------------------------------

    #[tool(description = "List a directory or read a file inside a service dir")]
    async fn service_files(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<PathArg>,
    ) -> Result<McpJson<Value>, ErrorData> {
        let q = api::files::PathQuery { path: p.path };
        finish(api::files::list_files(user, self.st(), Path(p.name), Query(q)).await).await
    }

    #[tool(description = "Write a file inside a service dir")]
    async fn service_write_file(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<WriteFileArgs>,
    ) -> Result<McpJson<Value>, ErrorData> {
        let req = api::files::WriteRequest {
            path: p.path,
            content: p.content,
        };
        finish(api::files::write_file(user, self.st(), Path(p.name), Json(req)).await).await
    }

    #[tool(description = "Create a directory inside a service dir")]
    async fn service_mkdir(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<PathArg>,
    ) -> Result<McpJson<Value>, ErrorData> {
        finish(
            api::files::mkdir(
                user,
                self.st(),
                Path(p.name),
                Json(api::files::MkdirRequest { path: p.path }),
            )
            .await,
        )
        .await
    }

    #[tool(description = "Rename/move a file inside a service dir")]
    async fn service_rename_file(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<RenameArgs>,
    ) -> Result<McpJson<Value>, ErrorData> {
        let req = api::files::RenameRequest {
            from: p.from,
            to: p.to,
        };
        finish(api::files::rename(user, self.st(), Path(p.name), Json(req)).await).await
    }

    #[tool(description = "Delete a file inside a service dir")]
    async fn service_delete_file(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<PathArg>,
    ) -> Result<McpJson<Value>, ErrorData> {
        let q = api::files::PathQuery { path: p.path };
        finish(api::files::delete_file(user, self.st(), Path(p.name), Query(q)).await).await
    }

    // -- git ------------------------------------------------------------------

    #[tool(description = "List git repos inside a service dir")]
    async fn service_git_repos(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<NameArg>,
    ) -> Result<McpJson<Value>, ErrorData> {
        finish(api::files::git_repos(user, self.st(), Path(p.name)).await).await
    }

    #[tool(description = "Git status of a repo inside a service dir")]
    async fn service_git_status(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<PathArg>,
    ) -> Result<McpJson<Value>, ErrorData> {
        let q = api::files::PathQuery { path: p.path };
        finish(api::files::git_status(user, self.st(), Path(p.name), Query(q)).await).await
    }

    #[tool(description = "Git log of a repo inside a service dir")]
    async fn service_git_log(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<GitLogArgs>,
    ) -> Result<McpJson<Value>, ErrorData> {
        let q = api::files::LogQuery {
            path: p.path,
            n: p.n,
        };
        finish(api::files::git_log(user, self.st(), Path(p.name), Query(q)).await).await
    }

    #[tool(description = "Git branches of a repo inside a service dir")]
    async fn service_git_branches(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<PathArg>,
    ) -> Result<McpJson<Value>, ErrorData> {
        let q = api::files::PathQuery { path: p.path };
        finish(api::files::git_branches(user, self.st(), Path(p.name), Query(q)).await).await
    }

    #[tool(description = "Clone a git repo into a service dir (returns execution_id)")]
    async fn service_git_clone(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<GitCloneArgs>,
    ) -> Result<McpJson<Value>, ErrorData> {
        let req = api::files::CloneRequest {
            url: p.url,
            path: p.path,
            branch: p.branch,
        };
        finish(api::files::git_clone(user, self.st(), Path(p.name), Json(req)).await).await
    }

    #[tool(
        description = "Git pull/fetch/checkout on a repo inside a service dir (returns execution_id)"
    )]
    async fn service_git_action(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<GitActionArgs>,
    ) -> Result<McpJson<Value>, ErrorData> {
        let req = api::files::GitActionRequest {
            path: p.path,
            op: p.op,
            git_ref: p.git_ref,
        };
        finish(api::files::git_action(user, self.st(), Path(p.name), Json(req)).await).await
    }

    // -- backup -----------------------------------------------------------------

    #[tool(description = "Get a service's backup configuration")]
    async fn service_get_backup(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<NameArg>,
    ) -> Result<McpJson<Value>, ErrorData> {
        finish(api::services::get_backup(user, self.st(), Path(p.name)).await).await
    }

    #[tool(
        description = "Set a service's backup configuration (JSON object: enabled, paths, excludes, stdin_dumps, schedule_enabled)"
    )]
    async fn service_put_backup(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<JsonConfigArgs>,
    ) -> Result<McpJson<Value>, ErrorData> {
        let cfg: crate::config::ServiceBackupConfig = parse(p.config)?;
        finish(api::services::put_backup(user, self.st(), Path(p.name), Json(cfg)).await).await
    }

    #[tool(description = "Check a service's backup setup (restic repo, scripts)")]
    async fn service_backup_check(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<NameArg>,
    ) -> Result<McpJson<Value>, ErrorData> {
        finish(api::services::backup_check(user, self.st(), Path(p.name)).await).await
    }

    #[tool(description = "Provision a service's backup (init repo, write scripts)")]
    async fn service_backup_provision(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<NameArg>,
    ) -> Result<McpJson<Value>, ErrorData> {
        finish(api::services::backup_provision(user, self.st(), Path(p.name)).await).await
    }

    #[tool(description = "Run a service's backup now (returns execution_id)")]
    async fn service_backup_run(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<NameArg>,
    ) -> Result<McpJson<Value>, ErrorData> {
        finish(api::services::backup_run(user, self.st(), Path(p.name)).await).await
    }

    #[tool(description = "List restic snapshots for a service")]
    async fn service_backup_snapshots(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<NameArg>,
    ) -> Result<McpJson<Value>, ErrorData> {
        finish(api::services::backup_snapshots(user, self.st(), Path(p.name)).await).await
    }

    #[tool(description = "Apply retention policy / forget snapshots (returns execution_id)")]
    async fn service_backup_forget(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<NameArg>,
    ) -> Result<McpJson<Value>, ErrorData> {
        finish(api::services::backup_forget(user, self.st(), Path(p.name)).await).await
    }

    #[tool(description = "Restore a backup snapshot to a target dir (returns execution_id)")]
    async fn service_backup_restore(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<RestoreArgs>,
    ) -> Result<McpJson<Value>, ErrorData> {
        let req = api::services::RestoreRequest {
            snapshot: p.snapshot,
            target_dir: p.target_dir,
        };
        finish(api::services::backup_restore(user, self.st(), Path(p.name), Json(req)).await).await
    }

    // -- monitoring ---------------------------------------------------------------

    #[tool(description = "Get a service's monitoring config and current state")]
    async fn service_get_monitoring(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<NameArg>,
    ) -> Result<McpJson<Value>, ErrorData> {
        finish(api::services::get_monitoring(user, self.st(), Path(p.name)).await).await
    }

    #[tool(description = "Set a service's monitoring config (JSON: health, log_alerts)")]
    async fn service_put_monitoring(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<JsonConfigArgs>,
    ) -> Result<McpJson<Value>, ErrorData> {
        let cfg: crate::config::ServiceMonitoringConfig = parse(p.config)?;
        finish(api::services::put_monitoring(user, self.st(), Path(p.name), Json(cfg)).await).await
    }

    #[tool(description = "Test a service's monitoring (container health snapshot)")]
    async fn service_monitoring_test(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<NameArg>,
    ) -> Result<McpJson<Value>, ErrorData> {
        finish(api::services::monitoring_test(user, self.st(), Path(p.name)).await).await
    }

    #[tool(description = "Monitoring status of all accessible services")]
    async fn monitoring_status(&self, McpUser(user): McpUser) -> Result<McpJson<Value>, ErrorData> {
        to_data(api::misc::monitor_status_all(user, self.st()).await)
    }

    #[tool(description = "Monitoring status of one service")]
    async fn monitoring_status_service(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<NameArg>,
    ) -> Result<McpJson<Value>, ErrorData> {
        finish(api::misc::monitor_status(user, self.st(), Path(p.name)).await).await
    }

    #[tool(description = "Recent monitoring alert events")]
    async fn monitoring_events(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<EventsArgs>,
    ) -> Result<McpJson<Value>, ErrorData> {
        let q = api::misc::EventsQuery {
            service: p.service,
            limit: p.limit,
        };
        to_data(api::misc::monitor_events(user, self.st(), Query(q)).await)
    }

    #[tool(description = "List configured notifiers (admin)")]
    async fn notifiers_list(&self, McpUser(user): McpUser) -> Result<McpJson<Value>, ErrorData> {
        finish(api::misc::notifiers(user, self.st()).await).await
    }

    #[tool(
        description = "Create a notifier (admin). Config JSON e.g. {\"type\":\"telegram\",\"id\":\"tg\",\"bot_token\":\"...\",\"chat_id\":\"...\"}"
    )]
    async fn notifier_create(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<NotifierConfigArgs>,
    ) -> Result<McpJson<Value>, ErrorData> {
        finish(api::misc::notifier_create(user, self.st(), Json(p.config)).await).await
    }

    #[tool(
        description = "Update a notifier (admin). Empty/\"***\" secret fields keep their current values"
    )]
    async fn notifier_update(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<NotifierUpdateArgs>,
    ) -> Result<McpJson<Value>, ErrorData> {
        finish(api::misc::notifier_update(user, self.st(), Path(p.id), Json(p.config)).await).await
    }

    #[tool(description = "Delete a notifier (admin)")]
    async fn notifier_delete(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<IdArg>,
    ) -> Result<McpJson<Value>, ErrorData> {
        finish(api::misc::notifier_delete(user, self.st(), Path(p.id)).await).await
    }

    #[tool(description = "Send a test message through a notifier (admin)")]
    async fn notifier_test(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<NotifierTestArgs>,
    ) -> Result<McpJson<Value>, ErrorData> {
        let req = api::misc::NotifierTest {
            message: p.message.unwrap_or_else(|| "ddm test notification".into()),
        };
        finish(api::misc::notifier_test(user, self.st(), Path(p.id), Json(req)).await).await
    }

    // -- systemd (host) -------------------------------------------------------------

    #[tool(description = "List configured host systemd unit groups")]
    async fn systemd_groups(&self, McpUser(user): McpUser) -> Result<McpJson<Value>, ErrorData> {
        finish(api::systemd_api::groups(user, self.st()).await).await
    }

    #[tool(description = "Status of all units in a systemd group")]
    async fn systemd_group_status(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<NameArg>,
    ) -> Result<McpJson<Value>, ErrorData> {
        finish(api::systemd_api::group_status(user, self.st(), Path(p.name)).await).await
    }

    #[tool(description = "Restart all units in a systemd group (returns execution_id)")]
    async fn systemd_group_restart(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<NameArg>,
    ) -> Result<McpJson<Value>, ErrorData> {
        finish(api::systemd_api::group_restart(user, self.st(), Path(p.name)).await).await
    }

    #[tool(description = "Run a group's custom command on all its units (returns execution_id)")]
    async fn systemd_group_execute(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<ExecuteArgs>,
    ) -> Result<McpJson<Value>, ErrorData> {
        let req = api::systemd_api::ExecuteRequest {
            command_id: p.command_id,
        };
        finish(api::systemd_api::group_execute(user, self.st(), Path(p.target), Json(req)).await)
            .await
    }

    #[tool(description = "Restart a systemd unit (returns execution_id)")]
    async fn systemd_unit_restart(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<NameArg>,
    ) -> Result<McpJson<Value>, ErrorData> {
        finish(api::systemd_api::unit_restart(user, self.st(), Path(p.name)).await).await
    }

    #[tool(description = "Run a custom command on one systemd unit (returns execution_id)")]
    async fn systemd_unit_execute(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<ExecuteArgs>,
    ) -> Result<McpJson<Value>, ErrorData> {
        let req = api::systemd_api::ExecuteRequest {
            command_id: p.command_id,
        };
        finish(api::systemd_api::unit_execute(user, self.st(), Path(p.target), Json(req)).await)
            .await
    }

    #[tool(description = "Journal logs of a systemd unit")]
    async fn systemd_unit_logs(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<UnitLogsArgs>,
    ) -> Result<McpJson<Value>, ErrorData> {
        let q = api::systemd_api::LogsQuery {
            lines: p.lines.unwrap_or(200),
        };
        finish(api::systemd_api::unit_logs(user, self.st(), Path(p.unit), Query(q)).await).await
    }

    // -- generic commands -------------------------------------------------------------

    #[tool(description = "List configured command sections and items")]
    async fn commands_list(&self, McpUser(user): McpUser) -> Result<McpJson<Value>, ErrorData> {
        finish(api::commands_api::list(user, self.st()).await).await
    }

    #[tool(description = "Run a configured command by section/item index (returns execution_id)")]
    async fn command_run(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<CommandRunArgs>,
    ) -> Result<McpJson<Value>, ErrorData> {
        let req = api::commands_api::RunRequest { params: p.params };
        finish(api::commands_api::run(user, self.st(), Path((p.section, p.item)), Json(req)).await)
            .await
    }

    // -- gitops -----------------------------------------------------------------

    #[tool(description = "GitOps sync status")]
    async fn gitops_status(&self, McpUser(user): McpUser) -> Result<McpJson<Value>, ErrorData> {
        to_data(api::misc::gitops_status(user, self.st()).await)
    }

    #[tool(description = "Pull the config repo and apply (admin)")]
    async fn gitops_sync(&self, McpUser(user): McpUser) -> Result<McpJson<Value>, ErrorData> {
        finish(api::misc::gitops_sync(user, self.st()).await).await
    }

    #[tool(description = "Commit and push local config changes to the gitops repo (admin)")]
    async fn gitops_push(&self, McpUser(user): McpUser) -> Result<McpJson<Value>, ErrorData> {
        finish(api::misc::gitops_push(user, self.st()).await).await
    }

    // -- misc -----------------------------------------------------------------

    #[tool(description = "Redacted effective server configuration (admin)")]
    async fn config_get(&self, McpUser(user): McpUser) -> Result<McpJson<Value>, ErrorData> {
        match api::misc::get_config(user, self.st()).await {
            Ok(j) => Ok(McpJson(j.0)),
            Err(resp) => Err(resp_err(resp).await),
        }
    }

    #[tool(description = "Config file reload status")]
    async fn config_status(&self, McpUser(user): McpUser) -> Result<McpJson<Value>, ErrorData> {
        to_data(api::misc::config_status(user, self.st()).await)
    }

    #[tool(description = "The caller's effective compose policy")]
    async fn effective_policy(&self, McpUser(user): McpUser) -> Result<McpJson<Value>, ErrorData> {
        to_data(api::misc::effective_policy(user, self.st()).await)
    }

    #[tool(description = "List service templates")]
    async fn templates(&self, McpUser(user): McpUser) -> Result<McpJson<Value>, ErrorData> {
        to_data(api::misc::templates(user, self.st()).await)
    }

    #[tool(description = "Audit log entries (admin)")]
    async fn audit_list(&self, McpUser(user): McpUser) -> Result<McpJson<Value>, ErrorData> {
        finish(api::misc::audit_entries(user, self.st()).await).await
    }

    #[tool(description = "List recent command/script executions")]
    async fn executions_list(&self, McpUser(user): McpUser) -> Result<McpJson<Value>, ErrorData> {
        to_data(api::misc::executions(user, self.st()).await)
    }

    #[tool(description = "Get one execution's status/output by id")]
    async fn execution_get(
        &self,
        McpUser(user): McpUser,
        Parameters(p): Parameters<IdArg>,
    ) -> Result<McpJson<Value>, ErrorData> {
        finish(api::misc::execution(user, self.st(), Path(p.id)).await).await
    }

    #[tool(description = "Health check")]
    async fn health(&self) -> Result<McpJson<Value>, ErrorData> {
        Ok(McpJson(api::misc::health().await.0))
    }
}

#[tool_handler]
impl ServerHandler for DdmMcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("ddm-server", env!("CARGO_PKG_VERSION")))
            .with_instructions(
                "Docker Deployment Manager: manage compose services, systemd units, \
                 files, git repos, backups, monitoring and users. Obtain a bearer \
                 token via POST /api/auth/login and pass it as Authorization: \
                 Bearer <token> (or ?token=). Long-running operations return an \
                 execution_id — poll it with execution_get.",
            )
    }
}
