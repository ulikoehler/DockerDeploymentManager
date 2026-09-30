pub mod auth;
pub mod commands_api;
pub mod files;
pub mod misc;
pub mod services;
pub mod systemd_api;
pub mod users;
pub mod ws;

use crate::AppState;
use axum::routing::{get, post, put};
use axum::Router;

pub fn api_router() -> Router<AppState> {
    Router::new()
        // auth
        .route("/api/auth/login", post(auth::login))
        .route("/api/auth/me", get(auth::me))
        .route("/api/auth/logout-all", post(auth::logout_all))
        // users (admin)
        .route("/api/users", get(users::list).post(users::create))
        .route(
            "/api/users/:name",
            get(users::get_one).put(users::update).delete(users::delete),
        )
        .route("/api/users/:name/password", put(users::set_password))
        .route("/api/users/:name/access", put(users::set_access))
        // services
        .route("/api/services", get(services::list).post(services::create))
        .route(
            "/api/services/:name",
            get(services::detail).delete(services::delete),
        )
        .route(
            "/api/services/:name/compose",
            get(services::get_compose).put(services::put_compose),
        )
        .route(
            "/api/services/:name/unit",
            get(services::get_unit).put(services::put_unit),
        )
        .route("/api/services/:name/unit/check", get(services::check_unit))
        .route(
            "/api/services/:name/unit/regenerate",
            post(services::regenerate_unit),
        )
        .route("/api/services/:name/actions", post(services::action))
        .route("/api/services/:name/logs", get(services::logs))
        // files + git
        .route(
            "/api/services/:name/files",
            get(files::list_files)
                .put(files::write_file)
                .delete(files::delete_file),
        )
        .route("/api/services/:name/files/mkdir", post(files::mkdir))
        .route("/api/services/:name/files/rename", post(files::rename))
        .route("/api/services/:name/git/repos", get(files::git_repos))
        .route("/api/services/:name/git/status", get(files::git_status))
        .route("/api/services/:name/git/log", get(files::git_log))
        .route("/api/services/:name/git/branches", get(files::git_branches))
        .route("/api/services/:name/git/clone", post(files::git_clone))
        .route("/api/services/:name/git/action", post(files::git_action))
        // backup
        .route(
            "/api/services/:name/backup",
            get(services::get_backup).put(services::put_backup),
        )
        .route(
            "/api/services/:name/backup/check",
            get(services::backup_check),
        )
        .route(
            "/api/services/:name/backup/provision",
            post(services::backup_provision),
        )
        .route("/api/services/:name/backup/run", post(services::backup_run))
        .route(
            "/api/services/:name/backup/snapshots",
            get(services::backup_snapshots),
        )
        .route(
            "/api/services/:name/backup/forget",
            post(services::backup_forget),
        )
        .route(
            "/api/services/:name/backup/restore",
            post(services::backup_restore),
        )
        // monitoring
        .route("/api/monitoring/status", get(misc::monitor_status_all))
        .route("/api/monitoring/status/:service", get(misc::monitor_status))
        .route("/api/monitoring/events", get(misc::monitor_events))
        .route(
            "/api/services/:name/monitoring",
            get(services::get_monitoring).put(services::put_monitoring),
        )
        .route(
            "/api/services/:name/monitoring/test",
            post(services::monitoring_test),
        )
        .route(
            "/api/monitoring/notifiers",
            get(misc::notifiers).post(misc::notifier_create),
        )
        .route(
            "/api/monitoring/notifiers/:id",
            put(misc::notifier_update).delete(misc::notifier_delete),
        )
        .route(
            "/api/monitoring/notifiers/:id/test",
            post(misc::notifier_test),
        )
        // systemd (host)
        .route("/api/systemd/groups", get(systemd_api::groups))
        .route(
            "/api/systemd/groups/:group/status",
            get(systemd_api::group_status),
        )
        .route(
            "/api/systemd/groups/:group/restart",
            post(systemd_api::group_restart),
        )
        .route(
            "/api/systemd/groups/:group/execute",
            post(systemd_api::group_execute),
        )
        .route(
            "/api/systemd/units/:unit/restart",
            post(systemd_api::unit_restart),
        )
        .route(
            "/api/systemd/units/:unit/execute",
            post(systemd_api::unit_execute),
        )
        .route("/api/systemd/units/:unit/logs", get(systemd_api::unit_logs))
        // generic commands
        .route("/api/commands", get(commands_api::list))
        .route("/api/commands/:section/:item", post(commands_api::run))
        // gitops (webhook is public, secret-verified)
        .route("/api/gitops/status", get(misc::gitops_status))
        .route("/api/gitops/sync", post(misc::gitops_sync))
        .route("/api/gitops/push", post(misc::gitops_push))
        .route("/api/gitops/webhook", post(misc::gitops_webhook))
        // misc
        .route("/api/config", get(misc::get_config))
        .route("/api/config/status", get(misc::config_status))
        .route("/api/policy", get(misc::effective_policy))
        .route("/api/templates", get(misc::templates))
        .route("/api/audit", get(misc::audit_entries))
        .route("/api/executions", get(misc::executions))
        .route("/api/executions/:id", get(misc::execution))
        .route("/api/health", get(misc::health))
        // websockets
        .route("/ws/execute", get(ws::execute_ws_root))
        .route("/ws/executions/:id", get(ws::execute_ws))
        .route("/ws/services/:name/logs", get(ws::service_logs_ws))
        .route("/ws/events", get(ws::events_ws))
}
