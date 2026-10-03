# API reference

All endpoints return `{"success": true, "data": …}` or
`{"success": false, "error": "…"}` with an HTTP error status.

Auth: `POST /api/auth/login` → `{token}`; send as `Authorization: Bearer
<token>`. WebSocket endpoints accept `?token=…` (browsers can't set headers).

## Auth

| Method | Path | Notes |
|---|---|---|
| POST | `/api/auth/login` | `{name, password}` → `{token, name, roles, expires_at}` |
| GET  | `/api/auth/me` | own profile (roles, features, access, compose_policy) |
| POST | `/api/auth/token` | `{ttl_minutes?, services?[], actions?[]}` → `{token, expires_at}` — time-limited token (e.g. for MCP); `services`/`actions` intersect with the caller's permissions (only narrows) |
| POST | `/api/auth/logout-all` | admin; rotates JWT secret → all sessions die |

## Services

| Method | Path | Notes |
|---|---|---|
| GET    | `/api/services` | list with containers, unit + monitor summary (access-filtered) |
| POST   | `/api/services` | create: `{name, compose?|template_id?, vars?, description?, create_unit?, enable?, start?}` |
| GET    | `/api/services/{name}` | detail |
| DELETE | `/api/services/{name}?down=&keep_dir=` | admin; optionally `down`s and removes unit |
| POST   | `/api/services/{name}/actions` | `{action}`: `pull` `up` `down` `restart` `update` `start` `stop` `enable` `disable` → `{execution_id}` |
| GET    | `/api/services/{name}/logs?tail=&since=&grep=&regex=&exclude_regex=&stream=&container=` | filtered snapshot |
| POST   | `/api/services/{name}/exec` | `{container, command}` — docker exec inside one of the service's containers (`exec_containers` feature or admin) → `{execution_id}` |
| POST   | `/api/containers/{id}/exec` | `{command}` — exec in *any* container (admin only) → `{execution_id}` |

### Compose file

| Method | Path | Notes |
|---|---|---|
| GET | `/api/services/{name}/compose` | `{content, violations[]}` |
| PUT | `/api/services/{name}/compose` | `{content, recreate?}` — validated against caller's policy; violations → 400 |

### systemd unit

| Method | Path | Notes |
|---|---|---|
| GET  | `/api/services/{name}/unit` | `{exists, content, rendered_template, generated}` |
| PUT  | `/api/services/{name}/unit` | `{content, enable?, restart?}` — requires `unit_edit_requires` role or `edit_units` |
| GET  | `/api/services/{name}/unit/check` | `UnitCheckReport`: `exists, enabled, active, in_sync, workdir_ok, issues[{code,message,fixable}]` |
| POST | `/api/services/{name}/unit/regenerate` | `{enable?, start?}` — re-render template + write |

Unit issue codes: `missing`, `not_enabled`, `inactive`, `workdir_mismatch`,
`compose_mismatch`, `content_drift`, `docker_dep_missing`, `invalid_unit`,
`check_error`.

## Backup

| Method | Path | Notes |
|---|---|---|
| GET  | `/api/services/{name}/backup` | `{enabled_global, repository, config}` |
| PUT  | `/api/services/{name}/backup` | save `ServiceBackupConfig` into `meta.yaml` |
| GET  | `/api/services/{name}/backup/check` | `BackupCheckReport` |
| POST | `/api/services/{name}/backup/provision` | idempotent: password file, backup.sh, timer units, `restic init` |
| POST | `/api/services/{name}/backup/run` | run `backup.sh` now → `{execution_id}` |
| GET  | `/api/services/{name}/backup/snapshots` | `restic snapshots --json` |
| POST | `/api/services/{name}/backup/forget` | `forget --prune` with configured retention |
| POST | `/api/services/{name}/backup/restore` | `{snapshot, target_dir}` — admin or `unrestricted` only |

## Monitoring

| Method | Path | Notes |
|---|---|---|
| GET | `/api/monitoring/status` | per-service check states (access-filtered) |
| GET | `/api/monitoring/status/{service}` | one service |
| GET | `/api/monitoring/events?service=&limit=` | alert history (max 512 retained) |
| GET | `/api/services/{name}/monitoring` | `{config, state}` |
| PUT | `/api/services/{name}/monitoring` | save `ServiceMonitoringConfig` into `meta.yaml` (regexes validated) |
| POST | `/api/services/{name}/monitoring/test` | container health snapshot |
| GET | `/api/monitoring/notifiers` | admin; secrets redacted to `***` |
| POST | `/api/monitoring/notifiers` | `{type, id, …}` — create (admin); id `^[a-z0-9_-]{1,64}$`, duplicate ids rejected |
| PUT | `/api/monitoring/notifiers/{id}` | update (admin); id immutable; secret fields left empty/`***` keep their current values |
| DELETE | `/api/monitoring/notifiers/{id}` | remove (admin) |
| POST | `/api/monitoring/notifiers/{id}/test` | `{message?}` — sends a test notification |

Notifier bodies are the `monitoring.notifiers[]` YAML entries as JSON. Secret
fields may be given directly (`url`, `bot_token`, `username`, `password`) or
by env indirection (`url_env`, `bot_token_env`, `username_env`,
`password_env`). Writes are persisted to `config.yaml` atomically and take
effect immediately (hot reload).

## Files (per service)

All paths are relative to the service dir; `..`, absolute paths, `.git`
internals, and `.restic_password`/`.restic_inited` are rejected. Writes and
git mutations need the `edit_files` feature or admin.

| Method | Path | Notes |
|---|---|---|
| GET | `/api/services/{name}/files?path=` | dir → `{kind:"dir", entries:[{name,kind,size}]}`; file → `{kind:"file", content, size, truncated}` (512 KiB cap; binary → `{kind:"binary"}`) |
| PUT | `/api/services/{name}/files` | `{path, content}` — atomic write, creates parents |
| POST | `/api/services/{name}/files/mkdir` | `{path}` |
| POST | `/api/services/{name}/files/rename` | `{from, to}` |
| DELETE | `/api/services/{name}/files?path=` | file or dir (recursive); refuses the root |

## Git (per service)

Repos are discovered in the service dir and up to 3 levels deep. `path` is
relative to the service dir (""/"." = the dir itself). Mutating ops return
`{execution_id}` — stream output via `WS /ws/executions/{id}`.

| Method | Path | Notes |
|---|---|---|
| GET | `/api/services/{name}/git/repos` | `[{path, branch, remote, dirty}]` |
| GET | `/api/services/{name}/git/status?path=` | `{branch, remote, tracking, changes[]}` |
| GET | `/api/services/{name}/git/log?path=&n=` | up to 200 `hash date author subject` lines |
| GET | `/api/services/{name}/git/branches?path=` | `{current, local[], remote[]}` |
| POST | `/api/services/{name}/git/clone` | `{url, path?, branch?}` → execution |
| POST | `/api/services/{name}/git/action` | `{path, op: pull|fetch|checkout, git_ref?}` → execution |

Git runs inside the container (`git` is in the image); the service dir is
bind-mounted so host-side units see the same files. Refs/URLs are validated
(no `-` prefix, no `..`, no shell metachars).

## Users (admin)

| Method | Path | Notes |
|---|---|---|
| GET/POST   | `/api/users` | list / create `{name, password, roles?, access?, features?, compose_policy?}` |
| GET/PUT/DELETE | `/api/users/{name}` | self may GET itself |
| PUT | `/api/users/{name}/password` | `{password}` — self or admin |
| PUT | `/api/users/{name}/access` | `[{type: exact|glob|regex, pattern, effect: allow|deny}]` |

## Host systemd groups

| Method | Path | Notes |
|---|---|---|
| GET  | `/api/systemd/groups` | configured groups + custom commands |
| GET  | `/api/systemd/groups/{group}/status` | `systemctl list-units` filtered by group regex |
| POST | `/api/systemd/groups/{group}/restart` | restart all matching units |
| POST | `/api/systemd/groups/{group}/execute` | `{command_id}` — run a group custom command on all units |
| POST | `/api/systemd/units/{unit}/restart` | |
| POST | `/api/systemd/units/{unit}/execute` | `{command_id}` |
| GET  | `/api/systemd/units/{unit}/logs?lines=` | `journalctl -u` |

Unit names must match a configured group's `unit_regex` (admins bypass).

## Generic commands

| Method | Path | Notes |
|---|---|---|
| GET  | `/api/commands` | sections+items the caller may see (role-filtered) |
| POST | `/api/commands/{section}/{item}` | `{params}` → `{execution_id}` |

## Misc

| Method | Path | Notes |
|---|---|---|
| GET | `/api/health` | unauthenticated liveness |
| GET | `/api/config` | admin; effective config with secrets redacted |
| GET | `/api/config/status` | last reload `{ok, error, at}` |
| GET | `/api/policy` | caller's effective compose policy |
| GET | `/api/templates` | service templates |
| GET | `/api/audit` | admin; in-memory audit ring |
| GET | `/api/executions` `/api/executions/{id}` | execution history |

## WebSockets

| Path | Description |
|---|---|
| `WS /ws/services/{name}/logs?follow=1&tail=&grep=&regex=&exclude_regex=&stream=&container=` | live filtered log lines as `{container, service, stream, text}` JSON |
| `WS /ws/executions/{id}` | execution stream: `{"type":"execution_started"|"log_output"|"execution_finished", "data":{...}}` |
| `WS /ws/execute` | same, plus client may send `{"type":"run","section":i,"item":j,"params":{}}` |
| `WS /ws/events` | monitoring events: `monitor_state`, `alert_fired`, `alert_resolved`, `auto_action`, `config_reloaded` |

## GitOps

| Method | Path | Description |
|---|---|---|
| GET | `/api/gitops/status` | sync status: url, branch, targets, last result, pending count |
| POST | `/api/gitops/sync` | admin: pull + apply now |
| POST | `/api/gitops/push` | admin: commit & push pending local changes (no-op unless `push_changes`) |
| POST | `/api/gitops/webhook` | **public**, secret-verified (GitHub `X-Hub-Signature-256` or GitLab `X-Gitlab-Token`); triggers an async sync |

## MCP (Model Context Protocol)

The server also exposes the entire API surface as MCP tools over streamable
HTTP at `POST/GET /mcp` (rmcp). Authenticate the same way as the REST API:
`Authorization: Bearer <token>` (or `?token=`); unauthenticated requests get
401. Tool calls run the same handlers, so permissions, compose policies and
audit logging are identical.

Tool names mirror the API: `services_list`, `service_get`,
`service_action` (`{name, action}`), `service_get_compose` /
`service_put_compose`, `service_*_unit`, `service_logs`, `service_files` /
`service_write_file` / `service_mkdir` / `service_rename_file` /
`service_delete_file`, `service_git_*`, `service_backup_*`,
`service_*_monitoring` / `monitoring_*` / `notifier_*`, `systemd_*`,
`commands_list` / `command_run`, `container_exec`, `gitops_*`, `user_*` / `users_list`, `me`,
`logout_all`, `config_get` / `config_status`, `effective_policy`,
`templates`, `audit_list`, `executions_list` / `execution_get`, `health`.

Tools that launch long-running work (actions, backups, executes, clones)
return `{"execution_id": "…"}` — poll with `execution_get`. Complex config
bodies (`service_put_backup`, `service_put_monitoring`, `notifier_*`,
`user_*` features/access) accept a `config`/`rules` JSON object with the
same shape as the REST body.
