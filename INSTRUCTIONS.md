# DDM — Agent Instructions

Docker Deployment Manager (ddm) is a self-hosting manager for docker-compose
deployments on a single host. It is exposed to agents over an MCP endpoint
(`/mcp`) and a REST API, both authenticated with a JWT bearer token.

This document describes every service surface ddm exposes, what it is for,
and concrete examples of how to use it. It is the canonical reference for
MCP-connected agents; keep it in sync with `crates/ddm-server/src/mcp.rs`.

## Conventions

- **Auth**: send `Authorization: Bearer <token>`. Tokens are minted via
  `POST /api/auth/token` (or the web UI) and can be scoped — `services`,
  `actions`, `ops`, `service_creates` (max number of services the token may
  create) and `manage_created` (token may fully manage services it created
  itself, even outside its `services` allowlist). Scoped tokens only ever
  narrow permissions.
- **Async operations**: long-running calls (git clone/pull, backup run,
  restores, command execution, systemd restarts) return an
  `execution_id`. Poll it with `execution_get` until `status` is
  `done`/`failed`; output streams into the execution record.
- **Service names**: every compose project under the configured
  `services_root` is a *service*, named by its directory. All
  `name`-taking tools refer to that name.
- **Compose policy**: all compose writes are validated against a security
  policy (`strict` by default). Host networking, privileged containers,
  docker-socket mounts etc. are denied unless the deployment configures a
  permissive `policy_floor`/`unrestricted` policy. Check
  `effective_policy` before authoring compose files that need them.

## Service surfaces

### 1. Compose services — lifecycle

The core resource. Each service is a directory containing
`docker-compose.yml` plus optional `meta.yaml`, `.env`, data dirs and git
repos.

| Capability | MCP tools | REST |
|---|---|---|
| List services with status | `services_list` | `GET /api/services` |
| Service detail (containers, unit, meta) | `service_get` | `GET /api/services/{name}` |
| Create from compose YAML or template | `service_create` | `POST /api/services` |
| Delete (optionally `compose down`, keep dir) | `service_delete` | `DELETE /api/services/{name}` |
| Lifecycle actions | `service_action` | `POST /api/services/{name}/action` |
| Read / replace compose file | `service_get_compose`, `service_put_compose` | `GET/PUT /api/services/{name}/compose` |
| Read / replace systemd unit | `service_get_unit`, `service_put_unit` | `GET/PUT /api/services/{name}/unit` |
| Unit health check / regenerate | `service_check_unit`, `service_regenerate_unit` | `…/unit/check`, `…/unit/regenerate` |
| Filtered container logs | `service_logs` | `GET /api/services/{name}/logs` |

Actions: `pull`, `up`, `down`, `restart`, `update` (pull + `up -d
--remove-orphans`), `start`, `stop`, `enable`, `disable`.

**Examples**

- *Deploy an update*: `service_action {name:"web", action:"update"}` —
  pulls new images and recreates containers.
- *Create a service from a template*:
  `service_create {name:"blog", template_id:"hello-world",
  vars:{image:"nginx:alpine", port:"8081"}, create_unit:true, enable:true,
  start:true}`.
- *Create from raw compose*:
  `service_create {name:"api", compose:"services:\n  api:\n    image:
  ghcr.io/acme/api:1.4\n    ports: [\"8080:8080\"]\n", create_unit:true}`.
- *Debug a crash*: `service_logs {name:"api", tail:500, grep:"error"}`,
  then `container_exec {name:"api", container:"api-api-1",
  command:["sh","-c","env | sort"]}` to inspect the runtime environment.

### 2. Files inside a service dir

Arbitrary file operations within a service's directory (path traversal and
symlink protected; `.git` and restic secrets are off-limits).

| Tool | Purpose |
|---|---|
| `service_files` | List a directory or read a file (`path:""` = service root) |
| `service_write_file` | Write/overwrite a file |
| `service_mkdir` | Create a directory |
| `service_rename_file` | Move/rename |
| `service_delete_file` | Delete |

**Examples**

- Drop a config file: `service_write_file {name:"web", path:"config/app.yaml",
  content:"..."}` then `service_action {name:"web", action:"restart"}`.
- Inspect env: `service_files {name:"web", path:".env"}`.
- Bulk upload: the REST/WebDAV surface also supports tar/tar.gz upload and
  download of whole directories — see `docs/API.md`.

### 3. Git inside service dirs

Git operations on repos found inside a service directory. Mutating ops are
async (`execution_id`).

| Tool | Purpose |
|---|---|
| `service_git_repos` | Discover repos under the service dir |
| `service_git_status` / `service_git_log` / `service_git_branches` | Read-only git state |
| `service_git_clone` | Clone a repo into the service dir or a subdir (`branch` optional) |
| `service_git_action` | `pull`, `fetch`, or `checkout` (`git_ref` for checkout) |

**Examples**

- Vendor a compose repo: `service_git_clone {name:"infra", url:
  "https://github.com/acme/infra.git", path:"compose"}` then point the
  service at the cloned `docker-compose.yml`.
- Deploy a new release: `service_git_action {name:"app", path:"",
  op:"checkout", git_ref:"v1.5.0"}` then `service_action
  {name:"app", action:"restart"}`.
- Check drift before updating: `service_git_status {name:"app", path:""}`.

### 4. Backups (restic)

Per-service restic repositories (`repository_base` + service name). Config
lives in `meta.yaml` (`backup:`) and is manageable via tools.

| Tool | Purpose |
|---|---|
| `service_get_backup` / `service_put_backup` | Read/write backup config |
| `service_backup_check` | Verify repo/scripts are provisioned |
| `service_backup_provision` | Init restic repo, write backup scripts |
| `service_backup_run` | Run a backup now (async) |
| `service_backup_snapshots` | List snapshots |
| `service_backup_forget` | Apply retention policy (async) |
| `service_backup_ls` | List files inside a snapshot |
| `service_backup_restore` | Restore a snapshot to a target dir (async; `include` patterns for selective restore) |

Backup config JSON (`ServiceBackupConfig`):

```json
{
  "enabled": true,
  "paths": ["docker-compose.yml", "meta.yaml", "config"],
  "excludes": ["*.tmp", "cache/**"],
  "stdin_dumps": [
    {"filename": "db.sql", "service": "db",
     "command": ["pg_dump", "-U", "${POSTGRES_USER}", "app"],
     "env_file": ".env"}
  ],
  "schedule_enabled": true
}
```

**Examples**

- Back up a Postgres service: enable `stdin_dumps` with a `pg_dump`
  command — ddm streams the dump into the restic repo without touching
  disk (see `examples/pg-app`).
- Disaster recovery drill:
  `service_backup_snapshots {name:"db"}` → `service_backup_ls
  {name:"db", snapshot:"<id>", path:"db.sql"}` →
  `service_backup_restore {name:"db", snapshot:"<id>",
  target_dir:"/tmp/restore", include:["db.sql"]}`.

### 5. Monitoring & alerting

Health checks and log watchers per service; alerts go to configured
notifiers; guarded auto-actions (restart/stop/exec) with cooldowns and
flap suppression.

| Tool | Purpose |
|---|---|
| `service_get_monitoring` / `service_put_monitoring` | Read/write monitoring config |
| `service_monitoring_test` | Snapshot current health state |
| `monitoring_status` / `monitoring_status_service` | Current check state |
| `monitoring_events` | Recent alert events (`service`, `limit`) |
| `notifiers_list` / `notifier_create` / `notifier_update` / `notifier_delete` / `notifier_test` | Notifier management (admin) |

Monitoring config JSON (`ServiceMonitoringConfig`):

```json
{
  "health": {
    "enabled": true,
    "kind": "docker_healthcheck",
    "interval_secs": 60,
    "failure_threshold": 3,
    "notify": ["slack-ops"],
    "actions": [{"type": "restart", "after_failures": 3,
                 "cooldown_secs": 600, "max_attempts": 3}]
  },
  "log_alerts": [
    {"id": "panic", "regex": "(?i)(panic|fatal error|segfault)",
     "container": "*", "notify": ["slack-ops"],
     "cooldown_secs": 300}
  ]
}
```

`kind` is one of `docker_healthcheck`, `http` (needs `target` URL +
optional `expect_status`), `tcp` (`target` host + `port`),
`container_running`. Auto-action types: `restart`, `stop`,
`exec_command` (`section_index`/`item_index` into the configured command
sections).

**Examples**

- Watch a web app's HTTP endpoint:
  `service_put_monitoring {name:"web", config:{"health":{"kind":"http",
  "target":"http://localhost:8080/healthz", "expect_status":200,
  "notify":["slack-ops"]}}}`.
- Alert on errors in logs:
  `{"log_alerts":[{"id":"errors","regex":"ERROR","container":"*",
  "notify":["telegram-alerts"]}]}`.
- Self-healing: add `"actions":[{"type":"restart","after_failures":3}]`
  and ddm restarts the service automatically (bounded by
  `max_attempts`/`window_secs`).
- Verify wiring: `notifier_test {id:"slack-ops", message:"hello from ddm"}`.

### 6. Host systemd

DDM manages host-level systemd units grouped into *groups* defined in
`config.yaml` (`systemd.groups`), each with a `unit_regex` and optional
`custom_commands` (`docker_compose_pull`, `docker_compose_pull_restart`,
exec commands, ...).

| Tool | Purpose |
|---|---|
| `systemd_groups` | List configured groups |
| `systemd_group_status` | Status of all units in a group |
| `systemd_group_restart` | Restart every unit in a group (async) |
| `systemd_group_execute` | Run a group's custom command on all units (async) |
| `systemd_unit_restart` | Restart one unit (async) |
| `systemd_unit_execute` | Run a custom command on one unit (async) |
| `systemd_unit_logs` | Journal output for a unit (`unit`, `lines`) |

**Examples**

- After a host update: `systemd_group_restart {name:"ddm-services"}`.
- Pull new images across a group: `systemd_group_execute
  {target:"ddm-services", command_id:"pull"}`.
- Diagnose a failing unit: `systemd_unit_logs {unit:"ddm-svc-web.service",
  lines:200}`.

### 7. Generic command sections

Admin-configured command sections (`sections:` in `config.yaml`) — e.g.
"Disk usage", "Docker prune" — each item runnable on the host or inside a
container, with typed parameters.

| Tool | Purpose |
|---|---|
| `commands_list` | List sections/items (with parameter schemas) |
| `command_run` | Run `section`/`item` by index, `params` map (async) |
| `container_exec` | `docker exec` into a service's container (`container`, `command` as string or argv) |

**Examples**

- `commands_list` → find the "Disk usage" item indices →
  `command_run {section:0, item:0, params:{}}`.
- One-off container shell: `container_exec {name:"db", container:"db-db-1",
  command:["psql","-U","app","-c","SELECT 1"]}`.
- Bulk cleanup: `command_run` on the "Docker prune" item with
  `params:{"all":true}` — note `required_role`/permissions apply.

### 8. Users & access control (admin)

| Tool | Purpose |
|---|---|
| `users_list`, `user_get` | Inspect users |
| `user_create` | Create user: `name`, `password`, `roles`, `access` rules (`exact`/`glob`/`regex` + `allow`/`deny`), `features`, `compose_policy`, `restrictions` |
| `user_update` / `user_delete` / `user_set_password` | Modify users |
| `user_set_access` | Replace access rules |
| `me` | Own profile/permissions |

**Examples**

- Provision a read-only viewer:
  `user_create {name:"ci-viewer", password:"…", roles:["viewer"],
  access:[{"type":"glob","pattern":"*","effect":"allow"}]}`.
- Lock down a deploy bot: create a user with `create_services` +
  `run_commands` features only, then mint a token via `/api/auth/token`
  with `service_creates: 5, manage_created: true` — it can create and
  manage at most 5 services and nothing else.

### 9. GitOps

Mirror a git repository into the service root and/or config dir.
Triggered by `POST /api/gitops/webhook` (HMAC/GitLab token verified) or
interval polling; optional push-back of local changes.

| Tool | Purpose |
|---|---|
| `gitops_status` | Current sync state |
| `gitops_sync` | Pull repo and apply now (admin) |
| `gitops_push` | Commit & push local changes to the repo (admin) |

**Examples**

- Config-as-code workflow: edit service files locally, then
  `gitops_push` to commit them into the config repo; on the next
  `gitops_sync` (webhook or interval) every host converges.
- Emergency pull: `gitops_sync` after pushing a fix to the repo.

### 10. OCI registry

DDM embeds a minimal OCI registry at `/v2/` — `docker push` images
straight to it; manifests are imported into the local docker daemon.
Auth is the standard docker token dance against DDM credentials;
writes need the `push_images` feature (or admin). Configure the daemon
with `ddm-server:5000` (or your listen address) as an insecure registry.

**Examples**

- `docker tag myapp:latest ddm.local:5000/myapp:latest && docker push
  ddm.local:5000/myapp:latest` — then reference `myapp` in compose files
  on the host without a separate registry.

### 11. WebDAV file surface

Optional (`webdav.enabled`) WebDAV endpoint at `/dav` exposing the same
service dirs for standard file clients — browse, read, write, upload
tar/tar.gz archives. Same auth and path protections as the file API.

### 12. Misc

| Tool | Purpose |
|---|---|
| `templates` | List configured `service_templates` |
| `executions_list` / `execution_get` | Async execution history/status/output |
| `audit_list` | Audit log of mutating actions (admin) |
| `config_get` / `config_status` | Redacted effective config / reload status (admin) |
| `effective_policy` | Caller's compose policy |
| `health` | Liveness probe |

## Typical workflows

**Deploy a new app end-to-end**
1. `templates` / `services_list` — check for a fitting template.
2. `service_create` (template or raw compose, `create_unit:true,
   enable:true, start:true`).
3. `service_files`/`service_write_file` — drop env/config files.
4. `service_put_monitoring` + `service_put_backup` — wire alerts and
   backups.
5. `service_action {action:"up"}` if not started; `service_logs` to
   verify.

**Investigate an incident**
`monitoring_events` → `service_get` (container state) →
`service_logs {grep:...}` → `service_files` for config →
`container_exec` for live inspection → `service_action restart` or a
`commands_list`/`command_run` remediation.

**Operate safely with scoped tokens**
Mint short-lived tokens with the narrowest scope (`services`, `actions`,
`ops`, `service_creates`, `manage_created`). A token with
`services:["web"], actions:["restart","logs"], ops:["service_logs"]`
can only restart and read logs of `web` — nothing else.
