# DockerDeploymentManager (DDM) — Implementation Plan

A generic, containerized deployment manager for docker-compose–based services,
inspired by `~/dev/Noxeco/NoxecoDeploymentManager` but fully vendor-neutral.

---

## 1. Goals

- **Service lifecycle management** for compose-based services: status checks,
  update (pull + recreate), start/stop/restart, enable/disable.
- **Log access**: fetch logs (REST snapshot) and stream them live over
  WebSocket, with **server-side filtering** (substring, regex, stream, since).
- **Self-hosted**: the manager itself runs as a Docker container with
  `privileged: true` and `pid: host`, so it can drive the host's docker daemon
  (via `/var/run/docker.sock`) and host systemd (via `nsenter` into PID 1).
- **YAML config with hot reload** (`config.yaml`, watched via `notify`).
- **Web UI**: TypeScript WebComponents (Lit) — service management, log viewer,
  compose/unit editors, user administration, generic command panels.
- **Multi-user auth** with per-user service access restrictions
  (literal / glob / regex matchers, allow/deny rules).
- **Service creation** from templates or raw compose input.
- **Compose + systemd unit editing** through the API/UI.
- **Compose security policy** engine with sane defaults (deny `privileged`,
  host namespaces, docker.sock mounts, …) and per-user opt-out profiles.
- **Backup management**: generalized restic integration — per-service repos
  under a configurable base/prefix, generated `backup.sh`, streamed stdin
  dumps (pg_dump-style), and host systemd timers; run/check/snapshots/
  forget/restore via API, UI and client.
- **Monitoring & alerting**: per-service online checks (docker HEALTHCHECK,
  HTTP, TCP, container-running) and server-side log watchers matching
  error patterns; notifications via Slack/Telegram/email/generic webhook;
  optional automatic reactions (restart …) with cooldowns and flap
  suppression.
- **Generic command framework** (parity with the original): config-defined
  sections of parameterized command sequences.
- **Python client library + CLI** mirroring the API.
- **Full docs, examples, and a comprehensive test suite.**

## 2. Non-goals

- Not a general container orchestrator (no scheduling, scaling, multi-host).
- No Noxeco-specific domain logic (no hub sync, no S3 flags, no traefik
  installer — only generic equivalents where useful).
- The manager is not responsible for TLS termination itself (documented as a
  reverse-proxy concern; plain HTTP + optional self-signed note in docs).

## 3. Tech stack

| Component      | Choice                                                              |
|----------------|---------------------------------------------------------------------|
| Backend        | Rust 2021, axum 0.7 (HTTP + WS), tokio, serde/serde_yaml, notify, clap (server CLI), reqwest + lettre (notifiers) |
| Docker access  | `bollard` for the Docker socket API; `docker compose` CLI for compose ops |
| Host access    | `nsenter` into PID 1 namespaces (trait `HostExec`, swappable)         |
| Auth           | JWT (`jsonwebtoken`), password hashing via `argon2`                 |
| Frontend       | TypeScript + Lit, bundled with esbuild, served by the backend       |
| Client         | Python ≥3.10, `httpx` + `websockets`, argparse CLI (`ddm`)          |
| Tests          | `cargo test` (unit + integration), `pytest` (client), `vitest` (web)|
| Packaging      | Multi-stage `Dockerfile`; sample `docker-compose.yml` for the manager itself |

## 4. Repository layout

```
PLAN.md                      this file
README.md                    quickstart + feature overview
Cargo.toml                   workspace root
Dockerfile                   multi-stage build → runtime image
docker-compose.yml           reference deployment of DDM itself
.dockerignore .gitignore
crates/
  ddm-server/
    Cargo.toml
    src/
      main.rs              bootstrap, router, config watch, shutdown
      cli.rs               clap subcommands (serve, user *, hash, check-config)
      config.rs            config schema, load, hot-reload broadcast
      users.rs             user store (users.yaml), roles, matchers, write-back
      auth.rs              JWT issue/verify, axum extractors, login
      permissions.rs       service access evaluation (allow/deny, glob/regex)
      policy.rs            compose security policy validation
      compose.rs           compose file parse/normalize/edit helpers
      systemd.rs           unit templates, unit file write, daemon-reload
      hostexec.rs          HostExec trait: NsenterExec (default) / LocalExec
      docker.rs            bollard status/logs + compose CLI wrapper
      services.rs          service registry: discovery, meta, lifecycle
      exec.rs              command execution engine + broadcast log channels
      commands.rs          generic config command items (sections/items)
      backup.rs            restic config, backup.sh render, timers, snapshots
      monitor.rs           health checks, log watchers, alert state machine
      notify.rs            notifiers: slack, telegram, email (lettre), webhook
      logs.rs              log filtering pipeline (grep/regex/since/stream)
      audit.rs             audit log (ring buffer + optional file append)
      ws.rs                websocket protocol & handlers
      webui.rs             static asset serving (rust-embed)
      api/
        mod.rs             router assembly
        auth.rs            /api/auth/*
        users.rs           /api/users/*
        services.rs        /api/services/*
        executions.rs      /api/executions/*
        systemd_api.rs     /api/systemd/*
        commands_api.rs    /api/commands/*
        config_api.rs      /api/config, /api/audit
    tests/
      policy.rs permissions.rs config.rs compose.rs systemd.rs
      api_auth.rs api_services.rs ws_logs.rs integration.rs
web/
  package.json tsconfig.json esbuild.mjs index.html
  src/
    api.ts auth-store.ts router.ts
    components/
      ddm-app.ts ddm-login.ts ddm-service-list.ts ddm-service-detail.ts
      ddm-log-viewer.ts ddm-compose-editor.ts ddm-unit-editor.ts
      ddm-service-wizard.ts ddm-user-list.ts ddm-user-edit.ts
      ddm-command-panel.ts ddm-exec-output.ts ddm-backup-panel.ts
      ddm-monitor-panel.ts ddm-events-view.ts
  test/ (vitest: matchers, log filter helpers)
client/
  pyproject.toml README.md
  ddm_client/
    __init__.py client.py cli.py ws.py models.py errors.py
  tests/ (pytest: client API against mocked transport + WS protocol)
examples/
  config.yaml users.yaml
  services/hello-world/docker-compose.yml
  services/pg-app/{docker-compose.yml,meta.yaml}   # stdin_dump + monitoring ex.
  templates/                 service templates
  systemd/ddm.service        unit template example
  deploy/docker-compose.yml  self-deployment example
  client_demo.py
docs/
  configuration.md api.md security.md web-ui.md client.md
  deployment.md development.md architecture.md
.github/workflows/ci.yml
```

## 5. How the container reaches the host

DDM runs `privileged: true`, `pid: "host"`, with these mounts:

```yaml
services:
  ddm:
    build: .
    privileged: true
    pid: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock   # docker daemon API
      - ./config.yaml:/etc/ddm/config.yaml:ro       # hot-reload config
      - ./users.yaml:/etc/ddm/users.yaml            # user store (rw via API)
      - /opt/services:/services                     # managed service dirs
      - /etc/systemd/system:/host/systemd           # unit file management
    ports: ["8080:8080"]
    restart: unless-stopped
```

Host command execution uses a `HostExec` trait with two implementations:

- **`NsenterExec` (default in container)** — runs
  `nsenter --target 1 --mount --uts --ipc --net -- <prog> <args>`
  (PID ns already shared via `pid: host`). Used for `systemctl`,
  `journalctl`, `systemd-analyze verify`. The host's own binaries do the work,
  so no systemd/dbus plumbing inside the image is needed.
- **`LocalExec`** — direct `Command::new` for dev/bare-metal runs
  (`host_exec: local` in config).

Docker operations never need nsenter: `docker compose` and `bollard` talk to
`/var/run/docker.sock` directly. Unit files are written to the bind-mounted
`/host/systemd`, then `systemctl daemon-reload` runs via `HostExec`.

## 6. Configuration

`config.yaml` (all sections hot-reloaded; invalid reloads are rejected with an
error surfaced via `GET /api/config/status` and the previous config stays live):

```yaml
server:
  listen: "0.0.0.0:8080"
  jwt_secret_env: DDM_JWT_SECRET      # env var name holding the HMAC secret
  token_ttl_minutes: 720
  cors_origins: []                    # empty = same-origin only

paths:
  services_root: /services            # path inside the container
  host_services_root: /opt/services   # same dir as seen by the HOST (units, backup.sh)
  compose_file: docker-compose.yml    # also accepts compose.yaml on discovery
  host_systemd_dir: /host/systemd
  host_exec: nsenter                  # nsenter | local
  nsenter_target: 1

docker:
  socket: /var/run/docker.sock
  compose_command: ["docker", "compose"]

logging:
  default_tail: 200
  max_tail: 5000
  history_executions: 200

security:
  default_access: deny                # for users without matching rule
  default_policy: strict
  policies:
    strict:
      deny_privileged: true
      deny_host_namespaces: true      # pid/network/ipc/uts/user "host"
      deny_docker_socket: true
      deny_devices: true
      cap_add: { mode: allowlist, list: [] }
      sysctls: { mode: allowlist, list: [] }
      allowed_bind_sources: ["/services/**", "/data/**"]
      deny_bind_targets: ["/", "/etc/**", "/root/**"]
      allowed_port_range: [1024, 65535]
      allowed_registries: []          # empty = any
      max_services_per_compose: 20
    relaxed: { ...subset of strict... }
  unit_edit_requires: admin           # role needed for raw unit file edits

backup:
  enabled: true
  restic_binary: auto              # resolved on the HOST via HostExec `which`
  # Per-service repo = base + service name ("directory/prefix" style).
  # Works for rest-server ("rest:http://…/"), s3 ("s3:…/prefix/"), local, sftp.
  repository_base: "rest:http://restic:pass@10.1.2.3:16383/"
  # repository_template: "{base}{service}"  # override; {base},{service} subst.
  password_mode: per_service_file  # .restic_password in the service dir (0600)
  extra_env: {}                    # e.g. AWS_ACCESS_KEY_ID for s3 backends
  excludes: ["**/__pycache__", "*.tmp", "**/.git"]   # appended to per-svc list
  retention:                       # optional forget --prune after each backup
    keep_last: 7
    keep_daily: 7
    keep_weekly: 4
  scheduler: systemd_timer         # systemd_timer | internal | none
  on_calendar: "daily"             # timer schedule
  unit_prefix: "ddm-backup"        # units: ddm-backup-<svc>.service/.timer

monitoring:
  enabled: true
  allow_auto_actions: true         # master switch for restart/exec reactions
  check_interval_secs: 30          # default interval for health checks
  state_dir: /var/lib/ddm          # alert state, cooldown bookkeeping
  notifiers:
    - id: slack-ops
      type: slack_webhook
      url_env: DDM_SLACK_WEBHOOK_URL     # secrets via env, not in yaml
    - id: telegram-ops
      type: telegram
      bot_token_env: DDM_TELEGRAM_TOKEN
      chat_id: "123456789"
    - id: mail-ops
      type: email
      smtp_host: smtp.example.com
      smtp_port: 587
      smtp_tls: starttls
      username_env: DDM_SMTP_USER
      password_env: DDM_SMTP_PASS
      from: "ddm@example.com"
      to: ["ops@example.com"]
    - id: generic-hook
      type: webhook                      # POST JSON {event, service, ...}
      url: "https://hooks.example.com/ddm"
      headers: {}
  defaults:                            # applied to every monitored service
    notify: [slack-ops]
    failure_threshold: 3
    cooldown_secs: 300
  rules:                               # global rules over service matchers
    - services: {glob: "db-*"}
      log_alerts:
        - {id: db-errors, regex: '(?i)(panic|fatal)', notify: [mail-ops]}

service_templates:
  - id: generic-web
    title: "Generic web service"
    description: "Compose + systemd unit skeleton"
    compose_template: /etc/ddm/templates/generic-web.compose.yml
    create_unit: true

systemd:
  # Default unit template follows the TechOverflow "docker-compose systemd
  # service" style (see §8a). {service}, {dir}, {compose_file}, {compose_bin}
  # are substituted. A custom template file may replace it.
  unit_template: /etc/ddm/templates/ddm.service.tpl   # optional; built-in default below
  compose_binary: auto              # auto | /usr/bin/docker-compose | "docker compose"
  daemon_reload_after_change: true
  groups:                             # parity w/ original: host unit views
    - id: infra
      title: "Infrastructure"
      unit_regex: '^ddm.*\.service$'
      parallel_group_actions: true
      max_group_concurrency: 4
      custom_commands:
        - type: docker_compose_pull
          id: pull
          label: "Pull"
        - type: docker_compose_pull_restart
          id: pull_restart
          label: "Pull+Restart"
        - type: shell
          id: status
          label: "systemctl status"
          program: systemctl
          args: ["status", "${unit}"]

sections:                             # generic parameterized commands
  - title: "Utilities"
    required_role: operator           # optional gate per section/item
    items:
      - title: "Disk usage"
        work_dir: "."
        parameters: []
        command_sequence:
          - program: /bin/df
            args: [{type: value, value: "-h"}]
```

`users.yaml` (separate file so config stays secret-free; hot-reloaded; the API
writes back on user mutations):

```yaml
users:
  - name: admin
    password_hash: "$argon2id$..."    # argon2id; bootstrap via env/CLI
    roles: [admin]
  - name: ops
    password_hash: "$argon2id$..."
    roles: [operator]
    access:                           # evaluated top-down, first match wins
      - {type: glob, pattern: "web-*", effect: allow}
      - {type: regex, pattern: '^staging-[0-9]+$', effect: allow}
      - {type: exact, pattern: "infra-core", effect: deny}
    features:
      create_services: true
      edit_compose: true
      edit_units: false
      run_commands: true
    compose_policy: strict            # named policy or "unrestricted" opt-out
```

Roles: `admin` (everything, bypasses matchers), `operator` (manage allowed
services), `viewer` (read-only status/logs on allowed services). A `deny` rule
always wins over earlier `allow`s — actually **first-match-wins** semantics:
rules are evaluated in order; document clearly. Deny listed first = blacklist
style; allows listed first with trailing implicit deny = whitelist style.

## 7. API surface (HTTP + WS)

All endpoints except `/api/auth/login` require `Authorization: Bearer <jwt>`.
WebSockets authenticate via `Sec-WebSocket-Protocol: bearer.<token>`
(preferred) or `?token=` fallback.

### Auth
- `POST /api/auth/login` `{name, password}` → `{token, user, roles, expires_at}`
- `GET /api/auth/me` → current user + effective permissions
- `POST /api/auth/logout-all` (admin) — rotate JWT secret, invalidate tokens

### Users (admin)
- `GET /api/users` · `POST /api/users` · `GET/PATCH/DELETE /api/users/{name}`
- `PUT /api/users/{name}/password` · `PUT /api/users/{name}/access`
- `PUT /api/users/{name}/features` · `PUT /api/users/{name}/policy`

### Services
- `GET /api/services` — list with aggregated container + unit status,
  **filtered to caller's allowed set**
- `GET /api/services/{name}` — detail (meta, containers, unit state, policy)
- `POST /api/services` — create: `{name, compose | template_id+vars,
  create_unit, enable, start}` → validated against caller's policy
- `DELETE /api/services/{name}` — remove (optional `--keep-dir`)
- `GET /api/services/{name}/compose` → raw YAML
- `PUT /api/services/{name}/compose` — replace; policy-validated, atomic write,
  optional `{"recreate": true}` to `up -d` after save
- `GET /api/services/{name}/unit` → unit file (+generated-vs-custom flag)
- `GET /api/services/{name}/unit/check` → `UnitCheckReport` for existing
  services (see §8a): `{exists, enabled, active, in_sync, workdir_ok,
  issues: [{code, message, fixable}]}`
- `PUT /api/services/{name}/unit` — write unit (requires `unit_edit` right),
  daemon-reload
- `POST /api/services/{name}/unit/regenerate` — re-render from template,
  daemon-reload (and optionally `enable`/`restart`) — the "repair" action for
  issues reported by `unit/check`
- `POST /api/services/{name}/actions` `{action: pull|up|down|restart|update|
  start|stop|enable|disable}` → `{execution_id}`
  (`update` = pull + up -d --remove-orphans, the "deploy" op)
- `GET /api/services/{name}/logs?tail=&since=&grep=&regex=&stream=&container=`
  → filtered snapshot

### Backup (restic, see §8b)
- `GET /api/services/{name}/backup` — effective backup config for the service
- `PUT /api/services/{name}/backup` — update per-service backup config
  (paths, excludes, stdin dumps, schedule enable)
- `GET /api/services/{name}/backup/check` → `BackupCheckReport`:
  `{password_file, script, repo_inited, timer_exists, timer_enabled,
  timer_active, last_run, issues[]}` — same pattern as `unit/check`
- `POST /api/services/{name}/backup/provision` — generate `.restic_password`,
  `backup.sh`, run `restic init`, install + enable the timer (idempotent repair)
- `POST /api/services/{name}/backup/run` → `{execution_id}` — run `backup.sh`
  now, output streamed via `/ws/executions/{id}`
- `GET /api/services/{name}/backup/snapshots` — `restic snapshots --json`
- `POST /api/services/{name}/backup/forget` → `{execution_id}` — retention
  (`forget --prune`) run
- `POST /api/services/{name}/backup/restore` `{snapshot, target_dir}` →
  `{execution_id}` — restores into `target_dir` (admin/unrestricted only;
  in-place restore is documented as a manual op)

### Monitoring & alerting (see §8c)
- `GET /api/monitoring/status` — per-service monitor state (filtered to
  caller's services): `{service, checks: [{id, type, state, last_ok,
  failures}], log_alerts: [{id, state, last_match}], suppressed}`
- `GET /api/monitoring/status/{service}` — detail incl. recent matched lines
- `GET /api/monitoring/events?service=&since=&limit=` — alert event history
  (firing/resolved/action taken/notification sent)
- `GET /api/services/{name}/monitoring` · `PUT` — per-service monitor config
  (persisted to `meta.yaml`; requires `edit_compose` right)
- `POST /api/services/{name}/monitoring/test` — run checks once, return results
- `POST /api/monitoring/notifiers/{id}/test` `{message}` — send test
  notification (admin)
- `GET /api/monitoring/notifiers` — configured notifiers, secrets redacted
- `WS /ws/events` — global push channel for UI badges:
  `MonitorState{service, check, state}`, `AlertFired{event}`,
  `AlertResolved{event}`, `AutoAction{service, action, result}`

### Log streaming
- `WS /ws/services/{name}/logs?follow=1&tail=&grep=&regex=&stream=` — live
  `docker compose logs -f` equivalent via bollard, server-side filtered
- `WS /ws/executions/{id}` — stream a running execution:
  `ExecutionStarted` / `LogOutput{id,text,stream}` / `ExecutionFinished{success}`
- `GET /api/executions` · `GET /api/executions/{id}` — history/status

### Systemd (host units, parity with original)
- `GET /api/systemd/groups` · `GET /api/systemd/groups/{id}/status`
- `POST /api/systemd/units/{unit}/restart` · `POST .../groups/{id}/restart`
- `POST /api/systemd/units/{unit}/execute` · `POST .../groups/{id}/execute`
- `GET /api/systemd/units/{unit}/logs?lines=` (journalctl via HostExec)

### Generic commands
- `GET /api/commands` — sections/items visible to caller
- `POST /api/commands/{section_idx}/{item_idx}` `{params}` → `{execution_id}`

### Misc
- `GET /api/config` — effective config (secrets redacted)
- `GET /api/config/status` — last reload result/timestamp
- `GET /api/policy` — caller's effective compose policy
- `GET /api/audit` — audit log (admin)
- `GET /api/health`

### 7a. Server CLI — user management inside the running container

The `ddm-server` binary doubles as an admin CLI (clap subcommands). It works
directly on `users.yaml`, so it functions **inside the running container**
(`docker compose exec ddm ddm-server user …`) and even when the HTTP API is
down — covering first-admin bootstrap and lockout recovery. Writes are
atomic (tmp+rename under `flock`); the running server picks them up via the
same hot-reload watch, no restart needed.

```
ddm-server serve [--config /etc/ddm/config.yaml]     # default: run the daemon
ddm-server user list
ddm-server user add <name> --role admin [--password P | --generate | --prompt]
ddm-server user remove <name>
ddm-server user passwd <name> [--password P | --generate | --prompt]
ddm-server user set-roles <name> --role operator --role viewer
ddm-server user set-access <name> \
    --allow 'glob:web-*' --allow 'regex:^stg-[0-9]+$' --deny 'exact:core'
ddm-server user set-features <name> --create-services --no-edit-units
ddm-server user set-policy <name> --policy strict|relaxed|unrestricted
ddm-server user show <name>
ddm-server hash [password]              # print an argon2 hash for manual edits
ddm-server check-config [--config …]    # validate config + users, exit non-0 on error
ddm-server unit-template <name> --dir /services/x   # print rendered unit (debug)
```

`--generate` prints a random password once; without secrets on the CLI it
prompts on TTY. All CLI ops are journaled to stderr/audit like API calls.
Bootstrap path for fresh installs: `docker compose exec ddm ddm-server user
add admin --role admin --generate` (documented in README quickstart).

## 8. Compose security policy

`policy.rs` parses compose YAML (via `serde_yaml` → typed model with
`#[serde(flatten)]` catch-alls) and produces `Vec<PolicyViolation>{path, rule,
message}`. Strict defaults reject:

- `privileged: true`, `cap_add` outside allowlist, `security_opt` disabling
  isolation, `user: root` warning (configurable to deny)
- `pid|network|ipc|uts|userns|cgroup` mode `host` / `service:*`
- bind-mounting `/var/run/docker.sock` or any source outside
  `allowed_bind_sources` globs; `..` path escapes; targets in
  `deny_bind_targets`
- `devices`, `sysctls` outside allowlist, `ports` host side outside allowed
  range, images outside `allowed_registries` (if non-empty)
- `extends`/`include` referencing paths outside the service dir
- service count above `max_services_per_compose`

Users carry `compose_policy: <name>`; `unrestricted` skips validation entirely
(the opt-out). Violations are returned in the API error and shown inline in
the compose editor. **All compose writes are validated server-side** — the UI
editor is never the enforcement point.

Systemd edits: raw `PUT unit` requires `edit_units` feature (default admin
only); `regenerate` produces a templated unit and is allowed for service
editors. Unit content is sanity-checked (must contain `[Unit]`/`[Service]`,
no `ExecStart` pointing outside allowed roots unless unrestricted).

### 8a. systemd unit management (TechOverflow style)

New services get a unit rendered in the style of the TechOverflow
"docker-compose systemd service" — the compose project runs **in the
foreground** under a `simple` unit so systemd tracks the compose process and
restarts it on failure:

```ini
[Unit]
Description={service}
Requires=docker.service
After=docker.service

[Service]
Restart=always
User=root
Group=docker
TimeoutStopSec=15
WorkingDirectory={dir}
# Shutdown container (if running) when unit is started
ExecStartPre={compose_bin} -f {compose_file} down
ExecStart={compose_bin} -f {compose_file} up
ExecStop={compose_bin} -f {compose_file} down

[Install]
WantedBy=multi-user.target
```

Notes:

- `{compose_bin}` resolves on the **host** (via `HostExec` `which`), not in
  the container — `compose_binary: auto` tries `docker compose` (v2 plugin)
  then `docker-compose`, and can be pinned in config.
- The unit deliberately runs `up` in the foreground (not `up -d`): with
  `Restart=always` + `TimeoutStopSec=15`, systemd supervises the compose
  process, and `ExecStartPre=down` cleans up leftovers on every start.
- Service name = directory name (validated `^[a-z0-9][a-z0-9_.-]*$`).
- Creation flow mirrors the article: render → write to
  `host_systemd_dir/{service}.service` → `daemon-reload` → `systemctl enable`
  → `systemctl start` (the last two driven by the create request's
  `enable`/`start` flags).

**Checks for existing services** — `GET /api/services/{name}/unit/check`
returns a `UnitCheckReport` so drift and missing pieces are diagnosable and
repairable from the UI/API:

| Check                        | Issue code        | Fixable via `regenerate` |
|------------------------------|-------------------|--------------------------|
| Unit file exists             | `missing`         | yes |
| `systemctl is-enabled`       | `not_enabled`     | yes |
| `systemctl is-active`        | `inactive`        | yes (with `start`) |
| `WorkingDirectory` = svc dir | `workdir_mismatch`| yes |
| `Exec*` references compose   | `compose_mismatch`| yes |
| Content == rendered template | `content_drift`   | yes |
| `Requires=docker.service`    | `docker_dep_missing` | yes |
| `systemd-analyze verify`     | `invalid_unit`    | yes |

The service detail endpoint embeds a compact `{unit: {exists, enabled,
active, in_sync}}` summary so the list view can badge unhealthy units. A
"Check/Repair" action in `ddm-service-detail` runs `unit/check` and offers
`regenerate` (+`enable`/`start`) when fixable issues exist.

### 8b. Backup management (restic)

Generalized version of the TechOverflow restic setup: each service gets a
generated `backup.sh` in its directory, a `.restic_password` (0600,
auto-generated, **never returned by the API**), a per-service repository
formed by `repository_base + service name` (the "directory/prefix" scheme —
`rest:http://host:port/<svc>`, `s3:bucket/prefix/<svc>`, local dir, sftp), a
`.restic_inited` marker for one-time `restic init`, streamed pre-backup dumps
via `docker compose exec -T … | restic backup --stdin`, and a host systemd
service+timer for scheduling. Generated `backup.sh` (conceptual):

```bash
#!/bin/bash
set -euo pipefail
export NAME="{service}"
export RESTIC_REPOSITORY="{repository}"          # base + name
export RESTIC_PASSWORD_FILE="{dir}/.restic_password"
{extra_env_exports}
cd "{dir}"                                       # HOST path (host_services_root)

[ -f ".restic_inited" ] || { restic init && touch .restic_inited; }

# streamed stdin dumps (e.g. PostgreSQL)
{for each stdin_dump:}
{compose_bin} exec -T {dump.service} {dump.command} \
  | restic --verbose backup --stdin --stdin-filename="{dump.filename}"
{/for}

restic --verbose backup {paths} {excludes...}
restic forget --prune {retention_args}            # if retention configured
```

Per-service backup config lives in `meta.yaml` next to the compose file:

```yaml
backup:
  enabled: true
  paths: ["docker-compose.yml", "backup.sh", "data"]   # relative to svc dir
  excludes: ["data/tmp"]
  stdin_dumps:                       # the pg_dump pattern, generalized
    - filename: "{service}.sql"      # or fixed name
      service: database              # compose service to exec into
      command: ["pg_dump", "-U", "${POSTGRES_USER}", "${POSTGRES_DB}"]
      env_file: .env                 # optional; sourced for ${VAR} expansion
  schedule_enabled: true             # install/enable the systemd timer
```

Details:

- `backup.sh` and the timer units run on the **host** via `HostExec`
  (restic must exist on the host — `restic_binary: auto` resolves it, and
  `backup/check` reports `restic_missing` if absent). `WorkingDirectory` and
  script paths use `paths.host_services_root` (the host-side equivalent of
  the container's `services_root` mount — required anyway for §8a units).
- Generated timer pair: `ddm-backup-<svc>.service` (`Type=oneshot`,
  `ExecStart=<host_dir>/backup.sh`) + `ddm-backup-<svc>.timer`
  (`OnCalendar=<on_calendar>`, `Persistent=true`); enabled via host
  `systemctl`. `scheduler: internal` instead runs generated scripts on a
  tokio interval; `none` = manual/API runs only.
- `backup/provision` is idempotent: create password (pwgen-style random),
  render script, `restic init`, write units, `daemon-reload`,
  `enable --now <timer>`. `backup/check` issues: `password_missing`,
  `script_missing`, `repo_not_inited`, `timer_missing`, `timer_disabled`,
  `restic_missing`, `never_run` — all fixable via `provision`.
- Snapshots/forget/restore run `restic --json` via HostExec with the
  service's env; parse and return structured JSON. Restore requires
  `edit_units`-equivalent elevation (admin or `compose_policy:
  unrestricted`) and writes to an explicit `target_dir`.
- `paths` in `meta.yaml` are validated: relative-only, no `..`, must exist
  inside the service dir. Compose policy also forbids bind-mounting
  `.restic_password` into containers.
- Backup runs go through the normal execution engine — visible under
  `/ws/executions/{id}` and in audit.

### 8c. Monitoring, alerting & auto-reactions

A lightweight in-process monitor (no external Prometheus dependency) covering
three primitives per service, configured in `meta.yaml` (merged with
`monitoring.defaults` and global `monitoring.rules` selected by the same
match engine used for user access):

```yaml
monitoring:
  health:
    enabled: true
    type: docker_healthcheck        # docker_healthcheck | http | tcp | container_running
    # http extras: url: http://127.0.0.1:8080/healthz  expect_status: 200
    #              timeout_secs: 5  (probed via the container network/ns)
    # tcp extras:  host: 127.0.0.1  port: 5432
    interval_secs: 30
    failure_threshold: 3            # consecutive failures → "down"
    recovery_threshold: 2           # consecutive successes → "recovered"
    notify: [slack-ops, mail-ops]
    actions:
      - type: restart             # docker compose restart / systemctl restart
        after_failures: 3
        cooldown_secs: 300
        max_attempts: 3           # per window_secs; then suppress+alert
        window_secs: 900
  log_alerts:
    - id: errors
      regex: '(?i)\b(error|panic|fatal|exception)\b'
      exclude_regex: '(?i)healthcheck'   # optional noise filter
      container: "*"                     # or a compose service name
      notify: [slack-ops]
      cooldown_secs: 300                 # min interval between notifications
      context_lines: 3                   # matched ±N lines in notification
      actions:
        - {type: restart, cooldown_secs: 600, max_attempts: 2, window_secs: 3600}
```

- **Health checks**: `docker_healthcheck` polls container `Health.Status`
  via bollard (uses the image's HEALTHCHECK — zero extra config); `http`
  probes a URL (inside the container's network namespace via `docker exec`
  `wget/curl` or from the manager when the port is published); `tcp` connects
  to host:port; `container_running` = "all compose containers running".
  Each check is a state machine `ok → failing(1..N) → down` and back
  through `recovery_threshold`; transitions emit events + notifications.
- **Log watchers**: long-lived `docker logs -f --since now` streams (bollard)
  per service; each line runs through the alert's `regex`/`exclude_regex`.
  Matches are grouped per alert id; a notification contains the matched
  excerpt. `cooldown_secs` + `max_per_cooldown` bound the noise; a dedup key
  (service+rule+line-hash) collapses repeats.
- **Notifiers** (`notify.rs`): `slack_webhook` (Incoming Webhook JSON),
  `telegram` (bot `sendMessage`), `email` (SMTP via `lettre`, starttls/tls),
  `webhook` (generic POST JSON for ntfy/Gotify/Discord-compatible endpoints).
  Secrets come from `*_env` indirection — never stored in config. All sends
  are retried with backoff and logged to audit; `notifiers/{id}/test` verifies.
- **Auto-reactions**: `restart` (compose restart, or `systemctl restart` when
  a managed unit exists), `stop`, and `exec_command` (a configured generic
  command item). Guard rails: `monitoring.allow_auto_actions` master switch,
  per-action `cooldown_secs`, `max_attempts` per `window_secs`, and flap
  detection — when attempts are exhausted the rule is `suppressed` and a
  final "auto-remediation exhausted" alert fires instead of looping.
- **State**: monitor state + cooldowns persist under `monitoring.state_dir`
  (survives container restarts); events feed `/api/monitoring/events`,
  `WS /ws/events`, and the audit log.
- **Permissions**: status/events visible to anyone with service access;
  editing monitor config requires `edit_compose`; notifier CRUD and
  auto-action toggles are admin-only.

## 9. Frontend (Lit + TS)

- `esbuild.mjs` bundles `web/src/main.ts` → `web/dist` (embedded via
  `rust-embed` in release, served from disk in dev).
- `api.ts`: typed REST client with token store (localStorage) + auto-401
  logout; `ws.ts`: reconnecting WS helper.
- Hash router (`#/services`, `#/services/:name`, `#/services/:name/logs`, …).
- Key components:
  - `ddm-service-list`: status cards, group-by group, actions per service
    (update/restart/stop), visible per permissions.
  - `ddm-service-detail`: containers, unit state, action buttons, links to
    editors/logs.
  - `ddm-log-viewer`: streaming view with follow toggle, filter inputs
    (grep/regex/stream) applied **server-side** on re-subscribe, ANSI-stripped
    rendering, pause buffer.
  - `ddm-compose-editor` / `ddm-unit-editor`: textareas with validation-error
    panel, save + recreate checkbox.
  - `ddm-service-wizard`: name + template or paste-compose + create-unit toggle.
  - `ddm-user-list` / `ddm-user-edit`: roles, feature toggles, matcher list
    editor (type/pattern/effect rows), policy select, password reset.
  - `ddm-backup-panel` (in service detail): backup config form, provision /
    check report, "run now", timer status, snapshot list, forget/restore.
  - `ddm-monitor-panel` (in service detail): live health state via
    `WS /ws/events`, health-check + log-alert rule editors, "test notifier"
    button, suppression indicators.
  - `ddm-events-view`: global event feed (firing/resolved/auto-actions).
  - Service list/detail get health badges driven by `WS /ws/events`.
  - `ddm-command-panel` + `ddm-exec-output`: render config sections; run
    commands and stream output via `/ws/executions/:id`.
- `vitest` for pure helpers (pattern matching display, filter building).

## 10. Python client

`client/ddm-client` package (`pip install ./client`):

```python
from ddm_client import Client
c = Client("http://host:8080", name="ops", password="...")
for s in c.services():          # list allowed services
    print(s.name, s.status)
print(c.logs("web-1", tail=100, grep="error"))
for ev in c.follow_logs("web-1", regex="WARN|ERROR"): ...
c.update("web-1", follow=True)  # pull+up, streams execution output
c.put_compose("web-1", yaml_text)
```

CLI `ddm`: `login`, `services`, `status`, `logs [--follow --grep --regex
--since --tail]`, `update|restart|start|stop [--unit|--all-allowed]`,
`create --template|--compose`,
`compose get|put`, `unit get|put|regenerate|check|repair`,
`backup run|check|provision|snapshots|forget|restore`,
`monitor status|events|test`, `notify-test <id>`,
`users list|add|passwd|access`, `exec <section> <item>` — mirroring
`noxeco_manager.py` ergonomics, but talking to the real API (JWT bearer).
Websocket via `websockets`; REST via `httpx`; `pytest` suite using
`httpx.MockTransport` + an in-proc WS echo harness for protocol tests.

## 11. Testing strategy

- **`cargo test`** unit tests next to each module:
  - config: schema parse, defaults, invalid reload rejection, redaction
  - permissions: glob/regex/exact, allow/deny ordering, defaults, admin bypass
  - policy: every rule (+ compose fixtures in `tests/fixtures/*.yml`),
    unrestricted bypass, edge cases (short/long volume syntax, port forms)
  - compose/service: discovery, name validation, atomic writes, meta
  - systemd: TechOverflow-style template render, `UnitCheckReport` logic
    (missing/not_enabled/workdir_mismatch/content_drift/…), unit validation,
    HostExec command building, `compose_binary: auto` resolution order
  - logs: filter pipeline correctness (grep/regex/since/stream)
  - commands: arg building (value/variable/conditional/optional — ported
    from the original), sequence stop-on-failure
  - cli: `user add/passwd/set-access` against a tempdir users.yaml (assert
    file round-trips, hashes verify, watcher-free standalone operation)
  - backup: `backup.sh` render (repo URL templating, stdin dumps, excludes,
    retention args), timer/service unit render, `BackupCheckReport` logic,
    meta.yaml parse + path validation, password-file generation/permissions
  - monitor: check state machine (thresholds, recovery), cooldown /
    max_attempts / flap suppression, log-line regex matching + dedup,
    notifier payload formatting (mock HTTP/SMTP), meta.yaml merge of
    monitoring config, `allow_auto_actions` gate
- **Integration tests** (`crates/ddm-server/tests/`): spin the axum `Router`
  against a `tempdir` services root with a **scripted `MockHostExec`** and a
  docker-socket shim; exercise login → service create → policy rejection →
  compose PUT → execution WS via `tokio-tungstenite` on an ephemeral port.
- **pytest** for `ddm_client` (mocked transport, WS handshake, filter params,
  error mapping).
- **vitest** for web helpers.
- Optional `tests_e2e/smoke.sh`: builds the image, runs DDM in a throwaway
  compose project on a docker-capable host, creates a hello-world service,
  updates it, fetches logs (documented; run manually).

## 12. Docs & examples

- `README.md`: 5-minute quickstart (`docker compose up` on the example).
- `docs/configuration.md`: full `config.yaml`/`users.yaml` reference.
- `docs/api.md`: every endpoint + WS protocol schemas.
- `docs/security.md`: threat model, policy rules table, opt-out guidance,
  hardening notes (why `privileged`/`pid:host` is needed, socket risk).
- `docs/deployment.md`: self-install as compose service + optional systemd
  unit for the manager itself; upgrades.
- `docs/web-ui.md`, `docs/client.md`, `docs/development.md`, a
  `docs/server-cli.md` covering in-container user management/recovery,
  `docs/backup.md` covering the restic setup end-to-end (incl. password
  handling warnings from the article: back up `.restic_password` separately),
  and `docs/monitoring.md` (check types, rule syntax, notifier setup,
  auto-action guard rails).
- `examples/`: ready-to-run config, users (with a printed bootstrap-password
  note), hello-world service, template, unit template, client demo.

## 13. Milestones

1. Workspace scaffold; config + users schema, hot reload, `HostExec`
2. Auth (JWT/argon2) + permission engine + server CLI user management + tests
3. Docker layer (bollard status/logs) + compose CLI wrapper + service registry
4. Execution engine + broadcast channels + WS streaming
5. Service CRUD + compose policy validator + systemd unit management
6. Generic command framework + systemd group endpoints (parity)
7. Backup management: restic provisioning, script + timer render, run/check/
   snapshots/forget/restore endpoints
8. Monitoring & alerting: health checks, log watchers, notifiers,
   auto-reactions, events API + WS push
9. Web UI (Lit): login, list/detail, logs, editors, wizard, users admin,
   backup panel, monitor panel, events view
10. Python client + CLI + pytest suite
11. Docs, examples, Dockerfile, self-compose, CI workflow
12. Final verification: `cargo test`, `cargo clippy`, web build+tsc, pytest,
    docker build, manual smoke checklist

## 14. Risks & open questions

- **nsenter/systemd**: requires host systemd; non-systemd hosts degrade to
  docker-only mode (unit endpoints return `unsupported`). Detection at
  startup, documented.
- **WS auth token in query**: browsers can't set headers on WS; we accept
  `Sec-WebSocket-Protocol: bearer.<token>` first, `?token=` as fallback
  (documented caveat; tokens are short-lived).
- **Compose spec coverage**: validator covers the common compose subset; the
  model keeps unknown keys via catch-alls so nothing is silently dropped on
  round-trip edits.
- **`docker compose` vs `docker-compose`**: configurable `compose_command`;
  default `docker compose` (v2 plugin bundled in the image). Host-side units
  and `backup.sh` use `systemd.compose_binary` resolved on the host — the two
  are independent.
- **restic on host**: backup scripts execute on the host via `HostExec`, so
  the image stays slim; `backup/check` surfaces `restic_missing`. Alternative
  `scheduler: internal` still shells out to host restic via nsenter.
- **Backup secrets**: `.restic_password` is 0600, excluded from API reads and
  compose bind-mount policy; `repository_base` may embed rest-server creds —
  redacted in `GET /api/config`, and `extra_env` is the escape hatch for
  backend creds (kept out of `meta.yaml`).
- **Log watcher cost**: one `docker logs -f` stream per service with active
  `log_alerts` — watchers start lazily (only for services with rules), share
  a single stream per service across rules, and have a bounded buffer.
  Restarted streams resume via `--since` with overlap dedup.
- **Alert loops**: auto-restart on a persistent crash could loop —
  mitigated by cooldowns, `max_attempts`/`window_secs`, flap suppression,
  and the `allow_auto_actions` master switch (documented default: on).
- **users.yaml write-back**: atomic write (tmp + rename) so the file watcher
  doesn't half-load; guarded against the watch loop re-entering.
