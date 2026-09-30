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
| Backend        | Rust 2021, axum 0.7 (HTTP + WS), tokio, serde/serde_yaml, notify    |
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
      ddm-command-panel.ts ddm-exec-output.ts
  test/ (vitest: matchers, log filter helpers)
client/
  pyproject.toml README.md
  ddm_client/
    __init__.py client.py cli.py ws.py models.py errors.py
  tests/ (pytest: client API against mocked transport + WS protocol)
examples/
  config.yaml users.yaml
  services/hello-world/docker-compose.yml
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
  services_root: /services
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

service_templates:
  - id: generic-web
    title: "Generic web service"
    description: "Compose + systemd unit skeleton"
    compose_template: /etc/ddm/templates/generic-web.compose.yml
    create_unit: true

systemd:
  unit_template: /etc/ddm/templates/ddm.service.tpl   # {service} {dir} subst.
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
- `PUT /api/services/{name}/unit` — write unit (requires `unit_edit` right),
  daemon-reload
- `POST /api/services/{name}/unit/regenerate` — re-render from template
- `POST /api/services/{name}/actions` `{action: pull|up|down|restart|update|
  start|stop|enable|disable}` → `{execution_id}`
  (`update` = pull + up -d --remove-orphans, the "deploy" op)
- `GET /api/services/{name}/logs?tail=&since=&grep=&regex=&stream=&container=`
  → filtered snapshot

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
`compose get|put`, `unit get|put|regenerate`, `create --template|--compose`,
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
  - systemd: template render, unit validation, HostExec command building
  - logs: filter pipeline correctness (grep/regex/since/stream)
  - commands: arg building (value/variable/conditional/optional — ported
    from the original), sequence stop-on-failure
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
- `docs/web-ui.md`, `docs/client.md`, `docs/development.md`.
- `examples/`: ready-to-run config, users (with a printed bootstrap-password
  note), hello-world service, template, unit template, client demo.

## 13. Milestones

1. Workspace scaffold; config + users schema, hot reload, `HostExec`
2. Auth (JWT/argon2) + permission engine + tests
3. Docker layer (bollard status/logs) + compose CLI wrapper + service registry
4. Execution engine + broadcast channels + WS streaming
5. Service CRUD + compose policy validator + systemd unit management
6. Generic command framework + systemd group endpoints (parity)
7. Web UI (Lit): login, list/detail, logs, editors, wizard, users admin
8. Python client + CLI + pytest suite
9. Docs, examples, Dockerfile, self-compose, CI workflow
10. Final verification: `cargo test`, `cargo clippy`, web build+tsc, pytest,
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
  default `docker compose` (v2 plugin bundled in the image).
- **users.yaml write-back**: atomic write (tmp + rename) so the file watcher
  doesn't half-load; guarded against the watch loop re-entering.
