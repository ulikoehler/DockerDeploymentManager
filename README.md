# Docker Deployment Manager (ddm)

A generic, self-hosting manager for docker-compose deployments on a single
host. ddm itself runs as a **privileged docker service** (`privileged: true`,
`pid: host`) and manages compose projects, their systemd units, restic
backups, and monitoring/alerting — all behind a web UI, REST API, and a
Python CLI.

## Features

- **Service management** — discover compose projects under a service root;
  pull / up / down / restart / update (pull + `up -d --remove-orphans`) /
  start / stop / systemd enable+disable.
- **Logs** — filtered snapshots and live follow over WebSocket
  (`grep`, `regex`, `exclude_regex`, `stream`, `container`, `tail`, `since`).
- **Compose editing** — in-browser editor with server-side security
  policy validation (`strict` default; `relaxed`; `unrestricted` opt-out
  per user).
- **systemd units** — TechOverflow-style generated units
  (`ExecStartPre=down` / foreground `ExecStart=up` / `ExecStop=down`,
  `Restart=always`, `Requires=docker.service`), plus `unit check` /
  `regenerate` for existing services (detects missing, disabled, inactive,
  workdir/compose drift, missing docker dependency, `systemd-analyze verify`
  failures).
- **Service creation** — raw compose paste or `service_templates` with
  variables; optional unit generation + enable + start.
- **Users & permissions** — argon2-hashed users in `users.yaml`; roles
  (`admin`/`operator`/`viewer`), ordered `exact`/`glob`/`regex` access rules,
  per-user feature flags and compose policies. Manageable via API, web UI,
  and an offline in-container CLI (`ddm-server user …`).
- **Backups** — restic per-service repos (`repository_base` + service name),
  streamed `pg_dump`-style stdin dumps, file backups with excludes,
  systemd timer scheduling, `snapshots`/`forget`/`restore`.
- **Monitoring & alerts** — health checks (`docker_healthcheck`, `http`,
  `tcp`, `container_running`), log regex watchers, Slack/Telegram/email/
  webhook notifications, guarded auto-actions (restart/stop/exec) with
  cooldowns and flap suppression.
- **Hot reload** — `config.yaml` and `users.yaml` are reloaded on change;
  invalid reloads never replace the running config.
- **Generic commands** — configurable command sections (with parameters)
  executed on the host or in-container, streamed over WebSocket.
- **Audit log** — every mutating action is recorded.

## Quickstart

```bash
# 1. prepare config
mkdir -p data data-state
cp config.example.yaml data/config.yaml
cp users.example.yaml   data/users.yaml   # or start empty; CLI bootstrap below
cp -r examples/templates data/templates

# 2. build + run (needs DDM_JWT_SECRET)
export DDM_JWT_SECRET=$(openssl rand -hex 32)
docker compose up -d --build

# 3. create the first admin (works even while debugging)
docker compose exec ddm ddm-server user add admin --role admin --generate
# → generated password for admin: …

# 4. open http://localhost:8080
```

Service directories live under `paths.services_root` (default
`/opt/ddm-services`). Copy `examples/hello-world` there and it shows up
in the UI immediately.

## Repository layout

```
crates/ddm-server/   Rust backend (axum, bollard, tokio)
web/                 Lit + TypeScript web UI (esbuild → web/dist)
python/              ddm_client package + `ddm` CLI (httpx, websockets)
examples/            hello-world service, pg-app (backup+monitoring), templates
docs/                API.md CONFIG.md SECURITY.md DEPLOYMENT.md CLIENT.md
                     BACKUP.md MONITORING.md SERVER_CLI.md ARCHITECTURE.md
Dockerfile           multi-stage build → runtime image
docker-compose.yml   self-deployment (privileged, pid: host)
```

## Development

```bash
cargo test                          # backend unit tests
cargo clippy --workspace            # lint
cd web && npm install && npm run build && npm run typecheck
cd python && pip install -e '.[dev]' && pytest
docker build -t ddm .
```

## Documentation

| Doc | Contents |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | components, request flows, host-access model |
| [docs/CONFIG.md](docs/CONFIG.md) | full `config.yaml` + `users.yaml` + `meta.yaml` reference |
| [docs/API.md](docs/API.md) | REST + WebSocket endpoints |
| [docs/SECURITY.md](docs/SECURITY.md) | threat model, compose policies, authn/authz |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | container requirements, mounts, privileges |
| [docs/SERVER_CLI.md](docs/SERVER_CLI.md) | in-container `ddm-server user …` commands |
| [docs/BACKUP.md](docs/BACKUP.md) | restic setup, timers, restore |
| [docs/MONITORING.md](docs/MONITORING.md) | checks, alerts, notifiers, auto-actions |
| [docs/CLIENT.md](docs/CLIENT.md) | Python client + `ddm` CLI reference |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) | hacking on ddm |
