# Docker Deployment Manager (ddm)

A generic, self-hosting manager for docker-compose deployments on a single
host. ddm is a **single binary** (`ddm-server`, web UI + REST API + MCP +
CLI compiled in) installed bare-metal as a systemd service. It manages
compose projects, their systemd units, restic backups, and
monitoring/alerting — all behind a web UI, REST API, and a Python CLI.
An optional privileged Docker image is published for hosts that prefer
`docker compose up`.

> **Warning:** ddm admin access is equivalent to SSH root on the host —
> it can exec into containers, write systemd units, and run arbitrary
> commands as root. Never give admin tokens to agents or automation;
> use scoped, short-lived tokens instead. See `docs/SECURITY.md`.

## How it works

ddm watches a directory of compose projects (the *service root*). Each
subdirectory containing a `docker-compose.yml` is a *service*. From the UI,
API, or CLI you can pull/update/restart them, edit their compose files and
generated systemd units, stream filtered logs, schedule restic backups, and
get notified on health-check failures or error patterns in logs.

Because it needs to control the **host**'s systemd and docker, ddm runs with
effective host root — bare-metal it calls `systemctl`/`docker`/`restic`
directly (`host_exec: local`); in the optional container deploy, host
commands run via `nsenter` into PID 1's namespaces. Compose files live on a
bind mount (container) or directly on the host (bare metal) so generated
systemd units reference real paths.

**Host requirements**: docker + compose, systemd, optionally `restic` for
backups.

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
- **File manager** — browse/read/edit/create/rename/delete arbitrary files
  inside a service dir (path traversal + symlink + `.git`/restic-secret
  protection; 512 KiB read cap; binary detection).
- **Git support** — discover repos inside a service dir, clone (into the
  dir or a subdirectory, optional branch), pull/fetch, switch branch,
  status, and log — output streams over the execution WebSocket.
- **Users & permissions** — argon2-hashed users in `users.yaml`; roles
  (`admin`/`operator`/`viewer`), ordered `exact`/`glob`/`regex` access rules,
  per-user feature flags and compose policies. Manageable via API, web UI,
  and an offline in-container CLI (`ddm-server user …`).
- **GitOps** — mirror a git repo into the service root/config dir via
  webhook (HMAC/GitLab-token verified) or interval pull; optional opt-in
  push-back of local changes.
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
# 1. install the latest release (bare metal + systemd; no clone needed)
curl -fsSL https://raw.githubusercontent.com/ulikoehler/DockerDeploymentManager/main/install.sh | sudo bash

# 2. create the first admin
/opt/ddm/bin/ddm-server --config /etc/ddm/config.yaml \
    user add admin --role admin --generate

# 3. open http://localhost:8080
```

The installer resolves the latest GitHub release, downloads the
arch-matched tarball (static musl binary, web UI embedded), verifies
its SHA256 checksum, and runs the packaged installer — every command
is echoed as it runs. Pin a version with `DDM_VERSION=vX.Y.Z`.

Service directories live under `paths.services_root` (default
`/opt/services`). Copy `examples/hello-world` there and it shows up
in the UI immediately.

Prefer containers? `docker compose up -d --build` still works — see
`docs/DEPLOYMENT.md` (Docker packaging is optional, not the standard
install path).

## Repository layout

```
crates/ddm-server/   Rust backend (axum, bollard, tokio)
web/                 Lit + TypeScript web UI (esbuild → web/dist)
python/              ddm_client package + `ddm` CLI (httpx, websockets)
examples/            hello-world service, pg-app (backup+monitoring), templates
docs/                API.md CONFIG.md SECURITY.md DEPLOYMENT.md CLIENT.md
                     BACKUP.md MONITORING.md SERVER_CLI.md ARCHITECTURE.md GITOPS.md
Dockerfile           optional image build (not the standard install path)
docker-compose.yml   optional self-deployment (privileged, pid: host)
install.sh            bootstrap: curl|bash one-liner → latest release
deploy/bare-metal/   systemd unit + config + install.sh for the standard install
.github/workflows/   ci.yml (test+image) and release.yml (binary tarballs)
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
| [docs/GITOPS.md](docs/GITOPS.md) | repo → services/config sync, webhook, push-back |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) | hacking on ddm |
