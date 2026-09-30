# Architecture

```
┌──────────────────────────── ddm container (privileged, pid:host) ─┐
│  axum HTTP/WS  →  handlers → auth/permission checks → core        │
│    ├─ docker socket (bollard)  ← containers, logs, health          │
│    ├─ compose CLI              ← pull/up/down… in service dirs     │
│    ├─ HostExec (nsenter -t 1)  ← systemctl/journalctl/restic       │
│    ├─ SharedConfig (notify)    ← config.yaml hot reload            │
│    ├─ UserStore (notify)       ← users.yaml hot reload             │
│    ├─ ExecutionManager         ← broadcast channels + history      │
│    ├─ Monitor                  ← health loops + log watchers       │
│    └─ AuditLog                 ← in-memory ring + tracing          │
└───────────────────────────────────────────────────────────────────┘
        ↓ docker.sock          ↓ nsenter               ↓ /host/systemd
   host containers        host systemctl etc.      host unit files
```

## Modules (`crates/ddm-server/src`)

| module | role |
|---|---|
| `config` | YAML schema, defaults, `SharedConfig` watcher (notify + debounce; invalid reloads rejected) |
| `users` | `users.yaml` schema, argon2, atomic locked writes, own watcher, CLI-facing mutations |
| `permissions` | service access matchers (exact/glob/regex, ordered), name validation, feature checks |
| `auth` | JWT issue/verify (`JwtKeys` with rotation), `AuthUser` extractor |
| `hostexec` | `HostExec` trait + `NsenterExec` / `LocalExec` / `MockExec` |
| `docker` | `DockerApi` trait + `BollardDocker` / `MockDocker`, `compose_argv` |
| `services` | service discovery under `services_root`, `meta.yaml` load/save |
| `exec` | `ExecutionManager`: runs command sequences, streams `ServerMessage`s over broadcast channels, keeps history |
| `policy` | compose security validation → `PolicyViolation[]` |
| `systemd` | TechOverflow unit template, resolve compose bin on host, `UnitCheckReport`, group/journal helpers |
| `logs` | server-side `LogFilter` → `CompiledFilter` pipeline |
| `compose` | read/write compose atomically, template rendering, parse check |
| `audit` | ring buffer of mutations |
| `backup` | `backup.sh` + timer rendering, provisioning, checks, restic helpers |
| `notify` | slack/telegram/email/webhook senders (env-indirected secrets) |
| `monitor` | supervisor reconciling desired checks → health loops + log watchers → notify + auto-actions |
| `cli` | clap offline CLI (user management etc.) |
| `api/` | REST + WS handlers |
| `protocol` | shared wire types |

## Request flow

1. `AuthUser` extractor: bearer token (header or `?token=`) → JWT verify →
   user lookup in `UserStore`.
2. Handler: role/feature checks → `can_access_service` per service → work.
3. Mutations audit-logged; long operations run via `ExecutionManager` and
   stream over `WS /ws/executions/{id}`.

## Host access

`HostExec::run`/`run_streaming`/`which` — the default implementation wraps
commands in `nsenter --target 1 --mount --uts --ipc --net --`. This is why
the container needs `pid: host` + `privileged: true`. `local` mode runs
directly (bare metal, tests).

## Data flow for long operations

REST actions return `{execution_id}` immediately; output streams on the WS.
`ExecutionManager` keeps a bounded broadcast channel per execution and a
bounded history list; subscribers attach live (no replay buffer — the
history list carries status only).

## Hot reload

`SharedConfig` (config.yaml) and `UserStore` (users.yaml) each run a
`notify` watcher with 150 ms debounce. Invalid parses are logged +
reflected in `/api/config/status`; the previous value stays live. Monitor
reconciles on config change; log watchers restart with dedup so a restart
doesn't re-alert old lines.

## Where state lives

- `config.yaml`, `users.yaml`, `meta.yaml` — YAML files (source of truth).
- `host_systemd_dir` — generated unit files on the host.
- `monitoring.state_dir` — monitor persistence (planned; currently in-memory).
- Audit + executions + monitor events — bounded in-memory rings.
