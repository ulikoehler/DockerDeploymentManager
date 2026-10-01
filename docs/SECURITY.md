# Security design

## Threat model

ddm manages docker deployments and host systemd units. Unmitigated, that is a
**root-equivalent service**: it owns the docker socket and (via
`nsenter -t 1` or a privileged container) host `systemctl`, restic backups and
arbitrary file writes under `services_root`. Anyone reaching the API with a
valid token can do what their roles/features/policies permit; `admin` or a
user with `compose_policy: unrestricted` effectively has root on the host.

The design goal is **maximally-compromisable server, minimal security
impact**: the large network-facing process (axum HTTP/WS, MCP, regex, YAML,
git, webhooks) may be fully compromised without giving up the host or the
credential material. One residual is inherent and accepted: a fully
compromised server can *relay* — e.g. wait for an admin's valid request and
reuse its justification for a different verb in the same instant. The
boundary still ensures it cannot mint credentials, widen a token's scope,
extract secrets, erase its audit trail, or execute anything the privileged
agent's verb set doesn't cover.

## Two-process privilege separation

```
            ┌──────────────────────────────────────────────────────┐
 browsers   │  ddm-server   (User=ddm — NOT in docker group,        │
 MCP ──────►│  NoNewPrivileges, ProtectSystem, seccomp)             │
 clients    │  axum · authz/roles/scopes · users · policy · WS      │
            └───────────────┬──────────────────────────────────────┘
                            │ unix socket /run/ddm/agent.sock
                            │ root:ddm 0660 + SO_PEERCRED check
                            ▼
            ┌──────────────────────────────────────────────────────┐
            │  ddm-agent   (root, small, no HTTP/TLS/YAML/regex,    │
            │  no shell)                                           │
            │  · JWT issue/verify + rotation (secret never leaves) │
            │  · argon2 verify + peppered hashes                   │
            │  · webhook HMAC / GitLab token verify                │
            │  · secret custody (env-only, referenced by id)       │
            │  · privileged verbs: compose · systemctl · file ops  │
            │    restic · git · host exec                          │
            │  · root-owned append-only justification log          │
            └──────────────────────────────────────────────────────┘
```

### ddm-server (unprivileged)

Everything that exists today: HTTP/WS/MCP routing, JWT *presentation*,
authorization decisions (roles, service access rules, feature flags,
compose policy), user store, config hot-reload, monitor, executions.

At startup it drops to a dedicated `ddm` user (`NoNewPrivileges=yes`,
`ProtectSystem=strict`, read-write only on state/service dirs, seccomp
allowlist). It is deliberately **not** in the `docker` group and has no
sudo — a compromised server cannot touch `docker.sock`, `systemctl`, or
root files on its own; every privileged effect goes through the socket.

### ddm-agent (privileged)

Run as `ddm-server agent` — a minimal daemon that owns every dangerous
capability. Hard rules:

- **No shell across the boundary.** Requests are typed verbs with argv
  vectors — never a command string. `Compose{project, action}` becomes
  `docker compose -p <project> <action>` constructed *inside* the agent.
  Whole injection classes (the `cd '{work_dir}'` case) become impossible.
- **Re-validation at the boundary** (defense in depth — the server also
  checks, the agent re-checks independently): service name charset +
  existence, file paths canonicalize inside `services_root/<service>`,
  unit names charset + configured group regex, verbs from a fixed
  allowlist, size/count limits.
- **Justification required.** Every privileged verb carries
  `Justification { user, roles, action, request_id, detail, token_id }`.
  The agent *itself verifies the referenced JWT* (it owns the signing
  key — see below) and appends the justification to a **root-owned
  append-only log** before executing. The unprivileged side can request
  work but can neither perform it nor forge/erase its record.

## Crypto & credential custody in the agent

All key material and all credential *verification* lives in the agent; the
server holds no secrets.

| operation | request → result |
|---|---|
| login | `Authenticate{name, password}` → agent verifies argon2(+pepper), issues JWT. Password verification and signing are atomic inside the agent — the server cannot mint a token without real credentials. |
| scoped token | `MintScoped{parent_token, scope, ttl}` → agent verifies the parent signature itself, intersects scopes, caps TTL at the parent's `exp`, signs the child. A compromised server can never widen a scope or forge a parent. |
| verify | `Verify{token}` → claims (gen/exp/scope). Cheap; server caches nothing. |
| rotate | `Rotate{admin_justification}` → new secret + generation bump. |
| passwords | `SetPassword{token, user, current}` — agent re-verifies the token is *unscoped* and checks `current_password` itself for self-changes. |
| peppered hashing | `Hash`/`Verify{password, hash}` — argon2 salt + a root-only **pepper**, so a stolen `users.yaml` is useless for offline cracking. |
| webhook | `VerifyWebhook{sig_headers, body}` → bool; the secret never leaves the agent. |
| secrets | notifiers, git tokens, restic passwords referenced by *id*; values resolved from env inside the agent. `GET /api/config` redaction stays defense-in-depth. |

Rate limiting for `Authenticate` lives **in the agent** (per-account
lockout + global attempt budget), so a compromised server can't bypass
brute-force protection by skipping the call.

`MintScoped` binds the child to the parent's `jti`, so the justification
log forms a chain: every privileged action traces to an issued token and
the login that produced it.

## Residual risks (accepted)

- **Relay**: a compromised server can attach a caller's live token to a
  different verb for the same caller — e.g. reuse an admin's token
  presented for `compose pull` to request `compose down`. Narrowed by
  binding `request_id`/verb hash into the token justification where
  feasible, and by scoped/short-lived MCP tokens. Cannot be fully
  eliminated without holding user keys in the agent.
- **Service-account identity**: `SO_PEERCRED` ties the socket to uid `ddm`;
  if two unprivileged components ever share it, the agent can't
  distinguish them — one server process per socket/user.
- **DoS**: the agent enforces verb-level quotas, but a compromised server
  can still flood the socket; impact is bounded to ddm availability.

## Authorization layers (unchanged, enforced in the server)

1. **Roles** — `admin` (everything), `operator` (lifecycle, systemd,
   commands), `viewer` (read).
2. **Service access rules** — ordered `exact|glob|regex` allow/deny, first
   match wins, else `security.default_access` (default `deny`).
3. **Feature flags** — `create_services`, `edit_compose`, `edit_units`,
   `run_commands`, `manage_backup`, `manage_monitoring`, `edit_files`.
4. **Compose policy** — per user; fail-closed (unknown names fall back to
   `default_policy`, then built-in strict). Strict denies `privileged`,
   host namespaces, docker-socket mounts, devices, `cap_add`, `sysctls`,
   bind mounts, isolation overrides, low ports, path escapes,
   `.restic_password` mounts, out-of-dir `extends`/`include`.
5. **Unit editing** — `security.unit_edit_requires` (default `admin`);
   the `edit_units` feature cannot bypass an `admin` gate.
6. **Token scopes** — `POST /api/auth/token` mints time-limited JWTs with
   `services`/`actions` restrictions that intersect (never widen) the
   caller's permissions on REST, WS and MCP alike; scoped tokens cannot
   mint unscoped children, outlive the parent token, or change passwords.
7. **Destructive ops** — backup `restore` requires `admin` or
   `unrestricted`; `target_dir` must be absolute without `..`.

## Transport & endpoint hardening

- `/mcp` requires a bearer JWT; browser `Origin` requests are rejected
  (host allowlisting is off — JWT is the boundary).
- `?token=` is honored only on `/ws/*` paths so tokens can't leak via
  URLs in logs/history/Referer.
- GitOps webhook is unauthenticated but HMAC/token-verified and fails
  closed on a missing/empty secret.
- No CORS headers are emitted; cookieless bearer auth is not
  CSRF-able.

## Audit

Two logs: the server's in-memory ring + `[audit]` tracing lines (who did
what via the API), and the agent's **root-owned append-only justification
log** (what privilege was exercised and on whose token). The agent's copy
survives full server compromise; discrepancies between the two are an
intrusion signal.

## Deployment

```yaml
security:
  agent_socket: /run/ddm/agent.sock   # enables privilege-separated mode
  agent_peer_uid: 1001                # optional SO_PEERCRED restriction (uid of ddm-server)
  pepper_file: /etc/ddm/pepper        # root:ddm-agent 0440
```

- `ddm-server agent` runs as root (or a uid with docker + systemd +
  host-exec capabilities) and owns: the JWT secret (`jwt_secret_env` is
  read there — the server never loads it), the pepper, `users.yaml`
  writes, `config.yaml` writes (notifier CRUD goes through a typed verb
  and re-checks the admin claim), docker/systemd/restic/git/file verbs,
  the monitor and gitsync loops, and the justification log
  (`justification.log` next to the config, root-owned append-only).
  `config.yaml` can therefore be root-owned `0640 root:ddm` — the server
  only reads it.
- `ddm-server serve` runs unprivileged (`User=ddm`,
  `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ReadWritePaths` on the
  state dir only, **not** in the docker group) and reaches the agent via
  `security.agent_socket` (socket `0660 root:ddm`, `agent_peer_uid`
  verified via `SO_PEERCRED`).
- When `agent_socket` is unset the server logs a warning and embeds the
  agent in-process — same code path, no separation. Intended for tests
  and development only.

## Operational guidance

Treat ddm like `root SSH`: TLS via reverse proxy or VPN,
`security.default_access: deny`, sparing use of `unrestricted`, set
`DDM_JWT_SECRET` explicitly on the **agent** process, run the agent
socket `0660 root:ddm`.
