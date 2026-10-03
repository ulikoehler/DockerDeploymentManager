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
- **Per-verb authorization re-check.** Before any verb runs, the agent
  re-loads the user from `users.yaml`, applies the token's scope, and
  re-evaluates the same gate the server uses: service access
  (`can_access_service`), feature flags (`edit_files`, `edit_compose`,
  `manage_monitoring`, `manage_backup`, `create_services`,
  `run_commands`, `exec_containers`), roles (`admin`, `operator`,
  `security.unit_edit_requires`) and per-command `required_role`s. A
  compromised server cannot use a valid token for a verb its user may not
  perform — and because the scope is applied *before* the check, the
  re-check narrows scoped tokens rather than widening them. Read verbs
  that list across services (`ServicesList`, `MonitorStatusAll`,
  `MonitorEvents`) are filtered agent-side by the same rules.
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
  different verb *for that same caller* — e.g. reuse an admin's token
  presented for `compose pull` to request `compose down`. Bounded by the
  agent's per-verb re-check (the relayed verb must still be one the
  token's user is allowed to perform, with the token's scope applied) and
  by binding `request_id`/verb hash into the token justification where
  feasible, plus scoped/short-lived MCP tokens. Cannot be fully
  eliminated without holding user keys in the agent.
- **Container log reads by id**: `ContainerLogsCollect` takes a container
  id, which the agent cannot map back to a service without an extra docker
  lookup; it therefore requires a valid token but not a service-access
  check. Impact is limited to reading logs of containers the caller's
  server-side request already resolved. (By contrast `ContainerExec` —
  `docker exec` — does resolve the container's `com.docker.compose.project`
  label agent-side and re-checks access to that service; unlabeled or
  unmanaged containers require admin.)
- **Service-account identity**: `SO_PEERCRED` ties the socket to uid `ddm`;
  if two unprivileged components ever share it, the agent can't
  distinguish them — one server process per socket/user.
- **DoS**: the agent enforces verb-level quotas, but a compromised server
  can still flood the socket; impact is bounded to ddm availability.

## Authorization layers (enforced in the server *and* re-checked in the agent)

1. **Roles** — `admin` (everything), `operator` (lifecycle, systemd,
   commands), `viewer` (read).
2. **Service access rules** — ordered `exact|glob|regex` allow/deny, first
   match wins, else `security.default_access` (default `deny`).
3. **Feature flags** — `create_services`, `edit_compose`, `edit_units`,
   `run_commands`, `exec_containers` (docker exec), `mount_files` (WebDAV),
   `manage_backup`, `manage_monitoring`, `edit_files`.
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
   A `services` scope **always drops the `admin` role** — otherwise the
   admin bypass in `can_access_service` would silently void the scope.
7. **Destructive ops** — backup `restore` requires `admin` or
   `unrestricted`; `target_dir` must be absolute without `..`.
8. **Privileged files are not editable through the file API** —
   `meta.yaml` (monitoring/backup config), `backup.sh` (runs as root, holds
   repo credentials) and `.restic_*` are denied to reads, writes, renames
   and deletes; use the dedicated endpoints, which apply their own gates.
   The check is applied to the *resolved* path, not just the request path —
   otherwise a symlink alias inside the service dir (`data -> meta.yaml`,
   which a cloned repo can deliver) would canonicalize straight onto a
   privileged file and be read or written through it.
   Writing the compose file through the file API additionally requires
   `edit_compose` and is validated against the caller's compose policy and
   the configured floor (renaming *onto* the compose file is refused
   outright).
9. **Monitoring auto-actions** — `exec_command` actions run a configured
   command with **no caller identity**, so configuring one is `admin`-only,
   indices must resolve to a real command item, and the target may not be
   `required_role`-gated (such items are also refused at execution time).
   `restart`/`stop` actions remain available to `manage_monitoring`.
10. **Backup `stdin_dumps`** are rendered into a root-run script, so the
   dump service name and every argv element are charset-validated
   (shell metacharacters rejected; only `${VAR}` expansion allowed), the
   `env_file` must be a relative in-service path, and the dump service must
   exist in the compose file. Validation runs server-side *and* inside the
   agent, and rendering re-validates before writing the script.
11. **WebDAV (`/dav`)** is a second transport into the same files, so it
   reuses this policy rather than restating it: `webdav.enabled` (off by
   default) plus `mount_files` to use the surface, service access for reads,
   `edit_files` for writes, and the *shared* compose guard for compose
   writes. Denied names, traversal and the service root are protected
   identically to the JSON file API, and a test
   (`webdav_matches_json_file_api_policy`) asserts both surfaces deny the
   same operations — the point is that a new path cannot silently become a
   weaker one. Uploads are authorized *before* the body is accepted, bounded
   by `webdav.max_upload_bytes`, staged in a temp file, fsynced and renamed
   atomically, and a short body (client disconnected mid-upload) is never
   committed. Locks are advisory only: in-memory, expiring, and not shared
   between instances.

## Transport & endpoint hardening

- `/mcp` requires a bearer JWT; browser `Origin` requests are rejected
  (host allowlisting is off — JWT is the boundary).
- `?token=` is honored only on `/ws/*` paths so tokens can't leak via
  URLs in logs/history/Referer.
- GitOps webhook is unauthenticated but HMAC/token-verified and fails
  closed on a missing/empty secret.
- `/ws/*` rejects browser handshakes whose `Origin` is neither
  same-origin with `Host` nor listed in `server.cors_origins` (non-browser
  clients send no `Origin` and are unaffected).
- CORS is **closed by default**: no cross-origin headers are emitted
  unless `server.cors_origins` lists an origin, and only
  `Authorization`/`Content-Type` are allowed. Cookieless bearer auth is
  not CSRF-able either way.
- Login throttling counts *failed* attempts only (5 per window, per
  account): guessing gains nothing, while a correct password still works —
  a hard lockout would let anyone lock every account out from outside.

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
  allow_local_git_clone: false        # default off: file:// / local clone URLs run as root in the agent
```

- `ddm-server agent` runs as root (or a uid with docker + systemd +
  host-exec capabilities) and owns: the JWT secret (`jwt_secret_env` is
  read there — the server never loads it), the pepper, `users.yaml`
  writes, `config.yaml` writes (notifier CRUD goes through a typed verb
  and re-checks the admin claim), docker/systemd/restic/git/file verbs,
  the monitor and gitsync loops, and the justification log
  (`justification.log` next to the config, root-owned append-only).
  `config.yaml` can therefore be root-owned `0640 root:ddm` — the server
  only reads it. `users.yaml` is written `0640` (group read so the server
  can list users; never world-accessible).
- **Fresh-record authorization**: every justified agent call re-loads the
  user from `users.yaml` — admin checks (`require_admin`) run against the
  live roles, not the claims signed at login. Deleting or demoting a user
  kills their privilege at the agent boundary immediately, before token
  expiry; minted child tokens carry roles intersected with the fresh
  record, so demoted roles cannot be resurrected.
- `git clone` verbs accept remote URLs only unless
  `security.allow_local_git_clone` is set — a `file://` or local-path
  clone would otherwise let a caller copy any root-readable repo on the
  host into a service dir. A finished clone is then sanitized: symlinks
  that escape the service dir are removed and denied filenames delivered
  by the repo are dropped; a compose file the clone placed is validated
  against the policy floor.
- **GitOps sync** never follows symlinks in either direction (a repo
  symlink would copy its target tree in; a planted destination symlink
  would be written *through*, i.e. arbitrary root file write). `meta.yaml`
  and `backup.sh` are treated as per-instance state and are never
  overwritten or pruned by a sync, and compose files a `Services` target
  would install are validated against the default policy before copying —
  repo push access must not bypass compose policy.
- `ddm-server serve` runs unprivileged (`User=ddm`,
  `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ReadWritePaths` on the
  state dir only, **not** in the docker group) and reaches the agent via
  `security.agent_socket` (socket `0660 root:ddm`, `agent_peer_uid`
  verified via `SO_PEERCRED`). In this mode it also holds **no secrets at
  all**: its config view is redacted at load (notifier URLs/tokens, git
  credentials, webhook secret, backup `extra_env`/repo creds are masked;
  `*_env` variable *names* are kept), and its user store keeps no password
  hashes. Secret-merge on notifier update runs inside the agent; config
  and user mutations are refused outright in the redacted process.
- The agent socket is bounded: requests capped at 16 MB *before*
  buffering, and at most 64 concurrent connections.
- When `agent_socket` is unset the server logs a warning and embeds the
  agent in-process — same code path, no separation. Intended for tests
  and development only.
- Scoped tokens are rejected outright for trust-root operations (user
  mutation/listing, JWT rotation, notifier changes) — a narrowed token
  can never perform them, even at the agent socket. Container ids
  (health, logs, exec) are re-resolved to their owning compose project
  inside the agent, and systemd verbs re-check configured group
  membership, so a compromised server cannot smuggle out-of-scope
  targets. The agent's `Watch` event stream requires a valid token.
- GitOps webhook deliveries are deduplicated (signature + body hash,
  10-minute window) and rate-limited (one accepted sync per 10 s) —
  captured deliveries cannot be replayed or used to busy-loop the host.
- WebDAV lock tokens are bearer credentials: `lockdiscovery` reports a
  lock to every reader but reveals the token only to its holder (or an
  admin).

## Operational guidance

Treat ddm like `root SSH`: TLS via reverse proxy or VPN,
`security.default_access: deny`, sparing use of `unrestricted`, set
`DDM_JWT_SECRET` explicitly on the **agent** process, run the agent
socket `0660 root:ddm`, and prefer `POST /api/auth/ws-ticket` +
`?ticket=` (single-use, 60 s) over `?token=` for WebSocket clients so
session JWTs stay out of URLs.
