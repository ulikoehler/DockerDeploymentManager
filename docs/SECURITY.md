# Security model

## Threat model

ddm is a **root-equivalent service**: it owns the docker socket and (via
`nsenter -t 1`) host `systemctl`. Anyone able to reach the API with a valid
token can do what their roles/features/policies permit; an `admin` or a user
with `compose_policy: unrestricted` effectively has root on the host.

Treat ddm like `root SSH`: put it behind TLS (reverse proxy or a VPN),
keep `security.default_access: deny`, and be stingy with `unrestricted`.

## Authentication

- Passwords are argon2id hashes in `users.yaml` (managed via API/UI/`ddm-server user`).
- Sessions are JWTs signed with `DDM_JWT_SECRET` (`server.jwt_secret_env`).
  `POST /api/auth/logout-all` (admin) rotates the secret → global re-auth.
- WS endpoints take `?token=` since browsers can't set headers — prefer the
  Authorization header everywhere else; don't paste tokens into logs.

## Authorization layers

1. **Roles** — `admin` (everything), `operator` (lifecycle actions, systemd,
   commands), `viewer` (read). Role checks live in the handlers.
2. **Service access rules** — ordered `exact|glob|regex` allow/deny list per
   user; first match wins, else `security.default_access` (default `deny`).
   Applied to every service-scoped endpoint, log stream, and monitor state.
3. **Feature flags** — `create_services`, `edit_compose`, `edit_units`,
   `run_commands`, `manage_backup`, `manage_monitoring`.
4. **Compose policy** — per user (`strict`/`relaxed`/named/`unrestricted`);
   enforced server-side on service create and compose PUT. Denied (strict):
   `privileged`, host namespaces (`network_mode: host`, `pid`, `ipc`, `uts`,
   `cgroup`, `service:`/`container:` modes), docker socket mounts, devices,
   any `cap_add`, any `sysctls`, all bind mounts (`allowed_bind_sources` is
   empty), isolation overrides, privileged ports, excessive service counts,
   path escapes, `.restic_password` mounts, out-of-dir `extends`/`include`.
5. **Unit editing** — raw unit PUT requires `security.unit_edit_requires`
   (default `admin`) or the `edit_units` feature; unit files are sanity-
   validated (`[Unit]`/`[Service]` sections, no NUL).
6. **Destructive backup ops** — `restore` requires `admin` or `unrestricted`;
   `target_dir` must be absolute without `..`.

## Secrets handling

- Notifier secrets come from `*_env` environment variables (never YAML values
  sent to clients). `GET /api/monitoring/notifiers` and `GET /api/config`
  redact secret-bearing fields.
- `.restic_password` is generated per service with mode 0600, never returned
  by the API, and excluded from backups.
- The `repository_base` URL may embed credentials (e.g. `rest:user:pw@host`):
  redacted in `GET /api/config`; prefer env-injected notifiers and a repo
  server with proper auth.

## Audit

Every mutating action (login, create/delete, compose/unit writes, actions,
backup ops, user changes, auto-actions) is recorded to a 2048-entry in-memory
ring and to the server log (`tracing`, `[audit]` lines). CLI user mutations
write `[audit]` lines to stderr.

## Hardening notes

- Run ddm with `read_only: false` only where needed; the socket + systemd
  mounts are the critical ones.
- Bind `server.listen` to localhost and front it with a TLS-terminating
  proxy that also enforces network ACLs.
- Review `allowed_bind_sources` — everything under it can be mounted by
  users who can write compose files.
- `unrestricted` policy and `admin` role are root-equivalent: audit them.
- The `?token=` WS query parameter may land in proxy logs; strip query
  logging or front WS endpoints carefully.
