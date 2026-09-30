# Configuration reference

ddm loads `config.yaml` (default `/etc/ddm/config.yaml`, `--config` to
override). Both `config.yaml` and `users.yaml` are **watched and hot-
reloaded** — invalid reloads are rejected and logged; the previous config
keeps running. Check `GET /api/config/status` for the last reload result.

## config.yaml

### `server`

| key | default | notes |
|---|---|---|
| `listen` | `0.0.0.0:8080` | bind address |
| `jwt_secret_env` | `DDM_JWT_SECRET` | env var holding the JWT secret. If unset a random secret is generated (all sessions die on restart) |
| `token_ttl_minutes` | `720` | JWT lifetime |
| `web_dir` | — | dir with `index.html`+`bundle.js`; omitted → API only |
| `cors_origins` | `[]` | additional CORS origins |

### `paths`

| key | default | notes |
|---|---|---|
| `services_root` | `/services` | service dirs inside the container |
| `host_services_root` | `services_root` | same path seen by the host — used in `WorkingDirectory=` and `backup.sh`. Keep identical inside and outside (easiest: mount the same host path at the same container path) |
| `compose_file` | `docker-compose.yml` | preferred compose filename |
| `host_systemd_dir` | `/host/systemd` | bind-mount of the host's `/etc/systemd/system` |
| `host_exec` | `nsenter` | `nsenter` (container) or `local` (bare metal/tests) |
| `nsenter_target` | `1` | host PID for nsenter |

### `docker`

| key | default | notes |
|---|---|---|
| `socket` | `/var/run/docker.sock` | |
| `compose_command` | `[docker, compose]` | in-container compose invocation |

### `logging`

`default_tail` (200), `max_tail` (5000), `history_executions` (200).

### `security`

| key | default | notes |
|---|---|---|
| `default_access` | `deny` | fallback when no access rule matches a user |
| `default_policy` | `strict` | policy for users without `compose_policy` |
| `unit_edit_requires` | `admin` | role needed to write raw unit files |
| `policies` | see below | named `ComposePolicy` map |

A `ComposePolicy` (all keys optional, strict defaults):

```yaml
deny_privileged: true            # no privileged: true
deny_host_namespaces: true       # no network_mode: host, pid: host, ipc/uts/cgroup host, service:/container: modes
deny_docker_socket: true         # no /var/run/docker.sock mounts
deny_devices: true               # no devices:
deny_root_user: false            # deny `user: root`/`user: "0"`
deny_isolation_overrides: true   # no userns_mode/cgroup_parent/security_opt overrides
cap_add:    { mode: allowlist, list: [] }         # allowlist|denylist
sysctls:    { mode: allowlist, list: [] }
allowed_bind_sources: []         # glob list of host paths; empty = deny all binds
deny_bind_targets: [...]         # glob list of container paths
allowed_port_range: [1024,65535] # published host ports
allowed_registries: []           # image prefix list; empty = any
max_services_per_compose: 20
```

Always rejected regardless of policy: `..` in bind sources, mounting
`.restic_password`, `extends`/`include` outside the service dir.

Users opt out of validation with `compose_policy: unrestricted` (explicit,
per-user; logged to the audit log on every save).

### `service_templates`

```yaml
- id: hello
  title: Hello world
  description: nginx
  compose_template: /etc/ddm/templates/hello-compose.yml
  create_unit: true
  vars:
    - { name: port, label: HTTP port, required: true, default: "8081" }
```

Template substitutions: `{service}`, `{dir}` (host dir), `${var}` and
`{{var}}` for each declared var.

### `systemd`

| key | default | notes |
|---|---|---|
| `unit_template` | built-in | path to a custom template ({service} {dir} {compose_file} {compose_bin}) |
| `compose_binary` | `auto` | `docker-compose` first, then `docker compose`; or an explicit binary |
| `daemon_reload_after_change` | `true` | |
| `groups` | `[]` | see below |

Groups expose host units and custom commands (e.g. "pull + restart"):

```yaml
groups:
  - id: managed
    title: Managed services
    unit_regex: "^web-.*\\.service$"
    custom_commands:
      - type: docker_compose_pull           # or docker_compose_pull_restart | shell
        id: pull
        label: Pull images
        work_dir_template: "/opt/ddm-services/{service}"   # {unit} {service} substituted
      - type: shell
        id: reload
        label: Reload
        program: systemctl
        args: ["reload", "${unit}"]
```

### `backup`

See [BACKUP.md](BACKUP.md). Keys: `enabled`, `restic_binary` (`auto` resolves
on host), `repository_base` (+ service name per repo) or
`repository_template` (`{base}`, `{service}`), `password_mode:
per_service_file`, `extra_env`, `excludes`, `retention {keep_*}`, `scheduler:
systemd_timer|internal|none`, `on_calendar`, `unit_prefix`.

### `monitoring`

See [MONITORING.md](MONITORING.md). Keys: `enabled`, `allow_auto_actions`,
`check_interval_secs`, `state_dir`, `defaults {notify, failure_threshold,
cooldown_secs}`, `rules` (global per-matcher log alerts), `notifiers`
(`slack_webhook`/`telegram`/`email`/`webhook`; secrets via `*_env`).

### `sections`

Generic command sections (see example in `config.example.yaml`). Items take
`title`, `description`, `work_dir`, `icon`, `parameters` (`string|boolean|
number` with `required`, `validation_regex`, `default`, `min`, `max`),
`button_label`, `required_role`, `on_host` (default `true`), and
`command_sequence` — a list of `{program, args}` where args are
`{type: value, value: "..."}` (with `${param}` substitution),
`{type: variable, name: p}`, `{type: conditional, variable: b, true_args: [],
false_args: []}` or `{type: optional, flag: --x, variable: p}`.

### `users_file`

Path to `users.yaml`; relative = next to `config.yaml`.

## users.yaml

```yaml
users:
  - name: admin
    password_hash: "$argon2id$v=19$…"
    roles: [admin]
    access: []
    compose_policy: unrestricted
  - name: ci
    password_hash: "$argon2id$v=19$…"
    roles: [operator]
    access:
      - { type: exact, pattern: core, effect: deny }
      - { type: glob, pattern: "web-*", effect: allow }
    features:
      create_services: true
      edit_compose: true
      edit_units: false
      run_commands: true
      manage_backup: false
      manage_monitoring: false
    compose_policy: strict
```

Access rules are evaluated in order; first match wins. No match →
`security.default_access`. Admins bypass access rules and feature flags.

## meta.yaml (per service)

Written by `PUT /api/services/{n}/backup` and `/monitoring`, or by hand:

```yaml
description: …
backup: { enabled: true, paths: [...], excludes: [...], stdin_dumps: [...], schedule_enabled: true }
monitoring:
  health: { kind: docker_healthcheck, interval_secs: 30, notify: [...], actions: [...] }
  log_alerts: [{ id, regex, exclude_regex?, container, notify?, cooldown_secs?, actions? }]
```
