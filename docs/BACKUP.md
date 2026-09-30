# Backup (restic)

Generalized from the
[TechOverflow restic/PostgreSQL pattern](https://techoverflow.net/2026/04/17/restic-based-backup-for-weblate-with-postgresql/):
each service gets a generated `backup.sh`, a `.restic_password` file, a
per-service repository (`repository_base` + service name), a one-time
`restic init` (`.restic_inited` marker), streamed DB dumps, and a systemd
timer for scheduling.

## Global config (`backup:` in config.yaml)

```yaml
backup:
  enabled: true
  restic_binary: auto                 # resolved on the host via `which`
  repository_base: "rest:http://restic:8000/"   # repo = base + service name
  # repository_template: "s3:bucket/{service}"  # optional override
  extra_env: {}                       # e.g. AWS_ACCESS_KEY_ID for s3:
  excludes: ["*.tmp"]
  retention: { keep_last: 7, keep_daily: 7, keep_weekly: 4 }
  scheduler: systemd_timer            # systemd_timer | internal | none
  on_calendar: daily
  unit_prefix: ddm-backup
```

Repository URL forms all work (`local path`, `rest:`, `s3:`, `sftp:`,
`rclone:`…) — restic handles them; extra env (`AWS_*`, `B2_*`, …) is
exported into the generated script. Prefer env indirection for secrets
(the URL may contain credentials and is redacted in `GET /api/config` but
embedded in `backup.sh`).

## Per-service config (`meta.yaml` or `PUT …/backup`)

```yaml
backup:
  enabled: true
  paths: [docker-compose.yml, meta.yaml, data]  # relative to service dir
  excludes: ["data/cache/**"]
  stdin_dumps:
    - filename: pg-app.sql            # stored name in the repo
      service: db                     # compose service to exec into
      command: [pg_dump, "-U", "${POSTGRES_USER}", app]
      env_file: .env                  # source for ${VAR} expansion
  schedule_enabled: true
```

`paths` are validated (relative, no `..`). `.restic_password` is always
excluded. `stdin_dumps` stream
`$COMPOSE_BIN -f docker-compose.yml exec -T <service> <command>` into
`restic backup --stdin --stdin-filename=<filename>`.

## Provision

`POST /api/services/{name}/backup/provision` (or UI → Backup → provision):

1. creates `.restic_password` (0600, random) if missing,
2. renders `backup.sh` (0755),
3. writes `ddm-backup-<svc>.service` (oneshot) + `.timer` into the host
   systemd dir and `enable --now`s the timer,
4. runs `restic init` once (`.restic_inited` marker).

Idempotent — safe to re-run.

## Generated backup.sh (example)

```bash
#!/bin/bash
set -euo pipefail
export NAME='pg-app'
export RESTIC_REPOSITORY='rest:http://restic:8000/pg-app'
export RESTIC_PASSWORD_FILE='/opt/ddm-services/pg-app/.restic_password'
cd '/opt/ddm-services/pg-app'
if [ ! -f ".restic_inited" ]; then restic init; touch .restic_inited; fi
docker compose -f 'docker-compose.yml' exec -T db pg_dump -U "${POSTGRES_USER}" app | restic --verbose backup --stdin --stdin-filename='pg-app.sql'
restic --verbose backup 'docker-compose.yml' 'meta.yaml' 'data' --exclude '*.tmp' --exclude 'data/cache/**' --exclude '.restic_password'
restic forget --prune --keep-last 7 --keep-daily 7 --keep-weekly 4
```

## Check / repair

`GET /api/services/{name}/backup/check` → `BackupCheckReport` with flags
(`password_file`, `script`, `repo_inited`, `timer_exists/enabled/active`,
`last_run`) and `issues[]` (`password_missing`, `script_missing`,
`repo_not_inited`, `restic_missing`, `timer_missing`, `timer_disabled`,
`timer_inactive`, `never_run`). `provision` fixes them.

## Operations

- `POST …/backup/run` — run `backup.sh` on the host, streamed via WS.
- `GET …/backup/snapshots` — `restic snapshots --json`.
- `POST …/backup/forget` — `forget --prune` with configured retention.
- `POST …/backup/restore` — `{snapshot, target_dir}`; admin or
  `unrestricted` only; `target_dir` must be absolute, no `..`.

## Host requirement

`restic` must exist on the **host** (scripts + units run there). Install
via the package manager or drop a static binary in `/usr/local/bin`.
