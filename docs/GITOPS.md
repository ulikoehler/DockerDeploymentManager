# GitOps — syncing a git repository into DDM

DDM can mirror a git repository into the service root and/or the config
directory. Synchronization is pull-based:

- **webhook**: `POST /api/gitops/webhook` — called by GitHub/GitLab/Gitea on
  push. Unauthenticated by JWT but **secret-verified**.
- **interval polling**: `gitops.interval_secs` (>0). Set `0` for webhook-only.

Optionally (`push_changes: true`, **opt-in**), local changes made through the
UI/API/CLI — new services, edited compose files, meta.yaml edits — are
committed back to the repo every `push_interval_secs`.

## How it works

1. DDM keeps a working clone ("mirror") at
   `monitoring.state_dir/gitops/repo`. It does `fetch` + `reset --hard
   origin/<branch>` on every sync — the mirror always tracks the remote
   exactly; the mirror's own commits only exist transiently during a push.
2. Each `target` maps a subdirectory of the repo to a local directory:
   - `into: services` → `paths.services_root` (e.g. `/opt/services`)
   - `into: config` → the directory containing `config.yaml`
3. The copy is a plain recursive file copy. `prune: true` additionally
   deletes local files missing from the repo.
4. When the config target changes `config.yaml` or `users.yaml`… actually
   `users.yaml` is **never synced** (it is per-instance state). Changes to
   `config.yaml` are picked up by the normal hot-reload watcher.
5. Protected files are never copied, pruned or pushed: `.git`,
   `.restic_password`, `.restic_inited`, `*.lock`, `*.tmp`, and the users
   file inside a `config` target.

## Configuration

```yaml
gitops:
  enabled: true
  url: https://github.com/org/ddm-config.git
  branch: main
  token_env: GITOPS_TOKEN            # PAT — used for clone/fetch/push
  interval_secs: 300                 # 0 = webhook only
  webhook_secret_env: GITOPS_WEBHOOK_SECRET
  push_changes: false                # default: repo is read-only
  push_interval_secs: 60
  commit_name: ddm
  commit_email: ddm@example.com
  prune: false
  targets:
    - { into: services, path: services }   # repo/services/* → /opt/services/*
    - { into: config,   path: config }     # repo/config/*   → /etc/ddm/*
```

Repository layout:

```
repo/
├── services/            # → services_root
│   ├── nginx/docker-compose.yml
│   └── pg-app/{docker-compose.yml,meta.yaml,backup.sh}
└── config/              # → config dir (config.yaml etc., NOT users.yaml)
    └── config.yaml
```

## Webhook setup

- **GitHub**: repo → Settings → Webhooks → payload URL
  `https://ddm.example.com/api/gitops/webhook`, content type any, secret =
  `GITOPS_WEBHOOK_SECRET`. DDM verifies `X-Hub-Signature-256` (HMAC-SHA256
  over the raw body).
- **GitLab**: Settings → Webhooks → URL as above, Secret token =
  `GITOPS_WEBHOOK_SECRET`. Verified via the `X-Gitlab-Token` header.
- Without a configured secret the webhook always returns 403 — it cannot be
  accidentally left open.

## Push-back of manual changes

With `push_changes: true`, every `push_interval_secs` DDM diffs the targets
against the mirror; if anything changed locally it resets the mirror to
`origin/<branch>` first (so local edits are never lost silently — they are
re-applied on top of the latest remote state), copies the local files over,
commits as `commit_name <commit_email>`, and pushes.

Conflict policy: last sync wins at file granularity — the local copy always
overwrites the mirror for push, and the repo always overwrites the target
for pull. Keep `prune: false` unless you want deletions replicated.

Manual triggers (admin only):

- `POST /api/gitops/sync` — pull + apply now
- `POST /api/gitops/push` — commit & push pending local changes now
- `GET  /api/gitops/status` — last sync result, revision, pending count

CLI: `ddm gitops status|sync|push`. Web UI: **GitOps** tab (admin).

## Security notes

- `token`/`webhook_secret` support `*_env` indirection; secrets are redacted
  (`***`) in `GET /api/config` and scrubbed from git error messages before
  they reach logs.
- Service sync does **not** start/stop containers — it only updates files.
  A follow-up `update` action (or systemd restart) applies compose changes.
- `push_changes` commits whatever is in the target dirs; compose policy
  validation still applies to API edits, but direct filesystem edits are
  pushed as-is.
