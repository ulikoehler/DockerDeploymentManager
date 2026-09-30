# Server CLI (`ddm-server <subcommand>`)

The server binary doubles as an **offline admin tool** — it operates
directly on `config.yaml`/`users.yaml`, so it works inside the container
even when the HTTP server is down (first-admin bootstrap, lockout
recovery):

```bash
docker compose exec ddm ddm-server user list
```

All commands accept `--config /path/to/config.yaml` (default
`/etc/ddm/config.yaml`). Writes are atomic (flock + tmp + rename); the
running daemon picks changes up via its file watcher — no restart needed.

## Commands

```
ddm-server serve                          # run the daemon
ddm-server check-config                   # validate config.yaml + print users path
ddm-server hash [password]                # argon2 hash for hand-editing users.yaml
ddm-server unit-template <name> --dir /opt/services/x   # render the unit template

ddm-server user list
ddm-server user show <name>
ddm-server user add <name> --role admin [--password P | --generate | --prompt]
ddm-server user remove <name>
ddm-server user passwd <name> [--password P | --generate | --prompt]
ddm-server user set-roles <name> --role operator --role viewer
ddm-server user set-access <name> \
    --deny 'exact:core' \
    --allow 'glob:web-*' \
    --allow 'regex:^stg-[0-9]+$'
ddm-server user set-features <name> \
    --create-services true --edit-compose true --edit-units false \
    --run-commands true --manage-backup true --manage-monitoring false
ddm-server user set-policy <name> strict|relaxed|unrestricted|default
```

Notes:

- Password resolution order: `--password` > `--generate` (random 24-char,
  printed once) > interactive prompt on stderr.
- `set-access` takes rules in `kind:pattern` form; `--deny` rules are placed
  before `--allow` rules (first match wins).
- `set-policy default` clears the per-user policy (falls back to
  `security.default_policy`).
- Every mutation prints an `[audit]` line to stderr.

## Bootstrap example

```bash
docker compose exec ddm ddm-server user add admin --role admin --generate
# generated password for admin: aBc…
```
