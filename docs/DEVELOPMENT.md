# Development

## Prerequisites

- Rust stable (1.75+), `cargo`
- Node 20+ (web UI)
- Python 3.10+ with pip (client)
- Optional: Docker + systemd host for end-to-end testing

## Build & test

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test

cd web
npm ci
npm run typecheck    # tsc --noEmit
npm run build        # esbuild → dist/bundle.js

cd ../python
pip install -e '.[dev]'
pytest -q
```

CI (`.github/workflows/ci.yml`) runs all of the above.

## Layout

- `crates/ddm-server/src/` — backend modules (see ARCHITECTURE.md table).
- `crates/ddm-server/src/api/` — REST + WS handlers.
- `web/src/` — Lit components; `api.ts` is the typed REST/WS client.
- `python/src/ddm_client/` — `client.py` (library), `cli.py` (`ddm`).

## Running locally without Docker

`host_exec: local` in config + a services dir you own; the docker socket is
still required for container listing (or point `docker.socket` at a remote
`tcp://`/`ssh://` host). `MockExec`/`MockDocker` cover unit tests.

## Conventions

- Server-side service names: `^[a-z0-9._-]+$`, no leading `.`, `-`, `_`.
- Mutable YAML writes go through atomic write helpers
  (`SharedConfig::mutate`, `write_users_atomic`) so the hot-reload watcher
  picks them up without races.
- Secrets are carried by `*_env` indirection or direct fields; all API
  responses redact secret-bearing keys to `***`.
- No locks held across `.await` where mutation ordering matters (see
  `monitor.rs` auto-action handling for the pattern).
