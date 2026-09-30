# Python client & `ddm` CLI

## Install

```bash
cd python
pip install -e .          # installs `ddm`
pip install -e '.[dev]'   # + pytest for tests
```

## CLI

Config via env or flags: `DDM_URL` (default `http://localhost:8080`),
`DDM_USER`, `DDM_PASSWORD`, or `DDM_TOKEN` (skips login).
`--json` for raw JSON output.

```
ddm login
ddm services
ddm status [service]
ddm logs <svc> [--follow] [--grep X] [--regex X] [--exclude-regex X]
     [--stream stderr] [--container web] [--since 1700000000] [--tail 500]
ddm update|pull|up|down|restart|start|stop|enable|disable <svc>
ddm create <name> --compose compose.yml | --template <id> [--var k=v]
     [--no-unit] [--no-enable] [--start]
ddm delete <svc> [--keep-dir]
ddm compose <svc> get | put [file|-] [--recreate]
ddm files <svc> ls|cat|write|mkdir|rename|rm [path] [arg]
ddm git <svc> repos|status|log|branches|clone|pull|fetch|checkout
     [path] [url|ref] [--branch B] [-n N]
ddm unit <svc> get | put [file|-] [--restart] | check | regenerate
ddm backup <svc> status|check|provision|run|snapshots|forget|restore
     [--snapshot S] [--target /path]
ddm monitor status|events|test [svc]
ddm notify list|add|update|remove <id> [--type telegram] [--set k=v]
     [--json-body '{...}']
ddm notify-test <id> [--message ...]
ddm users list|show|add|remove|passwd|access|roles|policy|features ...
ddm commands                              # list sections/items
ddm exec <section> <item> [--param k=v]   # run + stream output
ddm events                                # monitoring events
ddm audit                                 # audit ring (admin)
```

Lifecycle commands stream the execution output live and exit with the
execution's status.

## Library

```python
from ddm_client import DdmClient

c = DdmClient("http://localhost:8080")
c.login("admin", "secret")

for s in c.services():
    print(s["name"], s["running"], "/", s["total"])

# filtered logs snapshot
for line in c.logs("web", tail=500, grep="error", stream="stderr"):
    print(line["text"])

# live follow
import asyncio
async def tail():
    it = await c.follow_logs("web", regex="ERROR")
    async for line in it:
        print(line)
asyncio.run(tail())

# compose round-trip (policy-validated server-side)
comp = c.get_compose("web")
c.put_compose("web", new_content, recreate=True)

# users
c.create_user("ci", "…", roles=["operator"],
              access=[{"type": "glob", "pattern": "web-*", "effect": "allow"}])
c.set_access("ci", [{"type": "exact", "pattern": "core", "effect": "deny"}])

# backup / monitoring / commands
c.backup_run("pg-app")
c.backup_snapshots("pg-app")
r = c.run_command(0, 1, {"all": "true"})
print(r["execution_id"])
```

`DdmError` carries `.status` and `.message`. `stream_execution(id)` is an
async iterator of `ServerMessage` dicts (same for `follow_logs`).

### GitOps

```python
c.gitops_status(); c.gitops_sync(); c.gitops_push()
```

```bash
ddm gitops status|sync|push
```
