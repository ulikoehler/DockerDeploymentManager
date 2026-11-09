# Deployment

ddm is a **single static-ish binary** (`ddm-server`) with the web UI,
REST API, MCP server, and CLI compiled in. The standard install is
**bare-metal**: binary + config files + a systemd unit. It runs with
effective host root by design — it manages host systemd units, docker
containers, and the service root — so there is no sandbox to speak of
either way; running it in a privileged container adds complexity without
adding isolation.

## Bare-metal install (standard)

One-liner — fetches the latest release, verifies SHA256, installs:

```bash
curl -fsSL https://raw.githubusercontent.com/ulikoehler/DockerDeploymentManager/main/install.sh | sudo bash
```

Set `DDM_VERSION=vX.Y.Z` to pin a release instead of tracking latest.

Or manually — release tarballs (`ddm-<ver>-linux-<arch>.tar.gz`) are
attached to every `v*` GitHub release and contain `ddm-server`,
`config.yaml`, `ddm.service`, and `install.sh`:

```bash
tar xzf ddm-<ver>-linux-x86_64.tar.gz
cd ddm-<ver>-linux-x86_64
sudo ./install.sh
```

The installer:

- installs the binary to `/opt/ddm/bin/ddm-server`
- writes `/etc/ddm/config.yaml` (bare-metal variant: `host_exec: local`,
  `host_systemd_dir: /etc/systemd/system`), `/etc/ddm/ddm.env` (generated
  `DDM_JWT_SECRET`, mode 0600), and an empty `/etc/ddm/users.yaml`
- installs and enables `ddm.service`

Then create the first admin:

```bash
/opt/ddm/bin/ddm-server --config /etc/ddm/config.yaml \
    user add admin --role admin --generate
```

Manual equivalent (if you build from source):

```bash
cargo build --release -p ddm-server   # web/dist is embedded automatically
install -m755 target/release/ddm-server /opt/ddm/bin/ddm-server
cp deploy/bare-metal/config.yaml /etc/ddm/config.yaml
cp deploy/bare-metal/ddm.service /etc/systemd/system/ddm.service
# …then the env/users steps from install.sh
systemctl daemon-reload && systemctl enable --now ddm
```

### host paths (bare metal)

| path | purpose |
|---|---|
| `/opt/services` | service root — compose projects ddm manages |
| `/etc/ddm/config.yaml` | hot-reloaded config |
| `/etc/ddm/users.yaml` | users (argon2 hashes), mode 0600 |
| `/etc/ddm/ddm.env` | `DDM_JWT_SECRET` etc., mode 0600 |
| `/var/lib/ddm` | monitor/exec state |

`paths.host_exec: local` makes ddm run `systemctl`, `docker compose`,
`restic`, `git` etc. directly — they are host binaries, no nsenter.

## Docker image (optional)

For hosts where you prefer `docker compose up`, an image
`ulikoehler/ddm` is published to Docker Hub on every push to `main`
(amd64+arm64) and can also be built locally with `docker build .`.

```yaml
services:
  ddm:
    image: ulikoehler/ddm:latest   # or build: .
    restart: unless-stopped
    pid: host                  # nsenter -t 1 needs the host PID ns
    privileged: true           # nsenter needs CAP_SYS_ADMIN
    ports: ["8080:8080"]
    environment:
      DDM_JWT_SECRET: change-me
      # SLACK_WEBHOOK_URL: https://hooks.slack.com/…
      # TELEGRAM_BOT_TOKEN: …
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /opt/services:/opt/services    # same path both sides!
      - /etc/systemd/system:/host/systemd    # host unit dir
      - ./data:/etc/ddm                       # config + users
      - ./data-state:/var/lib/ddm             # monitor state
```

### Why each mount

| mount | purpose |
|---|---|
| `docker.sock` | container listing/logs (bollard) + `docker compose` CLI |
| service root (same path both sides) | compose files + `meta.yaml`; generated units and `backup.sh` reference `WorkingDirectory=`/`cd` paths that must be valid **on the host** |
| `/etc/systemd/system → /host/systemd` | unit files are written here; `systemctl` runs via nsenter on the host |
| `./data` | config.yaml + users.yaml (hot-reloaded) |
| `/var/lib/ddm` | monitor state dir |

If the service dir must have different paths inside/outside, set
`paths.host_services_root` to the host path.

### host_exec modes

- `nsenter` (default): host commands run as
  `nsenter --target 1 --mount --uts --ipc --net -- <cmd>` — host binaries,
  host systemd. Requires `pid: host` + `privileged: true`.
- `local`: commands run directly. Used by bare-metal installs and for
  development.

## Requirements on the host

- docker + compose (v2 plugin or `docker-compose`)
- systemd (for unit management, backup timers, group commands)
- `restic` (only if `backup.enabled` — resolved via `which` on the host)
- git (for git clone/pull features)

## Upgrades

**Bare metal:** download the new tarball, `systemctl stop ddm`, replace
`/opt/ddm/bin/ddm-server`, `systemctl start ddm`. Config and users live
in `/etc/ddm` and are untouched; new config keys fall back to defaults.

**Docker:** `docker compose pull && docker compose up -d`. The image's
embedded example config is shadowed by the `./data` volume and never
overwritten.
