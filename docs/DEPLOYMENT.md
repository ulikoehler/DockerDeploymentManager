# Deployment

ddm runs **inside docker** but manages the **host**'s systemd and other
containers. That works because it runs privileged with the host PID
namespace.

## docker-compose.yml (self-deployment)

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
- `local`: commands run inside the container. For development/bare-metal
  installs only.

## Bootstrap

```bash
mkdir -p data data-state /opt/services
cp config.example.yaml data/config.yaml
cp -r examples/templates data/templates
# users.yaml can start empty — bootstrap in-container:
docker compose pull && docker compose up -d
docker compose exec ddm ddm-server user add admin --role admin --generate
```

## Requirements on the host

- docker + compose (v2 plugin or `docker-compose`)
- systemd (for unit management, backup timers, group commands)
- `restic` (only if `backup.enabled` — resolved via `which` on the host)

## Upgrades

The image embeds `/opt/ddm/web` (the UI) and `/etc/ddm/config.yaml`
(example). Your real config lives in the `./data` volume and is never
overwritten by image updates.
