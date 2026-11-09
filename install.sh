#!/bin/sh
# ddm bootstrap installer — no repo clone needed.
#
#   curl -fsSL https://raw.githubusercontent.com/ulikoehler/DockerDeploymentManager/main/install.sh | sudo bash
#
# Fetches the latest GitHub release tarball (or $DDM_VERSION if set),
# verifies its SHA256 checksum, and runs the packaged bare-metal
# installer. Every command is echoed before it runs.
set -eu

REPO="ulikoehler/DockerDeploymentManager"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

say() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
# echo the command to stderr so stdout stays clean for $( ) captures
run() {
    printf '\033[1;36m+\033[0m' >&2
    printf ' %s' "$@" >&2
    printf '\n' >&2
    "$@"
}

if [ "$(id -u)" != "0" ]; then
    cat >&2 <<EOF
this installer must run as root — it writes /opt/ddm, /etc/ddm and a
systemd unit. Re-run:

  curl -fsSL https://raw.githubusercontent.com/$REPO/main/install.sh | sudo bash
EOF
    exit 1
fi

arch=$(uname -m)
case "$arch" in
    x86_64|amd64)  arch=x86_64 ;;
    aarch64|arm64) arch=aarch64 ;;
    *) echo "unsupported arch: $arch" >&2; exit 1 ;;
esac

if [ -n "${DDM_VERSION:-}" ]; then
    tag=$DDM_VERSION
    say "Using pinned release: $tag"
else
    say "Resolving latest release of $REPO ..."
    eff=$(run curl -fsSL -o /dev/null -w '%{url_effective}' \
        "https://github.com/$REPO/releases/latest")
    tag=${eff##*/}
    say "Latest release: $tag"
fi
case $tag in
    v*) ver=${tag#v} ;;
    *)  ver=$tag ;;
esac

base="https://github.com/$REPO/releases/download/$tag"
tb="ddm-${ver}-linux-${arch}.tar.gz"

# already installed? compare the on-disk binary's version with the target
installed_ver=""
if [ -x /opt/ddm/bin/ddm-server ]; then
    installed_ver=$(/opt/ddm/bin/ddm-server --version 2>/dev/null | awk '{print $2}')
fi

if [ -n "$installed_ver" ] && [ "$installed_ver" = "$ver" ] \
    && systemctl cat ddm.service >/dev/null 2>&1; then
    say "ddm-server $ver is already installed."
    if ! systemctl is-active --quiet ddm.service; then
        say "Service is not running — restarting it."
        run systemctl restart ddm.service
    else
        say "Service is active — nothing to do."
    fi
    exit 0
fi

if [ -n "$installed_ver" ]; then
    say "Updating ddm-server $installed_ver -> $ver"
else
    say "No existing install found — installing ddm-server $ver"
fi

say "Downloading $tb ..."
run curl -fsSL "$base/$tb" -o "$TMP/$tb"
run curl -fsSL "$base/SHA256SUMS" -o "$TMP/SHA256SUMS"

say "Verifying checksum ..."
( cd "$TMP" && run sh -c "grep -F '$tb' SHA256SUMS | sha256sum -c -" )

say "Extracting ..."
run tar -xzf "$TMP/$tb" -C "$TMP"
pkg="$TMP/ddm-${ver}-linux-${arch}"
[ -d "$pkg" ] || { echo "unexpected tarball layout: $pkg not found" >&2; exit 1; }

say "Installing (binary -> /opt/ddm, config -> /etc/ddm, systemd unit) ..."
( cd "$pkg" && run ./install.sh )

say "Done — ddm-server $ver is installed and running."
say "  systemctl status ddm"
say "  API/UI:  http://<this-host>:8080  (set server.listen in /etc/ddm/config.yaml)"
