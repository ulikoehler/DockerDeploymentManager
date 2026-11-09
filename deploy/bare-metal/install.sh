#!/bin/sh
# ddm bare-metal installer. Run from an extracted release tarball:
#   tar xzf ddm-<ver>-linux-<arch>.tar.gz && cd ddm-<ver>-linux-<arch>
#   sudo ./install.sh
#
# Installs the single ddm-server binary (web UI embedded) to /opt/ddm,
# writes /etc/ddm/{config.yaml,ddm.env,users.yaml} and a systemd unit.
set -eu

PREFIX=/opt/ddm
ETC=/etc/ddm
UNIT=/etc/systemd/system/ddm.service

if [ "$(id -u)" != "0" ]; then
    echo "run as root (sudo ./install.sh)" >&2
    exit 1
fi

arch=$(uname -m)
case "$arch" in
    x86_64|amd64)  arch=x86_64 ;;
    aarch64|arm64) arch=aarch64 ;;
    *) echo "unsupported arch: $arch" >&2; exit 1 ;;
esac

# the binary ships next to this script inside the tarball
if [ ! -f ./ddm-server ]; then
    echo "ddm-server binary not found — run from the extracted tarball" >&2
    exit 1
fi

mkdir -p "$PREFIX/bin" "$ETC" /var/lib/ddm

install -m 0755 ./ddm-server "$PREFIX/bin/ddm-server"

if [ ! -f "$ETC/config.yaml" ]; then
    install -m 0644 ./config.yaml "$ETC/config.yaml"
    echo "installed $ETC/config.yaml"
fi

if [ ! -f "$ETC/ddm.env" ]; then
    if command -v openssl >/dev/null 2>&1; then
        secret=$(openssl rand -hex 32)
    else
        secret=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
    fi
    printf 'DDM_JWT_SECRET=%s\n' "$secret" > "$ETC/ddm.env"
    chmod 0600 "$ETC/ddm.env"
    echo "generated $ETC/ddm.env (JWT secret)"
fi

[ -f "$ETC/users.yaml" ] || : > "$ETC/users.yaml"
chmod 0600 "$ETC/users.yaml" 2>/dev/null || true

install -m 0644 ./ddm.service "$UNIT"
systemctl daemon-reload
systemctl enable ddm.service
# restart (not --now): on upgrade the old process must be replaced;
# restart also starts the unit on a fresh install
systemctl restart ddm.service

echo
echo "ddm installed. Listening on :8080 (see $ETC/config.yaml server.listen)."
echo "Create the first admin:"
echo "  $PREFIX/bin/ddm-server --config $ETC/config.yaml user add admin --role admin --generate"
