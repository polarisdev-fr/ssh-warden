#!/usr/bin/env bash
#
# SSH-Warden quick installer
# Usage: curl -sSL https://raw.githubusercontent.com/polarisdev-fr/ssh-warden/main/scripts/install.sh | bash
#
# Options (via environment variables):
#   WARDEN_VERSION    - Release version to install (default: latest)
#   WARDEN_INSTALL_DIR - Installation directory (default: /usr/local/bin)
#   WARDEN_DATA_DIR   - Data directory for the DB (default: /var/lib/ssh-warden)
#   WARDEN_PORT       - API listen port (default: 8080)
#   WARDEN_FROM_SOURCE - Set to "1" to build from source instead of downloading a release

set -euo pipefail

REPO="polarisdev-fr/ssh-warden"
INSTALL_DIR="${WARDEN_INSTALL_DIR:-/usr/local/bin}"
DATA_DIR="${WARDEN_DATA_DIR:-/var/lib/ssh-warden}"
PORT="${WARDEN_PORT:-8080}"
VERSION="${WARDEN_VERSION:-}"
FROM_SOURCE="${WARDEN_FROM_SOURCE:-0}"

# --- Helpers -----------------------------------------------------------

info()  { printf "\033[1;34m[ssh-warden]\033[0m %s\n" "$*"; }
ok()    { printf "\033[1;32m[ssh-warden]\033[0m %s\n" "$*"; }
warn()  { printf "\033[1;33m[ssh-warden]\033[0m %s\n" "$*"; }
die()   { printf "\033[1;31m[ssh-warden]\033[0m %s\n" "$*" >&2; exit 1; }

need() {
    command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not found. Install it first."
}

# --- Preflight ---------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    die "This script must be run as root (use sudo)."
fi

need curl
need tar
need install

if [[ "$FROM_SOURCE" == "1" ]]; then
    need go
fi

# --- Resolve version ---------------------------------------------------

if [[ -z "$VERSION" ]]; then
    info "Fetching latest release version..."
    VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep '"tag_name"' | head -1 | cut -d '"' -f 4)
    if [[ -z "$VERSION" ]]; then
        die "Could not determine latest release. Set WARDEN_VERSION manually."
    fi
fi
info "Target version: ${VERSION}"

# --- Download or build -------------------------------------------------

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

if [[ "$FROM_SOURCE" == "1" ]]; then
    info "Building from source (${VERSION})..."
    need git
    git clone --depth 1 --branch "${VERSION}" "https://github.com/${REPO}.git" "${TMPDIR}/src"
    cd "${TMPDIR}/src"
    CGO_ENABLED=0 go build -ldflags="-s -w" -o "${TMPDIR}/ssh-warden-server" ./cmd/server
else
    info "Downloading release ${VERSION}..."
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64|amd64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        armv7l|armhf) ARCH="armv6" ;;
        *) die "Unsupported architecture: $ARCH" ;;
    esac

    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    # GoReleaser uses the bare version (no 'v' prefix) in filenames.
    FILE_VER="${VERSION#v}"
    TARBALL="ssh-warden-ssh-warden-server_${FILE_VER}_${OS}_${ARCH}.tar.gz"
    URL="https://github.com/${REPO}/releases/download/${VERSION}/${TARBALL}"

    info "Fetching ${TARBALL}..."
    curl -fsSL "$URL" -o "${TMPDIR}/${TARBALL}"
    tar -xzf "${TMPDIR}/${TARBALL}" -C "${TMPDIR}"

    # Find the server binary in the extracted archive. GoReleaser names it
    # after the build, e.g. "ssh-warden-server".
    SERVER_BIN=""
    for candidate in "${TMPDIR}/ssh-warden-server" "${TMPDIR}/bin/ssh-warden-server" \
                     "${TMPDIR}/ssh-warden-server.exe" "${TMPDIR}/bin/ssh-warden-server.exe"; do
        if [[ -f "$candidate" ]]; then
            SERVER_BIN="$candidate"
            break
        fi
    done
    if [[ -z "$SERVER_BIN" ]]; then
        die "Could not find ssh-warden-server in the release archive."
    fi
    mv "$SERVER_BIN" "${TMPDIR}/ssh-warden-server"
fi

# --- Install binary ----------------------------------------------------

info "Installing server binary to ${INSTALL_DIR}..."
install -o root -g root -m 755 "${TMPDIR}/ssh-warden-server" "${INSTALL_DIR}/ssh-warden-server"
ok "Binary installed: ${INSTALL_DIR}/ssh-warden-server"

# --- Create system user ------------------------------------------------

if ! id -u ssh-warden >/dev/null 2>&1; then
    info "Creating system user 'ssh-warden'..."
    useradd --system --home "${DATA_DIR}" --create-home --shell /usr/sbin/nologin ssh-warden
    ok "User 'ssh-warden' created"
else
    ok "User 'ssh-warden' already exists"
fi

# --- Data directory ----------------------------------------------------

info "Setting up data directory ${DATA_DIR}..."
install -d -o ssh-warden -g ssh-warden -m 750 "${DATA_DIR}"
ok "Data directory ready"

# --- Systemd unit ------------------------------------------------------

info "Installing systemd service..."
cat > /etc/systemd/system/ssh-warden.service <<UNIT
[Unit]
Description=SSH-Warden API (Just-In-Time SSH access broker)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ssh-warden
Group=ssh-warden
WorkingDirectory=${DATA_DIR}
Environment=WARDEN_DB_PATH=${DATA_DIR}/warden.db
Environment=WARDEN_PORT=${PORT}
ExecStart=${INSTALL_DIR}/ssh-warden-server
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${DATA_DIR}
PrivateTmp=true
UMask=0077

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now ssh-warden.service
ok "Service installed and started"

# --- Verify ------------------------------------------------------------

sleep 1
if curl -fs "http://localhost:${PORT}/health" >/dev/null 2>&1; then
    ok "Server is healthy at http://localhost:${PORT}"
else
    warn "Server started but health check failed — check: journalctl -u ssh-warden.service -n 20"
fi

# --- Summary -----------------------------------------------------------

echo ""
ok "SSH-Warden server ${VERSION} installed successfully!"
echo ""
echo "  Binary    : ${INSTALL_DIR}/ssh-warden-server"
echo "  Data      : ${DATA_DIR}/warden.db"
echo "  Service   : systemctl status ssh-warden"
echo "  Logs      : journalctl -u ssh-warden -f"
echo "  Health    : curl http://localhost:${PORT}/health"
echo ""
echo "Next steps:"
echo "  1. Install the CLI on your workstation:"
echo "       go install github.com/${REPO}/cmd/cli@${VERSION}"
echo "  2. Register a host:"
echo "       warden config set api_url http://localhost:${PORT}"
echo "  3. See docs/installation.md for OpenSSH host configuration"
echo ""
