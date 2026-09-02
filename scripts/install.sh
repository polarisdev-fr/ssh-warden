#!/usr/bin/env bash
#
# SSH-Warden admin script (server + helper)
#
# Usage:
#   curl -sSL .../scripts/install.sh | bash                       # install latest
#   curl -sSL .../scripts/install.sh | bash -s -- update          # update server + helper
#   curl -sSL .../scripts/install.sh | bash -s -- uninstall       # remove everything
#   curl -sSL .../scripts/install.sh | bash -s -- install-helper  # install/update only the helper
#
# 1st argument is the action (install|update|uninstall|install-helper), default install.
#
# Options (via environment variables):
#   WARDEN_VERSION      - Release version to use (default: latest)
#   WARDEN_INSTALL_DIR  - Installation directory (default: /usr/local/bin)
#   WARDEN_DATA_DIR     - Data directory for the DB (default: /var/lib/ssh-warden)
#   WARDEN_PORT         - API listen port (default: 8080)
#   WARDEN_API_URL      - URL the helper uses to reach the API (default: http://127.0.0.1:8080)
#   WARDEN_HOST_TOKEN   - Host bearer token to write to /etc/ssh-warden/token (optional)
#   WARDEN_WRITE_SSHD   - Set to "1" to append official sshd_config lines (default: 0)
#   WARDEN_FROM_SOURCE  - Set to "1" to build from source instead of downloading releases
#   KEEP_DATA           - With uninstall, set to "1" to preserve the data directory

set -euo pipefail

REPO="polarisdev-fr/ssh-warden"
INSTALL_DIR="${WARDEN_INSTALL_DIR:-/usr/local/bin}"
DATA_DIR="${WARDEN_DATA_DIR:-/var/lib/ssh-warden}"
PORT="${WARDEN_PORT:-8080}"
API_URL="${WARDEN_API_URL:-http://127.0.0.1:8080}"
VERSION="${WARDEN_VERSION:-}"
FROM_SOURCE="${WARDEN_FROM_SOURCE:-0}"
WRITE_SSHD="${WARDEN_WRITE_SSHD:-0}"

# File locations
SERVER_BIN="${INSTALL_DIR}/ssh-warden-server"
HELPER_BIN="${INSTALL_DIR}/ssh-warden-helper"
SERVICE="/etc/systemd/system/ssh-warden.service"
TOKEN_FILE="/etc/ssh-warden/token"
SSHD_CONF="/etc/ssh/sshd_config"
CONF_DIR="/etc/ssh-warden"

ACTION="${1:-install}"

# --- Helpers -----------------------------------------------------------

info()  { printf "\033[1;34m[ssh-warden]\033[0m %s\n" "$*" >&2; }
ok()    { printf "\033[1;32m[ssh-warden]\033[0m %s\n" "$*" >&2; }
warn()  { printf "\033[1;33m[ssh-warden]\033[0m %s\n" "$*" >&2; }
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

# --- Version helpers ---------------------------------------------------

# resolve_version sets VERSION to the latest release if it was left empty.
resolve_version() {
    if [[ -z "$VERSION" ]]; then
        info "Fetching latest release version..."
        VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
            | grep '"tag_name"' | head -1 | cut -d '"' -f 4)
        if [[ -z "$VERSION" ]]; then
            die "Could not determine latest release. Set WARDEN_VERSION manually."
        fi
    fi
    info "Target version: ${VERSION}"
}

# download_binary <binaryname> <dest-dir> -> echoes resolved path to stdout
# Downloads the GoReleaser archive for one binary (server or helper) and
# resolves the path of the extracted executable.
download_binary() {
    local name="$1" dest="$2"
    local arch_value os_value file_ver tarball url src candidate

    arch_value=$(uname -m)
    case "$arch_value" in
        x86_64|amd64) arch_value="amd64" ;;
        aarch64|arm64) arch_value="arm64" ;;
        armv7l|armhf) arch_value="armv6" ;;
        *) die "Unsupported architecture: $arch_value" ;;
    esac

    os_value=$(uname -s | tr '[:upper:]' '[:lower:]')
    # GoReleaser uses the bare version (no 'v' prefix) in filenames.
    file_ver="${VERSION#v}"
    tarball="ssh-warden-${name}_${file_ver}_${os_value}_${arch_value}.tar.gz"
    url="https://github.com/${REPO}/releases/download/${VERSION}/${tarball}"

    info "Fetching ${name} (${tarball})..."
    curl -fsSL "$url" -o "${dest}/${tarball}"
    tar -xzf "${dest}/${tarball}" -C "${dest}"

    src=""
    for candidate in \
        "${dest}/${name}" "${dest}/bin/${name}" \
        "${dest}/${name}.exe" "${dest}/bin/${name}.exe"; do
        if [[ -f "$candidate" ]]; then
            src="$candidate"
            break
        fi
    done
    if [[ -z "$src" ]]; then
        die "Could not find ${name} in the release archive."
    fi

    printf '%s' "$src"
}

# build_source <binaryname> builds one cmd from the cloned tree into dest and
# echoes the resolved source path to stdout.
build_source() {
    local name="$1"
    local pkg
    case "$name" in
        ssh-warden-server) pkg="./cmd/server" ;;
        ssh-warden-helper) pkg="./cmd/helper" ;;
        *) die "Unknown binary: $name" ;;
    esac
    info "Building ${name} from source (${VERSION})..."
    CGO_ENABLED=0 go build -ldflags="-s -w" -o "${TMPDIR}/${name}" "$pkg"
    printf '%s' "${TMPDIR}/${name}"
}

# --- Uninstall ---------------------------------------------------------

if [[ "$ACTION" == "uninstall" ]]; then
    info "Uninstalling SSH-Warden..."

    if [[ -f "$SERVICE" ]]; then
        info "Stopping and disabling systemd service..."
        systemctl disable --now ssh-warden.service 2>/dev/null || true
        rm -f "$SERVICE"
        systemctl daemon-reload
        ok "Service removed"
    fi

    for binpath in "$SERVER_BIN" "$HELPER_BIN"; do
        if [[ -f "$binpath" ]]; then
            rm -f "$binpath"
            ok "Binary removed: $binpath"
        fi
    done

    if [[ -d "$CONF_DIR" ]]; then
        rm -rf "$CONF_DIR"
        ok "Token/config directory removed: $CONF_DIR"
    fi

    if [[ -d "$DATA_DIR" ]]; then
        if [[ "${KEEP_DATA:-0}" != "1" ]]; then
            rm -rf "$DATA_DIR"
            ok "Data directory removed: $DATA_DIR"
        else
            ok "Data directory kept (KEEP_DATA=1): $DATA_DIR"
        fi
    fi

    if id -u ssh-warden >/dev/null 2>&1; then
        userdel -r ssh-warden 2>/dev/null || true
        ok "User 'ssh-warden' removed"
    fi

    # Best-effort: strip sshd_config lines this script may have added.
    if [[ -f "$SSHD_CONF" ]]; then
        cp "$SSHD_CONF" "${SSHD_CONF}.warden-bak"
        sed -i '/ssh-warden-helper/d; /# SSH-Warden/d; /AuthorizedKeysCommandUser/d' "$SSHD_CONF"
        ok "Removed ssh-warden entries from sshd_config (backup: ${SSHD_CONF}.warden-bak)"
        if command -v sshd >/dev/null 2>&1; then
            sshd -t 2>/dev/null && systemctl reload ssh 2>/dev/null || true
        fi
    fi

    echo ""
    ok "SSH-Warden uninstalled."
    exit 0
fi

# --- Resolve version ---------------------------------------------------

resolve_version

if [[ "$FROM_SOURCE" == "1" ]]; then
    need git
    need go
    TMPDIR=$(mktemp -d)
    trap 'rm -rf "$TMPDIR"' EXIT
    info "Cloning source tree..."
    git clone --depth 1 --branch "${VERSION}" "https://github.com/${REPO}.git" "${TMPDIR}/src"
    cd "${TMPDIR}/src"
else
    TMPDIR=$(mktemp -d)
    trap 'rm -rf "$TMPDIR"' EXIT
fi

# --- Build or download binaries ----------------------------------------

SERVER_SRC=""
HELPER_SRC=""

if [[ "$ACTION" == "install-helper" ]]; then
    if [[ "$FROM_SOURCE" == "1" ]]; then
        HELPER_SRC=$(build_source ssh-warden-helper)
    else
        HELPER_SRC=$(download_binary ssh-warden-helper "$TMPDIR")
    fi
else
    if [[ "$FROM_SOURCE" == "1" ]]; then
        SERVER_SRC=$(build_source ssh-warden-server)
        HELPER_SRC=$(build_source ssh-warden-helper)
    else
        SERVER_SRC=$(download_binary ssh-warden-server "$TMPDIR")
        HELPER_SRC=$(download_binary ssh-warden-helper "$TMPDIR")
    fi
fi

# Stop a running service before replacing the server binary (avoids
# "text file busy" / exec format race). systemd restarts it below.
if [[ -n "$SERVER_SRC" && -f "$SERVICE" ]] && \
    systemctl is-active --quiet ssh-warden.service 2>/dev/null; then
    info "Stopping running service for fresh binary..."
    systemctl stop ssh-warden.service || true
fi

# --- Install server ----------------------------------------------------

if [[ -n "$SERVER_SRC" ]]; then
    info "Installing server binary to ${INSTALL_DIR}..."
    install -o root -g root -m 755 "$SERVER_SRC" "$SERVER_BIN"
    ok "Server installed: $SERVER_BIN"
fi

# --- Install helper ----------------------------------------------------

if [[ -n "$HELPER_SRC" ]]; then
    info "Installing helper binary to ${INSTALL_DIR}..."
    install -o root -g root -m 755 "$HELPER_SRC" "$HELPER_BIN"
    ok "Helper installed: $HELPER_BIN"

    # Write host token (optional but recommended).
    if [[ -n "${WARDEN_HOST_TOKEN:-}" ]]; then
        install -d -o root -g root -m 711 "$CONF_DIR"
        printf '%s' "$WARDEN_HOST_TOKEN" > "$TOKEN_FILE"
        # The sshd AuthorizedKeysCommand runs as 'nobody', so the token must be
        # readable by that account. In production prefer passing the token via
        # the WARDEN_HOST_TOKEN environment variable (SetEnv / systemd override)
        # instead of a world-readable file, then lock the file down.
        chmod 644 "$TOKEN_FILE"
        ok "Host token written to $TOKEN_FILE (world-readable for AuthorizedKeysCommandUser)"
        warn "In production, prefer WARDEN_HOST_TOKEN env injection and a 600 token file."
    elif [[ -f "$TOKEN_FILE" ]]; then
        if [[ ! -r "$TOKEN_FILE" ]] && [[ "$WRITE_SSHD" == "1" ]]; then
            chmod 644 "$TOKEN_FILE"
            ok "Made existing host token readable by sshd (chmod 644): $TOKEN_FILE"
        else
            ok "Keeping existing host token at $TOKEN_FILE"
        fi
    else
        warn "No WARDEN_HOST_TOKEN provided; helper will fail until one is written to $TOKEN_FILE"
    fi

    # Optionally append sshd_config lines.
    if [[ "$WRITE_SSHD" == "1" ]]; then
        if [[ -f "$SSHD_CONF" ]] && ! grep -q 'ssh-warden-helper' "$SSHD_CONF"; then
            info "Appending ssh-warden helper entries to $SSHD_CONF..."
            cp "$SSHD_CONF" "${SSHD_CONF}.warden-bak"
            cat >> "$SSHD_CONF" <<EOF

# SSH-Warden just-in-time key resolution
AuthorizedKeysCommand ${HELPER_BIN} %u
AuthorizedKeysCommandUser nobody
PubkeyAcceptedAlgorithms +ssh-rsa
EOF
            systemctl reload ssh 2>/dev/null || true
            ok "sshd_config updated (backup: ${SSHD_CONF}.warden-bak)"
        else
            ok "sshd_config already contains ssh-warden entries"
        fi
    fi
fi

# --- Server service setup (skip for install-helper only) ---------------

if [[ "$ACTION" != "install-helper" ]]; then
    # Create system user.
    if ! id -u ssh-warden >/dev/null 2>&1; then
        info "Creating system user 'ssh-warden'..."
        useradd --system --home "$DATA_DIR" --create-home --shell /usr/sbin/nologin ssh-warden
        ok "User 'ssh-warden' created"
    else
        ok "User 'ssh-warden' already exists"
    fi

    # Data directory.
    info "Setting up data directory $DATA_DIR..."
    install -d -o ssh-warden -g ssh-warden -m 750 "$DATA_DIR"
    ok "Data directory ready"

    # Systemd unit.
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

    sleep 1
    if curl -fs "http://localhost:${PORT}/health" >/dev/null 2>&1; then
        ok "Server is healthy at http://localhost:${PORT}"
    else
        warn "Server started but health check failed — check: journalctl -u ssh-warden.service -n 20"
    fi
fi

# --- Summary -----------------------------------------------------------

echo ""
ok "SSH-Warden ${VERSION} ${ACTION} complete!"
echo ""
echo "  Server binary : ${SERVER_BIN}"
echo "  Helper binary : ${HELPER_BIN}"
echo "  Data          : ${DATA_DIR}/warden.db"
echo "  Service       : systemctl status ssh-warden"
echo "  Logs          : journalctl -u ssh-warden -f"
echo "  Health        : curl http://localhost:${PORT}/health"
echo ""
if [[ "$ACTION" != "install-helper" ]]; then
    echo "Next steps:"
    echo "  1. Install the CLI on your workstation:"
    echo "       go install github.com/${REPO}/cmd/cli@${VERSION}"
    echo "  2. Register a host:"
    echo "       warden config set api_url http://localhost:${PORT}"
    echo "  3. Configure OpenSSH (see docs/installation.md)."
    echo "     Tip: re-run with WARDEN_WRITE_SSHD=1 to wire AuthorizedKeysCommand automatically."
fi
