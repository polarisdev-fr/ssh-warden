# SSH-Warden Installation Guide

## Quick install (one-liner)

Install the server on a Linux host with a single command:

```sh
curl -sSL https://raw.githubusercontent.com/polarisdev-fr/ssh-warden/main/scripts/install.sh | sudo bash
```

This downloads the latest release, creates a `ssh-warden` system user, installs
the binary to `/usr/local/bin`, and starts a systemd service. Customize via
environment variables:

```sh
# Install a specific version
curl -sSL ... | sudo WARDEN_VERSION=v0.2.0 bash

# Install from source (requires Go)
curl -sSL ... | sudo WARDEN_FROM_SOURCE=1 bash

# Custom port and data directory
curl -sSL ... | sudo WARDEN_PORT=9090 WARDEN_DATA_DIR=/opt/ssh-warden bash
```

---

This guide covers two sides of the deployment:

1. **The server** — the `ssh-warden-server` (the Warden API + SQLite). You
   pick one method: a Linux `systemd` service built from source, or a Docker /
   Docker Compose container.
2. **The target hosts** — machines whose OpenSSH you want to protect. Each gets
   the `ssh-warden-helper` binary, an OpenSSH snippet, and a host token.

---

## 1. Server deployment

### Method A — Docker / Docker Compose

The provided `Dockerfile` builds a scratch- or Alpine-based image containing
the server binary. Because the binary is pure Go (no CGO), you can ship a
minimal final stage.

```dockerfile
# --- build stage ---
FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /warden-server ./cmd/server

# --- runtime stage ---
FROM scratch
COPY --from=build /warden-server /warden-server
VOLUME ["/data"]
EXPOSE 8080
ENV WARDEN_DB_PATH=/data/warden.db
ENTRYPOINT ["/warden-server"]
```

> Note: if the server does not yet read `WARDEN_DB_PATH`, use a fixed database
> path via the working directory instead (see the systemd method below). The
> important principle is that the database lives on a persistent, volume-mapped
> location.

A Compose manifest:

```yaml
# docker-compose.yml
services:
  warden:
    build: .
    image: ssh-warden:latest
    container_name: ssh-warden
    restart: unless-stopped
    ports:
      - "127.0.0.1:8080:8080"   # bind to loopback; TLS via reverse proxy
    volumes:
      - warden-data:/data
    environment:
      # WARDEN_WEBHOOK_URL: "https://discord.com/api/webhooks/..."
      TZ: "Etc/UTC"
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp

volumes:
  warden-data:
```

Run it:

```sh
docker compose up -d
docker compose logs -f warden
```

Hardening notes:

- Bind the published port to `127.0.0.1` and terminate TLS in front of it (see
  `security.md` > Reverse Proxy & TLS).
- Run with `read_only: true`, `no-new-privileges`, and a dedicated non-root
  user in the image so the process cannot write to the container filesystem
  (only the `/data` volume).
- Keep `WARDEN_DB_PATH` (or the working directory) on the persistent volume.

### Method B — Native Linux `systemd` service

Build and install the server binary and its service unit.

#### Build the binary

```sh
# from the repository root
CGO_ENABLED=0 go build -ldflags="-s -w" -o /usr/local/bin/ssh-warden-server ./cmd/server
```

#### Create the dedicated user and directories

```sh
useradd --system --home /var/lib/ssh-warden --create-home --shell /usr/sbin/nologin ssh-warden
install -d -o ssh-warden -g ssh-warden -m 750 /var/lib/ssh-warden
```

#### Systemd unit

Create `/etc/systemd/system/ssh-warden.service`:

```ini
[Unit]
Description=SSH-Warden API (Just-In-Time SSH access broker)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ssh-warden
Group=ssh-warden
WorkingDirectory=/var/lib/ssh-warden
Environment=WARDEN_DB_PATH=/var/lib/ssh-warden/warden.db
# Environment=WARDEN_WEBHOOK_URL=https://discord.com/api/webhooks/...
ExecStart=/usr/local/bin/ssh-warden-server
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/ssh-warden
PrivateTmp=true
# Limit the DB file exposure if the server binds a TCP socket
UMask=0077

[Install]
WantedBy=multi-user.target
```

Enable and start it:

```sh
systemctl daemon-reload
systemctl enable --now ssh-warden.service
systemctl status ssh-warden.service
journalctl -u ssh-warden.service -f
```

Verify the database file has the right ownership:

```sh
ls -l /var/lib/ssh-warden/warden.db
# -rw-rw----  ssh-warden ssh-warden ...  warden.db
```

---

## 1.C — Updating the server

### From source (systemd)

```sh
# 1. Pull the latest code
cd ~/ssh-warden
git pull origin main

# 2. Rebuild the binary
CGO_ENABLED=0 go build -ldflags="-s -w" -o /usr/local/bin/ssh-warden-server ./cmd/server

# 3. Restart the service (the database is untouched)
systemctl restart ssh-warden.service

# 4. Verify
systemctl status ssh-warden.service
curl -s http://localhost:8080/health
```

The SQLite database (`warden.db`) is persistent and backward-compatible: new
releases may add columns via automatic migrations — no manual schema changes
are needed.

### From Docker

```sh
# 1. Pull the latest code
cd ~/ssh-warden
git pull origin main

# 2. Rebuild the image
docker compose build warden

# 3. Recreate the container (data volume is preserved)
docker compose up -d warden

# 4. Verify
docker compose logs --tail=20 warden
curl -s http://localhost:8080/health
```

### Rollback

If the new version misbehaves, revert to the previous binary and restart:

```sh
# systemd
git checkout <previous-tag>
CGO_ENABLED=0 go build -ldflags="-s -w" -o /usr/local/bin/ssh-warden-server ./cmd/server
systemctl restart ssh-warden.service

# Docker
git checkout <previous-tag>
docker compose build warden && docker compose up -d warden
```

The database format is forward-compatible so rolling back the binary is safe.

---

## 2. Configuring target hosts (OpenSSH)

Each target host gets the helper binary, an OpenSSH snippet, and a host token.
Do this incrementally, one host at a time, to avoid losing SSH access globally.

### Step 1 — Install the helper binary

```sh
CGO_ENABLED=0 go build -ldflags="-s -w" -o ssh-warden-helper ./cmd/helper
scp ssh-warden-helper root@target:/tmp/ssh-warden-helper
```

On the target:

```sh
install -o root -g root -m 755 /tmp/ssh-warden-helper /usr/local/bin/ssh-warden-helper
rm /tmp/ssh-warden-helper
```

The helper must be owned by root with `chmod 755` so a compromised `nobody`
SSH process cannot replace it.

### Step 2 — Provision the host token

The host token is a shared secret stored on disk. Register the host and its
token server-side first, then drop the token file on the target.

Server-side registration (via the CLI):

```sh
# if a "register host" command exists, use it; otherwise seed via the
# RegisterHost helper or the DB directly. The token below must match the file
# on the target host.
```

On the target host:

```sh
install -d -o root -g root -m 700 /etc/ssh-warden
# the raw token (one line, no trailing newline)
printf '%s' 'your-super-secret-host-token' > /etc/ssh-warden/token
chown root:root /etc/ssh-warden/token
chmod 600 /etc/ssh-warden/token
```

Alternatively, pass the token via the `WARDEN_HOST_TOKEN` environment variable
in the helper environment (see below) if putting secrets in environment files
fits your operational model better.

### Step 3 — Configure OpenSSH

Use a snippet under `/etc/ssh/sshd_config.d/` (recommended on Debian/Ubuntu)
or edit `sshd_config` directly.

`/etc/ssh/sshd_config.d/warden.conf`:

```ini
# Resolve the caller's authorized keys from SSH-Warden instead of a static
# authorized_keys file.
AuthorizedKeysCommand /usr/local/bin/ssh-warden-helper %u
AuthorizedKeysCommandUser nobody

# Optional: restrict accepted key types to strong algorithms.
PubkeyAcceptedAlgorithms ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512
```

OpenSSH invokes the command with the connecting username as `%u`. The helper
reads:
- the API URL from `WARDEN_API_URL` (default `http://127.0.0.1:8080`),
- the host identity from `WARDEN_HOST_ID` (default: system hostname),
- the token from `WARDEN_HOST_TOKEN`, falling back to `/etc/ssh-warden/token`.

If you proxy through a sidecar or prefer environment-based config, export these
before the helper runs:

```ini
AuthorizedKeysCommand /usr/local/bin/ssh-warden-helper %u
AuthorizedKeysCommandUser nobody
```

> When `AuthorizedKeysCommandUser` is `nobody`, the helper runs without
> privileges. To pass environment config, either rely on the token file
> (simplest) or set the variables via an OpenSSH `environment` / wrapper script
> that is also executable by `nobody` and readable only by root.

Validate the config before reloading:

```sh
sshd -t
systemctl reload sshd    # or: systemctl reload ssh
```

### Step 4 — Set the API reachability

The helper in the snippet above defaults to `http://127.0.0.1:8080`. In
production the API typically sits on a dedicated node behind a reverse proxy,
so set `WARDEN_API_URL` to the public endpoint:

```sh
# either persist on the host or hardcode in a wrapper; see security.md for TLS
export WARDEN_API_URL="https://warden.example.com"
```

---

## 3. Testing safely (without locking yourself out)

Never switch a production host to `AuthorizedKeysCommand` while you only have
that same SSH session. Keep an escape hatch:

1. **Keep a static key fallback** during rollout. Until you are confident,
   keep the user's `~/.ssh/authorized_keys` intact and add a second
   `AuthorizedKeysCommand` line only after confirming the API responds. You can
   toggle between them by commenting one line out.

2. **Use a maintenance session** — open a second, independent SSH session to
   the host (console access, out-of-band serial/IPMI, or an internally-managed
   session) before changing `sshd_config`, so you can recover if `sshd -t`
   passes but the effective config locks you out.

3. **Prune-then-verify** — after enabling, from the API: request a lease,
   connect, then `warden revoke <id>` and confirm the next connection is
   refused. This validates the whole loop (helper → API → leases → audit)
   before you trust it at scale.

Verification commands:

```sh
# run the helper by hand as the SSH user to see what OpenSSH will see
sudo -u nobody /usr/local/bin/ssh-warden-helper alice
# -> prints alice's currently authorized keys, one per line, or nothing

# inspect the API audit trail for the decision
warden audit -u alice
```

---

## 4. Rollout checklist

- [ ] Server built, running under its dedicated user, DB writable only by it.
- [ ] Reverse proxy / TLS in place; clients and helpers use `https://`.
- [ ] Host registered server-side; token matches the `/etc/ssh-warden/token`.
- [ ] Helper installed as root-owner `755`; token `600` root-only.
- [ ] `sshd -t` clean; `AuthorizedKeysCommandUser nobody`.
- [ ] Maintenance/console session available before switching hosts.
- [ ] One host migrated and verified end-to-end (lease → connect → revoke).