<div align="center">

# SSH-Warden

**Just-In-Time ephemeral SSH access management**

Grant time-boxed SSH access that is automatically enforced by OpenSSH itself —
no background daemons, no shell wrappers, no lingering credentials.

[![Go Version](https://img.shields.io/badge/Go-1.27+-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![CI](https://github.com/polarisdev-fr/ssh-warden/actions/workflows/ci.yml/badge.svg)](https://github.com/polarisdev-fr/ssh-warden/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

</div>

---

## What is it?

SSH-Warden lets administrators mint **ephemeral leases** that grant a user the
right to SSH into a specific machine for a short, explicit window. Instead of
hand-editing `authorized_keys`, each OpenSSH host resolves its own set of valid
keys on demand through the small `ssh-warden-helper` executable wired into
`AuthorizedKeysCommand`. When a lease expires — or is revoked — the key simply
stops being returned and the SSH connection is refused.

```
┌─────────────┐   POST /api/v1/leases     ┌─────────────────┐
│  Warden CLI │ ────────────────────────▶ │                 │
└─────────────┘                           │   Warden API    │
                                          │  (SQLite)       │
┌─────────────┐   GET /api/v1/keys/...    │                 │
│  OpenSSH    │ ◀─────────────┐           │  users/keys/    │
│  host       │   Authorized- │           │  leases/hosts   │
│  (helper)   │   KeysCommand  │  Bearer  │                 │
└─────────────┘   + Bearer token           └─────────────────┘
                        ▲                          ▲
              WARDEN_HOST_TOKEN           registered host,
              WARDEN_HOST_ID              hashed SHA-256
```

## Documentation

The full documentation lives in [`docs/`](docs/):

| Guide | Contents |
|-------|----------|
| [Architecture](docs/architecture.md) | End-to-end flow diagrams, component layout, technology choices, threat model. |
| [Installation](docs/installation.md) | Server deployment (Docker/Compose, systemd) and OpenSSH host setup. |
| [CLI Reference](docs/cli-reference.md) | Every `warden` command, its flags, console output, and exit codes. |
| [Security](docs/security.md) | Host-token handling, key storage, OpenSSH hardening, reverse-proxy TLS. |
| [Contributing](docs/contributing.md) | Setup, Go code standards, git workflow, and validation gates. |

## Features

- **Ephemeral leases** — access exists only for a defined window, then expires
  automatically.
- **Target host scoping** — a lease applies to one host (`srv-prod-01`) or to
  all hosts (`*`); machines only ever see keys they are entitled to.
- **Approval workflows** — leases can be created in a pending state, requiring a
  second sign-off (`warden approve` / `warden reject`) before SSH access is
  granted.
- **mTLS host authentication** — hosts can authenticate to the API with mutual
  TLS client certificates, verified against a trusted CA, instead of (or in
  addition to) bearer tokens.
- **Web UI dashboard** — a built-in browser interface at `http://localhost:8080/ui`
  showing active leases, pending approvals, and approve/reject controls.
- **Machine host tokens** — each host authenticates with a bearer token whose
  SHA-256 digest is stored, checked in constant time.
- **Zero background daemons** — enforcement happens inside OpenSSH via
  `AuthorizedKeysCommand`; nothing runs continuously on the hosts.

## Installation

Requires **Go 1.22+**.

```sh
git clone https://github.com/polarisdev-fr/ssh-warden.git
cd ssh-warden

# Build all three binaries into ./bin
make build

# Or build individually
go build -o bin/ssh-warden        ./cmd/cli
go build -o bin/ssh-warden-server ./cmd/server
go build -o bin/ssh-warden-helper ./cmd/helper
```

## Configuration

### Server

Start the API (SQLite is created and seeded automatically on first run):

```sh
WARDEN_HOST_TOKEN="secret-host-token-123" ./bin/ssh-warden-server
# or
go run ./cmd/server
```

The server listens on `:8080` and exposes:

| Method | Path                        | Description                       |
| ------ | -------------------------- | --------------------------------- |
| GET    | `/api/v1/keys/{user}`      | Public keys for a user (Bearer)   |
| GET    | `/api/v1/leases`           | List active leases                |
| POST   | `/api/v1/leases`           | Create a lease (user token)       |
| DELETE | `/api/v1/leases/{id}`      | Revoke a lease (user token)       |
| GET    | `/api/v1/leases/pending`   | List pending approval leases      |
| POST   | `/api/v1/leases/{id}/approve` | Approve a pending lease (user token) |
| POST   | `/api/v1/leases/{id}/reject`  | Reject a pending lease (user token) |
| GET    | `/api/v1/audit`            | Audit log                         |
| POST   | `/api/v1/user-tokens`      | Mint a CLI user token (UI auth)   |
| GET    | `/api/v1/system`           | Server info (auth mode, mTLS, DB) |
| GET    | `/ui`                      | Web UI dashboard                  |
| GET    | `/ui/cli-auth`             | CLI approve page (UI auth)        |

### Web UI dashboard

When the server is running, open `http://localhost:8080/ui` in a browser to
access the built-in Web UI. It has a fixed left sidebar with three views:
**Leases** (combining pending approvals with Approve/Reject and active leases
with Revoke), **Audit Logs** (recent access logs), and **System & Info** (auth
mode, mTLS status, database path). A red badge on the Leases tab shows the
number of pending approvals. The dashboard auto-refreshes every 15 seconds and
offers a manual **Refresh** button in the sidebar; expiry badges are
color-coded (green > 30 min, orange ≤ 30 min, red ≤ 10 min). On mobile the
sidebar collapses into a hamburger drawer.

```sh
# Quick check in the browser
open http://localhost:8080/ui
```

By default the dashboard is served without authentication (it shows a warning
banner in that case). To require a login, set the `WARDEN_UI_USER` and
`WARDEN_UI_PASSWORD` environment variables on the server:

```sh
WARDEN_UI_USER=admin WARDEN_UI_PASSWORD=change-me go run ./cmd/server
# or, in systemd, add to the [Service] section:
#   Environment=WARDEN_UI_USER=admin
#   Environment=WARDEN_UI_PASSWORD=change-me
```

When both variables are set, the `/ui` route requires HTTP Basic Auth and the
warning banner disappears.

#### OpenID Connect (OIDC) single sign-on

Instead of Basic Auth you can protect the dashboard with **OpenID Connect**
(Authentik, Keycloak, Azure AD, Google, Discord, …). OIDC takes precedence over
Basic Auth when enabled:

```sh
WARDEN_OIDC_ENABLED=true \
WARDEN_OIDC_ISSUER_URL=https://auth.example.com/application/o/ssh-warden/ \
WARDEN_OIDC_CLIENT_ID=ssh-warden-client \
WARDEN_OIDC_CLIENT_SECRET=change-me \
WARDEN_OIDC_REDIRECT_URL=https://warden.example.com/auth/callback \
WARDEN_SESSION_SECRET=$(openssl rand -base64 32) \
go run ./cmd/server
```

Unauthenticated visitors to `/ui` are redirected to `GET /auth/login`, which
redirects to the identity provider. The callback (`/auth/callback`) verifies
the CSRF `state` cookie, exchanges the code, verifies the ID token, and sets a
signed `warden_session` (`HttpOnly`, `SameSite=Lax`). `GET /auth/logout`
clears it. The dashboard then shows **"Connecté en tant que <user> |
Déconnexion"** in the header. See `docs/security.md` § 8 for details and a
default caveat about the `Secure` cookie flag on plain HTTP.

### OpenSSH host

Install the helper and its config, then point `AuthorizedKeysCommand` at it in
`/etc/ssh/sshd_config`:

```
AuthorizedKeysCommand /usr/local/bin/ssh-warden-helper %u
AuthorizedKeysCommandUser nobody

# The helper picks these up from the environment:
#   WARDEN_HOST_TOKEN   machine bearer token (or /etc/ssh-warden/token)
#   WARDEN_HOST_ID      this host's identity (defaults to system hostname)
#   WARDEN_API_URL      the Warden API (default http://127.0.0.1:8080)
#   WARDEN_TLS_CA_CERT  path to CA cert for mTLS (optional, for HTTPS)
```

When OpenSSH receives a connection it runs the helper, which asks the Warden
API for the user's currently-valid keys and prints them back. Expired or
revoked leases yield an empty response, so the connection is refused.

## Usage

`warden` is the CLI used to register keys and manage leases.

```sh
# Register a public key for a user (user is created on the fly if missing)
warden key add ~/.ssh/id_ed25519.pub -u alice -c "ci-build-machine"

# Request a 30-minute lease against srv-prod-01
warden request -u alice -t srv-prod-01 -d 30m -r "Debug production issue"

# Request a lease valid on ALL hosts
warden request -u alice -d 2h -r "On-call maintenance"

# List every active lease
warden status

# List only alice's active leases
warden status -u alice

# Cut a lease immediately (SSH access stops at once)
warden revoke 42

# Approve a pending lease (grants SSH access)
warden approve 58

# Reject a pending lease (denies SSH access)
warden reject 59
```

Since `v0.3.2`, mutating commands are authenticated with a **CLI user token**
obtained by approving access in the browser. Run it once per client:

```sh
# Opens the browser; sign in to the dashboard and click "Approve CLI Access"
warden login
```

The token is stored in the CLI config (`api_token`) and expires after 30 days
(re-run `warden login` to refresh it). You can also supply it via the
`WARDEN_API_TOKEN` environment variable, which takes precedence. Read-only
commands (`status`, `audit`) do not require a token.

Pending leases are created via the API by passing `"requires_approval": true`
in the JSON body of `POST /api/v1/leases`. The CLI `warden approve` and
`warden reject` commands are used to process them.

Running `warden request` with no arguments opens an interactive wizard to fill
the username, target host, duration and reason step by step. It pre-fills the
username from `default_user` in your local config. Force it explicitly with the
`-i`/`--interactive` flag:

```sh
# Interactive wizard (also the default when -u is omitted)
warden request
warden request -i

# Fully automated: keeps working without a terminal (scripts / CI)
warden request -u alice -t srv-prod-01 -d 30m -r "Debug production issue"
```

The wizard supports `Tab`/`Enter` to advance, `⇧Tab` to go back, arrow keys to
pick a duration from the presets (`15m`, `30m`, `1h`, `2h`, `4h`, `8h` or
custom), and `Esc`/`Ctrl+C` to cancel without creating a lease.

### Audit log

Every time an OpenSSH host's helper asks the API to authorize a connection,
the API records a persistent audit event in SQLite — timestamp, client IP,
target host, user, and whether the key request was granted, denied, or the
machine failed authentication.

```sh
# Show the 20 most recent events
warden audit

# Filter by user, target host, or cap the number of lines
warden audit -u alice
warden audit -t srv-prod-01
warden audit -n 200
```

Example output:

```
DATE                  IP            HÔTE          UTILISATEUR   RÉSULTAT      DÉTAILS
01:31:39 02/09/2026   203.0.113.7   srv-prod-01   alice         ALLOWED       Active lease found
01:30:02 02/09/2026   203.0.113.7   srv-prod-01   bob           DENIED        No active lease or no keys
01:29:55 02/09/2026   198.51.100.2  srv-prod-01   alice         AUTH FAILED   invalid host token
```

The audit trail is stored in the `audit_logs` table, so it survives server
restarts and is queryable alongside the other data.

### Configuration

To avoid passing `--api` and `-u` every time, store local defaults in
`~/.config/ssh-warden/config.yaml` (or `%APPDATA%\ssh-warden\config.yaml`
on Windows):

```sh
# Show the active config file and current values
warden config show

# Set the API endpoint and default user
warden config set api_url http://192.168.1.50:8080
warden config set default_user alice

# With default_user configured, -u becomes optional:
warden request -t srv-prod-01 -d 30m -r "No -u needed"
```

The effective `api_url` is resolved by priority: `--api` flag,
`WARDEN_API_URL`, then the config file, then `http://localhost:8080`. The
effective username is resolved from `-u/--user`, then the config
`default_user`, then the OS user.

#### Environment variables

| Variable              | Description                                                                 |
|-----------------------|-----------------------------------------------------------------------------|
| `WARDEN_API_URL`      | Fallback API URL for the CLI (after the `--api` flag, before the config).   |
| `WARDEN_WEBHOOK_URL`  | Server-side webhook endpoint for critical audit notifications (optional).   |
| `WARDEN_TLS_CERT`     | Server TLS certificate file path — enables HTTPS (optional).               |
| `WARDEN_TLS_KEY`      | Server TLS private key file path — enables HTTPS (optional).               |
| `WARDEN_TLS_CA_CERT`  | CA certificate file path — enables mTLS, requiring client certs (optional).|
| `WARDEN_UI_USER`      | Basic Auth username for the `/ui` dashboard (optional).                   |
| `WARDEN_UI_PASSWORD`  | Basic Auth password for the `/ui` dashboard (optional).                   |
| `WARDEN_OIDC_ENABLED` | `"true"`/`"false"` — enable OpenID Connect auth for `/ui` (optional).     |
| `WARDEN_OIDC_ISSUER_URL` | OIDC issuer URL, e.g. `https://auth.example.com/application/o/warden/`. |
| `WARDEN_OIDC_CLIENT_ID` | OIDC client ID (required when OIDC enabled).                           |
| `WARDEN_OIDC_CLIENT_SECRET` | OIDC client secret (required when OIDC enabled).                  |
| `WARDEN_OIDC_REDIRECT_URL` | OIDC callback URL registered with the IdP (e.g. `.../auth/callback`). |
| `WARDEN_SESSION_SECRET` | Random key (≥32 bytes) that signs `warden_session` cookies (required when OIDC enabled). |

### Webhook Notifications

The server can notify an external service whenever a critical audit event
occurs. Set the optional `WARDEN_WEBHOOK_URL` environment variable when
starting the server:

```sh
WARDEN_WEBHOOK_URL="https://hooks.example.com/xxx" go run ./cmd/server
```

When the variable is empty (or unset), notifications are silently disabled.
When set, every `KEY_REQUEST_GRANTED`, `KEY_REQUEST_DENIED`,
`HOST_AUTH_FAILED`, `LEASE_APPROVED` and `LEASE_REJECTED` event triggers an
asynchronous, non-blocking webhook POST with a 3-second timeout, so the API
response time is never affected.

The payload format is chosen automatically:

- **Discord** — if the URL contains `discord.com/api/webhooks`, a formatted
  embed is sent, color-coded by outcome (green for granted/approved, orange for
  denied/rejected, red for failed authentication) with User, Target Host, Client
  IP, Reason and Timestamp fields.
- **Generic JSON** — otherwise a Slack / Gotify / Ntfy compatible payload is
  sent: `{"event": "...", "username": "...", "target_host": "...", "reason":
  "...", "client_ip": "...", "created_at": "..."}`.

## Roadmap

- [x] **mTLS** between hosts and the Warden API for mutual authentication.
- [x] **Web UI** for a friendly view of leases and approvals.
- [x] **Approval workflows** so leases can require a second sign-off before
  they take effect.

## License

Released under the [MIT License](LICENSE).