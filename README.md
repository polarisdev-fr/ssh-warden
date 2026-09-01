<div align="center">

# SSH-Warden

**Just-In-Time ephemeral SSH access management**

Grant time-boxed SSH access that is automatically enforced by OpenSSH itself —
no background daemons, no shell wrappers, no lingering credentials.

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go&logoColor=white)](https://go.dev/)
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

## Features

- **Ephemeral leases** — access exists only for a defined window, then expires
  automatically.
- **Target host scoping** — a lease applies to one host (`srv-prod-01`) or to
  all hosts (`*`); machines only ever see keys they are entitled to.
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

| Method | Path                     | Description                     |
| ------ | ------------------------ | ------------------------------- |
| GET    | `/api/v1/keys/{user}`    | Public keys for a user (Bearer) |
| GET    | `/api/v1/leases`         | List active leases              |
| POST   | `/api/v1/leases`         | Create a lease                  |
| DELETE | `/api/v1/leases/{id}`    | Revoke a lease                  |

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
```

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

## Roadmap

- **mTLS** between hosts and the Warden API for mutual authentication.
- **Web UI** for a friendly view of leases and approvals.
- **Approval workflows** so leases can require a second sign-off before
  they take effect.

## License

Released under the [MIT License](LICENSE).