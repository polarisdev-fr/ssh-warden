# warden CLI Reference

This is the complete reference for the `warden` command-line client. It covers
every subcommand, its flags, realistic console output, and exit codes.

```
warden
├── request          Request temporary access to a server
├── status           List active leases
├── revoke           Revoke an active lease immediately
├── approve          Approve a pending lease
├── reject           Reject a pending lease
├── key add          Register a public key for a user
├── config show      Show the current configuration and active config file
├── config set       Set a configuration value (api_url, default_user)
└── audit            List authorization audit events
```

**Global flag**

| Flag        | Default | Description                                             |
|-------------|---------|---------------------------------------------------------|
| `--api`     | *(none)*| Warden API URL. Overrides `config.yaml` and `WARDEN_API_URL`. |

The `--api` flag can be placed anywhere (before or after the subcommand).

**Exit codes**

`warden` returns `0` on success and `1` on any error. Errors are printed to
stderr prefixed with `Error:` and Cobra shows a short usage hint. A non-zero
status is also used when the API returns an unexpected status code or the
network request fails.

---

## 1. `warden request`

Request a time-limited lease from the API. The lease authorizes the given user
against the given host for the given duration.

```
Usage:
  warden request [flags]

Flags:
  -d, --duration string   Lease duration (e.g. 30m, 2h) (default "1h")
  -i, --interactive       Run the interactive wizard to fill the request
  -r, --reason string     Reason for the request
  -t, --target string     Target host (e.g. srv-prod-01 or *) (default "*")
  -u, --user string       Username (required)
```

### Flags

| Flag      | Default | Purpose |
|-----------|---------|---------|
| `-u, --user` | *resolved* | Username. If omitted, the CLI uses `config.yaml` `default_user`, then the OS user. Omission also activates the interactive wizard. Required if none of those resolve. |
| `-t, --target` | `*` | Target host. `*` covers every host. |
| `-d, --duration` | `1h` | Lease duration — any Go duration (`30m`, `2h`, `90s`). |
| `-r, --reason` | *(empty)* | Human-readable reason, stored and shown in the audit log. |
| `-i, --interactive` | `false` | Force the interactive wizard, even when flags are provided. |

### Interactive mode

Running `warden request` without a `-u`/`--user` flag (or with `-i`) launches a
step-by-step terminal wizard built with [Bubble Tea](https://github.com/charmbracelet/bubbletea):

1. **Username** — pre-filled from `config.yaml` `default_user`.
2. **Target host** — text field, defaults to `*`.
3. **Duration** — quick pick from `15m`, `30m`, `1h`, `2h`, `4h`, `8h`, or `Custom...` free text.
4. **Reason** — free text.

Navigation: `Tab`/`Enter` advance to the next step, `⇧Tab` goes back, arrow
keys move the cursor or change the duration selection, and `Esc`/`Ctrl+C`
cancels without creating a lease. On completion the request is submitted to the
API and the result is shown exactly as in the command-line mode.

```sh
# Interactive wizard — also the default when -u is omitted
warden request
warden request -i

# Fully automated, no terminal required (scripts / CI)
warden request -u alice -t srv-prod-01 -d 30m -r "Debug production issue"
```

### Examples

```sh
# 30-minute lease on srv-prod-01 for alice
warden request -u alice -t srv-prod-01 -d 30m -r "Debug production issue"

# 2-hour lease valid on all hosts (alice comes from config default_user)
warden request -d 2h -r "On-call maintenance"

# explicit API endpoint
warden --api https://warden.example.com request -u alice -t srv-prod-01
```

### Output

```
Access granted!
Lease ID     : 42
Target host  : srv-prod-01
Expires at   : 17:30:00 02/09/2026 (in 30m)
Reason       : Debug production issue
```

On failure (for example, an expired or unknown user, or the API is
unreachable):

```
Error: error contacting API: Post "http://localhost:8080/api/v1/leases": dial tcp 127.0.0.1:8080: connect: connection refused
```

---

## 2. `warden status`

List active leases, optionally filtered by username.

```
Usage:
  warden status [flags]

Flags:
  -u, --user string   Filter by username
```

### Examples

```sh
# all active leases
warden status

# only alice's active leases
warden status -u alice
```

### Output

```
ID   USER    TARGET       REASON                   TIME LEFT   EXPIRES
42   alice   srv-prod-01  Debug production issue   29m 50s     17:30:00 02/09/2026
41   bob     *            On-call maintenance      1h 12m 04s  18:12:04 02/09/2026
```

With no matching leases:

```
No active leases found.
```

---

## 3. `warden revoke`

Immediately revoke an active lease, cutting the user's SSH access at once.

```
Usage:
  warden revoke <lease_id>

Arguments:
  lease_id    Numeric ID of the lease to revoke
```

### Example

```sh
warden revoke 42
```

### Output

```
Lease #42 revoked. SSH access has been cut immediately.
```

Errors on an unknown or already-expired lease:

```
Error: lease not found
```

---

## 4. `warden approve`

Approve a pending lease, granting the user SSH access. The lease must be in
the `pending` state.

```
Usage:
  warden approve <lease_id>

Arguments:
  lease_id    Numeric ID of the pending lease to approve
```

### Example

```sh
warden approve 58
```

### Output

```
Lease #58 approved. SSH access has been granted.
```

Errors:

```
Error: lease not found
Error: lease is not pending approval
```

---

## 5. `warden reject`

Reject a pending lease, denying the user SSH access. The lease must be in
the `pending` state.

```
Usage:
  warden reject <lease_id>

Arguments:
  lease_id    Numeric ID of the pending lease to reject
```

### Example

```sh
warden reject 59
```

### Output

```
Lease #59 rejected. SSH access has been denied.
```

Errors:

```
Error: lease not found
Error: lease is not pending approval
```

---

## 6. `warden key add`

Register a public key for a user. The user is created on the fly if missing.
The key is only honored by OpenSSH while the user holds an active lease for the
requesting host.

```
Usage:
  warden key add <path/to/key.pub> [flags]

Flags:
  -c, --comment string   Custom label/comment for the key
  -u, --user string      Username to associate with the key (required)
```

### Arguments

| Argument | Description |
|----------|-------------|
| `<path/to/key.pub>` | Path to a public key file (`~/.ssh/id_ed25519.pub`, etc.). Required. |

### Flags

| Flag | Default | Purpose |
|------|---------|---------|
| `-u, --user` | *resolved* | Username to associate. Uses `default_user`, then OS user if omitted. |
| `-c, --comment` | *(from key)* | Custom label. Falls back to the key's own comment. |

### Examples

```sh
# register alice's key with a label
warden key add ~/.ssh/id_ed25519.pub -u alice -c "ci-build-machine"

# register with no explicit user (resolves default_user / OS user)
warden key add ~/.ssh/id_ed25519.pub
```

### Output

```
✓ Public key successfully registered for user alice
  Key ID     : 7
  Key        : ssh-ed25519 AAAAC3Nz...B4d6D alice@local
  Comment    : ci-build-machine
  Source file: /home/alice/.ssh/id_ed25519.pub
```

Error, when the key is malformed or the file is unreadable:

```
Error: invalid public key: ssh: no key found
Error: failed to read key file /etc/does-not-exist: open /etc/does-not-exist: no such file or directory
```

---

## 7. `warden config`

Manage the *local* CLI configuration (`config.yaml` in the user config
directory) so you do not repeat `--api` and `-u`.

```
Usage:
  warden config [command]

  set      Set a configuration value (api_url, default_user)
  show     Show the current configuration and active config file
```

The file lives at `~/.config/ssh-warden/config.yaml` (Linux) or
`%APPDATA%\ssh-warden\config.yaml` (Windows). It is created with restrictive
permissions (`0700` directory, `0600` file).

### 7.1 `warden config show`

Display the active config file path and the current values.

```
Usage:
  warden config show
```

Example:

```
Config file    : /home/alice/.config/ssh-warden/config.yaml
api_url        : http://192.168.1.50:8080
default_user   : alice
```

On first use (no file yet), it prints the environment-derived defaults.

### 7.2 `warden config set <key> <value>`

Update one key and persist it.

```
Usage:
  warden config set <key> <value>

Keys:
  api_url        Base API URL
  default_user   Default username used when -u/--user is omitted
```

Examples:

```sh
warden config set api_url http://192.168.1.50:8080
# Set api_url = http://192.168.1.50:8080

warden config set default_user alice
# Set default_user = alice
```

Unknown key (exit 1):

```
Error: unknown config key "bogus" (valid: api_url, default_user)
```

### Resolution precedence

- **api_url**: `--api` flag → `WARDEN_API_URL` env → `config.yaml` `api_url` →
  `http://localhost:8080`.
- **username**: `-u/--user` flag → `config.yaml` `default_user` → OS
  `$USER`/`$USERNAME`.

If a username is required but resolves to nothing, the CLI exits with a clear
hint:

```
Error: no username provided: set it with -u/--user or run 'warden config set default_user <name>'
```

---

## 8. `warden audit`

List authorization audit events recorded by the API.

```
Usage:
  warden audit [flags]

Flags:
  -n, --limit int       Maximum number of events to show (default 20)
  -t, --target string   Filter by target host
  -u, --user string     Filter by username
```

### Flags

| Flag | Default | Purpose |
|------|---------|---------|
| `-n, --limit` | `20` | Maximum rows to display. |
| `-u, --user` | *(none)* | Only events for the given username. |
| `-t, --target` | *(none)* | Only events for the given target host. |

### Examples

```sh
# default view, newest 20 events
warden audit

# alice's events, capped at 100
warden audit -u alice -n 100

# denials/grants on a specific host
warden audit -t srv-prod-01
```

### Output

```
DATE                  IP            HÔTE          UTILISATEUR   RÉSULTAT      DÉTAILS
01:31:39 02/09/2026   203.0.113.7   srv-prod-01   alice         ALLOWED       Active lease found
01:30:02 02/09/2026   203.0.113.7   srv-prod-01   bob           DENIED        No active lease or no keys
01:29:55 02/09/2026   198.51.100.2  srv-prod-01   alice         AUTH FAILED   invalid host token
```

Status mapping: `KEY_REQUEST_GRANTED` → `ALLOWED`,
`KEY_REQUEST_DENIED` → `DENIED`, `HOST_AUTH_FAILED` → `AUTH FAILED`.

With no events (or no events matching the filters):

```
No audit events recorded.
```

---

## 9. Autocompletion & help

Every command supports `--help` / `-h`. Cobra also auto-generates shell
completion:

```sh
warden completion bash       # bash completion script
warden completion zsh        # zsh completion script
warden completion fish       # fish completion script
warden completion powershell # PowerShell completion script
```

Source the output to enable tab-completion in your shell.

---

## Quick cheat sheet

| Need | Command |
|------|---------|
| Get access for 30 min | `warden request -u alice -t srv-prod-01 -d 30m -r "reason"` |
| See who has access | `warden status` |
| Kill someone's access | `warden revoke 42` |
| Approve a pending request | `warden approve 58` |
| Reject a pending request | `warden reject 59` |
| Register your key | `warden key add ~/.ssh/id_ed25519.pub -u alice` |
| Point at another API | `warden --api https://warden.example.com ...` or `warden config set api_url ...` |
| Stop passing `-u` | `warden config set default_user alice` |
| Review decisions | `warden audit -u alice` |