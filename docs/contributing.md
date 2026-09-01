# Contributing to SSH-Warden

Thank you for contributing. This guide describes the project conventions,
prerequisites, and the pull-request workflow to keep contributions consistent
and reviewable.

---

## 1. Prerequisites

- **Go 1.27+** (see `go.mod`). Install from <https://go.dev/dl/>.
- `git` and a GitHub account.
- (Optional) a local `go` environment capable of cross-compiling for Linux if
  you plan to test the helper/server on remote hosts:
  `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./...`.

There are no external runtime dependencies (SQLite is pure-Go, no CGO), so you
only need the Go toolchain.

## 2. Repository layout

```
cmd/server      HTTP API entrypoint
cmd/cli         `warden` client entrypoint
cmd/helper      `ssh-warden-helper` — OpenSSH AuthorizedKeysCommand
internal/api    router, handlers, auth middleware, audit endpoint
internal/database SQLite persistence (users, keys, leases, hosts, audit_logs)
internal/models Shared data structures
internal/webhook Asynchronous Discord/generic notifications
pkg/sshutil     Public-key validation and normalization
docs/           Architecture, installation, CLI, security, contributing
```

Read `docs/architecture.md` before making changes that touch the core flow.

---

## 3. Workflow

### 3.1 Branch

Create a short, descriptive branch off `main`, named after the work:

```sh
git checkout main
git pull origin main
git checkout -b feat/add-lease-expiry-notice
```

Suggested prefixes: `feat/`, `fix/`, `docs/`, `refactor/`, `test/`.

Keep branches focused: one logical change per branch/pr.

### 3.2 Conventional commits

Use [Conventional Commits](https://www.conventionalcommits.org/) so the history
stays greppable and release-notes-ready:

```
<type>(<scope>): <short imperative summary>

<body, optional>
```

Common types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `build`.

Examples from this repository:

```
feat(webhook): add asynchronous Discord and generic webhook notifications
feat(audit): persist key-check audit log and add warden audit
feat(cli): add persistent local configuration and user resolution
```

Rules:

- Summary is imperative, ≤ ~72 chars, no trailing period, no leading `feat` from
  the assistant/person names — keep it human and tonal.
- Scope (in parentheses) is optional but preferred and should be a package or
  area, e.g. `api`, `database`, `cli`, `webhook`, `docs`.
- Use the body for *why*, not only *what*.
- If not already auto-filled, verify unstaged/secrets are not committed before
  `git add`.

### 3.3 Commit hygiene

Before committing, review what is staged:

```sh
git status
git diff --cached --stat
```

These paths are intentionally **excluded** (see `.gitignore`): `bin/`, `*.exe`,
`*.test`, `*.out`, `warden.db*`, `.idea/`, `.vscode/`. Do not force-add them.
If you generate local config or databases during testing, they live outside the
repo (e.g. `%APPDATA%\ssh-warden\config.yaml`) or are git-ignored.

---

## 4. Code standards

Following the project's existing style keeps reviews fast:

- **Formatting.** Format with `gofmt` before committing — the tree must be clean
  under `gofmt -l .` (see §5).
- **Style.** Follow standard `gofmt`/`go vet` idioms; prefer idiomatic standard
  library. Keep exported identifiers documented; use package-level doc comments
  where a file/package establishes conventions.
- **Errors.** Wrap errors with context (`fmt.Errorf("...: %w", err)`) and never
  swallow important failures silently. Background/agent paths (e.g. webhook
  delivery, audit writes) may be best-effort **by design** — see
  `internal/webhook` and `internal/api/audit.go`, and keep that intent explicit
  in the comment.
- **Interfaces.** Keep the minimal interface you need (see `internal/api`
  middleware/audit helpers) — prefer small, composable surfaces over large
  ones.
- **`internal/` discipline.** Do not import from other projects' `internal/`
  packages; keep `internal/` packages cross-buildable by all `cmd/*` binaries.
- **No CGO where avoidable.** SQLite and SSH parsing already avoid CGO; keep new
  dependencies CGO-free so cross-compilation stays trivial.

---

## 5. Validation gates

Run these on the whole module before opening a pull request. All must pass:

```sh
# 1. Formatting — must output nothing
gofmt -l .

# 2. Vet — must produce no diagnostics
go vet ./...

# 3. Tests — all tests must pass
go test ./...

# 4. Build — all binaries must compile
go build ./...
```

Suggested extras before review:

```sh
# cross-compile guarantees stay green
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./...

# static analysis (recommended)
go vet ./...
```

### Adding tests

New behavior should come with tests. If your change adds a pure function (e.g.
payload formatting, token hashing, key parsing), prefer a table-driven unit test
in the same package.

---

## 6. Pull request process

1. Push your branch: `git push -u origin <branch>`.
2. Open a pull request against `main` and add a concise description: what/why,
   behavior change, and any migration/breaking notes.
3. Reference related GitHub issues when present.
4. Ensure the validation gates (§5) pass in CI (once configured) or locally.
5. Address review feedback in follow-up commits on the same branch; keep the
   branch singular and avoid force-pushing a shared branch unless asked.

### Definition of done

- [ ] `gofmt -l .` is clean.
- [ ] `go vet ./...` passes.
- [ ] `go test ./...` passes.
- [ ] `go build ./...` passes.
- [ ] Conventional (imperative) commit message.
- [ ] No artifacts or secrets staged.
- [ ] Relevant docs/ understood or updated (`docs/*`).

---

## 7. Reporting issues

Open a GitHub issue and include: expected vs actual behavior, the exact command
you ran, the Go version and OS, and the relevant portion of the audit log or
output. For security vulnerabilities, see `docs/security.md` and report privately
rather than opening a public issue.