# Contributing to SSH-Warden

Thanks for your interest in contributing! The full guidelines live in
[`docs/contributing.md`](docs/contributing.md) — please read them before
opening a pull request. The essentials are summarized here.

## Quick start

- Requires **Go 1.27+**. SQLite and SSH parsing are pure-Go, so there are no
  CGO dependencies.
- The layout is `cmd/` (server, CLI, helper) + `internal/` (api, database,
  models, webhook) + `pkg/sshutil`.

## Making changes

1. Create a short branch off `main` using a conventional prefix
   (`feat/`, `fix/`, `docs/`, `refactor/`, `test/`).
2. Make focused, single-purpose changes.
3. Use **Conventional Commits** for the commit message:
   `<type>(<scope>): <short imperative summary>`.

## Validation gates

The following must all pass before a pull request is merged:

```sh
gofmt -l .
go vet ./...
go test ./...
go build ./...
```

## Reporting bugs / security

- For bugs and feature requests, open an issue using the templates.
- **For security vulnerabilities, do not open a public issue** — report them
  privately via **Security → Report a vulnerability**, or see
  [`SECURITY.md`](SECURITY.md).

## Releases

Releases are cut from version tags push to `main`; see "[Creating a
release](docs/contributing.md#7-creating-a-release)" in the contributing guide.