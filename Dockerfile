# syntax=docker/dockerfile:1

# ---- Build stage ----
FROM golang:1.27 AS build
WORKDIR /src

# Cache Go module downloads first so dependency fetches are reused across builds.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# The server is pure Go (modernc.org/sqlite is a pure-Go SQLite driver), so it
# links a fully static binary that runs on distroless without CGO/libc*. Using
# -trimpath and -s -w keeps the image small.
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
      -trimpath \
      -ldflags="-s -w -X github.com/polarisdev-fr/ssh-warden/internal/api.version=$VERSION" \
      -o /out/ssh-warden-server ./cmd/server
# A tiny static probe used as the container healthcheck (distroless ships no
# shell or curl).
RUN CGO_ENABLED=0 GOOS=linux go build \
      -trimpath -ldflags="-s -w" \
      -o /out/warden-healthcheck ./cmd/healthcheck

# ---- Runtime stage ----
# distroless/static ships no shell, no package manager and no binaries beyond
# ours: a minimal, hardened base for the API server. It is non-root by design.
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /data

COPY --from=build /out/ssh-warden-server /usr/local/bin/ssh-warden-server
COPY --from=build /out/warden-healthcheck /usr/local/bin/warden-healthcheck

# The sqlite database live in the working directory. Mount a persistent volume
# here to keep warden.db across container restarts.
VOLUME ["/data"]

# Informational label (the server listens on WARDEN_PORT at runtime, default
# 8080); this is only a hint for tooling.
EXPOSE 8080

# Docker uses this executable as the healthcheck; it performs an HTTP GET to
# /health and exits non-zero when the server is not responding.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/usr/local/bin/warden-healthcheck"]

# The server captures SIGTERM for a graceful shutdown (see cmd/server/main.go),
# so K8s/Docker Compose can stop it cleanly.
ENTRYPOINT ["/usr/local/bin/ssh-warden-server"]