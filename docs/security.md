# SSH-Warden Security Practices

This document outlines the security model of SSH-Warden and the operational
practices required to run it safely in production. It is a companion to
`architecture.md` (threat model) and `installation.md` (deployment).

---

## 1. Security model: Just-In-Time access

SSH-Warden encodes the principle of **least privilege** directly into its
design:

- **No standing access.** A user's public key is meaningless on its own. It is
  only honored while the user holds a non-expired *lease* for the requesting
  host.
- **Ephemeral, revocable leases.** Leases carry an `expires_at` and can be cut
  at any moment with `warden revoke <id>`. Access disappears automatically when
  the lease lapses.
- **Host-scoped.** A lease targets a specific host (or `*`); a lease for
  `srv-web` grants nothing on `srv-db`.
- **Decisions are audited.** Every authorization decision is written to
  `audit_logs`, so "who was allowed where, when, and did it succeed" is always
  answerable.

---

## 2. Host-token management

### What the API stores

Target hosts authenticate to the API with a shared **host token**. The API never
persists the token itself — only its **SHA-256 digest** (`token_hash`) in the
`hosts` table. A dump of `warden.db` therefore reveals no usable credentials.

### Constant-time comparison

Token validation compares the computed digest against the stored one using a
constant-time routine (`crypto/subtle.ConstantTimeCompare`, see
`internal/database/hosts.go`). This prevents an attacker from recovering the
digest (and, by extension, probing the token) through response-timing
side-channels. The API also deliberately returns the same false result for
"unknown host" and "wrong token", so attackers cannot enumerate which hosts
exist.

### Operational practices

- **Generate strong, unique tokens** for every host and treat them like
  passwords. Use a CSPRNG, e.g. `openssl rand -hex 32`.
- **Register each host and its token server-side**, then place the token on the
  host at `/etc/ssh-warden/token` with `chown root:root` and `chmod 600`.
- **Do not commit tokens** to source control or paste them into chat. Prefer
  secret managers when provisioning many hosts.
- **Rotate tokens** by re-registering the host with a new token and updating the
  file — this can be orchestrated without an SSH downtime window if done
  carefully (register first, then push the new file to each host).
- **Revoke on compromise** by removing the host row (or replacing its token), so
  that host can no longer fetch keys.

---

## 3. Key storage

- SSH-Warden stores **public keys only**. Private keys never leave the user's
  workstation.
- Keys are validated and **normalized** on ingest (`pkg/sshutil`) so the database
  and the emitted `authorized_keys` always hold a canonical `type base64` form.
- A registered key grants nothing by itself — it is inert until paired with an
  active lease. This neutralizes the risk of a leaked/stolen key establishing
  access.

---

## 4. Database and filesystem hardening

### Server node

- Run the server under a **dedicated, non-login service account**
  (`ssh-warden`) as in the systemd example, or a non-root container user.
- Ensure `warden.db` and its WAL files are owned by that account and not
  world-readable: `-rw-rw----  ssh-warden ssh-warden`.
- Restrict file creation with `UMask=0077` (systemd) or equivalent.

### Target hosts

- `ssh-warden-helper`: owner `root:root`, mode `0755` — a compromised
  `nobody`-run SSH process must not be able to replace it.
- `/etc/ssh-warden/token`: owner `root:root`, mode `0600`.
- Run the helper with `AuthorizedKeysCommandUser nobody` so it executes
  unprivileged and cannot write to the filesystem.

---

## 5. OpenSSH hardening

On every target host, in addition to pointing `AuthorizedKeysCommand` at the
helper (`installation.md`):

```ini
# Disable password authentication — keys are now brokered by SSH-Warden.
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no

# Disable direct root login via password; if you use keys, keep it off
# unless explicitly required. Use a normal user + sudo instead.
PermitRootLogin prohibit-password
PermitRootLogin no

# Optional: restrict key algorithms to strong types.
PubkeyAcceptedAlgorithms ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512
```

Notes:

- `AuthorizedKeysCommand` output is limited in length by OpenSSH; keep the
  number of concurrent leases for a user small per host.
- Validate changes with `sshd -t` before reloading, and keep a maintenance
  session open (see `installation.md` → Testing safely).

---

## 6. mTLS configuration

SSH-Warden supports **mutual TLS (mTLS)** as an optional layer of
authentication between the OpenSSH host helpers and the Warden API. When
configured, both the server and the client validate each other's certificate,
providing stronger authentication than bearer tokens alone.

### Server-side setup

Set three environment variables when starting the server:

| Variable             | Description                                             |
|----------------------|---------------------------------------------------------|
| `WARDEN_TLS_CERT`    | Path to the server's TLS certificate (PEM).             |
| `WARDEN_TLS_KEY`     | Path to the server's TLS private key (PEM).             |
| `WARDEN_TLS_CA_CERT` | Path to the CA certificate that signed client certs.    |

When `WARDEN_TLS_CERT` and `WARDEN_TLS_KEY` are set, the server switches from
`ListenAndServe` to `ListenAndServeTLS` and begins serving HTTPS on `:8080`.

When `WARDEN_TLS_CA_CERT` is additionally set, the server requires all
connecting clients to present a valid client certificate signed by that CA.
The server enforces `tls.RequireAndVerifyClientCert` — unauthenticated HTTP
connections are refused.

```sh
WARDEN_TLS_CERT=server.crt \
WARDEN_TLS_KEY=server.key \
WARDEN_TLS_CA_CERT=ca.crt \
./bin/ssh-warden-server
```

### Client-side setup (helper)

The `ssh-warden-helper` reads the `WARDEN_TLS_CA_CERT` environment variable.
When set, it loads the CA certificate and uses it to verify the server's TLS
certificate over HTTPS. This prevents the helper from connecting to
unauthorized API endpoints.

```ini
# /etc/ssh/sshd_config
AuthorizedKeysCommand /usr/local/bin/ssh-warden-helper %u
AuthorizedKeysCommandUser nobody

# Environment for mTLS (can also be set in a wrapper script or systemd unit)
WARDEN_API_URL=https://warden.internal:8080
WARDEN_TLS_CA_CERT=/etc/ssh-warden/ca.crt
```

### Certificate generation example

```sh
# Generate a self-signed CA
openssl req -x509 -newkey rsa:4099 -days 365 -nodes \
  -keyout ca.key -out ca.crt -subj "/CN=SSH-Warden CA"

# Generate server certificate signed by the CA
openssl req -newkey rsa:4099 -nodes -keyout server.key \
  -out server.csr -subj "/CN=warden.internal"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt -days 365

# Generate a client certificate signed by the CA
openssl req -newkey rsa:4099 -nodes -keyout client.key \
  -out client.csr -subj "/CN=srv-prod-01"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out client.crt -days 365
```

Place `ca.crt`, `client.crt`, and `client.key` on each OpenSSH host under
`/etc/ssh-warden/` with `chmod 600` and `chown root:root`.

### When to use mTLS

mTLS is recommended when:

- Hosts are on an untrusted network and bearer tokens alone are insufficient.
- You want to enforce that only provisioned machines can query the API.
- Compliance requirements demand certificate-based authentication.

mTLS is optional and fully backward-compatible: hosts not configured with
`WARDEN_TLS_CA_CERT` continue to authenticate using bearer tokens.

---

## 7. Reverse proxy & TLS

The API carries sensitive payloads (public keys, host tokens in the
`Authorization` header, audit decisions). In production it **must** run behind
TLS. The API supports native mTLS (see section 6) or can run behind a reverse
proxy to terminate TLS.

### Recommended topology

```
warden CLI ──► HTTPS ──► reverse proxy ──► http://127.0.0.1:8080 (API)
host helper ─► HTTPS ───┘                    (bind API to loopback)
```

Terminating TLS at a proxy keeps the API simple while giving you:

- TLS certificate management (Let's Encrypt),
- HTTP/2, request-body size limits, and connection hardening,
- headers such as `X-Forwarded-For` that the API already honors when recording
  the client IP.

### Examples

**Traefik**:

```yaml
entryPoints:
  websecure:
    address: ":443"

# dynamic config
http:
  routers:
    warden:
      rule: "Host(`warden.example.com`)"
      service: warden
      tls:
        certResolver: le
  services:
    warden:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:8080"
```

**Caddy** (shortest):

```
warden.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

**Nginx** (snippet):

```nginx
server {
    listen 443 ssl;
    server_name warden.example.com;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header Host $host;
    }
}
```

### Notes

- Lock the published port to `127.0.0.1` on the server (no direct public TCP
  exposure to `:8080`).
- If you absolutely must run plain HTTP, restrict it to a trusted, isolated
  network segment — never the public internet.

---

## 8. OpenID Connect (OIDC) dashboard authentication

By default the `/ui` dashboard is protected by HTTP **Basic Auth**
(`WARDEN_UI_USER` / `WARDEN_UI_PASSWORD`) or left open with a warning banner.
For enterprise single sign-on you can instead protect it with **OpenID
Connect** (Authentik, Keycloak, Azure AD, Google, Discord, etc.). When OIDC is
enabled it **takes precedence over Basic Auth**.

### How it works

OIDC uses the **authorization-code flow**:

1. An unauthenticated visitor to `/ui` is redirected to `/auth/login`.
2. `/auth/login` generates a random `state`, stores it in a short-lived
   `HttpOnly` + `SameSite=Lax` cookie, and redirects to the identity provider.
3. The provider authenticates the user and redirects back to
   `/auth/callback` with a `code`.
4. `/auth/callback` verifies the `state` cookie (CSRF protection), exchanges
   the `code` for tokens, verifies the ID token's signature/issuer/audience
   against the provider's JWKS, and extracts the identity.
5. A signed `warden_session` cookie (`HttpOnly` + `SameSite=Lax`, HMAC-SHA256)
   is set, and the user lands on `/ui`.
6. `GET /auth/logout` clears the session cookie.

The session cookie is **HMAC-signed**, not merely base64-encoded: any tampering
with the payload invalidates the signature. It is only ever decoded server-side.

### Environment variables

| Variable                     | Description                                                        |
|------------------------------|--------------------------------------------------------------------|
| `WARDEN_OIDC_ENABLED`        | `"true"`/`"false"`, default `false`.                               |
| `WARDEN_OIDC_ISSUER_URL`     | OIDC issuer, e.g. `https://auth.example.com/application/o/warden/`.|
| `WARDEN_OIDC_CLIENT_ID`      | OIDC client ID.                                                    |
| `WARDEN_OIDC_CLIENT_SECRET`  | OIDC client secret.                                                |
| `WARDEN_OIDC_REDIRECT_URL`   | Callback URL registered with the IdP (e.g. `http://localhost:8080/auth/callback`). |
| `WARDEN_SESSION_SECRET`      | Random key used to sign session cookies (≥32 bytes).              |

### Security notes

- **`WARDEN_SESSION_SECRET` is the crown jewel.** Anyone holding it can forge
  sessions. Generate it with a CSPRNG and store it in a secret manager
  (`openssl rand -base64 32`).
- Session cookies are flagged `Secure` **only when the server is running TLS**
  (native mTLS or with `WARDEN_TLS_CERT`/`WARDEN_TLS_KEY`). On a plain-HTTP LAN
  deployment they are sent without the `Secure` flag so the flow works — make
  sure that network is trusted, or run behind the reverse proxy from section 7.
- Always register the exact `WARDEN_OIDC_REDIRECT_URL` in the IdP; mismatches
  cause the exchange to fail by design.
- The `state` cookie is single-use and enforced server-side (CSRF).

### Authentik example

Create an **OIDC provider** and application in Authentik and note the issuer,
client ID and client secret. Then set a `warden` outpost to expose them. On
the Warden server (e.g. via the systemd unit) add:

```ini
# /etc/ssh-warden/env (or the unit Environment= lines)
WARDEN_OIDC_ENABLED=true
WARDEN_OIDC_ISSUER_URL=https://auth.example.com/application/o/ssh-warden/
WARDEN_OIDC_CLIENT_ID=ssh-warden-client
WARDEN_OIDC_CLIENT_SECRET=change-me
WARDEN_OIDC_REDIRECT_URL=https://warden.example.com/auth/callback
WARDEN_SESSION_SECRET=$(openssl rand -base64 32)
```

In the Authentik provider, set **Redirect URIs/Origins** to the same
`WARDEN_OIDC_REDIRECT_URL`. After restarting the server, visiting `/ui`
redirects to Authentik's login page; on success the dashboard shows
**"Connecté en tant que <user> | Déconnexion"** in the header.

---

## 9. Webhook notifications

Webhooks can leak metadata to the receiving service. Decide consciously whether
you want the audited decisions (usernames, host names, IP addresses) to leave
your network:

- Use a **Discord** URL (contains `discord.com/api/webhooks`) for embed
  messages, or a **generic JSON** URL (Slack, Gotify, Ntfy) otherwise.
- Notifications are **asynchronous with a 3-second timeout** — they never block
  or slow the authorization decision.
- Keep webhook endpoints private/hard-to-guess, and prefer `https://`.

---

## 10. Summary checklist

- [ ] Server runs as a dedicated non-login user; DB files not world-readable.
- [ ] API bound to loopback; TLS terminated by a reverse proxy or mTLS enabled.
- [ ] mTLS CA and client certificates provisioned on hosts if using mutual TLS.
- [ ] Host tokens are `chmod 600`, root-owned, registered server-side, and
      never committed to git.
- [ ] Helper is root-owned `0755`, runs as `nobody`.
- [ ] `PasswordAuthentication no`; `PermitRootLogin` locked down.
- [ ] Audit trail reviewed (via `warden audit`) as part of change management.
- [ ] Webhook endpoint (if used) is HTTPS and its metadata is acceptable to
      share with the webhook provider.
- [ ] If OIDC is enabled: `WARDEN_SESSION_SECRET` is a CSPRNG secret in a
      secret manager, the redirect URL is exact-match in the IdP, and the
      dashboard is served over TLS (or a trusted LAN).