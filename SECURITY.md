# Security Policy

Thanks for helping keep SSH-Warden safe. This project manages access to
production systems, so security is taken seriously.

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.** Use the
private **Security Advisories** workflow instead:

1. Go to **Security → Report a vulnerability** on the repository.
2. Fill in the details: affected version/component, a summary of the issue, and
   how to reproduce it. Provide as much context as possible, but avoid including
   live credentials or tokens.
3. We will acknowledge the report promptly and work with your preferred timeline
   before anything is disclosed publicly.

If you are unable to use Security Advisories, contact the maintainers privately
through a direct channel rather than filing a public issue.

## Supported versions

Only the latest tagged release on `main` receives security fixes. Please upgrade
to the most recent release (`v0.1.1` or later) before reporting or relying on
patches.

## Security model

SSH-Warden enforces just-in-time, least-privilege SSH access:

- Public keys alone grant nothing; a non-expired **lease** for the target host
  is required.
- Leases are host-scoped, expire automatically, and can be revoked instantly.
- Host tokens are stored only as **SHA-256 digests** and compared in
  **constant time**.
- Every authorization decision is written to an **audit log**.

See [`docs/security.md`](docs/security.md) for the full threat model and
operational practices.