# Anoryx Sentinel — Deployment Attack Surface

This document covers the compose-stack attack surface for the F-010 Part 1 local
demo. It is written with honest language: "risk reduction" not "blocks all attacks",
"audit-ready" not "compliant".

## Exposed localhost ports (compose stack)

| Port  | Service                | Exposure                         |
|-------|------------------------|----------------------------------|
| 8000  | Gateway (sentinel-app) | All /v1 + /admin/* traffic       |
| 3000  | Admin console (Next.js)| Break-glass operator login UI    |
| 9001  | MinIO web console      | Bulk-storage admin (no auth TLS) |
| 5433  | Postgres               | Direct DB access (dev only)      |
| 4317  | OTel gRPC              | Trace ingestion                  |
| 4318  | OTel HTTP              | Trace ingestion                  |

All ports are bound to `0.0.0.0` by default in the compose stack. In a shared or
cloud environment, bind them to `127.0.0.1` by prefixing the port mapping:
`"127.0.0.1:8000:8000"`. The TLS profile (caddy, `docker compose --profile tls up`)
terminates TLS at 80/443 and is the recommended path for any internet-facing deploy.

## Admin token (break-glass)

`SENTINEL_ADMIN_TOKEN` is the single credential gating all `/admin/*` routes.

- Stored as a file-based Docker secret at `deploy/secrets/admin_token`.
- Mounted at `/run/secrets/admin_token`; the entrypoint exports it into the live
  process env. It is NEVER in the compose `environment:` block.
- `docker inspect sentinel-app` will not show the token value in `Config.Env`
  (threat vector 8 risk reduction).
- The frontend BFF reads it from `/run/secrets/admin_token` at container startup
  via the entrypoint override; the browser never receives this value.
- Risk: a user with host-level Docker access can read `/run/secrets/admin_token`
  inside the running container. Mitigate in production with Vault / External Secrets
  + restricted Docker socket access.

## File-based Docker secrets posture

Five secret files live in `deploy/secrets/` (git-ignored):

| File               | Contents                              |
|--------------------|---------------------------------------|
| postgres_password  | Postgres password for the `sentinel` role |
| redis_password     | Redis password (empty for bundled Redis)  |
| sentinel_key_secret| HMAC key for virtual API key fingerprints |
| admin_token        | Break-glass admin token               |
| session_secret     | Session cookie HMAC key               |

No password appears in `docker-compose.yml`, the `environment:` block, or
`docker inspect` output. The entrypoint assembles URLs at container start from
the mounted files. This is a risk reduction over plain env vars; it is NOT
equivalent to Vault/KMS (files persist on the host filesystem).

## Images run non-root

- Gateway / worker / seed: `uid 1000` (python:3.12-slim default non-root user).
- Admin console: `uid 1001` (`nextjs` user created in the frontend Dockerfile).

Running as non-root reduces the blast radius of a container escape or RCE but
does not prevent privilege escalation via misconfigured volume mounts or Docker
socket exposure.

## Dev-only settings (NEVER carry to production)

| Setting                  | Why dev-only                                               |
|--------------------------|------------------------------------------------------------|
| `NODE_ENV=development`   | Disables `Secure` flag on session cookie (plain HTTP only) |
| `postgres_password=sentinel` | Trivially guessable; use a strong random password in prod  |
| No TLS on gateway/console| Port 8000/3000 are plain HTTP; credentials in-flight unencrypted |
| MinIO default creds      | `minioadmin/minioadmin` — rotate in any internet-facing deploy |
| File secrets on host     | No HSM/KMS; secret files are readable by anyone with host access |

## Production hardening (Part 2 deferral)

The following hardening items are explicitly deferred to F-010 Part 2 (Helm/K8s):

- **Vault / KMS / External-Secrets Operator** for secret injection (no plaintext
  files on disk).
- **Helm chart** supporting both managed-cloud and self-hosted deployments.
- **KEDA** HPA on Redis Streams queue depth for bulk workers (scale to zero when idle).
- **OIDC/SAML SSO** configuration for enterprise operator authentication (F-014 has
  the backend; the Helm values inject IdP config at deploy time).
- **Public TLS** via Caddy auto-HTTPS or cert-manager (already scaffolded as a
  compose profile; Kubernetes uses cert-manager + ingress).
- **Network policies** restricting inter-service communication inside the cluster.
- **Read-only root filesystem** for containers.
- **Non-default Postgres password** and database-level audit logging.

## Known honest gaps

- The compose `postgres` service (port 5433) is accessible from the host with the
  default password. This is intentional for local dev convenience and must be
  restricted or replaced with a managed database in production.
- MinIO port 9001 (web console) has no password beyond the default `minioadmin`
  credentials. Restrict in production.
- The admin token is a static symmetric secret. It does not expire and is not
  scoped to a session. Per-operator attribution requires OIDC/SAML (F-014, already
  built) wired to the Helm deployment configuration.
- OTel collector ports (4317/4318) accept spans without authentication. In
  production, front them with mTLS or restrict to the cluster network only.
