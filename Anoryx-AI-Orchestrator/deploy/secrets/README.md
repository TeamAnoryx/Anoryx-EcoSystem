# Docker secrets — Anoryx-AI-Orchestrator (Docker Compose)

O-008 mounts credentials as **file-based Docker secrets** (mirrors Anoryx-Sentinel's
F-010, ADR-0012 §3), not environment variables. The `orchestrator-app` entrypoint
reads these files at `/run/secrets/*` and assembles the connection URLs / tokens at
startup, so no secret ever appears in `docker-compose.yml`, the container
`environment:`, or `docker inspect` output.

This directory is git-ignored (see `.gitignore`) — **the files you create here are
never committed.**

## Generate the secret files

Run from the repository root (`Anoryx-AI-Orchestrator/`):

```bash
bash deploy/secrets/gen-dev-secrets.sh
```

Or manually:

```bash
# 1. Postgres password — MUST match the postgres service password.
printf '%s' "${POSTGRES_PASSWORD:-orchestrator}" > deploy/secrets/postgres_password

# 2. Ingest HMAC signing secret (ORCH_INGEST_HMAC_SECRET) — random, 32+ bytes.
openssl rand -base64 48 > deploy/secrets/orch_ingest_hmac_secret

# 3. Admin/operator token (ORCH_ADMIN_TOKEN) — random, 32+ bytes.
openssl rand -base64 48 > deploy/secrets/orch_admin_token
```

## Required files

| File | Contents | Notes |
|------|----------|-------|
| `postgres_password` | Postgres password | Must equal the postgres service's `POSTGRES_PASSWORD`. |
| `orch_ingest_hmac_secret` | Random ≥32 bytes | HMAC key the ingest seam uses to verify Sentinel's signed events (`ORCH_INGEST_HMAC_SECRET`). |
| `orch_admin_token` | Random ≥32 bytes | Operator bearer for registry CRUD + the admin API/UI (`ORCH_ADMIN_TOKEN`). |

## Production note

The bundled Postgres is dev/demo-grade. For production, point the Orchestrator at
a managed Postgres instance (set `ORCH_DATABASE_URL` / `ORCH_APP_DATABASE_URL`
directly, or via a secret manager) — see `deploy/DEPLOY-K8s.md`. External Secrets
Operator / Vault / cloud KMS integration is documented future work (ADR-0008
§Honest deferrals), same posture Sentinel's own F-010 shipped with.
